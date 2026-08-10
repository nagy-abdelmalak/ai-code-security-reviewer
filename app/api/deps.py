from uuid import UUID
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError
from sqlmodel import Session

from app.models import Role, User
from app.core.config import settings, LLM_AVAILABLE_MODELS
from app.core.security import decode_token
from app.db.session import get_session
from app.core.logging import get_logger
from app.services.analysis_service import (
    AnalysisOrchestrator,
    SubmissionRepository,
    AnalysisService
)
from app.analyzers import SemgrepAnalyzer, LLMAnalyzer, Analyzer, BanditAnalyzer
from app.rag.port import Embedder
from app.rag.store import PgVectorKnowledgeStore
from app.services.grounding_service import GroundingService

logger = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def _build_sast_analyzers() -> list[Analyzer]:
    """Instantiate enabled SAST analyzers from config."""
    analyzers = []
    enabled = settings.get_sast_analyzers()

    for name in enabled:
        if name == "semgrep":
            try:
                analyzers.append(SemgrepAnalyzer())
                logger.info("sast_analyzer_loaded", name="semgrep")
            except Exception as e:
                logger.warning("sast_analyzer_failed", name="semgrep", error=str(e))

        elif name == "bandit":
            try:
                analyzers.append(BanditAnalyzer())
                logger.info("sast_analyzer_loaded", name="bandit")
            except Exception as e:
                logger.warning("sast_analyzer_failed", name="bandit", error=str(e))

        # elif name == "opengrep":
        #     try:
        #         analyzers.append(OpengrepAnalyzer())
        #         logger.info("sast_analyzer_loaded", name="opengrep")
        #     except Exception as e:
        #         logger.warning("sast_analyzer_failed", name="opengrep", error=str(e))

        else:
            logger.warning("unknown_sast_analyzer", name=name)

    return analyzers

def _build_llm_analyzers(selected_models: list[str] | None = None) -> list[Analyzer]:
    """
    Instantiate LLM analyzers.

    selected_models: list of "provider:model" strings chosen by the user.
                     If None, uses all configured in LLM_MODELS.
                     If empty list, returns no LLM analyzers.
    """
    available_models = LLM_AVAILABLE_MODELS
    if not available_models:
        return []

    # Filter to user selection if provided
    models = []
    if selected_models is not None:
        models = [m for m in selected_models if m in available_models]

    analyzers = []
    for model in models:
        config = settings.get_llm_config(model)
        if config is None:  # ← check None BEFORE accessing attributes
            logger.warning(
                "llm_analyzer_skipped",
                reason="no_api_key",
                model=model
            )
            continue
        try:
            analyzers.append(LLMAnalyzer(llm_config=config))
            logger.info("llm_analyzer_loaded", model=config.model)
        except Exception as e:
            logger.warning(
                "llm_analyzer_failed",
                model=config.model,
                error=str(e),
            )

    return analyzers

def get_current_user(
        token: str = Depends(oauth2_scheme),
        session: Session = Depends(get_session)
) -> User:
    """
    Extract and validate the current user from the JWT access token.

    Rejects: missing token, malformed token, expired token, refresh tokens,
    unknown user, disabled user.
    """
    CREDENTIALS_EXCEPTION = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        token_type = payload.get("type")
        if not user_id or token_type != "access":
            logger.warning("decoding_token_unsuccessful", reason="id_or_type_problem")
            raise CREDENTIALS_EXCEPTION
    except PyJWTError:
        logger.warning("decoding_token_unsuccessful", reason="generic_jwt_error")
        raise CREDENTIALS_EXCEPTION
    
    # Load user from DB
    user = session.get(User, UUID(user_id))
    if not user or not user.is_active:
        logger.warning("cant_load_from_db", reason="user_not_found_or_inactive")
        raise CREDENTIALS_EXCEPTION
    
    return user

def require_role(*allowed_roles: Role):
    """
    Factory: returns a dependency that asserts the user has one of the allowed roles.

    Usage on a route:
        @router.get("/admin-only")
        def admin_endpoint(user: User = Depends(require_role(Role.ADMIN))):
            ...
    """
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            logger.warning(
                "access_denied",
                user_id=str(user.id),
                user_role=user.role.value,
                required_roles=[r.value for r in allowed_roles]
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return checker

def get_analysis_service(
    session: Session = Depends(get_session),
    selected_llms: list[str] | None = None
) -> AnalysisService:
    """
    Build AnalysisService with all available analyzers.

    SAST analyzers: always all enabled ones from config.
    LLM analyzers: filtered by user selection if provided.
    Which analyzers actually RUN is decided by the orchestrator
    based on selected_llms list.
    """
    sast_analyzers = _build_sast_analyzers()
    llm_analyzers = _build_llm_analyzers(selected_models=selected_llms)
    analyzers = sast_analyzers + llm_analyzers

    repo = SubmissionRepository(session)
    orchestrator = AnalysisOrchestrator(session=session, analyzers=analyzers)

    return AnalysisService(
        repo=repo,
        orchestrator=orchestrator,
        session=session
    )

def get_embedder(request: Request) -> Embedder:
    return request.app.state.embedder

def get_grounding_service(
    session: Session = Depends(get_session),
    embedder: Embedder = Depends(get_embedder)
) -> GroundingService:
    store = PgVectorKnowledgeStore(session, embedder)
    return GroundingService