from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError
from sqlmodel import Session

from app.models import Role, User
from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_session
from app.core.logging import get_logger
from app.services.analysis_service import (
    AnalysisOrchestrator,
    SubmissionRepository,
    AnalysisService
)
from app.analyzers import SemgrepAnalyzer, LLMAnalyzer, Analyzer

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

        # elif name == "bandit":
        #     try:
        #         analyzers.append(BanditAnalyzer())
        #         logger.info("sast_analyzer_loaded", name="bandit")
        #     except Exception as e:
        #         logger.warning("sast_analyzer_failed", name="bandit", error=str(e))

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
    all_configs = settings.get_llm_configs()
    if not all_configs:
        return []

    # Filter to user selection if provided
    if selected_models is not None:
        all_configs = [c for c in all_configs if c["value"] in selected_models]

    analyzers = []
    for config in all_configs:
        if not config["api_key"]:
            logger.warning(
                "llm_analyzer_skipped",
                reason="no_api_key",
                model=config["value"],
            )
            continue
        try:
            analyzers.append(LLMAnalyzer(
                provider=config["provider"],
                model=config["model"],
                api_key=config["api_key"],
                prompt_version=settings.LLM_PROMPT_VERSION,
            ))
            logger.info("llm_analyzer_loaded", model=config["value"])
        except Exception as e:
            logger.warning(
                "llm_analyzer_failed",
                model=config["value"],
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

def get_analysis_service(session: Session = Depends(get_session)) -> AnalysisService:
    """
    Factory dependency that automatically constructs the AnalysisService 
    with its full structural tree pre-assembled.
    """
    repo = SubmissionRepository(session)   
    analyzers = [SemgrepAnalyzer(), LLMAnalyzer()] 
    orchestrator = AnalysisOrchestrator(session=session, analyzers=analyzers)

    return AnalysisService(
        repo=repo,
        orchestrator=orchestrator,
        session=session
    )
