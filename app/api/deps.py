from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError
from sqlmodel import Session

from app.models import Role, User
from app.core.security import decode_token
from app.db.session import get_session
from app.core.logging import get_logger
from app.services.analysis_service import (
    AnalysisOrchestrator,
    SubmissionRepository,
    AnalysisService
)
from app.analyzers import SemgrepAnalyzer, LLMAnalyzer

logger = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

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
        run_llm: bool = False
    ) -> AnalysisService:
    """
    Factory dependency that automatically constructs the AnalysisService 
    with its full structural tree pre-assembled.
    """
    analyzers = [SemgrepAnalyzer()]
    if run_llm:
        analyzers.append(LLMAnalyzer())

    repo = SubmissionRepository(session)    
    orchestrator = AnalysisOrchestrator(session=session, analyzers=analyzers)

    return AnalysisService(
        repo=repo,
        orchestrator=orchestrator,
        session=session
    )
