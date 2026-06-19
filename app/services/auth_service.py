from sqlmodel import Session, select

from app.models.user import Role, User
from app.schemas.auth import RegisterRequest, TokenResponse
from app.core.logging import get_logger
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token
)
from app.services.audit_service import AuditService
from app.models import EventType

logger = get_logger(__name__)

class EmailAlreadyRegistered(Exception):
    """Raised when attempting to register an email that already exists."""
    pass

class AuthService:
    def __init__(self, session: Session):
        self.session = session
        self.audit = AuditService(session)
    
    def register(self, req: RegisterRequest) -> User:
        existing = self.session.exec(
            select(User).where(User.email==req.email)
        ).first()
        if existing:
            logger.warning("registration_failed", email=req.email, reason="email_in_use")
            raise EmailAlreadyRegistered(req.email)
        
        user = User(
            email=req.email,
            password_hash=hash_password(req.password),
            role=Role.DEVELOPER
        )
        self.session.add(user)
        self.session.flush()

        self.audit.log(user.id, EventType.USER_CREATED, {"email": user.email, "role": user.role})
        self.session.commit()
        self.session.refresh(user)

        logger.info("user_registered", user_id=str(user.id), email=user.email)
        return user

    def _log_failed_login(self, reason: str, email: str, role: str, user_id: str = None):
        """Private helper function to eliminate repetive logging"""
        logger.warning("login_failed", email=email, reason=reason, user_id=user_id)
        self.audit.log(
            user_id, 
            EventType.LOGIN_FAILED, 
            {
                "reason": reason,
                "email": email,
                "role": role
            }
        )
        self.session.commit()

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.session.exec(
            select(User).where(User.email==email)
        ).first()
        
        if not user:
            self._log_failed_login(email=email, role=user.role.value, reason="user_not_found")
            return None
        
        if not user.is_active:
            self._log_failed_login(
                email=email, 
                reason="user_disabled", 
                user_id=str(user.id), 
                role= user.role.value
            )
            return None
        
        if not verify_password(password, user.password_hash):
            self._log_failed_login(
                email=email, 
                reason="bad_password", 
                user_id=str(user.id), 
                role= user.role.value
            )
            return None
        
        self.audit.log(user.id, EventType.LOGIN, {"email": email,  "role": user.role})
        self.session.commit()

        logger.info("login_success", user_id=str(user.id), email=email, role=user.role)
        return user
    
    def issue_tokens(self, user:User) -> TokenResponse:
        """Generate access + refresh JWT tokens for a successfully authenticated user"""
        return TokenResponse(
            access_token=create_access_token(subject=str(user.id), role=user.role.value),
            refresh_token=create_refresh_token(subject=str(user.id))
        )