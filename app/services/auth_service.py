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

logger = get_logger(__name__)

class EmailAlreadyRegistered(Exception):
    """Raised when attempting to register an email that already exists."""

class AuthService:
    def __init__(self, session: Session):
        self.session = session
    
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
        self.session.commit()
        self.session.refresh(user)

        logger.info("user_registered", user_id=str(user.id), email=user.email)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.session.exec(
            select(User).where(User.email==email)
        ).first()
        
        if not user:
            logger.warning("login_failed", email=email, reason="user_not_found")
            return None
        
        if not user.is_active:
            logger.warning("login_failed", email=email, reason="user_disabled", user_id=str(user.id))
            return None
        
        if not verify_password(password, user.password_hash):
            logger.warning("login_failed", email=email, reason="bad_password", user_id=str(user.id))
        
        logger.info("login_success", user_id=str(user.id), email=email, role=user.role)
        return user
    
    def issue_tokens(self, user:User) -> TokenResponse:
        """Generate access + refresh JWT tokens for a successfully authenticated user"""
        return TokenResponse(
            access_token=create_access_token(subject=str(user.id), role=user.role.value),
            refresh_token=create_refresh_token(subject=str(user.id))
        )