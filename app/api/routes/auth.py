from fastapi import APIRouter, status, Depends, HTTPException
from sqlmodel import Session

from app.schemas.auth import UserResponse, RegisterRequest, TokenResponse, LoginRequest
from app.db.session import get_session
from app.services.auth_service import AuthService, EmailAlreadyRegistered
from app.api.routes.deps import get_current_user
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(req: RegisterRequest, session: Session = Depends(get_session)):
    service = AuthService(session)
    try:
        user = service.register(req)
    except EmailAlreadyRegistered:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    return UserResponse(
        id=str(user.id),
        email=user.email,
        role=user.role.value
    )

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, session: Session = Depends(get_session)):
    service = AuthService(session)
    user = service.authenticate(req.email, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    return service.issue_tokens(user)

@router.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user)):
    return UserResponse(
        id=str(user.id),
        email=user.email,
        role=user.role.value
    )