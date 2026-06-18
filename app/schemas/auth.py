from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    """Payload for POST /auth/register."""
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    """Payload for POST /auth/login."""
    email: EmailStr
    password: str

class TokenRequest(BaseModel):
    """Response containing the JWT access + refresh tokens."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    """Payload for POST /auth/refresh."""
    refresh_token: str