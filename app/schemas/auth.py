from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    """Payload for POST /auth/register."""
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    """Payload for POST /auth/login."""
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    """Response containing the JWT access + refresh tokens."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    """Payload for POST /auth/refresh."""
    refresh_token: str

class UserResponse(BaseModel):
    """Public representation of a user (no password_hash, no is_active)."""
    id: str
    email: EmailStr
    role: str