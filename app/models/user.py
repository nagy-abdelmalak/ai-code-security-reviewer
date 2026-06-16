from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel

class Role(str, Enum):
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    ADMIN = "admin"

class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    role: Role = Field(default=Role.DEVELOPER)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(defualt_factory=datetime.now(timezone.utc))