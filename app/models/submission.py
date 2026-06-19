from datetime import datetime, timezone
from uuid import UUID, uuid4
from sqlmodel import SQLModel, Field

class Submission(SQLModel, table=True):
    """A frozen snapshot of code submitted for analysis."""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True)
    code: str = Field(min_length=1)
    language: str = "python"
    source_mode: str = "paste"
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )