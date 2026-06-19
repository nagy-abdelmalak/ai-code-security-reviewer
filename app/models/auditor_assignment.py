from datetime import datetime, timezone
from uuid import UUID, uuid4
from sqlmodel import Field, SQLModel

class AuditorAssignment(SQLModel, table=True):
    """Links an auditor to the developers they oversee (ADR-006)"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    auditor_id: UUID = Field(foreign_key="user.id", index=True)
    developer_id: UUID = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
