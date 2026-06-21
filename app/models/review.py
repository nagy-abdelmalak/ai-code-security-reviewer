from uuid import UUID, uuid4
from sqlmodel import SQLModel, Field
from datetime import datetime, timezone

from app.models import FindingStatus

class Review(SQLModel, table=True):
    """
    An auditor's annotation on a finding (ADR-001)
    
    A Review optionally proposes a status change. When proposed_status
    is non-null, the service updates Finding.status to match.
    Comment-only reviews (proposed_status=None) leave the status unchanged.
    """
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    finding_id: UUID = Field(foreign_key="finding.id", index=True)
    auditor_id: UUID = Field(foreign_key="user.id", index=True)
    proposed_status: FindingStatus | None = None
    comment: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )