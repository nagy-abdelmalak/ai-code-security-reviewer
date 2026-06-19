from datetime import datetime, timezone
from uuid import UUID, uuid4
from sqlmodel import SQLModel, Field
from enum import Enum

class EventType(str, Enum):
    """Security-relevant events for the audit log (ADR-009)"""
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    USER_CREATED = "user_created"
    ROLE_CHANGED = "role_changed"
    SUBMISSION_CREATED = "submission_created"
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    REVIEW_CREATED = "review_created"
    REVIEW_UPDATED = "review_updated"

class AuditEvent(SQLModel, table=True):
    """
    Immutable audit log entry.
    No Update/delete endpoints exposed (ADR-009)
    """
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True)
    event_type: EventType
    details: str = ""
    created_at: datetime = Field(
        default_factory= lambda: datetime.now(timezone.utc)
    )
