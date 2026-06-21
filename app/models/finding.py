from enum import Enum
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field
from uuid import UUID, uuid4

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    UNREVIEWED = "unreviewed"

class Finding(SQLModel, table=True):
    """A single security issue found by an analyzer"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    analysis_id: UUID = Field(foreign_key="analysis.id", index=True)
    severity: Severity
    line_number: int = Field(gt=0)
    rule_id: str
    message: str
    explanation: str | None = None
    status: FindingStatus = FindingStatus.UNREVIEWED
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
