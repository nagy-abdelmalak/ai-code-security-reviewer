from datetime import datetime, timezone
from uuid import UUID, uuid4
from enum import Enum
from sqlmodel import SQLModel, Field

class AnalyzerType(str, Enum):
    SEMGREP = "semgrep"
    LLM = "llm"

class AnalysisStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"

class Analysis(SQLModel, table=True):
    """One run of one analyzer on one submission"""
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    submission_id: UUID = Field(foreign_key="submission.id", index=True)
    status: AnalysisStatus
    analyzer_type: AnalyzerType
    prompt_version: str | None = Field(default=None)  # LLM only
    ruleset_version: str | None = Field(default=None)  # Semgrep only
    explanation_enabled: bool = Field(default=False)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    error_message: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))