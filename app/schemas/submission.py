from pydantic import BaseModel, Field

class SubmissionRequest(BaseModel):
    """payload for POST /submissions"""
    code: str = Field(min_length=1, max_length=1_000_000) # 1MB max (ADR-007)
    language: str = "python"
    run_llm: bool = False
    explanation_enabled: bool = False

class FindingResponse(BaseModel):
    id: str
    severity: str
    line_number: int
    rule_id: str
    message: str
    explanation: str | None = None
    status: str

class AnalaysisResponse(BaseModel):
    id: str
    analyze_type: str
    status: str
    finding_count: int
    findings: list[FindingResponse]
    error_message: str | None = None

class SubmissionResponse(BaseModel):
    id: str
    language: str
    source_mode: str
    created_at: str
    analyses: list[AnalaysisResponse]
