from pydantic import BaseModel, Field
from typing import Self 

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

class AnalysisResponse(BaseModel):
    id: str
    analyzer_type: str
    status: str
    findings_count: int
    findings: list[FindingResponse]
    error_message: str | None = None
    duration_ms: int | None = None

    @classmethod
    def from_orm(cls, analysis, findings) -> Self:
        return cls(
            id=str(analysis.id),
            analyzer_type=analysis.analyzer_type.value,
            status=analysis.status.value,
            findings_count=len(findings),
            error_message=analysis.error_message,
            duration_ms=(
                int((analysis.completed_at - analysis.started_at).total_seconds() * 1000)
                if analysis.completed_at and analysis.started_at
                else None
            ),
            findings=[
                FindingResponse(
                    id=str(f.id),
                    severity=f.severity.value,
                    line_number=f.line_number,
                    rule_id=f.rule_id,
                    message=f.message,
                    explanation=f.explanation,
                    status=f.status.value,
                )
                for f in findings
            ],
        )

class SubmissionResponse(BaseModel):
    id: str
    language: str
    source_mode: str
    created_at: str
    analyses: list[AnalysisResponse]

    @classmethod
    def from_orm(cls, submission, analyses_with_findings: list[tuple]) -> Self:
        """
        Build response from domain objects.
        analyses_with_findings: list of (Analysis, list[Finding]) tuples.
        """
        return cls(
            id=str(submission.id),
            language=submission.language,
            source_mode=submission.source_mode,
            created_at=submission.created_at.isoformat(),
            analyses=[
                AnalysisResponse.from_orm(analysis, findings)
                for analysis, findings in analyses_with_findings
            ],
        )
