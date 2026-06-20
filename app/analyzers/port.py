from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, Sequence, runtime_checkable

from app.models import Severity, AnalyzerType

class AnalysisStatus(str, Enum):
    """The status of an analysis"""
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"

@dataclass(frozen=True)
class AnalyzerFinding:
    """A finding as returned by an analyzer, before being saved to DB"""
    severity: Severity
    line_number: int
    rule_id: str
    message: str
    explanation: str | None = None

@dataclass
class AnalysisResult:
    """The outcome of running an analyzer on a piece of code"""
    status: AnalysisStatus
    findings: Sequence[AnalyzerFinding] = field(default_factory=tuple)
    error_message: str | None = None
    duration_ms: int = 0

@runtime_checkable
class Analyzer(Protocol):
    """
    A port for code analyzers. ADR-003
    Both SemgrepAnalyzer and LLMAnalyzer implement this interface.
    This service depends only on this protocol, not on the concrete analyzers
    """
    @property
    def name(self) -> str: ...

    @property
    def type(self) -> AnalyzerType: ...
    
    @property
    def version(self) -> str: ...

    async def analyze(self, code: str, language: str, explanation_enabled: bool) -> AnalysisResult:
        """Run the analyzer on the given code and return the result"""
        ...