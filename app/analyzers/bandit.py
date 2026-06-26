import json
import time

from app.analyzers.port import AnalysisResult, AnalyzerFinding, AnalysisStatus
from app.core.config import settings
from app.core.logging import get_logger
from app.core.sandbox import create_temp_file, delete_temp_file
from app.models.analysis import AnalyzerType
from app.models.finding import Severity
from app.analyzers.subprocess_runner  import run_subprocess

logger = get_logger(__name__)

TIMEOUT_SECONDS = 30

# Map semgrep severity strings to our Severity enum
_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class SemgrepAnalyzer:
    """
    Static analysis via bandit CE. ADR-007 defense-in-depth:
    - Static only (no code execution)
    - Temp file with UUID name, mode 0600, deleted in finally
    - asyncio subprocess with list args (never shell=True)
    - 30s hard timeout
    """

    @property
    def name(self) -> str:
        return "bandit"

    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.BANDIT

    @property
    def version(self) -> str:
        return f"Confidence: {settings.BANDIT_CONFIDENCE}, Severity {settings.BANDIT_SEVERITY}"

    async def analyze(
        self, code: str, 
        language: str, 
        explanation_enabled: bool = False
    ) -> AnalysisResult:
        start = time.monotonic()
        filepath = create_temp_file(code)

        try:
            result = await self._run_bandit(filepath)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        finally:
            delete_temp_file(filepath)

    async def _run_bandit(self, filepath) -> AnalysisResult:
        """Run semgrep subprocess with timeout. ADR-007 Layer 4."""

        # Build command with multiple rulesets from config
        args = [
            "bandit", "-f", "json",
            "--severity-level", settings.BANDIT_SEVERITY,
            "--confidence-level", settings.BANDIT_CONFIDENCE,
            str(filepath)
        ]

        logger.info("bandit_command", args=" ".join(args))

        result = await run_subprocess(args, tool_name="bandit")
        if result is None:
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message="Bandit timed out or is not installed"
        )

        stdout, stderr, returncode = result

        if returncode not in (0, 1):
            logger.error("bandit_execution_failed",
                            code=returncode, error=stderr[:300])
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message=f"Bandit failed with exit code {returncode}"
            )

        findings = self._parse_output(stdout)
        logger.info("bandit_completed", findings_count=len(findings))

        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings
        )

    def _parse_output(self, raw_json: str) -> AnalysisResult:
        """Parse bandit JSON output into AnalyzerFindings."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            test_id = result.get("test_id", "")
            more_info = result.get("more_info", "")
            explanation = f"{test_id} — {more_info}" if more_info else test_id or None

            findings.append(AnalyzerFinding(
                severity=_SEVERITY_MAP.get(
                    result.get("issue_severity", "LOW").upper(),
                    Severity.LOW,
                ),
                line_number=result.get("line_number", 0),
                rule_id=result.get("test_name", "bandit-finding"),
                message=result.get("issue_text", "No description"),
                explanation=explanation,
            ))

        return findings