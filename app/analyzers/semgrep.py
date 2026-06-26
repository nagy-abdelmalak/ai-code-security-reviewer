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
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAnalyzer:
    """
    Static analysis via Semgrep CE. ADR-007 defense-in-depth:
    - Static only (no code execution)
    - Temp file with UUID name, mode 0600, deleted in finally
    - asyncio subprocess with list args (never shell=True)
    - 30s hard timeout
    """

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.SEMGREP

    @property
    def version(self) -> str:
        return settings.SEMGREP_RULESET

    async def analyze(
        self, code: str, 
        language: str, 
        explanation_enabled: bool = False
    ) -> AnalysisResult:
        start = time.monotonic()
        filepath = create_temp_file(code)

        try:
            result = await self._run_semgrep(filepath)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        finally:
            delete_temp_file(filepath)

    async def _run_semgrep(self, filepath) -> AnalysisResult:
        """Run semgrep subprocess with timeout. ADR-007 Layer 4."""

        # Build command with multiple rulesets from config
        args = ["semgrep", "scan", "--no-git-ignore"]
        for ruleset in settings.SEMGREP_RULESET.split(","):
            if ruleset.strip():
                args.extend(["--config", ruleset.strip()])
        args.extend(["--json", "--quiet", str(filepath)])

        logger.info("semgrep_command", args=" ".join(args))

        result = await run_subprocess(args, tool_name="semgrep")
        if result is None:
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message="Semgrep timed out or is not installed"
            )

        stdout, stderr, returncode = result

        if returncode not in (0, 1):
            logger.error("semgrep_execution_failed",
                            code=returncode, error=stderr[:300])
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message=f"Semgrep failed with exit code {returncode}"
            )

        findings = self._parse_output(stdout)
        logger.info("semgrep_completed", findings_count=len(findings))

        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings
        )

    def _parse_output(self, raw_json: str) -> AnalysisResult:
        """Parse semgrep JSON output into AnalyzerFindings."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            severity_str = result.get("extra", {}).get("severity", "INFO")
            metadata = result.get("extra", {}).get("metadata", {})
            check_id = result.get("check_id", "unknown")

            owasp = metadata.get("owasp", [])
            cwe = metadata.get("cwe", [])
            vuln_class = metadata.get("vulnerability_class", [])
            explanation_parts = []
            if vuln_class:
                explanation_parts.append(f"Class: {', '.join(vuln_class)}")
            if owasp:
                explanation_parts.append(f"OWASP: {', '.join(owasp)}")
            if cwe:
                explanation_parts.append(f"CWE: {', '.join(cwe)}")

            findings.append(AnalyzerFinding(
                severity=_SEVERITY_MAP.get(severity_str, Severity.LOW),
                line_number=result.get("start", {}).get("line", 0),
                rule_id=check_id.rsplit(".", 1)[-1] if "." in check_id else check_id,
                message=result.get("extra", {}).get("message", "No description"),
                explanation=". ".join(explanation_parts) or None,
            ))

        return findings