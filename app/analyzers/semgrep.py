import asyncio
import json
import time

from app.analyzers.port import AnalysisResult, AnalyzerFinding, AnalysisStatus
from app.core.config import settings
from app.core.logging import get_logger
from app.core.sandbox import create_temp_file, delete_temp_file
from app.models.analysis import AnalyzerType
from app.models.finding import Severity

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
        self, code: str, language: str, explanation_enabled: bool = False
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
            ruleset = ruleset.strip()
            if ruleset:
                args.extend(["--config", ruleset])

        args.extend(["--json", "--quiet", str(filepath)])

        logger.info("semgrep_command", args=" ".join(args))

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=TIMEOUT_SECONDS,
            )

        except asyncio.TimeoutError:
            process.kill()
            logger.warning("semgrep_timeout", timeout=TIMEOUT_SECONDS)
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message=f"Semgrep timed out after {TIMEOUT_SECONDS}s",
            )
        except FileNotFoundError:
            logger.error("semgrep_not_installed")
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message="Semgrep is not installed on this system",
            )

        # Exit codes: 0 = clean, 1 = findings found, other = error
        if process.returncode not in (0, 1):
            error_msg = stderr.decode("utf-8", errors="replace")[:500]
            logger.error(
                "semgrep_execution_failed",
                code=process.returncode,
                error=error_msg,
            )
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message=f"Semgrep failed with exit code {process.returncode}: {error_msg}",
            )

        return self._parse_output(stdout.decode("utf-8", errors="replace"))

    def _parse_output(self, raw_json: str) -> AnalysisResult:
        """Parse semgrep JSON output into AnalyzerFindings."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("semgrep_parse_error", raw=raw_json[:200])
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message="Failed to parse semgrep output",
            )

        findings = []
        for result in data.get("results", []):
            # Extract severity from extra.severity
            severity_str = result.get("extra", {}).get("severity", "INFO")
            severity = _SEVERITY_MAP.get(severity_str, Severity.LOW)

            # Extract line number from start.line
            line_number = result.get("start", {}).get("line", 0)

            # Extract rule ID from check_id (shorten for readability)
            check_id = result.get("check_id", "unknown")
            # "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
            # → take last meaningful segment
            rule_id = check_id.rsplit(".", 1)[-1] if "." in check_id else check_id

            # Extract message
            message = result.get("extra", {}).get("message", "No description")

            # Extract metadata for enrichment
            metadata = result.get("extra", {}).get("metadata", {})
            owasp = metadata.get("owasp", [])
            cwe = metadata.get("cwe", [])
            vuln_class = metadata.get("vulnerability_class", [])

            # Build explanation from metadata (Semgrep's version of "explanation")
            explanation_parts = []
            if vuln_class:
                explanation_parts.append(f"Vulnerability class: {', '.join(vuln_class)}")
            if owasp:
                explanation_parts.append(f"OWASP: {', '.join(owasp)}")
            if cwe:
                explanation_parts.append(f"CWE: {', '.join(cwe)}")
            explanation = ". ".join(explanation_parts) if explanation_parts else None

            findings.append(
                AnalyzerFinding(
                    severity=severity,
                    line_number=line_number,
                    rule_id=rule_id,
                    message=message,
                    explanation=explanation,
                )
            )

        logger.info("semgrep_completed", findings_count=len(findings))
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings,
        )