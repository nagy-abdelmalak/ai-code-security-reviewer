import time
import asyncio
import json

from app.analyzers.port import AnalysisResult, AnalyzerFinding, Severity
from app.core.logging import get_logger
from app.core.sandbox import create_temp_file, delete_temp_file
from app.core.config import settings
from app.core.safe_subprocess import safe_subprocess
from app.models import AnalyzerType, AnalysisStatus

logger = get_logger(__name__)

_SEVERITY_MAP = {
    # Modern Semgrep Keys mapped to your 3-tier system
    "critical": Severity.HIGH,   # Upgraded to prevent missing critical exploits
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.LOW,        # Treated as low-risk informational notes

    # Legacy Backwards Compatibility (Crucial for community rulesets)
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
}

class SemgrepAnalyzer:
    """
    Static analysis via Semgrep. ADR-007 defense-in-depth:
    - Static only (no code execution)
    - Temp file with UUID name, mode 0600, deleted in finally
    - asyncio subprocess with list args (never shell=True)
    - 30s hard timeout with guaranteed process cleanup
    """
    @property
    def name(self) -> str:
        return "semgrep"
    
    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.SEMGREP
    
    @property
    def version(self) -> str:
        return "1.0"
    
    async def analyze(self, code: str, language: str, explanation_enabled: bool = False) -> AnalysisResult:
        start = time.monotonic()
        filepath = create_temp_file(code)

        try:
            result = await self._run_semgrep(filepath, language)
            elapsed = int((time.monotonic() - start) * 1000)
            result.duration_ms = elapsed 
            return result
        finally:
            delete_temp_file(filepath)

    async def _run_semgrep(self, filepath, language) -> AnalysisResult:
        logger.info(
            "inside_run_semgrep", 
            filepath=str(filepath), 
            language=language, 
            ruleset=settings.SEMGREP_RULESET
        )

        """Run semgrep subprocess with timeout (ADR-007)"""
        try:
            # 1. Initialize the process raw descriptor
            raw_process = await asyncio.create_subprocess_exec(
                "semgrep",
                "scan",                              # explicit subcommand
                "--config", settings.SEMGREP_RULESET, # e.g., "p/python" or "auto"
                "--json",
                "--quiet",
                str(filepath),                       # the file to scan
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )  

            # 2. Safely wrap execution inside the context manager
            async with safe_subprocess(raw_process) as process:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=settings.SEMGREP_TIMEOUT
                )

            # 3. Check for execution errors or bad configurations
            if process.returncode != 0 and not stdout:
                error_msg = stderr.decode("utf-8", errors="replace").strip()
                logger.error("semgrep_execution_failed", error=error_msg, code=process.returncode)
                return AnalysisResult(
                    status=AnalysisStatus.ERROR,
                    error_message=f"Semgrep execution faild with code {process.returncode}"
                )
            
            return self._parse_output(stdout.decode("utf-8", errors="replace"))

        except asyncio.TimeoutError:
            logger.warning("semgrep_timeout", timeout=settings.SEMGREP_TIMEOUT)
            return AnalysisResult(
                status=False,
                error_message=f"Semgrep timed out after {settings.SEMGREP_TIMEOUT}s",
            )
        except FileNotFoundError:
            logger.error("semgrep_not_installed")
            return AnalysisResult(
                status=False,
                error_message="Semgrep is not installed on this system",
            )
        except Exception as e:
            logger.exception("semgrep_unexpected_crash")
            return AnalysisResult(
                status=False,
                error_message=f"Unexpected internal analyzer error: {str(e)}"
            )
        
    def _parse_output(self, raw_json: str) -> AnalysisResult:
        """Parse semgrep JSON output into AnalyzerFindings"""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("semgrep_partial_payload_corruption")
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message="Payload corrupted mid-transfer"
            )
        
        results = data.get("results", [])

        limit_exceeded = len(results) > settings.MAX_FINDING_LIMIT

        findings = []
        for result in results[:settings.MAX_FINDING_LIMIT]:
            # 1. Safely extract and normalize the severity token to lowercase
            extra_data = result.get("extra", {})
            raw_severity = extra_data.get("severity", "low").strip().lower()
            result.get()
            # 2. Defensive resolution fallback: warn on unmapped tokens, default to HIGH/MEDIUM
            if raw_severity not in _SEVERITY_MAP:
                logger.warning("unknown_semgrep_severity_encountered", value=raw_severity)
                severity = Severity.HIGH  # Errs on the side of safety for unknown flags
            else:
                severity = _SEVERITY_MAP[raw_severity]

            # 3. Construct the clean domain-aligned finding object
            findings.append(
                AnalyzerFinding(
                    severity=severity,
                    line_number=result.get("start", {}).get("line", 0),
                    rule_id=result.get("check_id", "unknown"),
                    message=extra_data.get("message", "No description provided").strip()
                )
            )

            if limit_exceeded:
                logger.error("analyzer_findings_limit_exceeded", limit=settings.max_findings_limit)
                return AnalysisResult(
                    status=AnalysisStatus.FAILED,
                    findings=findings,  # Returns findings up to the limit threshold
                    error_message="Analysis halted: maximum allowed vulnerability findings cap exceeded."
                )

        logger.info("semgrep_completed", findings_count=len(findings))
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings
        )