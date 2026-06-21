from datetime import time
import json
from pathlib import Path

from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage

from app.models import Severity, AnalyzerType
from app.core.logging import get_logger
from app.core.config import settings
from app.analyzers.port import AnalysisResult, AnalyzerFinding
from app.models import LLMProvider, AnalysisStatus

logger = get_logger(__name__)

PROMPT_DIR = Path(__file__).parent / "prompts"

_SEVERITY_MAP = {
    "critical": Severity.HIGH,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW
}

class LLMAnalyzer:
    """
    LLM-based security analyzer (ADR-004)

    Uses LangChain for provider abstraction.
    The prompt template is loaded from versioned files in /prompts
    """

    def __init__(
        self,
        prompt_version: str = "v1",
        provider: LLMProvider | None = None,
        model: str | None = None,
        api_key: str | None = None,
        temperature: float | None = None
    ):  
        self.prompt_version = prompt_version
        self.provider = provider or settings.LLM_PROVIDER
        self.model = model or settings.LLM_MODEL
        self.temperature = temperature or settings.LLM_TEMPERATURE
        self._api_key = api_key or settings.active_llm_key

        # Initialize LangChain LLM
        self._llm = init_chat_model(
            model=self.model,
            model_provider=self.provider.value,
            api_key=self._api_key,
            temperature=self.temperature
        )

        # Load prompt template
        prompt_path = PROMPT_DIR / f"{self._prompt_version}.txt"
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt template not found: {prompt_path}")
        self._prompt_template = prompt_path.read_text()

    
    @property
    def name(self) -> str:
        return self.provider
    
    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.LLM

    @property
    def version(self) -> str:
        return self.prompt_version
    
    async def analyze(
        self,
        code: str,
        language: str,
        explanation_enabled: bool = True,
    ) -> AnalysisResult:
        start = time.monotonic()

        # Build the prompt from template
        prompt = self._prompt_template.format(
            language=language,
            code=code,
        )

        logger.info(
            "llm_analysis_started",
            model=self._model,
            prompt_version=self._prompt_version,
            code_lines=len(code.splitlines()),
        )

        try:
            # Call the LLM via LangChain
            response = await self._llm.ainvoke([
                HumanMessage(content=prompt),
            ])

            elapsed = int((time.monotonic() - start) * 1000)
            raw_text = response.content.strip()

            # Parse response
            findings = self._parse_response(raw_text, explanation_enabled)

            logger.info(
                "llm_analysis_completed",
                model=self._model,
                findings_count=len(findings),
                duration_ms=elapsed,
            )

            return AnalysisResult(
                status=AnalysisStatus.COMPLETED,
                findings=findings,
                duration_ms=elapsed,
            )
        
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            logger.warning(
                "llm_analysis_failed",
                model=self._model,
                error=str(e),
                duration_ms=elapsed,
            )
            return AnalysisResult(
                status=AnalysisStatus.FAILED,
                error_message=f"LLM analysis failed: {str(e)}",
                duration_ms=elapsed,
            )
    
    def _parse_response(
        self, raw_text: str, explanation_enabled: bool
    ) -> list[AnalyzerFinding]:
        """Parse LLM JSON response into AnalyzerFindings"""
        # Strip markdown fences if present (LLMs sometimes add them)
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("llm_parse_error", raw_text=raw_text[:200])
            return []

        if not isinstance(data, list):
            logger.warning("llm_unexpected_format", type=type(data).__name__)
            return []

        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue

            severity_str = item.get("severity", "low").lower()
            findings.append(
                AnalyzerFinding(
                    severity=_SEVERITY_MAP.get(severity_str, Severity.LOW),
                    line_number=item.get("line_number", 0),
                    rule_id=item.get("rule_id", "llm-finding"),
                    message=item.get("message", "No description"),
                    explanation=(
                        item.get("explanation") if explanation_enabled else None
                    ),
                )
            )

        return findings