import time
import json
import re
from pathlib import Path

from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage

from app.models import Severity, AnalyzerType
from app.core.logging import get_logger
from app.core.config import LLMConfig
from app.analyzers.port import AnalysisResult, AnalyzerFinding
from app.models import AnalysisStatus

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
        llm_config: LLMConfig
    ):  
        self.prompt_version = llm_config.prompt_version
        self.provider = llm_config.provider
        self.model = llm_config.model
        self.temperature = llm_config.temperature
        self._api_key = llm_config.api_key
        self.max_tokens = llm_config.max_tokens

        # Initialize LangChain LLM
        self._llm = init_chat_model(
            model=self.model,
            model_provider=self.provider,
            api_key=self._api_key,
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        # Load prompt template
        prompt_path = PROMPT_DIR / f"{self.prompt_version}.txt"
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt template not found: {prompt_path}")
        self._prompt_template = prompt_path.read_text()

    
    @property
    def name(self) -> str:
        return f"{self.provider}:{self.model}"
    
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
            model=self.model,
            prompt_version=self.prompt_version,
            code_lines=len(code.splitlines()),
        )

        try:
            # Call the LLM via LangChain
            response = await self._llm.ainvoke([
                HumanMessage(content=prompt),
            ])

            elapsed = int((time.monotonic() - start) * 1000)
            raw_text = (
                response.content
                if isinstance(response.content, str)
                else "".join(
                    block.get("text", "") if isinstance(block, dict) else str(block)
                    for block in response.content
                )
            ).strip()

            # Parse response
            findings = self._parse_response(raw_text, explanation_enabled)

            logger.info(
                "llm_analysis_completed",
                model=self.model,
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
                model=self.model,
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
        """Parse LLM JSON response into AnalyzerFindings."""
        if not raw_text:
            return []

        cleaned = raw_text.strip()

        # 1. Strip <think>...</think> tags FIRST (reasoning models like Qwen)
        if "<think>" in cleaned:
            think_end = cleaned.find("</think>")
            if think_end != -1:
                cleaned = cleaned[think_end + len("</think>"):].strip()
            else:
                # Unclosed <think> tag — take everything after it
                think_start = cleaned.find("<think>")
                cleaned = cleaned[think_start:]
                # Try to find JSON after the incomplete thinking
                bracket_pos = cleaned.rfind("[")
                if bracket_pos != -1:
                    cleaned = cleaned[bracket_pos:]
                else:
                    logger.warning("llm_no_json_after_think", raw_text=cleaned[:200])
                    return []

        # 2. Strip markdown fences
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()

        # 3. Try to find complete JSON array
        match = re.search(r"\[.*\]", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0).strip()
        else:
            # 4. Handle truncated JSON — try to repair by closing brackets
            if cleaned.startswith("["):
                cleaned = self._repair_truncated_json(cleaned)
            else:
                logger.warning("llm_no_json_array_found", raw_text=cleaned[:200])
                return []

        # 5. Parse JSON
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning("llm_parse_error", error=str(e), cleaned_text=cleaned[:200])
            return []

        if not isinstance(data, list):
            logger.warning("llm_unexpected_format", type=type(data).__name__)
            return []

        # 6. Map to findings
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


    def _repair_truncated_json(self, text: str) -> str:
        """
        Attempt to repair truncated JSON array by finding the last complete object.
        
        Example: '[{"a":1},{"b":2},{"c":3' → '[{"a":1},{"b":2}]'
        """
        # Find the last complete object (last '}' followed by nothing valid)
        last_complete = text.rfind("}")
        if last_complete == -1:
            return "[]"

        # Take everything up to and including the last complete '}'
        repaired = text[:last_complete + 1]

        # Remove trailing comma if present
        repaired = repaired.rstrip().rstrip(",")

        # Close the array
        repaired += "]"

        logger.info("llm_json_repaired", original_length=len(text), repaired_length=len(repaired))
        return repaired
    # def _parse_response(
    #     self, raw_text: str, explanation_enabled: bool
    # ) -> list[AnalyzerFinding]:
    #     """Parse LLM JSON response into AnalyzerFindings"""
    #     if not raw_text:
    #         return []
        
    #     # 1. Regex to locate the outermost JSON array structure safely
    #     # This ignores any prefix (like ```json) and any trailing conversational text.
    #     match = re.search(r"\[.*\]", raw_text, re.DOTALL)
    #     if not match:
    #         logger.warning("llm_no_json_array_found", raw_text=raw_text[:200])
    #         return []

    #     cleaned = match.group(0).strip()

    #     # Strip <think>...</think> tags
    #     if "<think>" in cleaned:
    #         think_end = cleaned.find("</think>")
    #     if think_end != -1:
    #         cleaned = cleaned[think_end + len("</think>"):].strip()

    #     try:
    #         data = json.loads(cleaned)
    #     except json.JSONDecodeError as e:
    #         # Include the exception error details for clearer local debugging
    #         logger.warning("llm_parse_error", error=str(e), cleaned_text=cleaned[:200])
    #         return []

    #     if not isinstance(data, list):
    #         logger.warning("llm_unexpected_format", type=type(data).__name__)
    #         return []

    #     findings = []
    #     for item in data:
    #         if not isinstance(item, dict):
    #             continue

    #         severity_str = item.get("severity", "low").lower()
    #         findings.append(
    #             AnalyzerFinding(
    #                 severity=_SEVERITY_MAP.get(severity_str, Severity.LOW),
    #                 line_number=item.get("line_number", 0),
    #                 rule_id=item.get("rule_id", "llm-finding"),
    #                 message=item.get("message", "No description"),
    #                 explanation=(
    #                     item.get("explanation") if explanation_enabled else None
    #                 ),
    #             )
    #         )

    #     return findings