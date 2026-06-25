from functools import lru_cache
from typing import Literal
from dataclasses import dataclass
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

@dataclass
class LLMConfig:
   """Class to hold specific LLM configurations"""
   provider: str
   model: str
   api_key: str
   temperature: float = 0.0  # For highly deterministic LLMs

class Settings(BaseSettings):
    # --- How Pydantic loads this ---
    model_config = SettingsConfigDict(
        env_file=".env",            # Read from .env in the working directory
        env_file_encoding="utf-8",
        core_sensitive=True,         
        extra="ignore"              # Ignore unknown env vars instead of crashing
    )

    # --- Application ---
    ENVIRONMENT: Literal["development", "test", "staging", "production"] = "development"
    PROJECT_NAME: str = "AI CODE SECURITY REVIEWER"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # --- Database ---
    DATABASE_URL: str = ""
    DB_POOL_MIN_SIZE: int = Field(default=2, ge=1, le=100)
    DB_POOL_MAX_SIZE: int = Field(default=10, ge=1, le=100)
    DB_POOL_TIMEOUT: float = 30.0

    # --- Admin ---
    INITIAL_ADMIN_EMAIL: str = "admin@example.com"
    INITIAL_ADMIN_PASSWORD: str = "ChangeMe_Password@123"

    # --- Security ---
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- Logging ---
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_DIR: str = "./logs"
    LOG_TO_FILE: bool = False

    # --- SAST ---
    ENABLED_SAST_ANALYZERS: str = "semgrep,bandit"
    SEMGREP_RULESET: str = "auto"  #"p/security-audit,p/python"
    BANDIT_SEVERITY: str = "medium"
    BANDIT_CONFIDENCE: str = "medium"

    # --- LLM Available Models ---
    """
    Comma-separated "provider:model" pairs.
    These appear in the UI dropdown and are selectable by the user.
    """
    LLM_AVAILABLE_MODELS: str = (
        "groq:qwen/qwen3.6-27b" ","
        "groq:llama-3.3-70b-versatile" ","
        "openrouter:qwen/qwen3-coder:free" ","
        "openrouter:openai/gpt-oss-20b:free" ","
        "openrouter:nvidia/nemotron-3-super-120b-a12b:free" ","
        "google:gemini-3.5-flash"
    )

    # --- LLM API keys ---
    GROQ_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # --- LLM defaults ---
    LLM_TEMPERATURE: float = 0.0
    LLM_MAX_TOKENS: int = 4096
    LLM_PROMPT_VERSION: str = "v1"

    def get_api_key(self, provider: str) -> str:
        """Return the API key for a given provider. Empty string if not set."""
        provider_keys = {
            "groq": self.GROQ_API_KEY,
            "gemini": self.GEMINI_API_KEY,
            "openrouter": self.OPENROUTER_API_KEY,
            "openai": self.OPENAI_API_KEY,
            "anthropic": self.ANTHROPIC_API_KEY,
        }
        return provider_keys.get(provider.lower(), "")

    def get_llm_config(self, provider_model_str: str) -> LLMConfig | None:
        """
        Resolve a 'provider:model' string into a fully configured LLMConfig.
        Returns None if the provider has no API key configured.
        """
        if ":" not in provider_model_str:
            return None

        provider, model = provider_model_str.split(":", 1)
        provider = provider.strip().lower()
        model = model.strip()

        api_key = self.get_api_key(provider)
        if not api_key:
            return None  # caller decides whether to warn or skip

        return LLMConfig(
            provider=provider,
            model=model,
            api_key=api_key,
            temperature=self.LLM_TEMPERATURE,
        )

    def get_available_models(self) -> list[LLMConfig]:
        """
        Return all LLMConfigs that have a valid API key.
        Used to populate the UI dropdown — only shows models the user can actually run.
        """
        configs = []
        for entry in self.LLM_AVAILABLE_MODELS.split(","):
            entry = entry.strip()
            if not entry:
                continue
            config = self.get_llm_config(entry)
            if config:
                configs.append(config)
        return configs

    def get_sast_analyzers(self) -> list[str]:
        return [a.strip().lower() for a in self.ENABLED_SAST_ANALYZERS.split(",") if a.strip()]
    
    @property
    def is_production(self) -> bool:
      return self.ENVIRONMENT == 'production'
    
    @property
    def is_test(self) -> bool:
      return self.ENVIRONMENT == 'test'

"""
lru_cache it tells python to create the below function only once, 
pull it from cache whenever you need it and no need to change the result.
When it get rexecuted:
 - different inputs
 - cache limit: with different inputs, different results gets saved in cache, setting
   limit @lru_cache(maxsize=128)tells python to drop the least recently
   used when the results saved exceed the limit (128 in this example)
 - manually clear cache: in this case getSettings().cache_clear()
 """
@lru_cache
def get_settings() -> Settings:
   return Settings()

settings = get_settings()