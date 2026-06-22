from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.models import LLMProvider

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

    # --- Semgrep ---
    SEMGREP_RULESET: str = "p/python,p/security-audit"
    SEMGREP_TIMEOUT: int = 30
    # 500 is a safe, production-grade default threshold for a single file
    MAX_FINDING_LIMIT: int = 500
    
    # # --- LLM ---
    LLM_PROVIDER: LLMProvider = LLMProvider.GROQ
    LLM_MODEL: str = "llama-3.1-8b-instant"
    LLM_TEMPERATURE: float = 0.0
    GROQ_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # # --- Security ---
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # # --- Admin 1 ---
    INITIAL_ADMIN_EMAIL: str = "admin@example.com"
    INITIAL_ADMIN_PASSWORD: str = "ChangeMe_Password@123"

    # --- Logging ---
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_DIR: str = "./logs"
    LOG_TO_FILE: bool = False

    @field_validator("DB_POOL_MAX_SIZE")
    @classmethod
    def max_must_exceed_min(cls, max: int, info) -> int:
        min = info.data.get("DB_POOL_MIN_SIZE")
        if max < min:
            raise ValueError(
                f"DB_POOL_MAX_SIZE ({max}) must be >= DB_POOL_MIN_SIZE"
            )
        return max
    
    @property
    def is_production(self) -> bool:
      return self.ENVIRONMENT == 'production'
    
    @property
    def is_test(self) -> bool:
      return self.ENVIRONMENT == 'test'
    
    @property
    def active_llm_key(self) -> str:
        """Dynamically fetch the key belonging to the active provider."""
        provider_keys = {
            "groq": self.GROQ_API_KEY,
            "openai": self.OPENAI_API_KEY,
            "anthropic": self.ANTHROPIC_API_KEY,
            "gemini": self.GEMINI_API_KEY
        }
        
        key = provider_keys.get(self.LLM_PROVIDER)
        if not key:
            raise ValueError(f"Missing API key for configured provider: '{self.llm_provider}'")
        return key

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