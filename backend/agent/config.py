from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from pathlib import Path

FREE_MODELS = {
    "minimax/minimax-m3:free",
    "qwen/qwen3-coder-plus:free",
    "qwen/qwen3-vl-plus:free",
    "qwen/qwen3.5-flash:free",
}

class AgentConfig(BaseSettings):
    xkiro_api_key: str = ""
    ai_provider: str = "xkiro"
    ai_base_url: str = "https://api.xkiro.com/v1"
    ai_primary_model: str = "minimax/minimax-m3:free"
    ai_coding_model: str = "qwen/qwen3-coder-plus:free"
    ai_vision_model: str = "qwen/qwen3-vl-plus:free"
    ai_fast_model: str = "qwen/qwen3.5-flash:free"
    ai_max_steps: int = 100
    ai_request_timeout: int = 120
    ai_require_approval_for_active_tests: bool = True
    ai_max_requests_per_scan: int = 500
    ai_max_concurrent_requests: int = 5

    @field_validator("ai_primary_model", "ai_coding_model", "ai_vision_model", "ai_fast_model")
    @classmethod
    def validate_free_model(cls, v: str) -> str:
        if v not in FREE_MODELS:
            raise ValueError(f"Model '{v}' is not an authorized free xKiro model. Allowed: {FREE_MODELS}")
        return v

    # Resolve the repository-root .env regardless of whether the process is
    # started from the repository root, backend/, or a packaged executable.
    model_config = SettingsConfigDict(
        env_file=(str(Path(__file__).resolve().parents[2] / ".env"), ".env"),
        extra="ignore",
    )

cfg = AgentConfig()
