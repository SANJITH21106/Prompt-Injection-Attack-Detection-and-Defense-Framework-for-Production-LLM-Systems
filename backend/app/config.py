"""
Application configuration loaded from environment variables via pydantic-settings.
GEMINI_MODEL and all security weights are configurable — never hard-coded.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./prompt_defense.db"

    # --- Gemini API ---
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.5-flash"

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    # --- Security Decision Engine Weights ---
    RULE_WEIGHT: float = 0.25
    SQL_WEIGHT: float = 0.20
    ML_WEIGHT: float = 0.25
    GUARDRAIL_WEIGHT: float = 0.20
    CHUNK_WEIGHT: float = 0.05
    ANOMALY_WEIGHT: float = 0.05

    # --- Security Thresholds ---
    SANITIZE_THRESHOLD: float = 0.45
    BLOCK_THRESHOLD: float = 0.75

    model_config = {"env_file": ("backend/.env", ".env"), "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
