"""Application configuration and settings helpers."""
from __future__ import annotations

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Centralized configuration loaded from environment variables."""

    app_name: str = Field(default="Secure Login Service")
    environment: str = Field(default="development")
    database_url: str = Field(default="sqlite:///./data/app.db", env="DATABASE_URL")
    jwt_secret_key: str = Field(default="change-me", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256")
    access_token_exp_minutes: int = Field(default=5, env="ACCESS_TOKEN_MINUTES")
    refresh_token_exp_minutes: int = Field(default=60 * 24 * 7, env="REFRESH_TOKEN_MINUTES")
    max_refresh_token_ttl_minutes: int = Field(default=60 * 24 * 30)
    verification_token_exp_minutes: int = Field(default=60 * 24, env="VERIFICATION_TOKEN_MINUTES")
    verification_base_url: str = Field(default="http://localhost:8000/auth/verify-email")
    refresh_token_cookie_name: str = Field(default="refresh_token")
    access_token_cookie_name: str = Field(default="access_token")
    csrf_cookie_name: str = Field(default="csrf_token")
    csrf_header_name: str = Field(default="X-CSRF-Token")
    cookie_domain: str | None = Field(default=None)
    cookie_secure: bool = Field(default=False)
    cookie_samesite: str = Field(default="lax")
    refresh_cookie_samesite: str = Field(default="strict")
    email_from: str = Field(default="no-reply@example.com")
    email_outbox_dir: str | None = Field(default="./data/outbox")
    argon2_time_cost: int = Field(default=3)
    argon2_memory_cost: int = Field(default=65536)
    argon2_parallelism: int = Field(default=2)
    rate_limit_attempts: int = Field(default=6)
    rate_limit_window_seconds: int = Field(default=60)
    account_lock_minutes: int = Field(default=5)
    password_min_length: int = Field(default=12)

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Return a cached settings instance for the application."""

    return Settings()
