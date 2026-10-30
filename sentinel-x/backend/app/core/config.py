"""Application Configuration Module.

Loads and strictly validates environment variables using Pydantic Settings.
Fails safely and immediately when critical security or operational configuration is missing.
"""

from functools import lru_cache
from typing import Any, List, Literal, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Sentinel-X Application Settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application Metadata
    PROJECT_NAME: str = Field(default="Sentinel-X", description="Platform Name")
    VERSION: str = Field(default="1.0.0", description="Application Version")
    API_V1_PREFIX: str = Field(default="/api/v1", description="API v1 URL Prefix")
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = Field(
        default="development", description="Runtime Environment"
    )
    DEBUG: bool = Field(default=False, description="Debug Mode")
    LOG_LEVEL: str = Field(default="INFO", description="Structured Log Level")

    # Host & Port
    HOST: str = Field(default="0.0.0.0", description="Binding Host")
    PORT: int = Field(default=8000, description="Binding Port")

    # Database Configuration (PostgreSQL 16+)
    DATABASE_URL: str = Field(
        ...,
        description="PostgreSQL Database Connection String",
    )
    DB_POOL_SIZE: int = Field(default=10, description="Database connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="Maximum connection pool overflow")
    DB_POOL_PRE_PING: bool = Field(default=True, description="Validate connections before use")

    # Redis Configuration
    REDIS_URL: str = Field(
        ...,
        description="Redis Connection String",
    )

    # Celery Background Worker Configuration
    CELERY_BROKER_URL: Optional[str] = Field(default=None, description="Celery broker URL")
    CELERY_RESULT_BACKEND: Optional[str] = Field(default=None, description="Celery backend URL")

    # Authentication & Cryptographic Secrets (Required)
    JWT_SECRET: str = Field(
        ...,
        description="HMAC Secret for Access Tokens",
    )
    JWT_REFRESH_SECRET: str = Field(
        ...,
        description="HMAC Secret for Refresh Tokens",
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT Signing Algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15, description="Access token expiration in minutes"
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7, description="Refresh token expiration in days"
    )

    # Administrative & Machine Learning Security Keys (Required)
    ADMIN_BOOTSTRAP_SECRET: str = Field(
        ...,
        description="Bootstrap secret for initializing admin role/user",
    )
    MODEL_SIGNING_KEY: str = Field(
        ...,
        description="Cryptographic key for signing ML model artifacts",
    )

    # External Threat Intelligence APIs (Optional per Section 2, Principle 11)
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None, description="VirusTotal API key")
    ABUSEIPDB_API_KEY: Optional[str] = Field(default=None, description="AbuseIPDB API key")

    # Security & Traffic Controls
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins",
    )
    RATE_LIMIT_PER_MINUTE: int = Field(default=120, description="Rate limit quota per IP/minute")

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        """Parse CORS origins from JSON list or comma-separated string."""
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level string."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Invalid LOG_LEVEL '{v}'. Must be one of {valid_levels}")
        return upper_v

    @model_validator(mode="after")
    def validate_environment_integrity(self) -> "Settings":
        """Strict validation for production security and default fallbacks."""
        # Fallback Celery URLs to REDIS_URL if not set
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL

        # Production Strict Enforcement
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                raise ValueError("CRITICAL: DEBUG must not be True in production environment.")

            # Validate minimum secret length (32 chars)
            secrets_to_check = {
                "JWT_SECRET": self.JWT_SECRET,
                "JWT_REFRESH_SECRET": self.JWT_REFRESH_SECRET,
                "ADMIN_BOOTSTRAP_SECRET": self.ADMIN_BOOTSTRAP_SECRET,
                "MODEL_SIGNING_KEY": self.MODEL_SIGNING_KEY,
            }
            for secret_name, secret_val in secrets_to_check.items():
                if len(secret_val) < 32:
                    raise ValueError(
                        f"CRITICAL: {secret_name} must be at least 32 characters in production."
                    )
                insecure_keywords = (
                    "replace_with",
                    "insecure",
                    "default",
                    "change_me",
                    "secret123",
                )
                if any(kw in secret_val.lower() for kw in insecure_keywords):
                    raise ValueError(
                        f"CRITICAL: {secret_name} contains placeholder/insecure keyword in production."
                    )

            if "sqlite" in self.DATABASE_URL.lower():
                raise ValueError(
                    "CRITICAL: Production cannot use SQLite; PostgreSQL 16+ is required."
                )

        return self


@lru_cache()
def get_settings() -> Settings:
    """Load cached application settings instance. Fails safely if missing."""
    return Settings()
