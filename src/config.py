from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = False
    APP_NAME: str = "auth-service"
    APP_VERSION: str = "0.1.0"
    BASE_URL: str = "http://localhost:8085"

    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    POSTGRES_DB: str

    POSTGRES_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    POSTGRES_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)

    @property
    def db_url(self) -> str:
        password = self.POSTGRES_PASSWORD.get_secret_value()
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{password}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}"
            f"/{self.POSTGRES_DB}"
        )

    JWT_ACCESS_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=60)
    JWT_ISSUER: str = "auth-service"
    JWT_AUDIENCE: str = "auth-service-api"


    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)
    MAX_SESSIONS_PER_USER: int = Field(default=10, ge=1, le=50)

    TOTP_ENCRYPTION_KEY: SecretStr
    TOTP_ISSUER_NAME: str = "AuthService"
    TOTP_VALID_WINDOW: int = Field(default=1, ge=0, le=3)

    @field_validator("TOTP_ENCRYPTION_KEY")
    @classmethod
    def validate_fernet_key(cls, v: SecretStr) -> SecretStr:
        import base64
        key = v.get_secret_value()
        try:
            decoded = base64.urlsafe_b64decode(key)
            if len(decoded) != 32:
                raise ValueError
        except Exception:
            raise ValueError(
                "TOTP_ENCRYPTION_KEY must be a valid Fernet key "
                "(32 bytes, URL-safe base64 encoded). "
                "Generate with: python -c "
                "'from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())'"
            )
        return v

    MAIL_USERNAME: str
    MAIL_PASSWORD: SecretStr
    MAIL_FROM: str
    MAIL_PORT: int = 587
    MAIL_SERVER: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False

    EMAIL_CONFIRM_TOKEN_EXPIRE_SECONDS: int = Field(default=900, ge=60)
    PASSWORD_RESET_TOKEN_EXPIRE_SECONDS: int = Field(default=900, ge=60)
    URL_SAFE_TOKEN_SECRET: SecretStr

    RATE_LIMIT_LOGIN_ATTEMPTS: int = Field(default=5, ge=1)
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = Field(default=300, ge=60)
    RATE_LIMIT_REGISTER_ATTEMPTS: int = Field(default=3, ge=1)
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = Field(default=3600, ge=60)

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
        if v not in allowed:
            raise ValueError(f"JWT_ALGORITHM must be one of {allowed}")
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == Environment.TESTING


def get_settings() -> Settings:
    return Settings()


settings = get_settings()