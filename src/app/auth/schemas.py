from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from src.core.constants import UserRole
from src.core.security import PasswordValidator, PhoneValidator

_password_validator = PasswordValidator()


class _EmailNormalizationMixin(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()

class RegisterRequest(_EmailNormalizationMixin):
    username: str = Field(
        min_length=3, max_length=50, examples=["john_doe"],
    )
    password: str = Field(
        min_length=8, max_length=128, examples=["SecurePass1!"],
    )
    phone_number: str | None = Field(
        default=None, examples=["+79001234567"],
    )

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        v = v.strip()
        if not v.isascii():
            raise ValueError("Username must contain only ASCII characters")
        if " " in v:
            raise ValueError("Username must not contain spaces")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        _password_validator.validate(v)
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str | None) -> str | None:
        if v is not None:
            return PhoneValidator.validate(v)
        return v


class LoginRequest(_EmailNormalizationMixin):
    password: str
    totp_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=6,
        description="TOTP 2FA code (required if 2FA is enabled)",
    )


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(
        description="Access token expiration in seconds",
    )


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class PasswordResetRequest(_EmailNormalizationMixin):
    pass


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        _password_validator.validate(v)
        return v


class EmailConfirmRequest(BaseModel):
    token: str


class MessageResponse(BaseModel):
    message: str


class ActiveSessionResponse(BaseModel):
    device: str
    ip_address: str | None
    created_at: str
    last_used_at: str | None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    uid: UUID
    username: str
    email: EmailStr
    phone_number: str | None
    role: UserRole
    is_active: bool
    is_email_verified: bool
    two_factor_enabled: bool
    created_at: datetime
    updated_at: datetime


class LoginStep1Request(BaseModel):
    requires_2fa: bool
    auth_token: str
    expires_in: int = Field(
        description="Auth token expiration in seconds",
    )

class LoginStep2Request(BaseModel):
    """Второй шаг - только TOTP"""
    auth_token: str
    totp_code: str = Field(
        default=None,
        min_length=6,
        max_length=6,
        description="TOTP 2FA code",
    )

