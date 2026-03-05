from pydantic import BaseModel, EmailStr, Field, field_validator

from src.core.security import PasswordValidator, PhoneValidator

_password_validator = PasswordValidator()


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        _password_validator.validate(v)
        return v


class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(min_length=3, max_length=50)

    @field_validator("new_username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v.isascii():
            raise ValueError("Username must contain only ASCII characters")
        if " " in v:
            raise ValueError("Username must not contain spaces")
        return v


class ChangePhoneRequest(BaseModel):
    new_phone_number: str | None = None

    @field_validator("new_phone_number")
    @classmethod
    def validate_phone(cls, v: str | None) -> str | None:
        if v is not None:
            return PhoneValidator.validate(v)
        return v


class Enable2FAResponse(BaseModel):
    qr_code_base64: str = Field(
        description="Base64-encoded QR code PNG image"
    )
    secret: str = Field(
        description="TOTP secret for manual entry"
    )
    uri: str = Field(
        description="otpauth:// URI"
    )
    message: str = "Scan the QR code with your authenticator app, "  \
                   "then confirm with a code"


class Confirm2FARequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class Disable2FARequest(BaseModel):
    code: str = Field(
        min_length=6, max_length=6, pattern=r"^\d{6}$",
        description="Current TOTP code for confirmation",
    )
    password: str = Field(
        min_length=1,
        description="Current password for confirmation",
    )