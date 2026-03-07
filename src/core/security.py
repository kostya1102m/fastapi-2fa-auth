import hmac
import re
from dataclasses import dataclass

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from src.config import settings
from src.core.constants import TokenPurpose
from src.core.exceptions import (
    InvalidTokenError,
    PasswordValidationError,
    TokenExpiredError,
)
from src.core.protocols import URLSafeTokenServiceProtocol


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    special_characters: str = r"!@#$%^&*()_+-=[]{}|;:',.<>?/~`"


class PasswordValidator:
    def __init__(self, policy: PasswordPolicy | None = None):
        self._policy = policy or PasswordPolicy()

    def validate(self, password: str) -> None:
        violations: list[str] = []

        if len(password) < self._policy.min_length:
            violations.append(
                f"Password must be at least "
                f"{self._policy.min_length} characters long"
            )

        if len(password) > self._policy.max_length:
            violations.append(
                f"Password must not exceed "
                f"{self._policy.max_length} characters"
            )

        if self._policy.require_uppercase and not re.search(r"[A-Z]", password):
            violations.append(
                "Password must contain at least one uppercase letter"
            )

        if self._policy.require_lowercase and not re.search(r"[a-z]", password):
            violations.append(
                "Password must contain at least one lowercase letter"
            )

        if self._policy.require_digit and not re.search(r"\d", password):
            violations.append(
                "Password must contain at least one digit"
            )

        if self._policy.require_special and not re.search(
            r"[!@#$%^&*()_+\-=\[\]{}|;:',.<>?/~`]", password
        ):
            violations.append(
                "Password must contain at least one special character"
            )

        if violations:
            raise PasswordValidationError(violations)


class PhoneValidator:
    _PATTERN = re.compile(r"^\+[1-9]\d{6,14}$")

    @classmethod
    def validate(cls, phone: str) -> str:
        normalized = phone.strip().replace(" ", "").replace("-", "")
        if not cls._PATTERN.match(normalized):
            raise ValueError(
                "Phone number must be in international format: +XXXXXXXXXXX"
            )
        return normalized


class URLSafeTokenService(URLSafeTokenServiceProtocol):
    def __init__(self):
        self._serializer = URLSafeTimedSerializer(
            settings.URL_SAFE_TOKEN_SECRET.get_secret_value()
        )

    def create_token(self, data: dict, purpose: str) -> str:
        return self._serializer.dumps(data, salt=purpose)

    def decode_token(self, token: str, purpose: str, max_age: int) -> dict:
        try:
            data = self._serializer.loads(
                token,
                salt=purpose,
                max_age=max_age,
            )
            return data
        except SignatureExpired:
            raise TokenExpiredError()
        except BadSignature:
            raise InvalidTokenError(reason="Invalid or tampered token")


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())