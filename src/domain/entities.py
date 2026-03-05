from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from src.core.constants import UserRole


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class UserEntity:
    uid: UUID = field(default_factory=uuid4)
    username: str = ""
    email: str = ""
    password_hash: str = ""
    phone_number: str | None = None
    role: UserRole = UserRole.USER
    is_active: bool = False
    two_factor_enabled: bool = False
    totp_secret: str | None = None
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    is_email_verified: bool = False

    @property
    def can_login(self) -> bool:
        return self.is_active and self.is_email_verified

    @property
    def is_admin(self) -> bool:
        return self.role in (UserRole.ADMIN, UserRole.OWNER)

    @property
    def is_owner(self) -> bool:
        return self.role == UserRole.OWNER


@dataclass
class TokenPayload:
    sub: UUID
    role: str
    token_type: str
    exp: datetime
    iat: datetime
    iss: str
    aud: str
    jti: UUID = field(default_factory=uuid4)


@dataclass
class RefreshSession:
    id: int | None = None
    token_hash: str = ""
    user_uid: UUID = field(default_factory=uuid4)
    ip_address: str | None = None
    user_agent: str | None = None
    device_name: str | None = None
    is_revoked: bool = False
    created_at: datetime = field(default_factory=_utc_now)
    expires_at: datetime = field(default_factory=_utc_now)
    last_used_at: datetime | None = None
    replaced_by: str | None = None

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired