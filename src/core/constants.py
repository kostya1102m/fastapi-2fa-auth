from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"
    OWNER = "owner"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value in cls._value2member_map_
    
class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class TokenPurpose(str, Enum):
    EMAIL_CONFIRMATION = "email_confirmation"
    PASSWORD_RESET = "password_reset"


class AuditAction(str, Enum):
    USER_REGISTERED = "user.registered"
    USER_LOGIN_SUCCESS = "user.login.success"
    USER_LOGIN_FAILED = "user.login.failed"
    USER_LOGOUT = "user.logout"
    USER_LOGOUT_ALL = "user.logout.all"
    TOKEN_REFRESHED = "token.refreshed"

    EMAIL_CONFIRMED = "email.confirmed"
    EMAIL_CONFIRMATION_SENT = "email.confirmation.sent"

    PASSWORD_CHANGED = "password.changed"
    PASSWORD_RESET_REQUESTED = "password.reset.requested"
    PASSWORD_RESET_COMPLETED = "password.reset.completed"

    USERNAME_CHANGED = "username.changed"
    PHONE_CHANGED = "phone.changed"

    TWO_FACTOR_SETUP = "2fa.setup"
    TWO_FACTOR_ENABLED = "2fa.enabled"
    TWO_FACTOR_DISABLED = "2fa.disabled"
    TWO_FACTOR_FAILED = "2fa.failed"

    ROLE_CHANGED = "role.changed"
    USER_DELETED = "user.deleted"
    USER_DEACTIVATED = "user.deactivated"
    USER_ACTIVATED = "user.activated"