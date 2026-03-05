from typing import Any


class AppException(Exception):

    def __init__(self, message: str, details: Any = None):
        self.message = message
        self.details = details
        super().__init__(message)


class AuthenticationError(AppException):
    pass


class InvalidCredentialsError(AuthenticationError):

    def __init__(self):
        super().__init__("Invalid email or password")


class AccountNotActiveError(AuthenticationError):

    def __init__(self):
        super().__init__("Account is not active. Please confirm your email")


class TwoFactorRequiredError(AuthenticationError):

    def __init__(self):
        super().__init__("Two-factor authentication code is required")


class InvalidTwoFactorCodeError(AuthenticationError):

    def __init__(self):
        super().__init__("Invalid two-factor authentication code")


class AuthorizationError(AppException):
    pass


class InsufficientPermissionsError(AuthorizationError):

    def __init__(self, required_role: str | None = None):
        msg = "Insufficient permissions"
        if required_role:
            msg += f". Required role: {required_role}"
        super().__init__(msg)


class TokenError(AppException):
    pass


class TokenExpiredError(TokenError):
    def __init__(self):
        super().__init__("Token has expired")


class InvalidTokenError(TokenError):
    def __init__(self, reason: str = "Token is invalid"):
        super().__init__(reason)


class TokenRevokedException(TokenError):
    def __init__(self):
        super().__init__("Token has been revoked")


class UserError(AppException):
    pass


class UserAlreadyExistsError(UserError):

    def __init__(self, field: str = "email"):
        super().__init__(f"User with this {field} already exists")
        self.field = field


class UserNotFoundError(UserError):
    def __init__(self):
        super().__init__("User not found")


class PasswordValidationError(UserError):

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__(
            "Password does not meet requirements",
            details=violations,
        )


class SamePasswordError(UserError):
    def __init__(self):
        super().__init__("New password must differ from the current one")


class TwoFactorError(AppException):
    pass


class TwoFactorAlreadyEnabledError(TwoFactorError):
    def __init__(self):
        super().__init__("Two-factor authentication is already enabled")


class TwoFactorNotEnabledError(TwoFactorError):
    def __init__(self):
        super().__init__("Two-factor authentication is not enabled")


class RateLimitExceededError(AppException):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded. Retry after {retry_after} seconds"
        )