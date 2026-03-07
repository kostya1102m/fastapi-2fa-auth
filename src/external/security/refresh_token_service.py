import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from src.config import settings
from src.domain.entities import RefreshSession


class RefreshTokenService:
    TOKEN_BYTES = 32
    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(RefreshTokenService.TOKEN_BYTES)

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def create_session(
        token: str,
        user_uid,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshSession:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
        )

        device_name = RefreshTokenService._parse_device(user_agent)

        return RefreshSession(
            token_hash=RefreshTokenService.hash_token(token),
            user_uid=user_uid,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
            device_name=device_name,
            created_at=now,
            expires_at=expires_at,
        )

    @staticmethod
    def _parse_device(user_agent: str | None) -> str | None:
        if not user_agent:
            return None

        ua = user_agent.lower()

        os_name = "Unknown"
        if "windows" in ua:
            os_name = "Windows"
        elif "mac os" in ua or "macintosh" in ua:
            os_name = "macOS"
        elif "linux" in ua:
            os_name = "Linux"
        elif "android" in ua:
            os_name = "Android"
        elif "iphone" in ua or "ipad" in ua:
            os_name = "iOS"

        browser = "Unknown"
        if "chrome" in ua and "edg" not in ua:
            browser = "Chrome"
        elif "firefox" in ua:
            browser = "Firefox"
        elif "safari" in ua and "chrome" not in ua:
            browser = "Safari"
        elif "edg" in ua:
            browser = "Edge"

        return f"{browser} on {os_name}"