import uuid
from datetime import datetime, timedelta, timezone

import jwt

from src.config import settings
from src.core.constants import TokenType
from src.core.exceptions import InvalidTokenError, TokenExpiredError
from src.core.protocols import TokenServiceProtocol
from src.domain.entities import TokenPayload, UserEntity


class JWTService(TokenServiceProtocol):
    def create_access_token(self, user: UserEntity) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user.uid),
            "role": user.role.value,
            "type": TokenType.ACCESS.value,
            "exp": now + timedelta(
                minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
            ),
            "iat": now,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(
            payload,
            settings.JWT_ACCESS_SECRET_KEY.get_secret_value(),
            algorithm=settings.JWT_ALGORITHM,
        )

    def decode_access_token(self, token: str) -> TokenPayload:
        try:
            payload = jwt.decode(
                token,
                settings.JWT_ACCESS_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
                options={
                    "require": [
                        "sub", "exp", "iat", "iss", "aud", "jti", "type",
                    ],
                },
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(reason=str(e))

        if payload.get("type") != TokenType.ACCESS.value:
            raise InvalidTokenError(
                reason="Expected access token",
            )

        return TokenPayload(
            sub=uuid.UUID(payload["sub"]),
            role=payload["role"],
            token_type=payload["type"],
            exp=datetime.fromtimestamp(
                payload["exp"], tz=timezone.utc,
            ),
            iat=datetime.fromtimestamp(
                payload["iat"], tz=timezone.utc,
            ),
            iss=payload["iss"],
            aud=payload["aud"],
            jti=uuid.UUID(payload["jti"]),
        )
    
    def create_auth_token(
        self, 
        user: UserEntity
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user.uid),
            "role": user.role.value,
            "type": TokenType.AUTH.value,
            "exp": now + timedelta(
                minutes=settings.JWT_AUTH_TOKEN_EXPIRE_MINUTES,
            ),
            "iat": now,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(
            payload,
            settings.JWT_AUTH_SECRET_KEY.get_secret_value(),
            algorithm=settings.JWT_ALGORITHM,
        )
    
    def decode_auth_token(self, token: str) -> TokenPayload:
        try:
            payload = jwt.decode(
                token,
                settings.JWT_AUTH_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
                options={
                    "require": [
                        "sub", "exp", "iat", "iss", "aud", "jti", "type",
                    ],
                },
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(reason=str(e))

        if payload.get("type") != TokenType.AUTH.value:
            raise InvalidTokenError(
                reason="Expected auth token",
            )

        return TokenPayload(
            sub=uuid.UUID(payload["sub"]),
            role=payload["role"],
            token_type=payload["type"],
            exp=datetime.fromtimestamp(
                payload["exp"], tz=timezone.utc,
            ),
            iat=datetime.fromtimestamp(
                payload["iat"], tz=timezone.utc,
            ),
            iss=payload["iss"],
            aud=payload["aud"],
            jti=uuid.UUID(payload["jti"]),
        )