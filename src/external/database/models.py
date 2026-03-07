import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from src.core.constants import UserRole


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    uid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    username: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    phone_number: Mapped[str | None] = mapped_column(
        String(20), unique=True, nullable=True, index=True
    )

    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role", create_constraint=True),
        default=UserRole.USER,
        server_default=UserRole.USER.value,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    two_factor_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    totp_secret: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    is_email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False,
        comment="Email confirmed via link",
    )

    __table_args__ = (
        Index("ix_users_email_active", "email", "is_active"),
        Index("ix_users_role", "role"),
    )

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.email})>"



class TokenBlacklistModel(Base):
    __tablename__ = "token_blacklist"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, index=True,
    )
    user_uid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    blacklisted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_token_blacklist_expires", "expires_at"),
    )


class UserTokenRevocationModel(Base):
    __tablename__ = "user_token_revocations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_uid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False, index=True,
    )
    revoked_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True,
    )

    actor_uid: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True,
    )

    target_uid: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True,
    )

    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True,
    )

    details: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(500), nullable=True,
    )
    request_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True,
    )

    success: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_audit_actor_action", "actor_uid", "action"),
        Index("ix_audit_created", "created_at"),
    )


class RefreshSessionModel(Base):
    __tablename__ = "refresh_sessions"

    id: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True,
    )

    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True,
        comment="SHA-256 hash of the refresh token",
    )

    user_uid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(500), nullable=True,
    )
    device_name: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
    )

    is_revoked: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    replaced_by: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
    )

    __table_args__ = (
        Index("ix_sessions_user_active", "user_uid", "is_revoked"),
        Index("ix_sessions_expires", "expires_at"),
    )