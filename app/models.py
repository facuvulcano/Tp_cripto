"""SQLAlchemy models representing the authentication domain."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(128))
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True))
    last_login_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    auth_logs = relationship("AuthLog", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_id = Column(String(64), unique=True, nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    session_expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    replaced_by = Column(String(64))
    ip_address = Column(String(64))
    user_agent = Column(Text)

    user = relationship("User", back_populates="refresh_tokens")


class AuthLog(Base):
    __tablename__ = "auth_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    event_type = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ip_address = Column(String(64))
    user_agent = Column(Text)
    details = Column(JSON)

    user = relationship("User", back_populates="auth_logs")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))

    user = relationship("User")


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User")
