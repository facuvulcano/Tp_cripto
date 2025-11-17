"""Pydantic schemas for request and response payloads."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Message(BaseModel):
    detail: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: str | None = Field(default=None, max_length=128)


class UserRead(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str]
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    pass


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AuditLogRead(BaseModel):
    id: str
    event_type: str
    created_at: datetime
    details: Optional[dict[str, Any]]

    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError("La contraseña debe tener al menos 12 caracteres")
        return value
