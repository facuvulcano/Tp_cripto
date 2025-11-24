"""Audit logging utilities."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlalchemy.orm import Session

from . import models


class AuthEvent(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REFRESH_FAILURE = "token_refresh_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION_SENT = "email_verification_sent"
    EMAIL_VERIFIED = "email_verified"


def log_event(
    db: Session,
    *,
    event_type: AuthEvent,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    entry = models.AuthLog(
        user_id=user_id,
        event_type=event_type.value,
        ip_address=ip_address,
        user_agent=user_agent,
        details=metadata,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
