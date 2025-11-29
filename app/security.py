"""Security helpers: password hashing, JWT handling and cookie utilities."""
from __future__ import annotations

import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import get_settings

settings = get_settings()
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=settings.argon2_memory_cost,
    argon2__time_cost=settings.argon2_time_cost,
    argon2__parallelism=settings.argon2_parallelism,
)


class TokenError(Exception):
    """Raised when a JWT is invalid or expired."""


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def _base_claims(subject: str, token_type: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {"sub": subject, "iat": int(now.timestamp()), "type": token_type}


def create_access_token(user_id: str) -> tuple[str, datetime]:
    expires_delta = timedelta(minutes=settings.access_token_exp_minutes)
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {**_base_claims(user_id, "access"), "exp": int(expire.timestamp())}
    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt, expire


def create_refresh_token(user_id: str, token_id: str) -> tuple[str, datetime]:
    expires_delta = timedelta(minutes=settings.refresh_token_exp_minutes)
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        **_base_claims(user_id, "refresh"),
        "jti": token_id,
        "exp": int(expire.timestamp()),
    }
    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt, expire


def decode_token(token: str, expected_type: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:  # pragma: no cover - jose already tested
        raise TokenError(str(exc)) from exc

    if payload.get("type") != expected_type:
        raise TokenError("Tipo de token inválido")

    return payload


def generate_token_identifier() -> str:
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(16)


def generate_random_token() -> str:
    """Generate a high-entropy one-time token for email and password reset flows."""

    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return an HMAC-SHA256 hash of a token so only the digest is stored."""

    secret = settings.jwt_secret_key.encode("utf-8")
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def attach_cookie(
    response,
    *,
    name: str,
    value: str | None,
    expires: datetime | None,
    http_only: bool = True,
    same_site: str | None = None,
) -> None:
    """Attach a secure cookie to the response."""

    response.set_cookie(
        key=name,
        value="" if value is None else value,
        expires=0 if value is None else expires,
        httponly=http_only,
        secure=settings.cookie_secure,
        samesite=same_site or settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )
