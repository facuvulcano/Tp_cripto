"""Shared FastAPI dependencies."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from . import models
from .config import get_settings
from .database import get_db
from .rate_limiter import rate_limiter
from .security import TokenError, decode_token

settings = get_settings()


def _extract_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1]
    return request.cookies.get(settings.access_token_cookie_name)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token faltante")

    try:
        payload = decode_token(token, expected_type="access")
    except TokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from None

    user = db.query(models.User).filter(models.User.id == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta inactiva")
    return user


def require_active_user(user: models.User = Depends(get_current_user)) -> models.User:
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta inactiva")
    return user


def require_csrf(request: Request) -> str:
    header_value = request.headers.get(settings.csrf_header_name)
    cookie_value = request.cookies.get(settings.csrf_cookie_name)
    if not header_value or not cookie_value or header_value != cookie_value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token inválido")
    return header_value


def rate_limit(request: Request) -> None:
    client_host = request.client.host if request.client else "unknown"
    key = f"{client_host}:{request.url.path}"
    if rate_limiter.is_limited(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiadas peticiones, inténtelo de nuevo más tarde",
        )
    rate_limiter.increment(key)
