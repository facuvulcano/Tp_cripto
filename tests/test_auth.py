"""Service-level tests that validate the authentication flows."""
from __future__ import annotations

import os
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from starlette.responses import Response

os.environ.setdefault("DATABASE_URL", "sqlite:///./data/test.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("EMAIL_OUTBOX_DIR", "./data/test_outbox")
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app.config import get_settings  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.rate_limiter import rate_limiter  # noqa: E402
from app.schemas import ChangePasswordRequest, LoginRequest, UserCreate  # noqa: E402
from app.services.auth_service import AuthService  # noqa: E402

settings = get_settings()
service = AuthService(settings)


@pytest.fixture(autouse=True)
def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    rate_limiter._windows.clear()
    outbox_dir = Path(settings.email_outbox_dir)
    if outbox_dir.exists():
        for file in outbox_dir.glob("*.eml"):
            file.unlink()
    service.email_service.last_message = None


@pytest.fixture()
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _cookie_from_response(response: Response, name: str) -> str | None:
    cookie = SimpleCookie()
    for header, value in response.raw_headers:
        if header.decode("latin1").lower() == "set-cookie":
            cookie.load(value.decode("latin1"))
            if name in cookie:
                return cookie[name].value
    return None


def _register_user(db, email: str, password: str):
    return service.register_user(db, UserCreate(email=email, password=password, name="Tester"))


def test_register_and_login_flow(db_session) -> None:
    user = _register_user(db_session, "user@example.com", "Secreta123!XYZ")
    assert user.email == "user@example.com"

    response = Response()
    metadata = service.login(
        db_session,
        response=response,
        payload=LoginRequest(email=user.email, password="Secreta123!XYZ"),
        ip_address="10.0.0.1",
        user_agent="pytest",
    )
    assert "refresh_token_id" in metadata
    assert _cookie_from_response(response, settings.access_token_cookie_name)
    assert _cookie_from_response(response, settings.refresh_token_cookie_name)


def test_register_sends_verification_email(db_session) -> None:
    user = _register_user(db_session, "verify@example.com", "Secreta123!XYZ")
    message = service.email_service.last_message
    assert message is not None
    assert message["to"] == user.email
    assert "token=" in message["body"]

    verification_line = [line for line in message["body"].splitlines() if "token=" in line][0].strip()
    params = parse_qs(urlparse(verification_line).query)
    token = params.get("token", [None])[0]
    assert token

    service.verify_email(db_session, token=token)
    db_session.refresh(user)
    assert user.is_email_verified is True


def test_refresh_rotates_tokens(db_session) -> None:
    user = _register_user(db_session, "rotate@example.com", "OtraSecreta123!")
    login_response = Response()
    service.login(
        db_session,
        response=login_response,
        payload=LoginRequest(email=user.email, password="OtraSecreta123!"),
        ip_address="10.0.0.2",
        user_agent="pytest",
    )
    old_refresh = _cookie_from_response(login_response, settings.refresh_token_cookie_name)
    assert old_refresh is not None

    refresh_response = Response()
    tokens = service.refresh(
        db=db_session,
        response=refresh_response,
        refresh_token=old_refresh,
        ip_address="10.0.0.2",
        user_agent="pytest",
    )
    new_refresh = _cookie_from_response(refresh_response, settings.refresh_token_cookie_name)
    assert new_refresh is not None and new_refresh != old_refresh
    assert tokens["refresh_token_id"] != ""

    with pytest.raises(HTTPException):
        service.refresh(
            db=db_session,
            response=Response(),
            refresh_token=old_refresh,
            ip_address="10.0.0.2",
            user_agent="pytest",
        )


def test_change_password_revokes_tokens(db_session) -> None:
    user = _register_user(db_session, "change@example.com", "Original1234!")
    login_response = Response()
    service.login(
        db_session,
        response=login_response,
        payload=LoginRequest(email=user.email, password="Original1234!"),
        ip_address="10.0.0.3",
        user_agent="pytest",
    )
    refresh_cookie = _cookie_from_response(login_response, settings.refresh_token_cookie_name)

    service.change_password(
        db=db_session,
        user=user,
        payload=ChangePasswordRequest(current_password="Original1234!", new_password="NuevoSeguro123$"),
        response=Response(),
        ip_address="10.0.0.3",
        user_agent="pytest",
    )

    with pytest.raises(HTTPException):
        service.refresh(
            db=db_session,
            response=Response(),
            refresh_token=refresh_cookie,
            ip_address="10.0.0.3",
            user_agent="pytest",
        )

    with pytest.raises(HTTPException):
        service.login(
            db_session,
            response=Response(),
            payload=LoginRequest(email=user.email, password="Original1234!"),
            ip_address="10.0.0.3",
            user_agent="pytest",
        )

    second_response = Response()
    login = service.login(
        db_session,
        response=second_response,
        payload=LoginRequest(email=user.email, password="NuevoSeguro123$"),
        ip_address="10.0.0.3",
        user_agent="pytest",
    )
    assert login["refresh_token_id"] != ""


def test_account_lockout_after_multiple_failures(db_session) -> None:
    user = _register_user(db_session, "lock@example.com", "ContraseñaFuerte1$")
    attempts = settings.max_failed_login_attempts

    for i in range(attempts):
        with pytest.raises(HTTPException):
            service.login(
                db_session,
                response=Response(),
                payload=LoginRequest(email=user.email, password="bad"),
                ip_address=f"10.0.0.{i+1}",
                user_agent="pytest",
            )

    with pytest.raises(HTTPException) as exc:
        service.login(
            db_session,
            response=Response(),
            payload=LoginRequest(email=user.email, password="ContraseñaFuerte1$"),
            ip_address="10.0.0.99",
            user_agent="pytest",
        )
    assert exc.value.status_code == 403
