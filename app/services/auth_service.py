"""Business logic for the authentication flows."""
from __future__ import annotations

import logging
import re
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Response, status
from sqlalchemy import and_
from sqlalchemy.orm import Session

from .. import models, schemas
from ..audit import AuthEvent, log_event
from ..config import Settings, get_settings
from ..email_service import EmailService
from ..rate_limiter import rate_limiter
from ..security import (
    TokenError,
    attach_cookie,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_csrf_token,
    generate_token_identifier,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, settings: Settings | None = None, email_service: EmailService | None = None) -> None:
        self.settings = settings or get_settings()
        self.email_service = email_service or EmailService(self.settings)

    # -------------------- Registration --------------------
    def register_user(self, db: Session, payload: schemas.UserCreate) -> models.User:
        email = payload.email.lower()
        existing = db.query(models.User).filter(models.User.email == email).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El correo ya existe")

        self._validate_password_strength(payload.password)

        user = models.User(
            email=email,
            name=payload.name,
            password_hash=hash_password(payload.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        token = self._create_verification_token(db, user)
        self.email_service.send_verification_email(to_email=user.email, token=token)
        log_event(db, event_type=AuthEvent.EMAIL_VERIFICATION_SENT, user_id=user.id)
        return user

    # -------------------- Login --------------------
    def login(
        self,
        db: Session,
        *,
        response: Response,
        payload: schemas.LoginRequest,
        ip_address: str,
        user_agent: str | None,
    ) -> dict:
        email = payload.email.lower()
        user = db.query(models.User).filter(models.User.email == email).first()

        if rate_limiter.is_limited(ip_address):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Demasiados intentos")

        if not user:
            self._register_failed_attempt(db=db, user=None, email=email, ip_address=ip_address, user_agent=user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

        now = datetime.now(timezone.utc)
        locked_until = user.locked_until
        if locked_until and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until and locked_until > now:
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Cuenta temporalmente bloqueada")

        if not verify_password(payload.password, user.password_hash):
            self._register_failed_attempt(db=db, user=user, email=email, ip_address=ip_address, user_agent=user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

        self._clear_failures(user, db)
        user.last_login_at = now
        db.commit()
        db.refresh(user)

        tokens = self._issue_tokens(db, user, response, ip_address=ip_address, user_agent=user_agent)
        log_event(
            db,
            event_type=AuthEvent.LOGIN_SUCCESS,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        rate_limiter.reset(ip_address)
        return tokens

    # -------------------- Refresh --------------------
    def refresh(self, *, db: Session, response: Response, refresh_token: str, ip_address: str, user_agent: str | None) -> dict:
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except TokenError:
            log_event(db, event_type=AuthEvent.TOKEN_REFRESH_FAILURE, metadata={"reason": "decode_error"})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

        token_id = payload.get("jti")
        if not token_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

        token_record = (
            db.query(models.RefreshToken)
            .filter(models.RefreshToken.token_id == token_id, models.RefreshToken.revoked_at.is_(None))
            .first()
        )
        if not token_record:
            log_event(
                db,
                event_type=AuthEvent.TOKEN_REFRESH_FAILURE,
                metadata={"reason": "missing_token", "token_id": token_id},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

        if token_record.replaced_by:
            logger.warning("Refresh token reutilizado: %s", token_id)
            self._revoke_all_refresh_tokens(db, user_id=token_record.user_id)
            log_event(
                db,
                event_type=AuthEvent.TOKEN_REFRESH_FAILURE,
                user_id=token_record.user_id,
                metadata={"reason": "reused_token"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token comprometido")

        now = datetime.now(timezone.utc)
        absolute_limit = token_record.session_expires_at
        if absolute_limit.tzinfo is None:
            absolute_limit = absolute_limit.replace(tzinfo=timezone.utc)
        if now > absolute_limit:
            self._revoke_token(db, token_record)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="La sesión caducó")

        user = db.query(models.User).filter(models.User.id == token_record.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Cuenta inválida")

        # rotate token
        new_tokens = self._issue_tokens(
            db,
            user,
            response,
            ip_address=ip_address,
            user_agent=user_agent,
            session_expires_at=token_record.session_expires_at,
        )
        token_record.revoked_at = now
        token_record.replaced_by = new_tokens["refresh_token_id"]
        db.commit()

        log_event(
            db,
            event_type=AuthEvent.TOKEN_REFRESH,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return new_tokens

    # -------------------- Logout --------------------
    def logout(self, *, db: Session, response: Response, refresh_token: Optional[str], ip_address: str, user_agent: str | None) -> None:
        if refresh_token:
            try:
                payload = decode_token(refresh_token, expected_type="refresh")
            except TokenError:
                payload = None
            if payload and payload.get("jti"):
                token_record = (
                    db.query(models.RefreshToken)
                    .filter(models.RefreshToken.token_id == payload["jti"])
                    .first()
                )
                if token_record:
                    self._revoke_token(db, token_record)
                    log_event(
                        db,
                        event_type=AuthEvent.LOGOUT,
                        user_id=token_record.user_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                    )

        self._clear_cookies(response)

    # -------------------- Password change --------------------
    def change_password(
        self,
        *,
        db: Session,
        user: models.User,
        payload: schemas.ChangePasswordRequest,
        response: Response,
        ip_address: str,
        user_agent: Optional[str],
    ) -> None:
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña actual no es válida")

        self._validate_password_strength(payload.new_password)
        user.password_hash = hash_password(payload.new_password)
        db.add(user)
        db.commit()

        self._revoke_all_refresh_tokens(db, user_id=user.id)
        self._clear_cookies(response)

        log_event(
            db,
            event_type=AuthEvent.PASSWORD_CHANGED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    # -------------------- Email verification --------------------
    def verify_email(self, db: Session, *, token: str) -> None:
        token_hash = self._hash_token(token)
        record = (
            db.query(models.EmailVerificationToken)
            .filter(models.EmailVerificationToken.token_hash == token_hash)
            .first()
        )
        now = datetime.now(timezone.utc)
        if not record:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token inválido")
        if record.used_at:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token ya utilizado")
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expirado")

        user = record.user
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cuenta no disponible")
        user.is_verified = True
        record.used_at = now
        db.add_all([user, record])
        db.commit()

        log_event(db, event_type=AuthEvent.EMAIL_VERIFIED, user_id=user.id)

    # -------------------- Helpers --------------------
    def _issue_tokens(
        self,
        db: Session,
        user: models.User,
        response: Response,
        *,
        ip_address: str,
        user_agent: Optional[str],
        session_expires_at: Optional[datetime] = None,
    ) -> dict:
        access_token, access_exp = create_access_token(user.id)
        token_id = generate_token_identifier()
        refresh_token, refresh_exp = create_refresh_token(user.id, token_id)
        now = datetime.now(timezone.utc)
        session_limit = session_expires_at or now + timedelta(minutes=self.settings.max_refresh_token_ttl_minutes)

        record = models.RefreshToken(
            user_id=user.id,
            token_id=token_id,
            expires_at=refresh_exp,
            issued_at=now,
            session_expires_at=session_limit,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(record)
        db.commit()

        attach_cookie(
            response,
            name=self.settings.access_token_cookie_name,
            value=access_token,
            expires=access_exp,
            http_only=True,
            same_site=self.settings.cookie_samesite,
        )
        attach_cookie(
            response,
            name=self.settings.refresh_token_cookie_name,
            value=refresh_token,
            expires=refresh_exp,
            http_only=True,
            same_site=self.settings.refresh_cookie_samesite,
        )
        csrf_value = generate_csrf_token()
        attach_cookie(
            response,
            name=self.settings.csrf_cookie_name,
            value=csrf_value,
            expires=access_exp,
            http_only=False,
            same_site="lax",
        )

        return {
            "access_token_expires_at": access_exp.isoformat(),
            "refresh_token_expires_at": refresh_exp.isoformat(),
            "refresh_token_id": token_id,
        }

    def _register_failed_attempt(
        self,
        *,
        db: Session,
        user: Optional[models.User],
        email: str,
        ip_address: str,
        user_agent: Optional[str],
    ) -> None:
        now = datetime.now(timezone.utc)
        rate_limiter.increment(ip_address)
        metadata = {"email": email}
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= self.settings.rate_limit_attempts:
                user.locked_until = now + timedelta(minutes=self.settings.account_lock_minutes)
            db.add(user)
            db.commit()
            metadata["failed_attempts"] = user.failed_login_attempts
        log_event(
            db,
            event_type=AuthEvent.LOGIN_FAILURE,
            user_id=user.id if user else None,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )

    def _clear_failures(self, user: models.User, db: Session) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.add(user)

    def _validate_password_strength(self, password: str) -> None:
        if len(password) < self.settings.password_min_length:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Contraseña demasiado corta")
        patterns = [r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"]
        if not all(re.search(pattern, password) for pattern in patterns):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La contraseña debe incluir mayúsculas, minúsculas, dígitos y símbolos",
            )

    def _clear_cookies(self, response: Response) -> None:
        attach_cookie(response, name=self.settings.access_token_cookie_name, value=None, expires=None)
        attach_cookie(response, name=self.settings.refresh_token_cookie_name, value=None, expires=None)
        attach_cookie(response, name=self.settings.csrf_cookie_name, value=None, expires=None, http_only=False)

    def _revoke_token(self, db: Session, token: models.RefreshToken) -> None:
        if not token.revoked_at:
            token.revoked_at = datetime.now(timezone.utc)
            db.add(token)
            db.commit()

    def _revoke_all_refresh_tokens(self, db: Session, *, user_id: str) -> None:
        tokens = (
            db.query(models.RefreshToken)
            .filter(and_(models.RefreshToken.user_id == user_id, models.RefreshToken.revoked_at.is_(None)))
            .all()
        )
        if not tokens:
            return
        now = datetime.now(timezone.utc)
        for token in tokens:
            token.revoked_at = now
        db.bulk_save_objects(tokens)
        db.commit()

    def _create_verification_token(self, db: Session, user: models.User) -> str:
        token = generate_token_identifier()
        token_hash = self._hash_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.settings.verification_token_exp_minutes)
        record = models.EmailVerificationToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at)
        db.add(record)
        db.commit()
        return token

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
