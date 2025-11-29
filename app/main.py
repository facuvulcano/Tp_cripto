"""FastAPI entrypoint exposing the secure authentication flows."""
from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import models, schemas
from .config import get_settings
from .database import get_db, init_db
from .dependencies import get_current_user, rate_limit, require_active_user, require_csrf
from .services.auth_service import AuthService

settings = get_settings()
auth_service = AuthService(settings)
app = FastAPI(title=settings.app_name, version="1.0.0")

# CORS can be restricted per deployment; defaults target localhost for demos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost", "http://127.0.0.1"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client_host = request.client.host if request.client else "0.0.0.0"
    return client_host


@app.get("/health", tags=["health"])
def healthcheck() -> dict:
    return {"status": "ok"}


@app.post("/auth/register", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED)
def register_user(*, payload: schemas.UserCreate, db: Session = Depends(get_db)) -> schemas.UserRead:
    user = auth_service.register_user(db, payload)
    return schemas.UserRead.from_orm(user)


@app.get("/auth/verify-email", response_model=schemas.Message)
def verify_email(token: str, db: Session = Depends(get_db)) -> schemas.Message:
    auth_service.verify_email(db, token=token)
    return schemas.Message(detail="Correo verificado")


@app.post("/auth/login", dependencies=[Depends(rate_limit)])
def login(
    *,
    payload: schemas.LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
):
    metadata = auth_service.login(
        db,
        response=response,
        payload=payload,
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"detail": "Autenticación exitosa", **metadata}


@app.post("/auth/refresh", dependencies=[Depends(rate_limit)])
def refresh_token(*, response: Response, request: Request, db: Session = Depends(get_db)):
    refresh_cookie = request.cookies.get(settings.refresh_token_cookie_name)
    if not refresh_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token faltante")

    metadata = auth_service.refresh(
        db=db,
        response=response,
        refresh_token=refresh_cookie,
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"detail": "Tokens renovados", **metadata}


@app.post("/auth/logout")
def logout(
    *,
    request: Request,
    response: Response,
    csrf_token: str = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    _ = csrf_token  # dependency already validated
    auth_service.logout(
        db=db,
        response=response,
        refresh_token=request.cookies.get(settings.refresh_token_cookie_name),
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"detail": "Sesión finalizada"}


@app.post("/auth/change-password")
def change_password(
    *,
    payload: schemas.ChangePasswordRequest,
    user: models.User = Depends(require_active_user),
    response: Response,
    request: Request,
    csrf_token: str = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    _ = csrf_token
    auth_service.change_password(
        db=db,
        user=user,
        payload=payload,
        response=response,
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"detail": "Contraseña actualizada"}


@app.post("/auth/forgot-password", response_model=schemas.Message)
def forgot_password(
    *,
    payload: schemas.ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    auth_service.initiate_password_reset(
        db=db,
        email=payload.email,
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return schemas.Message(detail="Si el correo existe, se ha enviado un enlace de recuperación")


@app.post("/auth/reset-password", response_model=schemas.Message)
def reset_password(
    *,
    payload: schemas.ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    auth_service.reset_password(
        db=db,
        token=payload.token,
        new_password=payload.new_password,
        ip_address=_get_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return schemas.Message(detail="Contraseña restablecida")


@app.post("/auth/mfa/setup", response_model=schemas.MfaSetupResponse)
def mfa_setup(user: models.User = Depends(require_active_user), db: Session = Depends(get_db)) -> schemas.MfaSetupResponse:
    return auth_service.mfa_setup(db=db, user=user)


@app.post("/auth/mfa/confirm", response_model=schemas.Message)
def mfa_confirm(
    payload: schemas.MfaConfirmRequest,
    user: models.User = Depends(require_active_user),
    db: Session = Depends(get_db),
) -> schemas.Message:
    auth_service.mfa_confirm(db=db, user=user, code=payload.code)
    return schemas.Message(detail="MFA habilitado")


@app.post("/auth/mfa/disable", response_model=schemas.Message)
def mfa_disable(
    payload: schemas.MfaDisableRequest,
    user: models.User = Depends(require_active_user),
    db: Session = Depends(get_db),
) -> schemas.Message:
    auth_service.mfa_disable(db=db, user=user, code=payload.code)
    return schemas.Message(detail="MFA deshabilitado")


@app.get("/auth/me", response_model=schemas.UserRead)
def read_profile(user: models.User = Depends(get_current_user)) -> schemas.UserRead:
    return schemas.UserRead.from_orm(user)


@app.get("/auth/logs", response_model=List[schemas.AuditLogRead])
def read_logs(user: models.User = Depends(require_active_user), db: Session = Depends(get_db)) -> List[schemas.AuditLogRead]:
    rows = (
        db.query(models.AuthLog)
        .filter(models.AuthLog.user_id == user.id)
        .order_by(models.AuthLog.created_at.desc())
        .limit(20)
        .all()
    )
    return [schemas.AuditLogRead.from_orm(row) for row in rows]
