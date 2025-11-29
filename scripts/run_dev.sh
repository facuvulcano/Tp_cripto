#!/usr/bin/env bash
set -euo pipefail

export DATABASE_URL="${DATABASE_URL:-sqlite:///./data/app.db}"
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-dev-secret-change-me}"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

uvicorn app.main:app --reload --host "${HOST}" --port "${PORT}"
