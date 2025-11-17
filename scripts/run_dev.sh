#!/usr/bin/env bash
set -euo pipefail

export DATABASE_URL="${DATABASE_URL:-sqlite:///./data/app.db}"
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-dev-secret-change-me}"

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
