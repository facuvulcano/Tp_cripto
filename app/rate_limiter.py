"""Simple in-memory rate limiter for login attempts."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict

from .config import get_settings

settings = get_settings()


@dataclass
class AttemptWindow:
    attempts: int = 0
    window_started: float = field(default_factory=time.time)


class RateLimiter:
    """Tracks attempts per key (IP) to prevent brute force attacks."""

    def __init__(self) -> None:
        self._windows: Dict[str, AttemptWindow] = {}

    def increment(self, key: str) -> int:
        window = self._windows.get(key)
        now = time.time()
        if not window or now - window.window_started > settings.rate_limit_window_seconds:
            window = AttemptWindow(attempts=0, window_started=now)
            self._windows[key] = window
        window.attempts += 1
        return window.attempts

    def is_limited(self, key: str) -> bool:
        window = self._windows.get(key)
        if not window:
            return False
        return (
            time.time() - window.window_started <= settings.rate_limit_window_seconds
            and window.attempts >= settings.rate_limit_attempts
        )

    def reset(self, key: str) -> None:
        if key in self._windows:
            del self._windows[key]


rate_limiter = RateLimiter()
