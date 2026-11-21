"""Dependency-free audit helpers; adapters own durable storage."""
from __future__ import annotations
from typing import Any, Mapping

DEFAULT_SECRET_KEYS = frozenset({
    "authorization", "cookie", "set-cookie", "password", "token",
    "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "secret", "client_secret", "api_key", "apikey", "otp", "cvv",
})

def redact(value: Any, *, secret_keys: frozenset[str] = DEFAULT_SECRET_KEYS) -> Any:
    """Return a recursively redacted copy of JSON-like data."""
    if isinstance(value, Mapping):
        return {str(k): "[REDACTED]" if str(k).lower() in secret_keys
                else redact(v, secret_keys=secret_keys) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [redact(item, secret_keys=secret_keys) for item in value]
    return value

def summarize_decision(decision: str, reason: str | None = None) -> str:
    return f"decision={decision}" + (f" reason={reason}" if reason else "")
