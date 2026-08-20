"""API key authentication and per-key rate limiting.

Rate limiting is a fixed window counted in SQLite. Two users do not
justify a Redis dependency, and counting in the database means the limit
survives a restart.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header

from api import store
from api.config import Settings, get_settings


class AuthError(Exception):
    def __init__(
        self, message: str, code: str, status: int, retry_after: Optional[int] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.retry_after = retry_after


def _bearer_token(header):
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def authenticate(db_path: str, header):
    token = _bearer_token(header)
    if not token:
        raise AuthError(
            "Provide your key as: Authorization: Bearer sk_live_...",
            "unauthorized",
            401,
        )

    row = store.find_key_by_hash(db_path, store.hash_key(token))
    if row is None or row["revoked_at"] is not None:
        raise AuthError("Unknown or revoked API key.", "unauthorized", 401)

    return row


def check_rate_limit(db_path: str, key_id: str, limit: int) -> None:
    now = datetime.now(timezone.utc)
    window = now.strftime("%Y-%m-%dT%H:%M")

    with store.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO rate_windows (key_id, window_start, count) VALUES (?, ?, 1)"
            " ON CONFLICT(key_id, window_start) DO UPDATE SET count = count + 1",
            (key_id, window),
        )
        row = conn.execute(
            "SELECT count FROM rate_windows WHERE key_id = ? AND window_start = ?",
            (key_id, window),
        ).fetchone()

        # Keep the table from growing without bound.
        conn.execute(
            "DELETE FROM rate_windows WHERE window_start < ?", (window,)
        )

    if row["count"] > limit:
        raise AuthError(
            f"Rate limit of {limit} requests per minute exceeded.",
            "rate_limited",
            429,
            retry_after=60 - now.second,
        )


def require_key(
    authorization: str = Header(default=None),
    settings: Settings = Depends(get_settings),
):
    """FastAPI dependency: authenticate, rate limit, record use."""
    row = authenticate(settings.db_path, authorization)
    check_rate_limit(settings.db_path, row["id"], row["rate_limit"])
    store.touch_key(settings.db_path, row["id"])
    return row
