"""SQLite persistence for API keys and scan history.

A connection is opened per operation rather than shared. FastAPI runs
sync endpoints in a thread pool, and SQLite connections are not safe to
share across threads. Opening per call is cheap and removes the problem
entirely.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

# Dashboard scans are attributed here so history queries need no special
# case for "the scan had no API key".
INTERNAL_KEY_ID = "key_internal_dashboard"

CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  key_hash      TEXT NOT NULL UNIQUE,
  threshold     REAL NOT NULL DEFAULT 0.30,
  rate_limit    INTEGER NOT NULL DEFAULT 60,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT,
  revoked_at    TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id             TEXT PRIMARY KEY,
  key_id         TEXT REFERENCES api_keys(id),
  source         TEXT NOT NULL,
  target         TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  score          REAL NOT NULL,
  verdict        TEXT NOT NULL,
  threshold      REAL NOT NULL,
  features       TEXT NOT NULL,
  warnings       TEXT NOT NULL,
  tls_verified   INTEGER,
  model_version  TEXT NOT NULL,
  elapsed_ms     INTEGER NOT NULL,
  created_at     TEXT NOT NULL,
  raw_html       TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_key_created
  ON scans(key_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS rate_windows (
  key_id       TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count        INTEGER NOT NULL,
  PRIMARY KEY (key_id, window_start)
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_sequence_lock = threading.Lock()
_last_stamp = [0, 0]  # [milliseconds, counter within that millisecond]


def _encode(value: int, width: int) -> str:
    out = ""
    for _ in range(width):
        out = CROCKFORD[value & 31] + out
        value >>= 5
    return out


def new_id(prefix: str) -> str:
    """Strictly increasing id: millisecond timestamp, then a counter, then
    randomness.

    The counter matters. Several scans can land in the same millisecond,
    and without it two ids from that millisecond would sort by their
    random tail — which would make 'newest first' ordering unreliable
    exactly when it is most likely to be tested.
    """
    with _sequence_lock:
        ms = int(time.time() * 1000)
        if ms == _last_stamp[0]:
            _last_stamp[1] += 1
        else:
            _last_stamp[0] = ms
            _last_stamp[1] = 0
        counter = _last_stamp[1]

    rand = "".join(secrets.choice(CROCKFORD) for _ in range(12))
    return f"{prefix}_{_encode(ms, 10)}{_encode(counter, 4)}{rand}"


@contextmanager
def connect(db_path: str):
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def create_key(db_path: str, name: str, threshold=None, rate_limit: int = 60):
    """Create a key. The plaintext is returned once and never recoverable."""
    key_id = new_id("key")
    plaintext = "sk_live_" + secrets.token_urlsafe(24)[:32]

    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO api_keys (id, name, key_hash, threshold, rate_limit, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                key_id,
                name,
                hash_key(plaintext),
                0.30 if threshold is None else float(threshold),
                int(rate_limit),
                utcnow(),
            ),
        )
    return key_id, plaintext


def find_key_by_hash(db_path: str, key_hash: str):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()


def list_keys(db_path: str):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT id, name, threshold, rate_limit, created_at, last_used_at,"
            " revoked_at FROM api_keys ORDER BY created_at"
        ).fetchall()


def revoke_key(db_path: str, key_id: str) -> bool:
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (utcnow(), key_id),
        )
        return cursor.rowcount > 0


def touch_key(db_path: str, key_id: str) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utcnow(), key_id)
        )


def ensure_internal_key(db_path: str, threshold: float) -> None:
    """The dashboard's own key row. No plaintext exists for it, so the
    hash is a value no real key can hash to."""
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO api_keys (id, name, key_hash, threshold,"
            " rate_limit, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                INTERNAL_KEY_ID,
                "dashboard",
                "internal-no-plaintext",
                float(threshold),
                100000,
                utcnow(),
            ),
        )


def save_scan(db_path: str, record: dict, store_raw_html: bool) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, key_id, source, target, content_sha256, score,"
            " verdict, threshold, features, warnings, tls_verified, model_version,"
            " elapsed_ms, created_at, raw_html)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record["id"],
                record["key_id"],
                record["source"],
                record["target"],
                record["content_sha256"],
                float(record["score"]),
                record["verdict"],
                float(record["threshold"]),
                json.dumps(record["features"]),
                json.dumps(record["warnings"]),
                None if record["tls_verified"] is None else int(record["tls_verified"]),
                record["model_version"],
                int(record["elapsed_ms"]),
                record.get("created_at") or utcnow(),
                record.get("raw_html") if store_raw_html else None,
            ),
        )


def _row_to_scan(row) -> dict:
    return {
        "id": row["id"],
        "source": row["source"],
        "target": row["target"],
        "score": row["score"],
        "verdict": row["verdict"],
        "threshold": row["threshold"],
        "features": json.loads(row["features"]),
        "warnings": json.loads(row["warnings"]),
        "tls_verified": None if row["tls_verified"] is None else bool(row["tls_verified"]),
        "model_version": row["model_version"],
        "elapsed_ms": row["elapsed_ms"],
        "created_at": row["created_at"],
    }


def list_scans(db_path: str, key_id: str, limit: int = 50, offset: int = 0):
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE key_id = ?"
            " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (key_id, int(limit), int(offset)),
        ).fetchall()
    return [_row_to_scan(r) for r in rows]


def count_scans(db_path: str, key_id: str) -> int:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE key_id = ?", (key_id,)
        ).fetchone()
    return row["n"]


def get_scan(db_path: str, key_id: str, scan_id: str):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND key_id = ?", (scan_id, key_id)
        ).fetchone()
    return _row_to_scan(row) if row else None
