"""HMAC-signed session cookie.

Hand-rolled rather than pulling in itsdangerous — it is a dozen lines
and the dependency buys nothing else here.
"""

import base64
import hashlib
import hmac

SEPARATOR = "."


def _signature(value: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def sign(value: str, secret: str) -> str:
    return f"{value}{SEPARATOR}{_signature(value, secret)}"


def verify(token: str, secret: str):
    if not token or SEPARATOR not in token:
        return None
    value, _, signature = token.rpartition(SEPARATOR)
    if not hmac.compare_digest(signature, _signature(value, secret)):
        return None
    return value
