"""Optional HMAC authentication for local Sentinel event imports."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path


DOMAIN = b"SIYAQ-SENTINEL-EVENT-V1\n"
PREFIX = "hmac-sha256-v1:"
KEY_BYTES = 32
SIGNABLE_FIELDS = frozenset(("id", "timestamp", "product", "action", "outcome", "actor_id", "evidence", "trace"))


def load_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise ValueError("event authentication key must contain exactly 32 bytes")
    return key


def create_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(secrets.token_bytes(KEY_BYTES))


def canonical_bytes(event: dict) -> bytes:
    extra = set(event) - SIGNABLE_FIELDS - {"signature"}
    if extra:
        raise ValueError("event contains fields outside the signed contract")
    payload = {field: event[field] for field in SIGNABLE_FIELDS if field in event}
    return DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_event(event: dict, key: bytes) -> str:
    if len(key) != KEY_BYTES:
        raise ValueError("event authentication key must contain exactly 32 bytes")
    return PREFIX + hmac.new(key, canonical_bytes(event), hashlib.sha256).hexdigest()


def verify_event(event: dict, key: bytes) -> bool:
    signature = event.get("signature")
    if not isinstance(signature, str) or len(signature) != len(PREFIX) + 64 or not signature.startswith(PREFIX):
        return False
    expected = sign_event(event, key)
    return hmac.compare_digest(signature, expected)
