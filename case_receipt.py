"""Challenge-bound HMAC receipt for a redacted local incident snapshot."""

from __future__ import annotations

import hashlib
import hmac
import json
import re


DOMAIN = b"SIYAQ-SENTINEL-CASE-RECEIPT-V1\n"
EVENT_FIELDS = ("id", "timestamp", "product", "action", "outcome", "actor_id",
                "evidence", "trace", "signature", "_origin")


def snapshot(case: dict, events: list[dict]) -> dict:
    by_id = {event["id"]: event for event in events}
    return {"case": case,
            "events": [{field: by_id[event_id][field] for field in EVENT_FIELDS
                        if field in by_id[event_id]} for event_id in case["event_ids"]]}


def _body(payload: dict) -> bytes:
    return DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")


def make_receipt(case: dict, events: list[dict], key: bytes, challenge: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32,128}", challenge):
        raise ValueError("challenge must be 16-64 random bytes as lowercase hex")
    if len(key) != 32:
        raise ValueError("receipt key must contain exactly 32 bytes")
    payload = {"version": 1, "challenge": challenge, "snapshot": snapshot(case, events)}
    return {"payload": payload,
            "mac": hmac.new(key, _body(payload), hashlib.sha256).hexdigest()}


def verify_receipt(receipt: dict, key: bytes, challenge: str, current: dict | None = None) -> bool:
    if len(key) != 32 or not isinstance(receipt, dict) or set(receipt) != {"payload", "mac"}:
        return False
    payload, mac = receipt["payload"], receipt["mac"]
    if not isinstance(payload, dict) or set(payload) != {"version", "challenge", "snapshot"}:
        return False
    if payload["version"] != 1 or payload["challenge"] != challenge or not isinstance(mac, str):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", mac):
        return False
    expected = hmac.new(key, _body(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected) and (current is None or payload["snapshot"] == current)
