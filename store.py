"""Append-only local event store and analyst case state for SIYAQ Sentinel."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from sentinel import detect


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_event(event: dict) -> dict:
    """Keep only the event fields Sentinel needs; never persist arbitrary headers."""
    return {key: event[key] for key in ("id", "timestamp", "product", "action", "outcome", "actor_id")}


def _stored_event(event: dict) -> dict:
    result = _public_event(event)
    result["evidence"] = event.get("evidence", [])
    if "trace" in event:
        result["trace"] = event["trace"]
    if "signature" in event:
        result["signature"] = event["signature"]
    result["origin"] = event.get("_origin", "supplied event record")
    return result


def _loaded_event(value: str) -> dict:
    event = json.loads(value)
    event["_time"] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    event["_origin"] = event.pop("origin")
    return event


class IncidentStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    case_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
                    analyst_note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
                    analyst_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_legacy_decision_per_case
                ON decisions(case_id) WHERE analyst_id = 'legacy-unknown';
            """)
            db.execute("""
                INSERT OR IGNORE INTO decisions (case_id, status, analyst_id, note, recorded_at)
                SELECT c.case_id, c.status, 'legacy-unknown', c.analyst_note, c.updated_at
                FROM cases AS c
                WHERE c.analyst_note <> ''
                  AND NOT EXISTS (SELECT 1 FROM decisions AS d WHERE d.case_id = c.case_id)
            """)
            db.commit()

    def ingest(self, events: list[dict]) -> tuple[int, int]:
        added = 0
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                for event in events:
                    stored = _stored_event(event)
                    encoded = json.dumps(stored, sort_keys=True, separators=(",", ":"))
                    old = db.execute("SELECT event_json FROM events WHERE id = ?", (event["id"],)).fetchone()
                    if old:
                        prior = json.loads(old[0])
                        if prior != stored:
                            # A repeat local source inspection has the same content identity,
                            # but a new inspection time. Retain the first observation.
                            same_grid_source = (stored["origin"] == prior["origin"] ==
                                                "read-only local source inspection" and
                                                {k: v for k, v in stored.items() if k != "timestamp"} ==
                                                {k: v for k, v in prior.items() if k != "timestamp"})
                            if not same_grid_source:
                                raise ValueError(f"event ID {event['id']} was reused with different content")
                        continue
                    db.execute("INSERT INTO events (id, event_json) VALUES (?, ?)", (event["id"], encoded))
                    added += 1
                all_events = [_loaded_event(row[0]) for row in db.execute("SELECT event_json FROM events")]
                all_events.sort(key=lambda item: (item["_time"], item["id"]))
                cases = detect(all_events)
                for case in cases:
                    db.execute("""
                        INSERT INTO cases (case_id, case_json, status, updated_at)
                        VALUES (?, ?, 'open', ?)
                        ON CONFLICT(case_id) DO UPDATE SET case_json = excluded.case_json
                    """, (case["case_id"], json.dumps(case, sort_keys=True), _utc_now()))
        return added, len(cases)

    def events(self) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as db:
            result = [_loaded_event(row[0]) for row in db.execute("SELECT event_json FROM events")]
        return sorted(result, key=lambda item: (item["_time"], item["id"]))

    def cases(self) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT case_json, status, analyst_note, updated_at FROM cases").fetchall()
            decisions = db.execute("SELECT decision_id, case_id, status, analyst_id, note, recorded_at FROM decisions ORDER BY decision_id").fetchall()
        history: dict[str, list[dict]] = {}
        for decision_id, case_id, status, analyst_id, note, recorded_at in decisions:
            history.setdefault(case_id, []).append({"decision_id": decision_id, "status": status,
                                                       "analyst_id": analyst_id, "note": note,
                                                       "recorded_at": recorded_at,
                                                       "origin": ("legacy latest note; original author and decision time unknown"
                                                                  if analyst_id == "legacy-unknown" else "analyst action")})
        result = []
        for data, status, note, updated_at in rows:
            case = json.loads(data)
            case.update(status=status, analyst_note=note, updated_at=updated_at,
                        decision_history=history.get(case["case_id"], []))
            result.append(case)
        return sorted(result, key=lambda case: (case["first_seen"], case["case_id"]))

    def set_status(self, case_id: str, status: str, note: str, analyst_id: str = "local-analyst") -> bool:
        if not re.fullmatch(r"[0-9a-f]{12}", case_id):
            raise ValueError("invalid case ID")
        if status not in {"open", "closed"}:
            raise ValueError("status must be open or closed")
        if not note.strip() or len(note) > 2_000:
            raise ValueError("analyst note must contain 1-2000 characters")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", analyst_id):
            raise ValueError("analyst ID must be a 1-64 character pseudonym")
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                recorded_at = _utc_now()
                result = db.execute("UPDATE cases SET status = ?, analyst_note = ?, updated_at = ? WHERE case_id = ?",
                                    (status, note.strip(), recorded_at, case_id))
                if result.rowcount != 1:
                    return False
                db.execute("INSERT INTO decisions (case_id, status, analyst_id, note, recorded_at) VALUES (?, ?, ?, ?, ?)",
                           (case_id, status, analyst_id, note.strip(), recorded_at))
                return True
