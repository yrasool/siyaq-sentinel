import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from event_auth import create_key, load_key, sign_event
from sentinel import read_events, render_html
from store import IncidentStore


class EventAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))  # Deterministic test material, never a production key.
        self.event = {
            "id": "signed-1", "timestamp": "2026-09-29T12:00:00Z", "product": "paperstack",
            "action": "media-fetch", "outcome": "blocked-redirect", "actor_id": "fixture-actor",
            "evidence": ["paperstack/src/lib/mediaPolicy.ts"],
        }

    def write_event(self, path, event):
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    def test_signed_event_is_verified_stored_and_labeled(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event.jsonl"
            event = self.event | {"signature": sign_event(self.event, self.key)}
            self.write_event(path, event)
            parsed = read_events(path, key=self.key)
            self.assertEqual(parsed[0]["_origin"], "HMAC-verified local event")
            store = IncidentStore(Path(directory) / "sentinel.db")
            self.assertEqual(store.ingest(parsed), (1, 1))
            self.assertEqual(store.events()[0]["signature"], event["signature"])
            self.assertIn("HMAC-verified local event", render_html(store.cases(), store.events()))
            self.assertEqual(store.ingest(parsed), (0, 1))

    def test_tamper_wrong_key_and_missing_key_fail_before_storage(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event.jsonl"
            event = self.event | {"signature": sign_event(self.event, self.key)}
            self.write_event(path, event)
            with self.assertRaisesRegex(ValueError, "requires a verification key"):
                read_events(path)
            with self.assertRaisesRegex(ValueError, "invalid event signature"):
                read_events(path, key=b"x" * 32)
            self.write_event(path, event | {"outcome": "allowed"})
            with self.assertRaisesRegex(ValueError, "invalid event signature"):
                read_events(path, key=self.key)
            self.write_event(path, self.event)
            with self.assertRaisesRegex(ValueError, "missing or invalid event signature"):
                read_events(path, key=self.key)

    def test_valid_new_signature_cannot_reuse_an_existing_id_with_new_content(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event.jsonl"
            store = IncidentStore(Path(directory) / "sentinel.db")
            self.write_event(path, self.event | {"signature": sign_event(self.event, self.key)})
            store.ingest(read_events(path, key=self.key))
            changed = self.event | {"outcome": "allowed"}
            self.write_event(path, changed | {"signature": sign_event(changed, self.key)})
            with self.assertRaisesRegex(ValueError, "reused with different content"):
                store.ingest(read_events(path, key=self.key))
            self.assertEqual(store.events()[0]["outcome"], "blocked-redirect")

    def test_key_generation_refuses_to_overwrite(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event.key"
            create_key(path)
            before = load_key(path)
            self.assertEqual(len(before), 32)
            with self.assertRaises(FileExistsError):
                create_key(path)
            self.assertEqual(load_key(path), before)

    def test_cli_rejects_tampered_input_before_creating_database(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            key_path = root / "event.key"
            key_path.write_bytes(self.key)
            event_path = root / "tampered.jsonl"
            event = self.event | {"signature": sign_event(self.event, self.key)}
            self.write_event(event_path, event | {"outcome": "allowed"})
            database = root / "sentinel.db"
            result = subprocess.run(
                [sys.executable, str(Path(__file__).parent / "app.py"), "--db", str(database),
                 "ingest", str(event_path), "--key-file", str(key_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid event signature", result.stderr)
            self.assertFalse(database.exists())


if __name__ == "__main__":
    unittest.main()
