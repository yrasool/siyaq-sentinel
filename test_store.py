import copy
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from sentinel import inspect_local_grid_scripts, read_events, render_html
from store import IncidentStore
from test_helpers import make_grid_repo


class IncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = IncidentStore(Path(self.directory.name) / "sentinel.db")
        self.events = read_events(Path(__file__).parent / "fixtures" / "parks-demo.jsonl")

    def test_reimport_is_idempotent_and_preserves_triage(self):
        self.assertEqual(self.store.ingest(self.events), (7, 2))
        case_id = self.store.cases()[0]["case_id"]
        self.assertTrue(self.store.set_status(case_id, "closed", "Reviewed local demo; no live effect."))
        self.assertEqual(self.store.ingest(self.events), (0, 2))
        case = self.store.cases()[0]
        self.assertEqual(case["status"], "closed")
        self.assertIn("Reviewed local demo", case["analyst_note"])
        self.assertIn("closed", render_html(self.store.cases(), self.store.events()))

    def test_changed_event_under_same_id_is_rejected(self):
        self.store.ingest(self.events)
        changed = copy.deepcopy(self.events[0])
        changed["outcome"] = "authorized"
        with self.assertRaisesRegex(ValueError, "reused with different content"):
            self.store.ingest([changed])
        self.assertEqual(len(self.store.events()), 7)

    def test_source_inspection_reimport_keeps_first_observation(self):
        repo = make_grid_repo(Path(self.directory.name) / "grid")
        first = inspect_local_grid_scripts(repo)
        later = copy.deepcopy(first)
        later["_time"] += timedelta(seconds=10)
        later["timestamp"] = later["_time"].isoformat().replace("+00:00", "Z")
        self.assertEqual(self.store.ingest([first]), (1, 1))
        self.assertEqual(self.store.ingest([later]), (0, 1))
        self.assertEqual(self.store.events()[0]["timestamp"], first["timestamp"])

    def test_status_requires_case_and_note(self):
        self.store.ingest(self.events)
        self.assertFalse(self.store.set_status("a" * 12, "closed", "checked"))
        with self.assertRaisesRegex(ValueError, "analyst note"):
            self.store.set_status(self.store.cases()[0]["case_id"], "closed", " ")

    def test_agent_trace_survives_storage(self):
        events = read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl")
        self.assertEqual(self.store.ingest(events), (1, 1))
        self.assertIn("scp", self.store.events()[0]["trace"]["proposed"])
        self.assertIn("Agent proposed", render_html(self.store.cases(), self.store.events()))

    def test_claude_note_overwrite_scenario_keeps_each_decision(self):
        self.store.ingest(self.events)
        case_id = self.store.cases()[0]["case_id"]
        self.store.set_status(case_id, "open", "Escalation unresolved; await source review.", "analyst-a")
        self.store.set_status(case_id, "closed", "Credential retry appears benign.", "analyst-b")
        self.store.set_status(case_id, "open", "Prior escalation still needs review.", "analyst-c")
        self.store.set_status(case_id, "closed", "Credential retry appears benign again.", "analyst-b")
        reopened = IncidentStore(self.store.path)
        case = next(item for item in reopened.cases() if item["case_id"] == case_id)
        self.assertEqual(len(case["decision_history"]), 4)
        self.assertEqual([item["analyst_id"] for item in case["decision_history"]],
                         ["analyst-a", "analyst-b", "analyst-c", "analyst-b"])
        self.assertIn("Escalation unresolved", case["decision_history"][0]["note"])
        self.assertIn("Escalation unresolved", render_html(reopened.cases(), reopened.events()))
        self.assertEqual(case["status"], "closed")

    def test_legacy_note_is_preserved_when_journal_is_added(self):
        self.store.ingest(self.events)
        case_id = self.store.cases()[0]["case_id"]
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.store.path)) as db:
            with db:
                db.execute("UPDATE cases SET status = 'closed', analyst_note = 'Earlier reasoning' WHERE case_id = ?", (case_id,))
        migrated = IncidentStore(self.store.path)
        self.assertEqual([item["note"] for item in migrated.cases()[0]["decision_history"]],
                         ["Earlier reasoning"])
        self.assertIn("original author and decision time unknown",
                      migrated.cases()[0]["decision_history"][0]["origin"])
        self.assertEqual(len(IncidentStore(self.store.path).cases()[0]["decision_history"]), 1)
        migrated.set_status(case_id, "open", "Review again", "analyst-a")
        self.assertEqual([item["note"] for item in migrated.cases()[0]["decision_history"]],
                         ["Earlier reasoning", "Review again"])


if __name__ == "__main__":
    unittest.main()
