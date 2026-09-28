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


if __name__ == "__main__":
    unittest.main()
