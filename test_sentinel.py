import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel import detect, inspect_local_grid_scripts, read_events, render_html
from test_helpers import make_grid_repo


class SentinelTests(unittest.TestCase):
    def test_demo_detects_parks_and_paperstack_without_control_alerts(self):
        events = read_events(Path(__file__).parent / "fixtures" / "parks-demo.jsonl")
        cases = detect(events)
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0]["event_ids"], ["e1", "e2", "e4"])
        self.assertEqual(cases[1]["event_ids"], ["e6"])
        self.assertIn("paperstack/src/lib/mediaPolicy.ts", cases[1]["source_refs"])
        self.assertEqual(cases, detect(events))
        self.assertNotIn("e5", cases[0]["event_ids"])
        self.assertNotIn("e7", cases[1]["event_ids"])

    def test_attempts_outside_window_do_not_alert(self):
        events = []
        for number, minute in enumerate((0, 11, 22), 1):
            events.append({"id": str(number), "timestamp": f"2026-09-25T12:{minute:02d}:00Z",
                           "_time": read_time(minute), "product": "parks", "action": "refresh",
                           "outcome": "unauthorized", "actor_id": "a"})
        self.assertEqual(detect(events), [])

    def test_html_escapes_event_values(self):
        events = read_events(Path(__file__).parent / "fixtures" / "parks-demo.jsonl")
        for event in events:
            if event["actor_id"] == "demo-actor-a":
                event["actor_id"] = "<script>alert(1)</script>"
        page = render_html(detect(events), events)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_local_grid_inspection_matches_recognized_scripts(self):
        with TemporaryDirectory() as directory:
            repo = make_grid_repo(Path(directory))
            event = inspect_local_grid_scripts(repo)
            self.assertIsNotNone(event)
            self.assertEqual(event["outcome"], "build-test-mismatch")
            self.assertEqual(event["evidence"], ["package.json", "apps/grid/package.json", "scripts/deploy-cf-worker.mjs"])
            events = read_events(Path(__file__).parent / "fixtures" / "parks-demo.jsonl")
            self.assertEqual(len(detect(events + [event])), 3)
            (repo / "package.json").write_text('{"scripts": {"cf:deploy:grid": "npm run check"}}', encoding="utf-8")
            self.assertIsNone(inspect_local_grid_scripts(repo))

    def test_rejects_invalid_evidence_shape(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('{"id":"x","timestamp":"2026-09-25T12:00:00Z","product":"grid","action":"release-check","outcome":"build-test-mismatch","actor_id":"a","evidence":{"secret":"value"}}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "evidence must be a list"):
                read_events(path)

    def test_agent_trace_is_case_not_attack_claim(self):
        events = read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl")
        cases = detect(events)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["rule"], "agent-action-scope-review-v1")
        page = render_html(cases, events)
        self.assertIn("scp command was proposed", page)
        self.assertIn("not proof that a command ran", page)


def read_time(minute):
    from datetime import datetime, timezone
    return datetime(2026, 9, 25, 12, minute, tzinfo=timezone.utc)


if __name__ == "__main__":
    unittest.main()
