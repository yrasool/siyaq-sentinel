import unittest
import json
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
        for number, minute in enumerate((0, 31, 62), 1):
            moment = read_time(minute)
            events.append({"id": str(number), "timestamp": moment.isoformat(),
                           "_time": moment, "product": "parks", "action": "refresh",
                           "outcome": "unauthorized", "actor_id": "a"})
        self.assertEqual(detect(events), [])

    def test_low_and_slow_attempts_create_one_review_case(self):
        events = read_events(Path(__file__).parent / "fixtures" / "model-attack-luna.jsonl")
        cases = detect(events)
        self.assertEqual([case["rule"] for case in cases], ["parks-refresh-repeated-unauthorized-30m-v1"])
        self.assertEqual(cases[0]["event_ids"], ["review-1", "review-2", "review-3"])
        self.assertIn("cannot distinguish", cases[0]["unknown"])

    def test_paced_pairs_proposed_by_claude_create_one_review_case(self):
        events = read_events(Path(__file__).parent / "fixtures" / "model-attack-claude.jsonl")
        cases = detect(events)
        self.assertEqual([case["rule"] for case in cases], ["parks-refresh-denied-volume-90m-v1"])
        self.assertEqual(cases[0]["event_ids"], [f"c{i}" for i in range(1, 7)])

    def test_volume_rule_does_not_duplicate_existing_burst_case(self):
        events = []
        for number, minute in enumerate((0, 1, 2, 35, 36, 37), 1):
            moment = read_time(minute)
            events.append({"id": str(number), "timestamp": moment.isoformat(),
                           "_time": moment, "product": "parks", "action": "refresh",
                           "outcome": "unauthorized", "actor_id": "a"})
        self.assertEqual([case["rule"] for case in detect(events)],
                         ["parks-refresh-repeated-unauthorized-v1"] * 2)

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

    def test_import_rejects_extra_request_data_and_unsafe_references(self):
        base = {"id": "x", "timestamp": "2026-09-25T12:00:00Z", "product": "parks",
                "action": "refresh", "outcome": "unauthorized", "actor_id": "pseudonym"}
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            for extra in ({"headers": {"Authorization": "Bearer example"}},
                          {"url": "https://example.test/refresh?token=example"}):
                path.write_text(json.dumps(base | extra) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "unexpected event fields"):
                    read_events(path)
            for ref in ("../secret.txt", "C:/private/file.txt", "https://example.test/log", "apps//route.ts"):
                path.write_text(json.dumps(base | {"evidence": [ref]}) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "bounded relative source paths"):
                    read_events(path)

    def test_import_rejects_oversized_actor_id(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(json.dumps({"id": "x", "timestamp": "2026-09-25T12:00:00Z", "product": "parks",
                                        "action": "refresh", "outcome": "unauthorized", "actor_id": "a" * 129}) + "\n",
                            encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "size limit"):
                read_events(path)

    def test_agent_trace_is_case_not_attack_claim(self):
        events = read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl")
        cases = detect(events)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["rule"], "agent-action-scope-review-v1")
        page = render_html(cases, events)
        self.assertIn("scp command was proposed", page)
        self.assertIn("not proof that a command ran", page)

    def test_unverified_grid_command_opens_review_without_release_claim(self):
        event = {"id": "grid-unknown", "timestamp": "2026-09-25T12:00:00Z",
                 "product": "grid", "action": "release-check", "outcome": "unverified-command",
                 "actor_id": "local-check", "evidence": ["package.json"]}
        cases = detect([event, event | {"id": "grid-ok", "outcome": "verified"}])
        self.assertEqual([case["rule"] for case in cases], ["grid-release-unverified-command-v1"])
        self.assertIn("does not prove", cases[0]["unknown"])
        self.assertIn("artifact", cases[0]["recommended_action"])

    def test_unclassified_agent_trace_opens_review_without_scope_claim(self):
        source = read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl")[0]
        cases = detect([source | {"id": "unclassified", "outcome": "unclassified"},
                        source | {"id": "approved", "outcome": "approved"},
                        {key: value for key, value in (source | {"id": "empty", "outcome": "unclassified"}).items()
                         if key != "trace"}])
        self.assertEqual([case["rule"] for case in cases], ["agent-action-unclassified-v1"])
        self.assertIn("does not prove", cases[0]["unknown"])
        self.assertIn("classify", cases[0]["recommended_action"])


def read_time(minute):
    from datetime import datetime, timedelta, timezone
    return datetime(2026, 9, 25, 12, tzinfo=timezone.utc) + timedelta(minutes=minute)


if __name__ == "__main__":
    unittest.main()
