import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from evaluate_local import evaluate


ROOT = Path(__file__).parent
LABELS = ROOT / "fixtures" / "labeled-local-decisions.json"
EVENTS = ROOT / "fixtures" / "observed-local-decisions.jsonl"
PROBE = ROOT / "fixtures" / "observed-local-probe.json"


class LocalEvaluationTests(unittest.TestCase):
    def test_recorded_app_decisions_and_review_labels(self):
        result = evaluate(LABELS, EVENTS, PROBE)
        self.assertEqual(result["case_count"], 3)
        self.assertEqual(result["counts"], {
            "covered": 4, "missed": 0, "over-alert": 1, "quiet-control": 4,
        })
        self.assertEqual(next(row for row in result["rows"] if row["id"] == "media-provider-change")["verdict"],
                         "over-alert")

    def test_label_drift_and_off_policy_fetch_fail_evaluation(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "probe.json"
            probe = json.loads(PROBE.read_text(encoding="utf-8"))
            probe["results"][0]["expected_decision"] = "authorized"
            path.write_text(json.dumps(probe), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "decision or fetch policy failed"):
                evaluate(LABELS, EVENTS, path)

            probe["results"][0]["expected_decision"] = "unauthorized"
            probe["results"][0]["off_policy_fetch"] = True
            path.write_text(json.dumps(probe), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "decision or fetch policy failed"):
                evaluate(LABELS, EVENTS, path)


if __name__ == "__main__":
    unittest.main()
