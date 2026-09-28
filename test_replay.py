import unittest

from replay import evaluate, render


class ReplayTests(unittest.TestCase):
    def test_reports_known_strengths_and_gaps(self):
        report = evaluate()
        self.assertEqual(report["counts"], {
            "caught": 4, "partial": 1, "missed": 5, "over-alert": 1, "quiet-control": 2,
        })
        by_id = {item["id"]: item for item in report["scenarios"]}
        self.assertEqual(by_id["P2"]["verdict"], "missed")
        self.assertEqual(by_id["M2"]["verdict"], "over-alert")
        self.assertEqual(by_id["A1"]["verdict"], "caught")
        self.assertEqual(by_id["X1"]["verdict"], "partial")
        self.assertEqual(by_id["T1"]["verdict"], "missed")
        self.assertIn("synthetic", report["scope"].lower())
        self.assertIn("Evidence limits", render(report))


if __name__ == "__main__":
    unittest.main()
