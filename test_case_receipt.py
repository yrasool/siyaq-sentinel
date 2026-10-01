import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from case_receipt import make_receipt, snapshot, verify_receipt
from sentinel import read_events
from store import IncidentStore


class CaseReceiptTests(unittest.TestCase):
    def test_receipt_binds_challenge_events_and_decision_history(self):
        with TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "cases.db")
            store.ingest(read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl"))
            case_id = store.cases()[0]["case_id"]
            store.set_status(case_id, "closed", "Reviewed source; no execution evidence.", "analyst-a")
            original = snapshot(store.cases()[0], store.events())
            key = bytes(range(32))
            challenge = "a1" * 16
            receipt = make_receipt(store.cases()[0], store.events(), key, challenge)
            self.assertTrue(verify_receipt(receipt, key, challenge, original))
            self.assertFalse(verify_receipt(receipt, key, "b2" * 16))
            self.assertFalse(verify_receipt(receipt, b"x" * 32, challenge))
            changed = copy.deepcopy(receipt)
            changed["payload"]["snapshot"]["case"]["decision_history"][0]["note"] = "No review needed"
            self.assertFalse(verify_receipt(changed, key, challenge))
            store.set_status(case_id, "open", "Prior uncertainty remains.", "analyst-b")
            self.assertTrue(verify_receipt(receipt, key, challenge))
            self.assertFalse(verify_receipt(receipt, key, challenge,
                                            snapshot(store.cases()[0], store.events())))


if __name__ == "__main__":
    unittest.main()
