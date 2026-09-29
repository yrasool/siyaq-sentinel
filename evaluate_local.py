"""Compare pre-labeled local app decisions with Sentinel's cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_auth import load_key
from sentinel import detect, read_events


def evaluate(labels_path: Path, events_path: Path, probe_path: Path, key: bytes | None = None) -> dict:
    labels = json.loads(labels_path.read_text(encoding="utf-8"))["cases"]
    events = read_events(events_path, key=key)
    probe = json.loads(probe_path.read_text(encoding="utf-8"))
    label_by_id = {item["id"]: item for item in labels}
    event_by_id = {item["id"]: item for item in events}
    probe_by_id = {item["id"]: item for item in probe["results"]}
    if (len(label_by_id) != len(labels) or len(event_by_id) != len(events) or
            len(probe_by_id) != len(probe["results"]) or
            not set(label_by_id) == set(event_by_id) == set(probe_by_id)):
        raise ValueError("label, probe, and event IDs do not match exactly")
    for event_id, label in label_by_id.items():
        observed = probe_by_id[event_id]
        if (observed["expected_decision"] != label["expected_decision"] or
                observed["observed_decision"] != event_by_id[event_id]["outcome"] or
                not observed["decision_match"] or observed["off_policy_fetch"]):
            raise ValueError(f"local app decision or fetch policy failed for {event_id}")
    cases = detect(events)
    alerted_ids = {event_id for case in cases for event_id in case["event_ids"]}
    rows = []
    for event_id, label in label_by_id.items():
        alerted = event_id in alerted_ids
        verdict = "covered" if label["expected_review"] and alerted else (
            "missed" if label["expected_review"] else (
                "over-alert" if alerted else "quiet-control"
            )
        )
        rows.append({
            "id": event_id, "expected_review": label["expected_review"],
            "alerted": alerted, "verdict": verdict,
        })
    return {
        "scope": "Nine pre-labeled synthetic inputs executed against actual local app functions; not live telemetry or a field accuracy estimate.",
        "source_sha256": probe["source_sha256"],
        "case_count": len(cases),
        "counts": {key: sum(row["verdict"] == key for row in rows)
                   for key in ("covered", "missed", "over-alert", "quiet-control")},
        "rows": rows,
        "case_rules": [case["rule"] for case in cases],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate local app decisions against pre-written review labels")
    parser.add_argument("--labels", type=Path, default=Path(__file__).parent / "fixtures" / "labeled-local-decisions.json")
    parser.add_argument("--events", type=Path, default=Path(__file__).parent / "out" / "local-probe" / "local-decisions.jsonl")
    parser.add_argument("--probe", type=Path, default=Path(__file__).parent / "out" / "local-probe" / "local-decision-probe.json")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "out" / "local-probe" / "evaluation.json")
    parser.add_argument("--key-file", type=Path, help="verify signed local decision events")
    args = parser.parse_args()
    result = evaluate(args.labels, args.events, args.probe,
                      key=load_key(args.key_file) if args.key_file else None)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": result["case_count"], **result["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
