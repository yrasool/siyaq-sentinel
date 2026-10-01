"""Local command-line incident workflow. No network listeners or cloud calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_auth import create_key, load_key
from case_receipt import make_receipt, snapshot, verify_receipt
from sentinel import inspect_local_grid_scripts, read_events, render_html
from store import IncidentStore


DEFAULT_DB = Path(__file__).parent / "out" / "sentinel.db"


def main() -> None:
    parser = argparse.ArgumentParser(description="SIYAQ Sentinel local incident workflow")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest", help="import JSONL events and update cases")
    ingest.add_argument("events", type=Path)
    ingest.add_argument("--grid-repo", type=Path, help="also inspect local Grid scripts")
    ingest.add_argument("--key-file", type=Path, help="require and verify HMAC signatures on every input event")
    keygen = commands.add_parser("keygen", help="create a local 32-byte event key without printing it")
    keygen.add_argument("--out", type=Path, required=True)
    commands.add_parser("list", help="list cases and statuses")
    show = commands.add_parser("show", help="show one case")
    show.add_argument("case_id")
    for name in ("close", "reopen"):
        command = commands.add_parser(name, help=f"{name} a case with an analyst note")
        command.add_argument("case_id")
        command.add_argument("--note", required=True)
        command.add_argument("--analyst", default="local-analyst", help="pseudonymous analyst ID")
    render = commands.add_parser("render", help="write a local HTML incident view")
    render.add_argument("--out", type=Path, default=Path(__file__).parent / "out" / "incidents.html")
    receipt = commands.add_parser("receipt", help="write a challenge-bound case evidence receipt")
    receipt.add_argument("case_id")
    receipt.add_argument("--key-file", type=Path, required=True)
    receipt.add_argument("--challenge", required=True)
    receipt.add_argument("--out", type=Path, required=True)
    verify = commands.add_parser("verify-receipt", help="verify a case receipt and its fresh challenge")
    verify.add_argument("receipt_file", type=Path)
    verify.add_argument("--key-file", type=Path, required=True)
    verify.add_argument("--challenge", required=True)
    verify.add_argument("--against-db", action="store_true", help="also compare with the current SQLite case")
    args = parser.parse_args()
    if args.command == "keygen":
        try:
            create_key(args.out)
        except OSError as error:
            parser.error(str(error))
        print(f"Created local 32-byte key at {args.out}")
        return

    if args.command == "verify-receipt":
        try:
            supplied = json.loads(args.receipt_file.read_text(encoding="utf-8"))
            current = None
            if args.against_db:
                if not args.db.is_file():
                    raise ValueError("case database does not exist")
                case_id = supplied["payload"]["snapshot"]["case"]["case_id"]
                store = IncidentStore(args.db)
                case = next((item for item in store.cases() if item["case_id"] == case_id), None)
                current = snapshot(case, store.events()) if case else {}
            valid = verify_receipt(supplied, load_key(args.key_file), args.challenge, current)
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            parser.error("receipt failed verification")
        print("Receipt verified against current case" if args.against_db
              else "Historical receipt MAC verified; current case not checked")
        return

    if args.command == "ingest":
        if args.key_file and args.grid_repo:
            parser.error("signed input and Grid source inspection must be imported separately")
        try:
            events = read_events(args.events, key=load_key(args.key_file) if args.key_file else None)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        if args.grid_repo:
            grid_event = inspect_local_grid_scripts(args.grid_repo)
            if grid_event:
                events.append(grid_event)
            else:
                print("Grid script pattern not recognized; no Grid event inferred")
        store = IncidentStore(args.db)
        try:
            added, case_count = store.ingest(events)
        except ValueError as error:
            parser.error(str(error))
        print(f"Imported {added} new event(s); {case_count} case(s) detected")
        return

    store = IncidentStore(args.db)
    if args.command == "list":
        for case in store.cases():
            print(f"{case['case_id']}  {case['status']:6}  {case['title']}")
    elif args.command == "show":
        case = next((item for item in store.cases() if item["case_id"] == args.case_id), None)
        if case is None:
            parser.error("case not found")
        print(json.dumps(case, indent=2))
    elif args.command in {"close", "reopen"}:
        try:
            changed = store.set_status(args.case_id, "closed" if args.command == "close" else "open",
                                       args.note, args.analyst)
        except ValueError as error:
            parser.error(str(error))
        if not changed:
            parser.error("case not found")
        print(f"Case {args.case_id} {'closed' if args.command == 'close' else 'reopened'}")
    elif args.command == "render":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_html(store.cases(), store.events()), encoding="utf-8")
        print(f"Wrote {args.out}")
    elif args.command == "receipt":
        case = next((item for item in store.cases() if item["case_id"] == args.case_id), None)
        if case is None:
            parser.error("case not found")
        try:
            signed = make_receipt(case, store.events(), load_key(args.key_file), args.challenge)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("x", encoding="utf-8") as output:
                json.dump(signed, output, indent=2, ensure_ascii=False)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
