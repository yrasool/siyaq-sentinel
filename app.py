"""Local command-line incident workflow. No network listeners or cloud calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_auth import create_key, load_key
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
    render = commands.add_parser("render", help="write a local HTML incident view")
    render.add_argument("--out", type=Path, default=Path(__file__).parent / "out" / "incidents.html")
    args = parser.parse_args()
    if args.command == "keygen":
        try:
            create_key(args.out)
        except OSError as error:
            parser.error(str(error))
        print(f"Created local event key at {args.out}")
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
        if not store.set_status(args.case_id, "closed" if args.command == "close" else "open", args.note):
            parser.error("case not found")
        print(f"Case {args.case_id} {'closed' if args.command == 'close' else 'reopened'}")
    elif args.command == "render":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_html(store.cases(), store.events()), encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
