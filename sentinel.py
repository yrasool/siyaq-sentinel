"""Local SIYAQ Sentinel prototype. Reads event records; never contacts a service."""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from event_auth import verify_event


WINDOW = timedelta(minutes=10)
SLOW_WINDOW = timedelta(minutes=30)
VOLUME_WINDOW = timedelta(minutes=90)
THRESHOLD = 3
VOLUME_THRESHOLD = 6
MAX_EVENTS = 10_000
MAX_LINE_CHARS = 8_192
TRACE_FIELDS = ("wanted", "available", "proposed", "simpler_candidate", "observed", "assessment")
EVENT_FIELDS = frozenset(("id", "timestamp", "product", "action", "outcome", "actor_id", "evidence", "trace", "signature"))
FIELD_LIMITS = {"id": 128, "timestamp": 64, "product": 40, "action": 40, "outcome": 40, "actor_id": 128}
SOURCE_REF = re.compile(r"[A-Za-z0-9._/-]{1,200}\Z")


def read_events(path: Path, key: bytes | None = None) -> list[dict]:
    events = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            if len(events) >= MAX_EVENTS or len(line) > MAX_LINE_CHARS:
                raise ValueError("event input exceeds the local size limit")
            event = json.loads(line)
            required = ("id", "timestamp", "product", "action", "outcome", "actor_id")
            if not isinstance(event, dict) or any(not isinstance(event.get(key), str) or not event[key] for key in required):
                raise ValueError(f"line {number}: missing or invalid event field")
            unknown_fields = set(event) - EVENT_FIELDS
            if unknown_fields:
                raise ValueError(f"line {number}: unexpected event fields: {', '.join(sorted(unknown_fields))}")
            if any(len(event[key]) > limit for key, limit in FIELD_LIMITS.items()):
                raise ValueError(f"line {number}: event field exceeds its size limit")
            try:
                stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError(f"line {number}: invalid timestamp") from error
            if stamp.tzinfo is None:
                raise ValueError(f"line {number}: timestamp needs a timezone")
            if "evidence" in event and (not isinstance(event["evidence"], list)
                                        or any(not isinstance(item, str) for item in event["evidence"])):
                raise ValueError(f"line {number}: evidence must be a list of strings")
            if "evidence" in event and (len(event["evidence"]) > 12 or any(
                not SOURCE_REF.fullmatch(ref) or any(part in {"", ".", ".."} for part in ref.split("/"))
                for ref in event["evidence"]
            )):
                raise ValueError(f"line {number}: evidence must contain bounded relative source paths")
            if "trace" in event and (not isinstance(event["trace"], dict)
                                     or set(event["trace"]) != set(TRACE_FIELDS)
                                     or any(not isinstance(event["trace"][key], str)
                                            or len(event["trace"][key]) > 500 for key in TRACE_FIELDS)):
                raise ValueError(f"line {number}: trace must contain six bounded text fields")
            if key is None and "signature" in event:
                raise ValueError(f"line {number}: signed event requires a verification key")
            if key is not None and not verify_event(event, key):
                raise ValueError(f"line {number}: missing or invalid event signature")
            event["_time"] = stamp.astimezone(timezone.utc)
            event["_origin"] = "HMAC-verified local event" if key is not None else "supplied event record"
            events.append(event)
    if len({event["id"] for event in events}) != len(events):
        raise ValueError("event IDs must be unique")
    return sorted(events, key=lambda event: (event["_time"], event["id"]))


def inspect_local_grid_scripts(repo: Path) -> dict | None:
    """Emit a source-inspection event only for the two recognized Grid paths."""
    root_package = repo / "package.json"
    isolated_package = repo / "apps/grid/package.json"
    wrapper_path = repo / "scripts/deploy-cf-worker.mjs"
    root_script = json.loads(root_package.read_text(encoding="utf-8"))["scripts"].get("cf:deploy:grid", "")
    isolated_check = json.loads(isolated_package.read_text(encoding="utf-8"))["scripts"].get("check", "")
    wrapper = wrapper_path.read_text(encoding="utf-8")
    recognized = (
        "scripts/deploy-cf-worker.mjs grid" in root_script
        and "opennextjs-cloudflare build" in wrapper
        and "opennextjs-cloudflare deploy" in wrapper
        and "cf:dry-run" in isolated_check
        and "verify:boundary" in isolated_check
        and "verify:boundary" not in root_script
    )
    if not recognized:
        return None
    stamp = datetime.now(timezone.utc)
    return {
        "id": "grid-local-" + hashlib.sha256((root_script + isolated_check + wrapper).encode()).hexdigest()[:12],
        "timestamp": stamp.isoformat().replace("+00:00", "Z"),
        "_time": stamp,
        "product": "grid",
        "action": "release-check",
        "outcome": "build-test-mismatch",
        "actor_id": "local-source-inspection",
        "_origin": "read-only local source inspection",
        "evidence": ["package.json", "apps/grid/package.json", "scripts/deploy-cf-worker.mjs"],
    }


def detect(events: list[dict]) -> list[dict]:
    """Detect bounded patterns in local, pseudonymous application events."""
    by_actor = defaultdict(list)
    for event in events:
        if (event["product"], event["action"], event["outcome"]) == (
            "parks", "refresh", "unauthorized"
        ):
            by_actor[event["actor_id"]].append(event)

    cases = []
    for actor, attempts in sorted(by_actor.items()):
        attempts.sort(key=lambda event: (event["_time"], event["id"]))
        burst_ids = set()
        start = 0
        while start < len(attempts):
            end = start
            while end < len(attempts) and attempts[end]["_time"] - attempts[start]["_time"] <= WINDOW:
                end += 1
            window = attempts[start:end]
            if len(window) >= THRESHOLD:
                burst_ids.update(event["id"] for event in window)
                cases.append({
                    "rule": "parks-refresh-repeated-unauthorized-v1",
                    "title": "Repeated unauthorized Parks refresh attempts",
                    "actor_id": actor,
                    "status": "open",
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                    "event_ids": [event["id"] for event in window],
                    "trigger_event_ids": [event["id"] for event in window[:THRESHOLD]],
                    "source_refs": ["workers/national-parks-refresh/src/auth.ts",
                                    "workers/national-parks-refresh/src/index.ts"],
                    "summary": f"{len(window)} unauthorized refresh attempts within 10 minutes",
                    "unknown": "Actor identity and intent are not established by these events.",
                    "recommended_action": "Review refresh access logs and rate-limit coverage; do not infer compromise from rejected requests alone.",
                })
                start = end
            else:
                start += 1
        remaining = [event for event in attempts if event["id"] not in burst_ids]
        slow_ids = set()
        start = 0
        while start < len(remaining):
            end = start
            while end < len(remaining) and remaining[end]["_time"] - remaining[start]["_time"] <= SLOW_WINDOW:
                end += 1
            window = remaining[start:end]
            if len(window) >= THRESHOLD:
                slow_ids.update(event["id"] for event in window)
                cases.append({
                    "rule": "parks-refresh-repeated-unauthorized-30m-v1",
                    "title": "Repeated Parks refresh denials over a longer window",
                    "actor_id": actor,
                    "status": "open",
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                    "event_ids": [event["id"] for event in window],
                    "trigger_event_ids": [event["id"] for event in window[:THRESHOLD]],
                    "source_refs": ["workers/national-parks-refresh/src/auth.ts",
                                    "workers/national-parks-refresh/src/index.ts"],
                    "summary": f"{len(window)} unauthorized refresh attempts within 30 minutes",
                    "unknown": "Timing alone cannot distinguish deliberate probing from a user retrying after an expired session.",
                    "recommended_action": "Review the authorization context and retry pattern before deciding whether to escalate.",
                })
                start = end
            else:
                start += 1
        remaining = [event for event in remaining if event["id"] not in slow_ids]
        start = 0
        while start < len(remaining):
            end = start
            while end < len(remaining) and remaining[end]["_time"] - remaining[start]["_time"] <= VOLUME_WINDOW:
                end += 1
            window = remaining[start:end]
            if len(window) >= VOLUME_THRESHOLD:
                cases.append({
                    "rule": "parks-refresh-denied-volume-90m-v1",
                    "title": "Repeated Parks refresh denials across short windows",
                    "actor_id": actor,
                    "status": "open",
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                    "event_ids": [event["id"] for event in window],
                    "trigger_event_ids": [event["id"] for event in window[:VOLUME_THRESHOLD]],
                    "source_refs": ["workers/national-parks-refresh/src/auth.ts",
                                    "workers/national-parks-refresh/src/index.ts"],
                    "summary": f"{len(window)} unauthorized refresh attempts within 90 minutes",
                    "unknown": "This pattern may be deliberate probing or an internal client retrying with expired authorization.",
                    "recommended_action": "Review client ownership and authorization context before deciding whether to escalate.",
                })
                start = end
            else:
                start += 1
    for event in events:
        if (event["product"], event["action"], event["outcome"]) == (
            "paperstack", "media-fetch", "blocked-redirect"
        ):
            cases.append({
                "rule": "paperstack-media-blocked-redirect-v1",
                "title": "Paperstack media redirect left the approved hosts",
                "actor_id": event["actor_id"],
                "status": "open",
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [event["id"]],
                "trigger_event_ids": [event["id"]],
                "source_refs": ["paperstack/src/lib/mediaPolicy.ts"],
                "summary": "A media fetch was stopped at a disallowed redirect",
                "unknown": "The event does not establish whether the redirect was malicious or caused by an upstream change.",
                "recommended_action": "Inspect the provider URL and redirect chain; retain the host allowlist until the destination is verified.",
            })
        elif (event["product"], event["action"], event["outcome"]) == (
            "grid", "release-check", "build-test-mismatch"
        ):
            cases.append({
                "rule": "grid-release-build-test-mismatch-v1",
                "title": "Grid release path differs from tested path",
                "actor_id": event["actor_id"],
                "status": "open",
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [event["id"]],
                "trigger_event_ids": [event["id"]],
                "source_refs": event.get("evidence", []),
                "summary": "A local check reported that the release command and passing tests select different app roots",
                "unknown": "The event alone does not prove what is currently deployed.",
                "recommended_action": "Inspect the command, build artifact, route inventory, and test target before release.",
            })
        elif (event["product"], event["action"], event["outcome"]) == (
            "grid", "release-check", "unverified-command"
        ):
            cases.append({
                "rule": "grid-release-unverified-command-v1",
                "title": "Grid release command needs verification",
                "actor_id": event["actor_id"],
                "status": "open",
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [event["id"]],
                "trigger_event_ids": [event["id"]],
                "source_refs": event.get("evidence", []),
                "summary": "The local checker could not verify the proposed release command",
                "unknown": "This event does not prove an unsafe release or what is currently deployed.",
                "recommended_action": "Review the command, generated artifact, bindings, route inventory, and test target before release.",
            })
        elif (event["product"], event["action"], event["outcome"]) == (
            "actiontrace", "agent-proposal", "review-needed"
        ) and "trace" in event:
            cases.append({
                "rule": "agent-action-scope-review-v1",
                "title": "Agent-proposed action needs scope review",
                "actor_id": event["actor_id"],
                "status": "open",
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [event["id"]],
                "trigger_event_ids": [event["id"]],
                "source_refs": event.get("evidence", []),
                "summary": "Review whether the proposed action adds unnecessary transfer, access, or side effects",
                "unknown": "A proposal is not proof that a command ran or that a simpler candidate would succeed.",
                "recommended_action": "Compare the proposed and simpler paths against the task, available access, and observed effects before acting.",
            })
        elif (event["product"], event["action"], event["outcome"]) == (
            "actiontrace", "agent-proposal", "unclassified"
        ) and "trace" in event:
            cases.append({
                "rule": "agent-action-unclassified-v1",
                "title": "Agent proposal has no review classification",
                "actor_id": event["actor_id"],
                "status": "open",
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [event["id"]],
                "trigger_event_ids": [event["id"]],
                "source_refs": event.get("evidence", []),
                "summary": "An agent proposal has a task trace but no upstream review decision",
                "unknown": "The trace does not prove the action ran, expanded access, or was unsafe.",
                "recommended_action": "Compare the proposal with the task, available access, simpler candidates, and observed effects; then classify it.",
            })
    for case in cases:
        identity = json.dumps([case["rule"], case["trigger_event_ids"]], separators=(",", ":"))
        case["case_id"] = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return sorted(cases, key=lambda case: (case["first_seen"], case["rule"], case["actor_id"]))


def render_html(cases: list[dict], events: list[dict]) -> str:
    by_id = {event["id"]: event for event in events}
    esc = html.escape
    open_count = sum(case.get("status", "open") == "open" for case in cases)
    parts = ["<!doctype html><html lang='en'><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width, initial-scale=1'>",
             "<title>SIYAQ Sentinel — incident casebook</title>",
             """<style>
             :root{--paper:#f3efe6;--ink:#222820;--muted:#626960;--rule:#bcb8a8;--signal:#a43d30;--soft:#e7e3d8}
             *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.52 Georgia,serif}
             a{color:inherit}a:focus-visible{outline:3px solid var(--signal);outline-offset:3px}
             .mast{border-bottom:1px solid var(--ink);padding:22px clamp(20px,5vw,72px) 28px;display:flex;justify-content:space-between;align-items:start;gap:20px}
             .brand{font:700 13px/1.2 system-ui,sans-serif;letter-spacing:.19em;text-transform:uppercase}.edition{font:12px/1.35 ui-monospace,monospace;text-align:right;color:var(--muted)}
             .hero{padding:54px clamp(20px,5vw,72px) 44px;border-bottom:1px solid var(--ink);display:grid;grid-template-columns:minmax(0,1fr) minmax(230px,330px);gap:28px;align-items:end}
             .eyebrow,.label{font:700 11px/1.3 system-ui,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:var(--signal)}
             h1{font:normal clamp(40px,6vw,82px)/.98 Georgia,serif;letter-spacing:-.045em;margin:12px 0 0;max-width:950px}
             .hero p{margin:0 0 4px;color:var(--muted);font-size:15px}.counts{display:flex;gap:28px;margin-top:26px}.count strong{display:block;font:normal 35px/1 Georgia,serif}.count span{font:11px/1.4 system-ui,sans-serif;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
             .shell{display:grid;grid-template-columns:245px minmax(0,1fr);gap:clamp(28px,4vw,66px);padding:0 clamp(20px,5vw,72px)}
             .rail{border-right:1px solid var(--rule);padding:32px 24px 40px 0;align-self:start;position:sticky;top:0}.rail a{display:block;text-decoration:none;border-bottom:1px solid var(--rule);padding:13px 0;font:13px/1.35 system-ui,sans-serif}.rail a:hover{text-decoration:underline;text-decoration-thickness:1px}.rail .id{font:11px ui-monospace,monospace;color:var(--muted);display:block;margin-bottom:4px}
             main{min-width:0;padding:4px 0 70px}.case{padding:40px 0 48px;border-bottom:1px solid var(--ink);scroll-margin-top:20px}.casehead{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.status{font:700 11px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.08em;padding:5px 8px;border:1px solid currentColor}.status.open{color:var(--signal)}.status.closed{color:#4e6954}
             .case h2{font:normal clamp(30px,3.5vw,48px)/1.08 Georgia,serif;letter-spacing:-.03em;margin:14px 0}.summary{font-size:18px;max-width:700px}.meta{font:12px/1.5 ui-monospace,monospace;color:var(--muted);overflow-wrap:anywhere}
             .trace{list-style:none;margin:28px 0;padding:0;border-top:1px solid var(--rule)}.trace li{display:grid;grid-template-columns:145px minmax(0,1fr);gap:20px;border-bottom:1px solid var(--rule);padding:17px 0}.trace time{font:12px/1.4 ui-monospace,monospace;color:var(--muted)}.trace strong{font-weight:600}.trace .event-origin{display:block;margin-top:4px;font:11px/1.4 ui-monospace,monospace;color:var(--muted)}
             .agent-trace{margin:15px 0 0;padding:15px 20px;background:var(--soft);border-left:2px solid var(--ink)}.agent-trace div{margin:8px 0}.agent-trace dt{font:700 11px/1.3 system-ui,sans-serif;text-transform:uppercase;letter-spacing:.08em}.agent-trace dd{margin:2px 0 0;font-size:15px}
             .evidence{display:grid;grid-template-columns:150px minmax(0,1fr);gap:20px;margin:23px 0}.evidence .label{color:var(--muted)}.evidence p{margin:0}.evidence code{font:12px/1.5 ui-monospace,monospace;background:var(--soft);padding:2px 5px;overflow-wrap:anywhere}.unknown{border-left:3px solid var(--signal);padding-left:16px}.note{border-left:3px solid #4e6954;padding-left:16px}
             .empty{padding:45px 0}footer{border-top:1px solid var(--ink);padding:20px clamp(20px,5vw,72px);font:12px/1.5 system-ui,sans-serif;color:var(--muted)}
             @media(max-width:760px){.hero{grid-template-columns:1fr;padding-top:38px}.counts{margin-top:0}.shell{display:block}.rail{position:static;border-right:0;border-bottom:1px solid var(--rule);padding:23px 0}.rail a{display:inline-block;vertical-align:top;width:48%;margin-right:2%}.case{padding-top:34px}.trace li,.evidence{grid-template-columns:1fr;gap:6px}.trace li{padding:15px 0}.mast{padding-bottom:20px}}
             </style>""",
             "<header class='mast'><div class='brand'>SIYAQ / Sentinel</div><div class='edition'>LOCAL INCIDENT CASEBOOK<br>NO LIVE TELEMETRY</div></header>",
             "<section class='hero'><div><div class='eyebrow'>Investigation record · local prototype</div><h1>Follow the signal back to its source.</h1></div>",
             "<div><p>Each case separates what an event says from what the source code proves. Unknowns stay visible.</p>",
             f"<div class='counts'><div class='count'><strong>{len(cases)}</strong><span>cases</span></div><div class='count'><strong>{open_count}</strong><span>open</span></div></div></div></section>",
             "<div class='shell'><nav class='rail' aria-label='Case index'><div class='label'>Case index</div>"]
    for case in cases:
        parts.append(f"<a href='#case-{esc(case['case_id'])}'><span class='id'>{esc(case['case_id'])} · {esc(case.get('status', 'open'))}</span>{esc(case['title'])}</a>")
    parts.append("</nav><main id='cases'>")
    if not cases:
        parts.append("<p class='empty'>No incidents matched the current rules.</p>")
    for case in cases:
        status = case.get("status", "open")
        parts.append(f"<article class='case' id='case-{esc(case['case_id'])}'><div class='casehead'><span class='status {esc(status)}'>{esc(status)}</span><span class='meta'>CASE {esc(case['case_id'])} / {esc(case['rule'])}</span></div><h2>{esc(case['title'])}</h2>")
        parts.append(f"<p class='summary'>{esc(case['summary'])}</p><p class='meta'>ACTOR: {esc(case['actor_id'])} · FIRST SEEN: {esc(case['first_seen'])}</p>")
        parts.append("<div class='label'>Observed sequence</div><ol class='trace'>")
        for event_id in case["event_ids"]:
            event = by_id[event_id]
            parts.append(f"<li><time>{esc(event['timestamp'])}</time><div><strong>{esc(event['product'])} / {esc(event['action'])}: {esc(event['outcome'])}</strong><span class='event-origin'>EVENT {esc(event_id)} · {esc(event.get('_origin', 'supplied event record'))}</span>")
            if "trace" in event:
                trace = event["trace"]
                labels = (("wanted", "Wanted"), ("available", "Available"),
                          ("proposed", "Agent proposed"), ("simpler_candidate", "Simpler candidate"),
                          ("observed", "Observed"), ("assessment", "Assessment"))
                parts.append("<dl class='agent-trace'>")
                for key, label in labels:
                    parts.append(f"<div><dt>{label}</dt><dd>{esc(trace[key])}</dd></div>")
                parts.append("</dl>")
            parts.append("</div></li>")
        parts.append("</ol>")
        if case["source_refs"]:
            refs = ", ".join(f"<code>{esc(ref)}</code>" for ref in case["source_refs"])
            parts.append(f"<div class='evidence'><div class='label'>Relevant source</div><p>{refs}</p></div>")
        parts.append(f"<div class='evidence unknown'><div class='label'>Unknown</div><p>{esc(case['unknown'])}</p></div>")
        if case.get("analyst_note"):
            parts.append(f"<div class='evidence note'><div class='label'>Analyst note</div><p>{esc(case['analyst_note'])}</p></div>")
        parts.append(f"<div class='evidence'><div class='label'>Next step</div><p>{esc(case['recommended_action'])}</p></div></article>")
    parts.append("</main></div><footer>Local demonstration. Fixture events are invented; source inspections are read-only. A case is a reason to review, not proof of compromise.</footer></html>")
    return "\n".join(parts)
