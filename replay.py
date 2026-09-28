"""Controlled local red-team replay for Sentinel's detection rules.

All traffic here is invented in memory. No request, command, or cloud API runs.
"""

from __future__ import annotations

import argparse
import html
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel import detect, read_events


BASE = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def event(event_id: str, minute: int, product: str, action: str,
          outcome: str, actor: str) -> dict:
    moment = BASE + timedelta(minutes=minute)
    return {
        "id": event_id,
        "timestamp": moment.isoformat().replace("+00:00", "Z"),
        "_time": moment,
        "_origin": "synthetic red-team replay",
        "product": product,
        "action": action,
        "outcome": outcome,
        "actor_id": actor,
    }


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    kind: str
    capability: str
    expected_review: bool
    events: list[dict]
    interpretation: str
    required_rule: str | None = None


def scenarios() -> list[Scenario]:
    parks_burst = [event(f"p{i}", minute, "parks", "refresh", "unauthorized", "actor-a")
                   for i, minute in enumerate((0, 2, 4), 1)]
    distributed = [event(f"d{i}", minute, "parks", "refresh", "unauthorized", f"actor-{i}")
                   for i, minute in enumerate((0, 2, 4), 1)]
    slow = [event(f"s{i}", minute, "parks", "refresh", "unauthorized", "actor-a")
            for i, minute in enumerate((0, 11, 22), 1)]
    agent = read_events(Path(__file__).parent / "fixtures" / "actiontrace-demo.jsonl")
    unreviewed = [dict(agent[0], id="agent-unreviewed", outcome="unclassified")]
    grid = read_events(Path(__file__).parent / "fixtures" / "grid-demo.jsonl")
    claude_cadence = read_events(Path(__file__).parent / "fixtures" / "model-attack-claude.jsonl")
    return [
        Scenario("P1", "Same-actor refresh burst", "adversarial",
                 "Three rejected refresh attempts under one pseudonymous actor in four minutes.",
                 True, parks_burst, "The threshold rule should create a Parks case; the protected operation remains rejected."),
        Scenario("P2", "Rotating-identity refresh attempts", "adversarial",
                 "The same attempt pattern is divided among three actor IDs.",
                 True, distributed, "Per-actor grouping alone cannot connect these attempts; shared origin is not established by the current event schema."),
        Scenario("P3", "Low-and-slow refresh attempts", "adversarial",
                 "One actor spaces three rejected attempts eleven minutes apart.",
                 True, slow, "The 30-minute review rule should catch the sequence without claiming malicious intent."),
        Scenario("P4", "Paced pairs evade short windows", "adversarial",
                 "One actor makes six denied attempts in pairs over 75 minutes; this sequence was proposed by Claude Sonnet.",
                 True, claude_cadence, "A longer volume rule should request review without treating a denied request as compromise."),
        Scenario("M1", "Media redirect leaves allowlist", "adversarial",
                 "A media fetch reaches a redirect that the host policy rejects.",
                 True, [event("m1", 0, "paperstack", "media-fetch", "blocked-redirect", "actor-m")],
                 "The case records a blocked attempt, not a successful outbound fetch."),
        Scenario("M2", "Benign provider migration", "benign",
                 "An upstream provider changes its image host; the same allowlist blocks it.",
                 False, [event("m2", 0, "paperstack", "media-fetch", "blocked-redirect", "provider-change")],
                 "The rule cannot distinguish provider maintenance from hostile redirection without enrichment."),
        Scenario("G1", "Recognized release/test mismatch", "adversarial",
                 "A release check reports that the proposed command and passing tests target different roots.",
                 True, grid, "The mismatch event should open a case; it says nothing about the deployed Worker."),
        Scenario("G2", "Unrecognized release path", "adversarial",
                 "A changed release command yields an unverified-command outcome.",
                 True, [event("g2", 0, "grid", "release-check", "unverified-command", "local-check")],
                 "Sentinel currently has no hold-for-review rule for unknown release paths."),
        Scenario("A1", "Agent proposes expanded transfer workflow", "adversarial",
                 "A review-needed ActionTrace record describes the historical scp proposal.",
                 True, agent, "The event opens a scope-review case; neither command execution nor exfiltration is implied."),
        Scenario("A2", "Agent proposal lacks upstream classification", "adversarial",
                 "The same proposal arrives as unclassified rather than review-needed.",
                 True, unreviewed, "Sentinel trusts the upstream classification and cannot independently recognize scope expansion."),
        Scenario("X1", "Multi-product sequence without shared identity", "adversarial",
                 "A blocked media redirect, one rejected refresh attempt, and an unverified Grid release occur close together.",
                 True, [event("x1m", 0, "paperstack", "media-fetch", "blocked-redirect", "actor-m"),
                        event("x1p", 2, "parks", "refresh", "unauthorized", "actor-p"),
                        event("x1g", 3, "grid", "release-check", "unverified-command", "local-check")],
                 "The media event alerts, but the three records cannot be safely linked as one actor or incident. A correlation claim needs shared identity evidence.",
                 "cross-product-correlation-v1"),
        Scenario("T1", "First-seen telemetry falsification", "adversarial",
                 "A supplied record claims an authorized refresh despite the scenario author's rejected-action ground truth.",
                 True, [event("t1", 0, "parks", "refresh", "authorized", "actor-t")],
                 "The local import has no source authentication. It cannot tell a forged first-seen record from a genuine authorized event."),
        Scenario("B1", "Ordinary Parks read", "benign",
                 "An authorized public read has no security-relevant outcome.",
                 False, [event("b1", 0, "parks", "read", "ok", "visitor")],
                 "A quiet control for ordinary application use."),
        Scenario("B2", "Allowed Paperstack image", "benign",
                 "A media fetch stays on an approved path.",
                 False, [event("b2", 0, "paperstack", "media-fetch", "allowed", "visitor")],
                 "A quiet control for the media rule."),
        Scenario("B3", "Session-expiry retry pattern", "benign",
                 "A legitimate operator retries a denied refresh at 0, 11, and 22 minutes after losing authorization.",
                 False, [event(f"b3-{i}", minute, "parks", "refresh", "unauthorized", "operator")
                         for i, minute in enumerate((0, 11, 22), 1)],
                 "The event schema cannot distinguish this from deliberate low-and-slow attempts; review alert is an over-alert for this labeled control."),
        Scenario("B4", "Stale-credential client retry", "benign",
                 "A misconfigured internal client makes six denied refresh attempts at the same cadence as P4.",
                 False, [event(f"b4-{i}", minute, "parks", "refresh", "unauthorized", "internal-client")
                         for i, minute in enumerate((0, 5, 35, 40, 70, 75), 1)],
                 "The event shape is observationally indistinguishable from P4; this labeled benign control exposes a predictable over-alert."),
    ]


def evaluate() -> dict:
    results = []
    for scenario in scenarios():
        cases = detect(scenario.events)
        alerted = bool(cases)
        if scenario.expected_review:
            verdict = ("partial" if scenario.required_rule and
                       scenario.required_rule not in [case["rule"] for case in cases]
                       else "caught") if alerted else "missed"
        else:
            verdict = "over-alert" if alerted else "quiet-control"
        results.append({
            "id": scenario.scenario_id,
            "title": scenario.title,
            "kind": scenario.kind,
            "capability": scenario.capability,
            "expected_review": scenario.expected_review,
            "alerted": alerted,
            "rules": [case["rule"] for case in cases],
            "verdict": verdict,
            "interpretation": scenario.interpretation,
        })
    return {
        "scope": "Curated local synthetic replay; no live requests or independent prevalence estimate.",
        "counts": {key: sum(item["verdict"] == key for item in results)
                   for key in ("caught", "partial", "missed", "over-alert", "quiet-control")},
        "scenarios": results,
        "limits": [
            "The actor IDs, outcomes, and attacker capabilities are authored fixtures, not observed incidents.",
            "A review alert is not a proven attack; a quiet result is not proof of safety.",
            "Event authenticity is not established. A forged first-seen record could mislead this local collector.",
            "Parks and Paperstack application controls are not executed by this replay; only Sentinel's detection rules are evaluated.",
        ],
    }


def render(report: dict) -> str:
    esc = html.escape
    parts = ["<!doctype html><html lang='en'><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width, initial-scale=1'>",
             "<title>SIYAQ Sentinel — local red-team replay</title>",
             "<style>body{font:17px/1.5 Georgia,serif;max-width:900px;margin:4vw auto;padding:0 24px;color:#22251e;background:#f4f0e7}h1{font-size:2.8rem;line-height:1.05}h2{margin-bottom:.2rem}article{border-top:1px solid #302f2b;padding:1.2rem 0}small,.meta{font:13px/1.4 system-ui,sans-serif;letter-spacing:.03em;color:#555}strong{font-weight:700}.missed{color:#a43124}.caught{color:#206448}.partial{color:#755632}.over-alert{color:#865e13}.quiet-control{color:#596175}code{font:13px monospace}</style>",
             "<main><p class='meta'>LOCAL RED-TEAM REPLAY / SYNTHETIC EVENTS</p>",
             "<h1>Where the detector holds,<br>and where it does not.</h1>",
             f"<p>{esc(report['scope'])}</p>"]
    counts = report["counts"]
    parts.append("<p><strong>Curated scenarios:</strong> " + ", ".join(
        f"{counts[key]} {key.replace('-', ' ')}" for key in ("caught", "partial", "missed", "over-alert", "quiet-control")) + "</p>")
    for item in report["scenarios"]:
        parts.append(f"<article><small>{esc(item['id'])} / {esc(item['kind'])}</small><h2>{esc(item['title'])}</h2>")
        parts.append(f"<p class='{esc(item['verdict'])}'><strong>{esc(item['verdict'].upper().replace('-', ' '))}</strong> · {'alert' if item['alerted'] else 'no alert'}</p>")
        parts.append(f"<p>{esc(item['capability'])}</p><p>{esc(item['interpretation'])}</p>")
        if item["rules"]:
            parts.append("<p class='meta'>Matched: " + ", ".join(esc(rule) for rule in item["rules"]) + "</p>")
        parts.append("</article>")
    parts.append("<h2>Evidence limits</h2><ul>")
    parts.extend(f"<li>{esc(limit)}</li>" for limit in report["limits"])
    parts.append("</ul></main></html>")
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay curated local attacks against Sentinel detections")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "out")
    args = parser.parse_args()
    report = evaluate()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "red-team-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.out / "red-team-report.html").write_text(render(report), encoding="utf-8")
    print(json.dumps(report["counts"], sort_keys=True))
    print(f"Wrote {args.out / 'red-team-report.html'}")


if __name__ == "__main__":
    main()
