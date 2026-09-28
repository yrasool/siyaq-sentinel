# SIYAQ Sentinel: step-by-step engineering record

This document records what was built, why it was built that way, how it was checked, and what remains deliberately unbuilt. It describes the local prototype in this repository, not a deployed security service.

## 1. Choose a bounded security problem

**What:** Start with three concrete boundaries in Yusra's SIYAQ projects: the protected Parks refresh operation, Paperstack's outbound media-fetch host policy, and Grid's release/test path. Add a fourth signal type for proposals from the separate ActionTrace project. A Sentinel case answers what was observed, which rule matched, which event IDs support it, which source files matter, and what remains unknown.

**Why:** These boundaries come from real code and previously reproduced local failure modes. They yield specific security questions a reviewer can verify. A single generic “suspicious activity” score would obscure why an alert fired.

**Why not a live SOC connection yet:** The existing apps have separate deployment and data boundaries. Publishing a new collector or reading production logs would require a route, binding, privacy, and final-artifact review. No such release has been approved or verified for Sentinel.

## 2. Define the event contract

**What:** Each JSONL event needs an ID, timezone-aware timestamp, product, action, outcome, and pseudonymous actor ID. Optional `evidence` contains only relative source references. A redacted ActionTrace event adds six bounded text fields: wanted, available, proposed, simpler candidate, observed, and assessment. The parser rejects missing or unexpected fields, duplicate IDs, oversized lines or fields, too many events, timestamps without timezones, and invalid evidence or trace shapes.

**Why:** A small schema makes each detection explainable. Timezones are required for a correct ten-minute window. Duplicate IDs would make a timeline ambiguous.

**Why not raw request bodies, headers, IP addresses, or tokens:** The current detections do not need them. Keeping them out of the stored event projection reduces the risk of collecting credentials or personal data. A later live adapter must make its own privacy and retention decision before use.

**Privacy limit:** The parser rejects raw URLs and headers as extra fields and absolute source paths in `evidence`. It cannot know whether a value placed inside an allowed free-text field or actor ID is sensitive. The producer must pseudonymize actor IDs and redact ActionTrace text before import; this is a schema guard, not a data-loss-prevention system.

## 3. Add three narrow detection rules

**Parks:** Three or more `refresh/unauthorized` events from the same pseudonymous actor within ten minutes create a case. This threshold is a demonstration setting, not a measured production baseline. An authorized refresh and an ordinary read are negative controls. The rule does not infer identity, intent, or compromise.

**Paperstack:** A `media-fetch/blocked-redirect` event creates a review case. The relevant code manually follows redirects and checks the destination against approved hosts. A blocked redirect may result from an upstream change, so the case asks for review rather than naming an attacker. An allowed fetch is a negative control.

**Grid:** A `release-check/build-test-mismatch` event creates a case. A fixture makes the standalone demo runnable; the optional collector reads the root release command, wrapper, and isolated Grid check script. It emits an event only for the recognized mismatch pattern. The source check is not a build-artifact or production-deployment check.

**ActionTrace:** An `agent-proposal/review-needed` event opens an action-scope review. The `scp` fixture records what was wanted, what access existed, what was proposed, a candidate alternative, and what the historical audit actually established. The rule does not claim the command ran, that data left the machine, or that `scp` was categorically wrong. ActionTrace remains a separate project; Sentinel consumes its redacted event shape.

**Why not a universal shell parser or anomaly model:** Neither is required to demonstrate these known boundaries. A parser that guesses at arbitrary commands would produce confident but unreliable incidents; an anomaly model would need meaningful training and false-positive evaluation first.

## 4. Give every case a trace

**What:** The case contains its triggering event IDs, first and last observed times, rule, relevant source paths, unknowns, and a recommended next step. The rendered timeline labels a supplied event record differently from read-only local source inspection.

**Why:** The analyst should be able to move from an alert back to the specific observations and code. The source paths explain the rule; they are not proof that an event happened. All event-derived text is escaped before HTML rendering.

**Why not claim HMAC or chain of custody now:** A truncated SHA-256 case ID helps identify a case but does not authenticate a log. The separate ActionTrace prototype explores HMAC; Sentinel has not yet established a protected collection key, trusted collector, or external checkpoint. Calling these case IDs tamper-proof would be false.

## 5. Preserve cases and analyst decisions

**What:** SQLite stores a narrow event projection and incident state. Reimporting the same event is idempotent. Reusing an ID with different supplied content is rejected. A repeated Grid source inspection of identical script content keeps the first observation time. Cases can be closed or reopened only with an analyst note. A reimport updates case evidence while preserving that decision.

**Why:** A static HTML file is a report, not an incident workflow. Analysts need to return to a case and know whether it was reviewed. SQLite transactions prevent a half-import if an ID conflict is found. A note explains why a status changed.

**Why not automatic blocking:** Rejected requests and source mismatches require context. Automatically blocking an actor or changing a Cloudflare release from these prototype signals would exceed the evidence and create operational risk.

## 6. Show the result without exposing a new service

**What:** `app.py render` writes a static, escaped HTML investigation casebook. The command-line interface supports `ingest`, `list`, `show`, `close`, `reopen`, and `render`.

**Why:** This is enough to exercise the complete local loop: event → detection → case → review → recorded decision. Static output does not add an unauthenticated HTTP endpoint.

**Why not a public dashboard yet:** A web UI would need authentication, authorization, session protection, CSRF defenses, rate limits, retention rules, and a reviewed deployment artifact. Those should be built when real telemetry is ready, not hidden behind a polished mockup.

## 7. Verify the behavior

Run `python -m unittest discover -s . -p 'test_*.py'` from this repository. The tests cover the positive and negative rule controls, ten-minute boundary, HTML escaping, the optional Grid source pattern, malformed evidence, ActionTrace rendering, event reimport, event-ID conflict, preserved analyst status, and Grid reinspection. Run the fixture imports and `render` to verify the generated case file as well.

**Why not an accuracy percentage:** The fixtures were chosen to test specific rules. They are not an independent sample of real attacks or benign traffic. Report exact passing cases and failures instead of a misleading detection-rate claim.

## 8. Publish only this project

This project is kept in a standalone GitHub repository. The broad SIYAQ workspace contains unrelated source, generated artifacts, local databases, and active changes; it must not be pushed as part of Sentinel. The repo ignores `out/` and `__pycache__/`. The demo records use invented actor IDs and contain no usable credentials. Publication is limited to the files required to run and understand Sentinel.

## 9. Local verification on 2026-09-28

The initial standalone copy passed nine Python unit tests. Importing the Parks/Paperstack fixture added seven events and two cases; importing the Grid fixture added one event and one case. Closing a case with a note changed its stored status, `show` returned that status and note, and the rendered HTML included the decision. Reimporting the Parks/Paperstack fixture added zero events and preserved the three cases. These checks establish local workflow behavior only. After adding ActionTrace and replay, all twelve tests passed. A fresh import of all three fixtures produced four cases.

## 10. Include agent-action tracing without merging the projects

**What:** Sentinel accepts a redacted ActionTrace event and renders the six-part action context inside an incident case. The first fixture is the historical `scp` workflow objection. The separate ActionTrace project is responsible for collecting and validating agent actions; Sentinel treats its event as supplied evidence, not as a trusted command receipt.

**Why:** A security analyst needs to see why an agent's proposed action may exceed the user's task or available access. The fields preserve the difference between proposal and execution. Including this signal also makes the cloud-app and agent-action boundaries visible in one local casebook.

**Why not ingest full agent transcripts or execute commands:** Transcripts can contain secrets, unrelated personal data, and tool output. Sentinel stores only the bounded redacted fields needed for review. It never runs the proposal.

## 11. Exercise the detector with controlled adversarial replays

**What:** `python replay.py` runs thirteen in-memory scenarios and writes `out/red-team-report.json` and `out/red-team-report.html`. They include same-actor refresh bursts, rotating pseudonymous actors, low-and-slow attempts, hostile and benign redirects, recognized and unknown Grid release paths, ActionTrace classification gaps, a multi-product sequence, falsified first-seen telemetry, and quiet controls. Only Sentinel's detection code runs; no request reaches a real app.

**Observed local rule outcomes:** Four scenarios alert as intended; five intended-review scenarios remain quiet; one multi-product scenario produces a partial signal without justified cross-product correlation; one benign redirect produces a review alert; and two benign controls remain quiet. These counts are for hand-authored cases, not a detection rate or a production risk estimate.

**Why:** A casebook with only successful alerts would hide the rules' failure modes. The replay gives a reviewer exact, reproducible misses and over-alerts. The falsified first-seen event demonstrates that rejecting a changed ID on reimport does not authenticate an event before its first import.

**Why not live attacks:** These are defensive tests of Sentinel's rules. Sending attack traffic to public services would create unnecessary risk and would not improve the first local measurement.

## 12. Compare with existing work

The [landscape review](LANDSCAPE.md) checks official documentation for TheHive, Sigma, OCSF, OpenTelemetry, OWASP agentic security, and ReliaQuest. It shows which ideas inform Sentinel and which compatibility or enterprise-product claims are not made. Sentinel is intentionally narrower: boundary-specific event traces, explicit unknowns, and reproducible detection gaps in Yusra's own application context.

## 13. Publish and verify the standalone repository

**What:** Published [yrasool/siyaq-sentinel](https://github.com/yrasool/siyaq-sentinel) as a public GitHub repository on 2026-09-28. GitHub reported `PUBLIC` visibility and `main` as the default branch. The committed files are the source, tests, fixtures, and documentation; generated reports and the SQLite database remain ignored under `out/`.

**Why:** A separate public repository makes the project reproducible and reviewable without exposing the broad SIYAQ workspace. The final standalone test run passed twelve tests. The local demo import yielded four cases. A mobile browser check found no horizontal overflow at 390 pixels.

**Why not deploy the casebook:** The local HTML demo is sufficient to inspect the workflow. A public analyst service would need the access, retention, and Cloudflare release controls described above.

## 14. Reject accidental sensitive fields at import

**What:** The JSONL importer now rejects unexpected top-level fields, including a supplied `headers` object or raw `url`. It bounds each required field and accepts only short, relative source paths in `evidence`. Tests check traversal, absolute paths, URL references, and oversized actor IDs. All fourteen tests pass with the existing fixtures.

**Why:** Silently dropping extra fields during SQLite storage still leaves a risky ingestion contract: callers could believe a raw log was safe to submit. Explicit rejection makes that mistake visible before any event is stored.

**Why not call this complete privacy protection:** Allowed free-text fields can still contain sensitive content. A later producer must redact before submission, and first-seen telemetry remains unauthenticated. The rules still have the misses and over-alerts documented by the replay.

## 15. Let different models challenge and repair the local detector

**What:** Codex Luna proposed a low-and-slow Parks event sequence already present in the replay; Codex Sol proposed a 30-minute review rule. Claude Sonnet then proposed a distinct six-event paced sequence that the local detector missed; Codex Sol proposed a volume rule. The [model attack/defense trace](MODEL_ATTACK_DEFEND.md) records the proposals, exact fixtures, baseline and post-change results, and benign controls.

**Why:** Running the model-generated events through the same parser and detector separates plausible-sounding attack claims from observed misses. Running benign lookalikes after each defense reveals the cost of broader detection. The current sixteen-scenario replay has six caught, four missed, one partial, three over-alerts, and two quiet controls; these hand-authored counts are not a field accuracy estimate.

**Why not call this a live attack or solved security issue:** No request reached Parks, Paperstack, Grid, Cloudflare, or the GPU server. The new rules improve local review coverage but do not change an application's authorization boundary. The benign controls remain hard to distinguish with the current event fields.

## Next milestones

1. Add privacy-reviewed event adapters for actual Parks and Paperstack application telemetry, with controlled local replay before any live connection.
2. Verify final Cloudflare route and binding artifacts before adding release-event collection. A source-script pattern alone is insufficient.
3. Add event correlation across products only when a defensible shared actor or asset identity exists. Do not join events merely because their times are close.
4. Evaluate detection fidelity on separately labeled benign and adversarial replays, then tune thresholds and report exact counts.
5. Add an authenticated analyst UI only after the storage, retention, and access model is defined.
