# SIYAQ Sentinel

SIYAQ Sentinel is a local security-incident workbench for National Parks refresh authorization, Paperstack media redirects, Grid release-path verification, and redacted ActionTrace proposals. It imports pseudonymous events, applies narrow detection rules, stores cases in SQLite, and renders an evidence-linked timeline. An analyst can close or reopen a case with a decision history that survives later changes.

The demo records are invented fixtures. A [local application connector](docs/LOCAL_APP_INTEGRATION.md) also executes the actual Parks authorization and Paperstack media-redirect functions with synthetic inputs and a mock fetch, then sends their sanitized decisions to Sentinel. The optional Grid collector reads scripts in a local SIYAQ checkout. Sentinel does not collect live Cloudflare logs, contact the GPU server, or deploy anything.

Imports accept only the documented event fields. Raw URLs, headers, request bodies, and absolute source paths are rejected; source references must be short relative paths. ActionTrace's six free-text fields still require human redaction before import. An [optional local HMAC import](docs/EVENT_AUTHENTICATION.md) verifies signed event bytes before storage; ordinary fixture imports remain unauthenticated. Neither mode proves that a pseudonymous actor ID was actually anonymized or that a producer reported a true event.

From this standalone repository's directory in Windows PowerShell:

```powershell
python app.py ingest fixtures/parks-demo.jsonl
python app.py ingest fixtures/grid-demo.jsonl
python app.py ingest fixtures/actiontrace-demo.jsonl
python app.py list
python app.py render
python replay.py
python -m unittest discover -s . -p 'test_*.py'
```

Open `out/incidents.html`. The three imports should produce four cases. Open `out/red-team-report.html` to see how the current detector behaves on sixteen curated local scenarios, including misses and over-alerts. The [model attack/defense trace](docs/MODEL_ATTACK_DEFEND.md) shows exact Codex and Claude proposals, what ran locally, and the observed before/after results. Re-running an import adds no duplicates. To record an analyst decision, copy a case ID from `python app.py list`:

```powershell
python app.py close CASE_ID --note "Reviewed the local fixture; no live incident."
python app.py render
python app.py reopen CASE_ID --note "Reopened for further review."
```

Use `--analyst ANALYST_ID` on close/reopen to identify a pseudonymous reviewer. Each decision is preserved in the case timeline; opening an older database migrates its latest note into the journal, though earlier overwritten notes cannot be recovered. The [crypto case workflow](docs/CRYPTO_CASE_WORKFLOW.md) shows how to issue and verify a fresh-challenge HMAC receipt for a redacted case snapshot. It ties HW1's HMAC and challenge-response ideas to the investigator workflow, and explains why HW2's toy discrete-log attack belongs in a separate strength demonstration rather than the production evidence path.

The SQLite database and generated HTML stay under ignored `out/`. To add a **read-only source inspection** of actual Grid scripts, run `python app.py ingest fixtures/parks-demo.jsonl --grid-repo PATH_TO_SIYAQ` in a fresh database. The collector emits a case only when it recognizes the legacy root release command and separate isolated Grid check. It does not inspect a fresh build or deployed Worker; an unrecognized pattern produces no event.

Parks rules request review for three unauthorized refresh attempts from one pseudonymous actor within ten or thirty minutes, or six in ninety minutes when shorter-window cases do not already explain the events. These are demo thresholds, not production-calibrated limits. Other rules handle a Paperstack media fetch blocked at an unapproved redirect, a Grid release-path mismatch or unverified command, and classified or unclassified ActionTrace proposals with a task trace. Authorized refreshes, ordinary reads, and allowed media fetches remain quiet controls. Two benign retry patterns now over-alert, as the replay makes visible.

Each case separates triggering event IDs from relevant local source files and states what remains unknown. A rejected request is not proof of an attacker or compromise. The short case ID is a stable identifier, not an authenticity guarantee. This version has no live telemetry or cross-product correlation.

The [step-by-step build log](docs/BUILD_LOG.md) explains what was done, why each choice was made, how it was verified, and why other features were deferred. The [landscape review](docs/LANDSCAPE.md) compares the project with established security tools and standards using their official documentation.

The recorded [local Parks/Paperstack decisions](fixtures/observed-local-decisions.jsonl) and [pre-written labels](fixtures/labeled-local-decisions.json) can be checked without the SIYAQ checkout using `python evaluate_local.py --events fixtures/observed-local-decisions.jsonl --probe fixtures/observed-local-probe.json --out out/recorded-evaluation.json`. See the [integration record](docs/LOCAL_APP_INTEGRATION.md) for the source-code probe and the [event authentication guide](docs/EVENT_AUTHENTICATION.md) for the signed local run and its limits.
