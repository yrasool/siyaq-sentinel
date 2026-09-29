# Parks and Paperstack local decision integration

Sentinel now has a **local source-code connector** for two real SIYAQ decisions. It calls Parks' `authorizeRefreshRequest()` and Paperstack's `fetchUpstreamImage()` with invented requests and an injected, bounded mock fetch. The output is Sentinel JSONL with only an ID, time, product, action, outcome, synthetic actor ID, and relative source reference. It does not read production logs, invoke a deployed route, contact a provider, or modify the SIYAQ apps.

## Architecture and boundaries

```text
Pre-written scenario labels ─┐
                             ├─> local_decisions.mjs ─> sanitized JSONL ─> Sentinel rules ─> cases
Actual Parks auth.ts ────────┤                         └─> probe evidence ──┐
Actual Paperstack mediaPolicy.ts ┘                                            ├─> evaluate_local.py
Pre-written review labels ────────────────────────────────────────────────────┘
```

The Parks probe executes the authorization helper only; a successful authorization does **not** run a refresh job. The Paperstack probe executes the redirect-handling helper only; it does **not** exercise the full media route, D1, or R2. Its `fetchImpl` is a local mock, and a global fetch guard throws if code tries to make an uninjected request. The probe reports whether any mock call reached a host outside the approved policy. The source functions are read from the local SIYAQ checkout and fingerprinted with SHA-256 so a later run can identify source drift.

The relevant SIYAQ source files were already modified or untracked in the user's broader workspace. This integration leaves them untouched and lives entirely in the standalone Sentinel repository. No Cloudflare route, binding, or deployment artifact changed.

## Labels before results

The nine [scenario labels](../fixtures/labeled-local-decisions.json) were committed in `ed56220` before the recorded output was generated. They specify the expected application decision and whether an analyst should review each synthetic event. They were authored from scenario intent without looking at Sentinel's alert result; they are **not** labels from external analysts or real incidents. The separate [recorded event file](../fixtures/observed-local-decisions.jsonl), [probe evidence](../fixtures/observed-local-probe.json), and [evaluation](../fixtures/local-decision-evaluation.json) preserve the output of that run.

The local application functions made all **nine** expected decisions. The Paperstack mock observed **zero** off-policy fetch calls. Sentinel opened **three** cases: one for the three Parks denials and two for Paperstack blocked redirects. Across the nine labeled events, four review-worthy events were covered, none missed, four benign controls stayed quiet, and one invented benign provider change over-alerted. These are curated case counts, not an accuracy estimate.

## Run it locally

In Windows PowerShell, from the Sentinel repository, set `$siyaqRepo` to a local SIYAQ checkout with dependencies already installed, then run:

```powershell
$siyaqRepo = 'C:\path\to\siyaq'
& (Join-Path $siyaqRepo 'node_modules\.bin\tsx.cmd') scripts/local_decisions.mjs --siyaq-root $siyaqRepo --out out/local-probe
python evaluate_local.py
python app.py --db out/local-probe/incident.db ingest out/local-probe/local-decisions.jsonl
python app.py --db out/local-probe/incident.db render --out out/local-probe/incidents.html
```

`evaluate_local.py` refuses mismatched scenario IDs, application decisions, or an off-policy mock fetch. To evaluate the recorded sanitized files without the SIYAQ checkout, run:

```powershell
python evaluate_local.py --events fixtures/observed-local-decisions.jsonl --probe fixtures/observed-local-probe.json --out out/recorded-evaluation.json
```

The recorded source hashes identify the local code that produced the decisions; this repository does not vendor or publish those app source files. A fresh run on another checkout may produce different hashes or decisions. Recheck labels if the app policy changes.

## Why this step, and what remains

The earlier replay sent authored outcomes straight to Sentinel. This connector first asks the **actual application functions** for their decisions, then tests how Sentinel investigates those decisions. It exercises a real security boundary without copying a secret, raw header, URL, IP address, request body, or provider response into Sentinel's event store.

It does **not** establish live telemetry. A production event producer would require a reviewed privacy model, stable pseudonymization, retention rules, authenticated collection, rate and size controls, environment isolation, and a verified Worker artifact. The current local label set is too small and too deliberately chosen to tune thresholds or claim field performance. A genuinely independent evaluation would need new, separately reviewed labels from a dataset not used to choose the rules.
