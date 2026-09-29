# Signed local event import

The local app probe can now sign each sanitized event, and Sentinel can require a valid signature before importing it. This addresses one narrow failure in the original replay: an altered, first-seen JSONL record cannot be accepted in **signed mode** without the signing key. Unsigned fixture imports remain available and are labeled “supplied event record” in the casebook.

## Run the signed path

From the standalone Sentinel repository in Windows PowerShell, set `$siyaqRepo` to a local SIYAQ checkout with `tsx` installed:

```powershell
$siyaqRepo = 'C:\path\to\siyaq'
python app.py keygen --out out/signed-local/event.key
& (Join-Path $siyaqRepo 'node_modules\.bin\tsx.cmd') scripts/local_decisions.mjs --siyaq-root $siyaqRepo --out out/signed-local --key-file out/signed-local/event.key
python evaluate_local.py --events out/signed-local/local-decisions.jsonl --probe out/signed-local/local-decision-probe.json --out out/signed-local/evaluation.json --key-file out/signed-local/event.key
python app.py --db out/signed-local/sentinel.db ingest out/signed-local/local-decisions.jsonl --key-file out/signed-local/event.key
python app.py --db out/signed-local/sentinel.db render --out out/signed-local/incidents.html
```

`keygen` creates 32 random bytes in an ignored `out/` file and refuses to overwrite an existing file. It prints the path, never the key. Do not reuse this local key for a live service or commit it. To rerun the probe, reuse the same file; do not run `keygen` again at that path.

## Exact contract

The signature is `hmac-sha256-v1:` followed by the hex HMAC-SHA-256 of `SIYAQ-SENTINEL-EVENT-V1\n` and canonical UTF-8 JSON. Canonicalization sorts object keys, omits the signature, and runs before the parser adds internal fields. The signed content is limited to `id`, `timestamp`, `product`, `action`, `outcome`, `actor_id`, and the optional bounded `evidence` and `trace` fields. Python verifies with a constant-time comparison before constructing the incident store. A signed record without `--key-file`, an unsigned record with `--key-file`, an altered outcome, a wrong key, or an event ID reused for different signed content is rejected. The signature is retained in SQLite; the case timeline labels verified events individually.

In the verified local run, Node signed nine events from the real Parks and Paperstack decision functions. Python verified and evaluated all nine, producing three cases with the same labels and outcomes as the unsigned run. Altering one outcome in the signed JSONL made import exit with “missing or invalid event signature”; no new database was created. The Sentinel suite covers tampering, wrong-key, missing-key, key-overwrite, event-ID conflict, and CLI rejection before database creation.

## Trust boundary and remaining work

This is **authentication of event bytes at import**, not proof that the application decision was truthful. Anyone with the local key can sign a false event. The key is shared by the local producer and verifier, so this pilot does not distinguish Parks from Paperstack as separate producers. It also does not protect the SQLite database after import, prevent replay of a valid signed event into a fresh database, guarantee that actor IDs are pseudonymous, or authenticate unsigned imports. The demo CLI permits unsigned mode for existing fixtures; a production collector would need a required signed policy, separate producer identities/keys, key rotation, replay controls, protected secret storage, retention, and access review.

No Cloudflare Worker, public route, binding, live log source, or GPU server was changed or contacted. The signed output and key stay under ignored `out/`; the public recorded local-decision fixture remains unsigned so readers do not mistake a published test key for a trust anchor.
