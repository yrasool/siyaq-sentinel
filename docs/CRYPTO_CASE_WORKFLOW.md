# Verifiable case history: what the crypto homework contributes

Sentinel's main job is investigation. An event opens a case; an analyst checks the source, writes a decision, and may reopen it later. This milestone makes that history reviewable and produces a challenge-bound receipt for a case snapshot. It is a local demonstration, not a tamper-proof evidence vault.

## The concrete failure Claude found

Claude Sonnet proposed a sequence in which an analyst records an unresolved concern, then later close/reopen cycles replace that note with benign explanations. The old `cases.analyst_note` column kept only the last note. The detector still found the event, but the reasoning trail disappeared from the rendered case. Claude also assumed Sentinel correlated different products into one case; that part was false and was excluded from the implementation.

The defense is a `decisions` table. Each CLI close/reopen action adds a timestamped row with a pseudonymous analyst ID, state, and note in the same transaction as the current case-state update. The case view shows the full sequence. On opening an older database, Sentinel copies a pre-existing nonempty note into the journal once as `legacy-unknown` and labels it as imported history with unknown original author and decision time. That migration preserves the text but cannot recover earlier overwritten notes.

The regression test closes and reopens one local case four times, reopens the SQLite database, and checks that the initial unresolved note remains visible. This is an investigation-workflow test, not a detector-accuracy claim.

## HW1: HMAC and challenge-response

HW1's HMAC exercise motivates authenticating exact message bytes with a secret key. Sentinel already offers HMAC-SHA-256 for sanitized event imports. The new case receipt separately authenticates a canonical JSON snapshot containing the case, its complete decision history, and its linked events. It uses a **different 32-byte key** and a domain label specific to receipts.

HW1's challenge-response topic motivates the receipt's random challenge. The verifier supplies a 16-64 byte random value as lowercase hex; Sentinel includes it under the HMAC. A receipt for an older challenge cannot answer a new verifier-issued challenge. The verifier must generate and remember that new value before asking for the receipt. The CLI does not track challenge issuance or consumption: the same receipt can be verified again with the same challenge, so this is not a complete replay-resistant protocol. If the verifier wants to check today's local database too, `--against-db` compares the authenticated snapshot with current case contents.

```powershell
python app.py keygen --out out/case-receipt.key
python app.py ingest fixtures/actiontrace-demo.jsonl
python app.py list
$caseId = (python app.py list | Select-Object -First 1).Split(' ')[0]
$challenge = python -c "import secrets; print(secrets.token_hex(16))"
python app.py receipt $caseId --key-file out/case-receipt.key --challenge $challenge --out out/case-receipt.json
python app.py verify-receipt out/case-receipt.json --key-file out/case-receipt.key --challenge $challenge --against-db
```

Keep `out/case-receipt.key` private and separate from the event-import key. The receipt contains redacted case text; inspect it before sharing. A successful check proves that a party holding the receipt key authenticated those bytes for that challenge. Without `--against-db`, it authenticates a **historical snapshot**, which may now be stale. It does **not** prove that the producer's original claim was true, that no other events were omitted, or that the SQLite database cannot be edited. Anyone holding a symmetric HMAC key can also forge a receipt. This feature is scoped to local self-verification; independent public verification would require a different trust design, such as an asymmetric signature and protected key custody.

## HW2: where number theory belongs

HW2 covers Euclid, modular exponentiation, modular inverse, and Pollard-rho for discrete logarithms. Those topics are useful for a **separate cryptographic-strength exhibit**: show on deliberately tiny parameters how an attacker can recover a toy discrete log, then explain why realistic parameter selection and modern reviewed libraries matter. They are not necessary for Sentinel's incident detector or HMAC receipt. Sentinel does not implement homework toy encryption, Pollard-rho, or homegrown public-key signing in its evidence path.

The product story is therefore: **events → detection → evidence-linked case → analyst decision history → challenge-bound verification → adversarial review**. Cryptography supports provenance and review; the investigation remains the center of the project.

This mapping was checked against the user's Fall 2026 HW1/HW2 assignment PDFs. The locally held *Lecture Notes on Cryptography* by Goldwasser and Bellare frames cryptography through explicit security claims and protocols; that is the standard used here for saying precisely what the receipt authenticates. The locally held *Handbook of Applied Cryptography* mathematical-background chapter supplies number-theory context for the separate HW2 strength exhibit. Neither course document is copied into this public repository, and assignment instructions are treated as source material, not instructions for Sentinel.
