# Local model attack and defense trace

This is a controlled test of **Sentinel's detector**, not an attack on a live app. All event records are invented. The models could propose sequences or rules; Python tests and the local replay determined what actually happened. No model was given credentials or permission to contact the GPU server, Cloudflare, or other services.

## What each model did

| Role | Model | Proposed | What actually ran | Observed result |
| --- | --- | --- | --- | --- |
| Attacker 1 | Codex `gpt-6-luna` | Three rejected Parks refresh attempts from one actor at 0, 11, and 22 minutes. | Its [exact event sequence](../fixtures/model-attack-luna.jsonl) was parsed and passed to `detect()` locally. | Zero cases before the defense; one 30-minute review case after. This was an **independent rediscovery** of existing replay scenario P3, not a new finding. |
| Defender 1 | Codex `gpt-6-sol` | Add a 30-minute, three-denial review rule without duplicating a 10-minute burst. Test an expired-session retry control. | A human-reviewed version was implemented in `sentinel.py`, tested, and replayed. | P3 became caught; benign B3 also became an over-alert. The model proposed a rule; it did not edit code. |
| Attacker 2 | Claude Code `sonnet` | Six rejected Parks refresh attempts in pairs at 0, 5, 35, 40, 70, and 75 minutes. | Its [exact event sequence](../fixtures/model-attack-claude.jsonl) was parsed and passed to `detect()` locally. | Zero cases before the second defense; one volume-review case after. This was distinct from the existing 11-minute scenario. |
| Defender 2 | Codex `gpt-6-sol` | Add a six-denial rolling-volume rule and test a stale-credential client. | A 90-minute review rule was implemented and replayed. The model suggested 75 minutes; the implementation used a round 90-minute window, still an uncalibrated demo threshold. | P4 became caught; observationally similar benign B4 became an over-alert. The model proposed a rule; it did not edit code. |

The model calls were read-only or tool-restricted. The attacker model's output was a **proposal**, not an executed request. The only executed actions were local parser, detector, test, and replay commands. The ActionTrace distinction matters here: “model suggested an attack” does not mean it reached an app, and “model suggested a defense” does not mean the defense worked until the same input was rerun.

## ActionTrace view of the Claude round

| Field | Recorded value |
| --- | --- |
| Wanted | Find a review-worthy event sequence missed by the improved local detector, then repair the miss. |
| Available | Read-only access to local detector and replay source for Claude; a tool-free rule-design prompt for Codex Sol; local Python tests for verification. |
| Proposed | Claude proposed six paced denied-refresh events. Sol proposed a six-denial rule within 75 minutes and attaching uncovered events to existing cases. |
| Simpler candidate | Use the exact model fixture as a regression test and add one independent volume-review case only when the shorter rules did not cover the events. |
| Observed | Before: fixture parsed, zero cases. After: fixture parsed, one case; 17 unit tests pass. A benign client at the same cadence also produces a case. |
| Assessment | Local detector coverage improved. The implementation chose a 90-minute demo window and did not implement case attachment, which would complicate stable case identity. Neither the model output nor the case proves malicious activity. |

This is a sanitized action trace, not a trusted command log or cryptographic receipt. Raw model terminal output remains in ignored local `out/` files and is not needed to reproduce the detector result.

## Reproduce the checks

From the repository root, run `python -m unittest discover -v` and `python replay.py`. To inspect Claude's sequence as an incident, run:

```powershell
python app.py --db out/model-trial.db ingest fixtures/model-attack-claude.jsonl
python app.py --db out/model-trial.db list
python app.py --db out/model-trial.db render --out out/model-trial.html
```

The generated HTML and SQLite database remain under ignored `out/`.

| Scenario | Before | After | Meaning |
| --- | --- | --- | --- |
| P3: 0/11/22-minute denied refreshes | No case | 30-minute review case | Known miss addressed. |
| P4: six paced denials over 75 minutes | No case | 90-minute volume case | Claude's newly proposed local gap addressed. |
| B3: benign expired-session retries | No case | Review case | New over-alert. |
| B4: benign stale-credential client at P4 cadence | No case | Review case | New over-alert; events alone cannot separate B4 from P4. |

The original 13-scenario replay had 4 caught, 5 missed, 1 partial, 1 over-alert, and 2 quiet controls. The current 16-scenario replay has 6 caught, 4 missed, 1 partial, 3 over-alerts, and 2 quiet controls. **These totals are not directly comparable accuracy percentages** because three scenarios were added. The per-scenario transitions above are the meaningful result.

The public repository's pre-trial commit is `59ed3f8`. It preserves the original detector so the two model fixtures can be rerun against that version in a separate checkout. The current tests and `replay.py` verify the post-change behavior.

## What remains unsolved

The new rules only request analyst review. They do not strengthen Parks authorization or prove an attacker existed. Pseudonymous actor IDs can rotate, unsigned first-seen events can be falsified, and a legitimate client can produce the same timing pattern. The optional local HMAC import can reject altered event bytes but does not establish that a producer told the truth. The current thresholds were chosen to exercise the local replay, not calibrated on production traffic. The next meaningful step is a privacy-reviewed producer for actual authorization decisions, followed by independently labeled benign and adversarial events; until then, no real-world false-positive or detection rate is claimed.
