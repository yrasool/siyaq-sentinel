# Where Sentinel fits

Checked against official project documentation on 2026-09-28. These are comparisons of scope, not claims that Sentinel replaces or integrates with the listed products.

| Existing work | What it already does | Sentinel's narrower contribution |
| --- | --- | --- |
| [TheHive](https://github.com/TheHive-Project/TheHive) | Collaborative security case management. | A local, source-linked casebook for a few owned cloud-app and agent-action boundaries; no attempt to clone enterprise collaboration or response automation. |
| [Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) | A shareable detection-rule specification. | A small Python rule engine with explicit controls and replay outcomes. Sentinel's rules are **not** Sigma rules and are not portable to a SIEM yet. |
| [OCSF](https://ocsf.io/) | A common schema for security events and findings from differing sources. | A deliberately small JSONL event contract for four local signal types. It is **not** OCSF-conformant; mapping to OCSF is a future interoperability task. |
| [OpenTelemetry logs](https://opentelemetry.io/docs/specs/otel/logs/data-model/) | A general log data model for heterogeneous sources. | A curated local trace with source/evidence/unknown boundaries. A future live adapter should normalize actual app telemetry rather than asking every app to emit Sentinel's fixture shape. |
| [OWASP Agentic Skills Top 10](https://owasp.org/projects/agentic-skills-top-10) | Security risks in the agent skill and tool-behavior layer. | A bounded ActionTrace event showing desired task, available access, proposed action, simpler candidate, and observed effects; it does not automatically decide that `scp` or another tool is malicious. |
| [ReliaQuest GreyMatter for software](https://reliaquest.com/solution-brief/greymatter-for-software) | Enterprise detection and investigation across developer, CI/CD, cloud, and AI-application telemetry. | An independent portfolio project using Yusra's own apps. No GreyMatter access, integration, performance, or feature parity is claimed. |

The design choice is to make **evidence lineage and coverage gaps visible**. Existing platforms are much broader. Sentinel currently answers only a few concrete questions and shows the exact synthetic cases in which those answers fail. Its strongest differentiator is the combination of app-boundary events with a separate agent-action trace, while preserving what is merely proposed, observed, blocked, or unknown.
