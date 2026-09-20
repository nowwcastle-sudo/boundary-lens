# ADR-0001: Keep the first validation private and read-only

- Status: Historical initial scope; public-source distribution policy superseded by [ADR-0006](0006-experimental-public-release.md). Read-only and no-false-safe constraints remain.
- Date: 2026-09-04
- Decision owners: repository owner

## Context

A retrospective audit selected 18 Windows agent boundary incidents across Codex, Claude Code, and VS Code/Copilot. A common read-only evidence workflow could directly narrow 12 and partially narrow 4. That 16/18 result supports technical investigation, but the sample is selected and historical. It does not establish prospective accuracy, repeated use, market size, or willingness to pay.

The most costly failure mode is false-safe output: a diagnostic that turns incomplete static evidence into "safe" or "normal." Repair actions also have asymmetric cost because ACL, inheritance, reparse, or product-setting changes can require a separate restoration procedure.

## Decision

The first phase is a private, manual concierge prototype with these boundaries:

- Read only the workspace and failed path explicitly named by the participant.
- Correlate evidence and report cause-class candidates, collection failures, and `UNKNOWN`.
- Never output `SAFE` or an equivalent security/normality assertion.
- Never change ACLs, owner, inheritance, reparse points, attributes, filters, sandbox policy, product configuration, or target files.
- Do not add telemetry, upload, background monitoring, auto-repair, public distribution, or broad machine scanning.
- Do not implement product code until the staged design gate is approved. This ADR records product scope, while the private development approval record at that time remained unapproved.

## Why this option

It is simpler, reversible, and directly tests whether operators reuse the evidence handoff. It also preserves an explainable manual baseline before automation and reduces the chance that an incomplete collector is treated as a security verifier.

## Rejected alternatives

### Build a broad cross-product product immediately

Rejected because repeated use and prospective false-negative rate remain `UNKNOWN`. A minimal private diagnostic prototype is authorized after the staged design gate because it is the instrument used to measure those unknowns.

### Add ACL repair or automated workarounds

Rejected because repair is outside diagnosis, can be hard to reverse, and would change the observed boundary.

### Ship a doctor-style green/red verdict

Rejected because existing evidence includes doctor-green/runtime-red and error-output/exit-zero counterexamples.

### Limit validation to GitHub issue counts

Rejected because issue reports do not measure active users, incidence, retention, or willingness to pay.

## Consequences

- Initial validation is slower and operator-assisted.
- The report must make missing privileged observations visible.
- Runtime-only cases will remain unresolved until a separately authorized runtime observation exists.
- No public artifact or automated repair is produced during this phase.

## Revisit conditions

- Consider public/product release only if at least 6 of 8 real incidents are narrowed to two or fewer cause classes within 15 minutes, at least 4 participants reuse or attach the report, false-safe remains zero, and at least 2 request installation or automatic execution.
- Drop or narrow scope if only 3 or fewer incidents are narrowed or users do not reuse the workflow.
- Split remote URI diagnosis if it cannot share a clear operator model with local Windows path/ACL diagnosis.
