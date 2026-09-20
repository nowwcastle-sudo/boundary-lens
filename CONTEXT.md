# Boundary Lens context

## Domain statement

Boundary Lens is a read-only diagnostic concept for Windows agent file-boundary incidents. Its implemented scope correlates local path/reparse and selected ACL identity metadata so an operator can narrow possible cause classes and prepare a support handoff. Runtime enforcement remains unknown. It does not verify safety or repair a system.

## Glossary

| Term | Meaning | Do not collapse into |
|---|---|---|
| **Incident boundary** | The operator-declared workspace root, failed path, product, and runtime being investigated. | The whole machine or every user path. |
| **Raw path** | The exact path string supplied by a product, user, setting, or log. | A canonical/final path. |
| **Lexical path** | An absolute path normalized syntactically without claiming target identity. | A resolved target or containment proof. |
| **Final target** | The destination reached after resolving supported path indirections. | The logical path shown to the user. |
| **Path identity graph** | Raw, lexical, existing-segment, reparse-target, URI, UNC/drive, and remote forms kept as related but distinct nodes. | A single canonical string. |
| **Runtime identity** | The local, WSL, SSH, sandbox account, process, URI scheme, and authority context in which access occurs. | The interactive user's identity alone. |
| **Evidence** | A timestamped observation or collection failure produced by a named probe. | A verdict. |
| **Cause class** | A bounded family of explanations consistent with stated evidence. | Confirmed root cause or safety judgment. |
| **Collection failure** | A probe that could not provide its intended observation, including contradictory status/output. | Absence of the property being probed. |
| **UNKNOWN** | A fact or attribution not established by available evidence. | False, safe, normal, or irrelevant. |
| **False-safe** | A conclusion that implies safety or normality without evidence sufficient to establish it. | A benign false positive. |
| **Handoff bundle** | A minimized report of evidence, failures, candidates, unknowns, and the next observation. | Automatic issue submission or a security certificate. |
| **Concierge probe** | A manually operated, read-only validation session used before product automation. | The MVP software implementation. |

## Invariants

1. Logical path and final target remain separately visible.
2. Evidence and `UNKNOWN` are never replaced by a safety verdict.
3. Collection never mutates ACLs or any other investigated boundary state.
4. A green doctor result or exit 0 cannot close an incident by itself.
5. Static evidence cannot prove runtime enforcement.
6. Scope expands only through an explicit ADR or product decision.

## Current posture

- Experimental open-source release, authorized on 2026-09-20; not proof of human adoption or prospective accuracy.
- One PowerShell script, Text/JSON reports, inspectable native collector and a four-member ZIP; no installer or service.
- ADR-0005 defines native identity-held collection; ADR-0006 authorizes the separate public history and preserves remaining limits.
- Original private development history and release artifacts remain privately retained and are not included here.
- README.md contains the current install, synthetic first use and safe report-handoff route.
