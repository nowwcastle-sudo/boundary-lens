# Local incident completion evidence — 2026-09-20

The table below records the first Task 3 commit. The review-fix evidence
at the end supersedes its affected assertion counts and limitations.

Scope: local Windows/PowerShell 7 checks on the source candidate. This is not a public-release, all-environment, runtime-enforcement, or network-isolation certificate. Task 1 and 2 implementation details are in their local SDD reports; this table uses the actual source tests and this task's rerun. Assertion counts are per script, not additive coverage claims for each row.

| Requirement | Positive and negative case | Source | Executed command | Assertions / exit | Observed result |
|---|---|---|---|---|---|
| BL-L01 context | Valid incident schema and optional fields; malformed/duplicate/nonscalar and forged fields rejected | `src/IncidentInput.psm1`, `tests/incident-input.ps1` | `pwsh -NoProfile -File tests/incident-input.ps1` | 45 / 0 | Strict parser and real synthetic core accepted; invalid incident shapes rejected. |
| BL-L02 selected process | Current PID observed with incident-time identity unconfirmed; missing, exited, changed/reused, denied doubles unavailable | `src/IncidentObservations.psm1`, `tests/incident-observations.ps1` | `pwsh -NoProfile -File tests/incident-observations.ps1` | 129 / 0 | Second fresh process object and null failure values checked. Actual enterprise denial was not verified. |
| BL-L03 logs | Explicit JSON/JSONL, exact 10,000-record and 1 MiB bounds; malformed batch/overflow rejected, arbitrary message discarded | `src/IncidentInput.psm1`, `tests/incident-input.ps1`, `tests/incident-interface.ps1` | `pwsh -NoProfile -File tests/incident-input.ps1`; `pwsh -NoProfile -File tests/incident-interface.ps1` | 45 / 0; 13 / 0 | Repeated `-LogPath` pairs exported only aliased log metadata; malformed inputs produced no partial output. Deterministic concurrent changed-read proof remains open. |
| BL-L04 volume/filter | Local volume metadata and operator-supplied filter; unready/unsupported/denied doubles unavailable, supplied `SAFE` not measured | `src/IncidentObservations.psm1`, `src/IncidentHandoff.psm1`, `tests/incident-observations.ps1`, `tests/incident-handoff.ps1` | `pwsh -NoProfile -File tests/incident-observations.ps1`; `pwsh -NoProfile -File tests/incident-handoff.ps1` | 129 / 0; 29 / 0 | Filter content aliased; forged supplied→observed handoff case first failed (exit 1), then passed after downgrade (exit 0). Actual denied volume was not verified. |
| BL-L05 URI | Local/remote/invalid URI classification; remote value not fetched, relation unknown, forbidden named network/process APIs AST check | `src/IncidentObservations.psm1`, `tests/incident-observations.ps1` | `pwsh -NoProfile -File tests/incident-observations.ps1` | 129 / 0 | Syntax-only URI result and positive-control AST rule passed. This bounded static test does not prove process-wide network isolation. |
| BL-L06 handoff | Synthetic full core, privacy sentinels, HTML encoding, no-clobber, hardlink/junction/inside-path rejection; component-boundary sibling allowed; unsupported flags exit 2, unavailable optional exit 1 | `src/IncidentHandoff.psm1`, `src/BoundaryIncident.ps1`, `tests/incident-handoff.ps1`, `tests/incident-interface.ps1` | `pwsh -NoProfile -File tests/incident-handoff.ps1`; `pwsh -NoProfile -File tests/incident-interface.ps1` | 29 / 0; 13 / 0 | Four-key envelope, `RUNTIME_ENFORCEMENT_UNKNOWN`, static HTML and unchanged synthetic original verified. Write-failure after opening was not forced; exclusive create's failure artifact remains a bounded design claim. |

The 11 preexisting CI suites, native race (12 assertions), native review (2 + 183 assertions), original documented report handoff, candidate package, standalone core UX (26 cases), extracted core UX (26 cases), and extracted companion interface (13 assertions) passed locally with exit 0 after the README route fix. The old report-handoff run failed when an added example became a fifth code block in the historical four-block section; the final rerun passed. The source-built ZIP has eight members. The already published four-member ZIP and its checksum were not modified. Two-Windows remote CI is pending authorized branch publication. Unsupported filesystems, privileged namespace replacement, real denied environments, and whole-product network isolation remain unverified.

## Review fix round 1

Focused failing tests first showed three defects: a genuine junction workspace
could place output in its real target, a locked valid input was reported as a
path/resource error, and HTML had no readable summary/observation tables.
After the fix, the source tests returned:

| Script | Assertions | Exit | New positive and negative evidence |
|---|---:|---:|---|
| tests/incident-input.ps1 | 47 | 0 | Locked incident/core/log reads retain fixed IO failure; invalid/oversize input remains a distinct path/resource rejection. |
| tests/incident-handoff.ps1 | 36 | 0 | Unverified or empty workspace fails before output creation; injected post-open write failure retains a one-byte partial artifact; separate HTML tables encode injected markup; private URI scheme becomes other. |
| tests/incident-interface.ps1 | 20 | 0 | Genuine junction target output is rejected with INCIDENT_OUTPUT_INVALID/exit 2 and no file; outside alias and missing failed target with verified parent still export; locked core is INCIDENT_FILE_IO_FAILED/exit 1; invalid UNC remains exit 2. |

The physical boundary check inspects local link targets, obtains the current
parent-directory NT path through a read-only metadata handle, and compares
component boundaries before exclusive creation. Saved core NT paths add
exclusions but do not authenticate the report or current topology. Unknown or
remote link targets are not followed. A privileged replacement race remains
outside the guarantee. The earlier unforced write-failure limitation is
superseded by the injected partial-artifact test; actual disk-full or denied
write conditions were not exercised. The eight-member candidate package and
extracted companion test also passed after the fix. Two-Windows remote CI and
the Task 1 node/changed-read proof gaps remain open.
