# ADR-0006: Publish a separate experimental source release

- Date: 2026-09-20
- Status: accepted by the owner
- Supersedes: ADR-0001's private-only distribution gate, for experimental source availability only

The owner authorized public release while preserving private development
history. This repository starts a clean public history under the product name.
Original private commits, issues, execution logs and release assets are not
imported. The Apache-2.0 license and source attribution are preserved.

Public availability is not a claim that prospective accuracy, human adoption,
repeat use, market demand or all-device compatibility has been established.
Those questions remain open. Native collection in ADR-0005 and all read-only,
input/privacy, UNKNOWN and no-safety-verdict boundaries remain in force.

Release identity is v0.2.0-experimental.1. It uses the reviewed native collector
without changing product behavior. Publication changes the distribution guide,
support routes, packaging name and repository metadata. Source, CI and package
hashes identify actual release bytes; historical private hashes are not reused
for changed archives.

The public intake uses GitHub private vulnerability reporting. Public issues
and PRs are synthetic-only. No telemetry, incident upload, remote probing,
repair, elevated policy change or authorization decision is introduced.
