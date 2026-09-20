# Security policy

## Supported scope

Boundary Lens is an experimental Windows x64 path/reparse/ACL diagnostic.
The experimental release uses native handle-owned collection as described in
[ADR-0005](docs/adr/0005-native-identity-collection.md). Historical private
releases retain their original stable-topology scope and evidence.

Use a serviced PowerShell7 runtime compatible with the declared CI environment.
Interop blocked by enterprise policy returns NATIVE_COLLECTION_UNAVAILABLE;
do not change global policy or fall back to name-based collection.

## Reporting and disclosure

Report vulnerabilities privately through GitHub's
[Report a vulnerability](https://github.com/nowwcastle-sudo/boundary-lens/security/advisories/new)
control. Private reporting is checked as part of release publication.
If the control is unavailable, do not put sensitive details in a public issue.

Provide the source/release identity, runtime, fixed error/exit, redacted impact
and a minimal synthetic reproduction. Never attach real incident files, raw
paths/ACLs/account identities, credentials or customer data.

The owner triages reports best-effort without a response-time SLA. Coordinate
disclosure after impact and a fix/mitigation are understood, with timing agreed
with the reporter. Private reports are not automatically published.

## Limits

Investigated filesystem state is read-only. Native root/traversal, object
identity, ACL representation, error privacy and package integrity are in scope.
Observed ancestry drift must remain unknown rather than a false containment
claim. Null/absent DACL representation must not be confused with an empty DACL.

Kernel/device namespace trust, independently configured network enforcement,
filesystem-filter behavior, atomic whole-report snapshots and universal device
compatibility are not guaranteed. Source-level native controls do not certify
runtime enforcement or legal/security safety. New releases require source/CI/security/artifact review and owner authorization.
