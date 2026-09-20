# ADR-0005: Hold native filesystem identities during collection

- Date: 2026-09-20
- Status: accepted native implementation; experimental distribution authorized by [ADR-0006](0006-experimental-public-release.md)
- Partially supersedes: [ADR-0004](0004-stable-topology-boundary.md) for the new candidate only
- Historical private releases and their accepted scope are unchanged

## Why this direction

ADR-0004 explicitly requires identity-stable native collection before
cross-organization distribution. Keeping only a warning would not meet that
condition. Rejecting every local reparse point would remove the principal
diagnostic. A constrained native collector preserves that capability in the
single inspectable PowerShell script.

## Boundary

Resolve PSDrive/DOS backing metadata without reopening the original name.
Only local native HarddiskVolume roots are accepted; current native collection
accepts NTFS/ReFS. Open one path component relative to a held parent with
existing-object, read/query permissions and non-following reparse behavior.
Read the reparse buffer directly, validate its lengths/tag/target, and traverse
supported local symlink/junction targets explicitly. Remote and ambiguous forms
fail closed.

Use the same held object for final path, file/volume identity and security
descriptor. Keep both input sessions alive until relation processing finishes.
Observe ancestry consistently; an observed topology change must not become a
confident final-containment claim. Null/absent DACLs that the current report
cannot distinguish must not look like an observed empty DACL.

The namespace/kernel and configured local volume mappings are trusted. Handle
pinning does not make ACLs or the whole machine an atomic snapshot, and does not
control filesystem filters. Absolute outbound prevention still requires a
separately verified external boundary.

## Observable compatibility changes

- Original and lexical paths retain their drive-qualified meaning.
- final_path, nearest_existing_path and observed reparse paths use native NT
  device notation such as backslash-Device-backslash-HarddiskVolumeN.
- Final containment uses object identity and observed ancestry, not only string
  prefixes.
- Object keys qualify file IDs with the held native volume identity as well as
  its serial; a serial duplicated by a cloned volume is not global identity.
- Identity fingerprints keep the 12-hex SHA-256-prefix format but hash SID
  strings, avoiding account-name translation. They are not comparable to old
  account-name fingerprints.
- NATIVE_COLLECTION_UNAVAILABLE reports unavailable/blocked interop, and
  NATIVE_VOLUME_UNSUPPORTED reports unsupported volumes. There is no name-based
  fallback.
- Known post-load interop failures retain NATIVE_COLLECTION_UNAVAILABLE.
  Unexpected managed collector failures use neutral NATIVE_COLLECTION_FAILED,
  not a claim that the filesystem path caused the failure. Native exception
  text is not copied to the report.
- Traversal is bounded by 16 reparse/alias steps and 256 components/owned handles;
  exceeding any applicable budget fails closed. ADS and ambiguous component
  forms remain unsupported.
- PATH_TOPOLOGY_CHANGED or PATH_TOPOLOGY_UNAVAILABLE preserves object evidence
  but makes final containment null and the relation explicitly UNKNOWN.
- Captured controls must be coherent within and across the paired sessions.
  Reparse presence and original reparse bytes are rechecked through held
  handles; conflicting captured controls for the same object also invalidate
  containment. Revalidation never follows a newly observed target.
- A missing declared suffix after a successfully resolved local reparse target
  remains ordinary missing-path evidence. A missing target-expansion component
  remains an unresolved reparse target; those cases are not collapsed together.
- ACL_DACL_UNSUPPORTED distinguishes unsupported null/absent DACLs from an
  observed empty DACL; this report is not an effective-access evaluator.
- ACL_ACE_UNSUPPORTED rejects conditional/callback, opaque or object-specific
  entries that the current summary cannot faithfully represent. Generic access
  mask bits are retained rather than rejected for lacking an enum label.
- Reserved DOS device components and their extension forms are ambiguous for
  the supported filesystem path model and are rejected before native traversal.
  Supported volume GUID aliases are case-insensitive.
- existing_segment_count retains declared lexical-segment meaning; separate
  internal traversal/owned-handle counters enforce resource budgets.
- Reusing a loaded native type requires a matching collector contract marker.
  This guards accidental mixed versions, not hostile same-process execution.

## Proof and release gate

The embedded native source requires its own API/access/disposition/control-code
review as well as the PowerShell AST allowlist. Add-Type allowlisting or a body
hash alone does not establish native safety. Test failures and old mock-case
migration remain explicit.

Current local evidence includes modern PowerShell and a verified historical
7.0.13 runtime on this Windows host. Historical runtime execution is not a
recommendation to deploy an unsupported runtime or proof of all Windows/ReFS
environments. Final source CI, independent review, security review and package
identity are required before a public candidate can be declared ready.
