# ADR-0004: Limit path evidence to stable, non-adversarial topology

**Date**: 2026-09-13

**Status**: accepted for historical private releases; new native candidate direction is specified by [ADR-0005](0005-native-identity-collection.md)

**Deciders**: repository owner, explicit user approval of option A

**Partially supersedes**: [ADR-0003](0003-reject-unc-private-prototype.md),
whose visible remote-input and remote-target rejection remains in force

## Context

The S7D scan at source
`6926e207c8ad14a8f27e1c126ba885df2c121293` found that locality and reparse
checks retain path strings, while later final-path and ACL probes reopen names.
A local actor that can retarget the selected namespace between those operations
can make one report combine different filesystem identities. A replacement
that becomes remote may also cause network behavior before the collector can
reject it.

Identity-stable support for adversarial mutation would require native
handle-relative traversal and handle-based final-path and security-descriptor
collection. That changes the approved one-script architecture, proof allowlist,
compatibility surface, and package review. The private prototype is an operator
aid, not a security verifier, and public demand remains unvalidated.

## Decision

Keep the current implementation and reparse diagnostic. Support it only when
the operator controls the supplied namespace and can exclude concurrent path,
reparse-target, and PowerShell-drive retargeting for the duration of collection.
If that condition cannot be established, do not run the prototype or rely on
its final-path and ACL observations.

ADR-0003 continues to reject visible remote inputs, remote drive backing, and
remote targets discovered in metadata. Those checks are not a network-enforced
sandbox and do not prove network silence under concurrent namespace mutation.
When outbound prevention is required, the operator must use a separately
verified external network-denial boundary. Boundary Lens does not configure,
modify, or certify that boundary.

Repository-facing records use repository-relative or opaque evidence
references and non-linkable redaction labels. Full machine-local evidence stays
in approved private evidence storage and is not copied into the tracked tree.

## Consequences

- Existing public commands, schema, reparse behavior, and package layout remain
  unchanged.
- The S7D TOCTOU finding is resolved by an explicit scope decision, not by a
  claim that the code defect was fixed.
- Concurrent topology mutation can still invalidate evidence; this limitation
  remains visible in operator and security documentation.
- Cross-organization distribution, adversarial-local use, or a requirement for
  code-enforced network silence reverses this decision and requires a new ADR
  for identity-stable native handles.
