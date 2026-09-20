# ADR-0003: Reject UNC paths in the private prototype

**Date**: 2026-09-05

**Status**: accepted; network-silence implication partially superseded by [ADR-0004](0004-stable-topology-boundary.md)

**Deciders**: repository owner, controller ruling

**Partially supersedes**: [ADR-0002](0002-powershell-readonly-module-shape.md), which links back here in its later-decision note

## Context

The prior private-prototype design allowed drive-qualified and UNC filesystem paths when the local PowerShell process could address them. That allowance is too broad for this bounded diagnostic: even a metadata probe of a UNC path can initiate DNS, SMB, or authentication activity before a report exists. Those effects are outside the private Windows-local, no-network validation boundary.

The prototype needs no UNC evidence to exercise its first path/reparse hypothesis. Reclassifying a rejected input as a local collection failure would hide the boundary and invite adapter-like fallback behavior.

## Decision

Before collection, reject these inputs with the terminating stable identifier `BOUNDARY_REMOTE_UNSUPPORTED`:

- literal UNC paths beginning with `\\`;
- a FileSystem PSDrive whose declared root is UNC-backed.

Require the raw caller input to begin with a one-letter absolute drive form (`^[A-Za-z]:[\\/]`) before lexical normalization. Relative, current-drive-rooted, slash-rooted, provider-qualified, multi-character drive, and leading-whitespace forms remain terminating `BOUNDARY_INPUT_INVALID` values.

After each local segment metadata read, inspect reparse metadata before probing any descendant. If a local reparse segment declares a UNC, remote URI, or remote redirector target, stop that path collector with `collection-failure` / `REMOTE_REPARSE_TARGET_UNSUPPORTED`; retain the observed local segment, emit final-relation unknowns with null unobserved fields, and do not pass a descendant or target to `Get-Item`, `Resolve-Path`, or `Get-Acl`.

Accept only a drive-qualified local FileSystem path for this private prototype. Provider-qualified and non-FileSystem PSDrive inputs remain terminating `BOUNDARY_INPUT_INVALID` values. No UNC probing, DNS lookup, SMB connection, authentication attempt, or remote adapter fallback is permitted.

This partially supersedes the UNC allowance in [ADR-0002](0002-powershell-readonly-module-shape.md) and the associated earlier design text. ADR-0002 remains accepted for the single-script, read-only module shape and links here as its later-decision note.

## Consequences

- The public report is not produced for UNC or UNC-backed drive input; the stable error makes the scope boundary explicit.
- Tests exercise literal UNC rejection only at the validator boundary, so they do not make a network request.
- Reparse-escape tests use synthetic local item metadata and intercepted commands; they never create, resolve, or ACL-probe a remote path.
- UNC support requires a future explicit ADR with a network/authentication safety model and fixture-backed verification.
- [ADR-0004](0004-stable-topology-boundary.md) clarifies that these visible-form
  and metadata checks do not pin a filesystem identity and therefore do not
  prove network silence under concurrent namespace replacement.
