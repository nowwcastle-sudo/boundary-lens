# ADR-0002: Use one PowerShell read-only module shape

**Date**: 2026-09-04

**Status**: accepted

**Deciders**: repository owner

## Context

The private prototype needs Windows path, reparse, and ACL metadata while remaining inspectable, dependency-free, non-elevated, and read-only. Demand beyond private validation is not established, so compiled distribution and runtime tracing would add decisions that do not test the immediate hypothesis.

## Decision

Use one PowerShell 7 script with the sole supported interface `Invoke-BoundaryLens -Workspace -FailedPath -Format`. Keep collectors, a pure classifier, and renderers as internal functions. Scope the first classifier to Windows-local `REPARSE_TARGET_MISMATCH`; exclude remote URI adapters and every mutation or safety verdict.

## Alternatives Considered

### .NET or Rust binary

- **Pros**: stronger compile-time types, direct executable packaging, higher performance ceiling.
- **Cons**: toolchain, project, build, interop, signing, and packaging overhead before demand is proven.
- **Why not**: PowerShell 7 can test the private hypothesis with fewer owned parts.

### Sysinternals/ProcMon wrapper

- **Pros**: mature effective-access and runtime event observation.
- **Cons**: external dependencies, broad sensitive traces, reproduction requirement, parser maintenance, and frequent elevation needs.
- **Why not**: it violates the no-dependency/no-elevation first scope and does not isolate the common evidence model.

## Consequences

### Positive

- One inspectable file and no dependency installation.
- One deep external interface hides collection, normalization, classification, and formatting.
- Pure synthetic classification tests need no junction, ACL change, elevation, or live incident.

### Negative

- PowerShell path/object coercion needs explicit validation and tests.
- The private invocation requires PowerShell 7 and dot-sourcing the script.
- Compiled packaging and remote adapters require a later replacement or extension decision.

### Risks

- A report may be mistaken for a security verdict; mitigate with fixed `cause-candidate`, `collection-failure`, and `unknown` statuses and forbidden-verdict tests.
- A hidden write could violate the product premise; mitigate with a strict command allowlist, static scan, synthetic tests, and isolated before/after observation.

## Later decision

On 2026-09-05, [ADR-0003](0003-reject-unc-private-prototype.md) partially superseded this ADR's earlier input and traversal allowance: the private prototype now requires raw one-letter absolute local input, rejects literal UNC paths and UNC-backed FileSystem drives before collection, and stops at locally observed remote-reparse metadata before descendant, resolution, or ACL probes. This record remains the historical decision for the one-script, read-only module shape.
