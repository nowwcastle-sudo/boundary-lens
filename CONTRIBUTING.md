# Contributing to Boundary Lens

Issues and pull requests using synthetic examples are welcome. This is
experimental open source, not a security verifier or supported incident service.

Before a change, read CONTEXT.md, README.md and the relevant ADR. Preserve the
drive-qualified local input boundary, fixed process errors, UNKNOWN meanings,
native identity coherence, bounded resources and read-only behavior.
Use synthetic local fixtures only; never commit real paths, raw ACL output,
incident documents, credentials or customer data.

## Development checks

From the repository root in PowerShell 7:

```powershell
pwsh -NoProfile -File tests/repro.ps1
if ($LASTEXITCODE -ne 0) { throw 'Classification checks failed.' }
pwsh -NoProfile -File tests/read-only.ps1
if ($LASTEXITCODE -ne 0) { throw 'Read-only checks failed.' }
pwsh -NoProfile -File tests/native-review-regressions.ps1
if ($LASTEXITCODE -ne 0) { throw 'Native review regressions failed.' }
```

The complete configured Windows gate is in .github/workflows/ci.yml. Keep failed
artifacts and capture immediate native exits. Update the reviewed native body
digest only after reviewing the actual native delta; never weaken an assertion
to conceal a product failure. Build into a fresh system-temp directory using
README's source-build instructions.

## Pull requests and disclosure

Describe changed behavior, source/fixture evidence, privacy impact and a
reversal path. Keep collector logic changes separate from release metadata.
A public source release does not authorize repair, elevation, telemetry,
remote probing or an effective-access/safety claim. Those require a separate
design decision. Preserve the Apache-2.0 license and required attribution.

Use GitHub issues for non-sensitive bugs and proposals.
Use the private reporting route in SECURITY.md for vulnerabilities. Do not
put sensitive reports into public issues or PR comments.
