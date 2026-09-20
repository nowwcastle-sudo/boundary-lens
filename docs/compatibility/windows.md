# Windows runtime and portability contract

Boundary Lens targets Windows x64 and PowerShell 7. Use the latest serviced
PowerShell 7.6 LTS for operational work, subject to Microsoft's current support
matrix. The historical 7.0 compatibility floor is a separate execution contract;
an unsupported old runtime is not recommended for real incidents. The product
uses compatible SHA256.Create/ComputeHash/BitConverter primitives while keeping
the same 12-character lowercase identity fingerprint format. The native
candidate hashes SID strings, so values differ from old display-name hashes.

The current native candidate accepts local NTFS/ReFS and uses NT device-path
notation for final/reparse observations. Local verification was on NTFS; an
actual ReFS environment and every enterprise policy are not certified here.
Interop failure is explicit and does not trigger a name-based fallback. See
[ADR-0005](../adr/0005-native-identity-collection.md) for the changed boundary.

The 0.2.0 candidate requires recorded synthetic checks on the actual portable
7.0.13 runtime and the modern runtime, plus fresh package and Windows runner
evidence. A modern-runtime pass does not prove the historical floor. A runtime
that cannot launch on the test host is recorded as unavailable, not passed.
The existing pre-change baseline was observed on PowerShell 7.6.5 / .NET 10.0.11;
it does not certify the changed 0.2.0 source by itself.

No administrator session is needed and investigated filesystem state is
read-only. Reports and command arguments may contain sensitive local paths.
The operator controls their handling; fixed support errors are available
through the direct -File entry after the script has loaded successfully.

The certification gate runs the same checkout on two clean GitHub-hosted Windows
images: `windows-2022` and `windows-latest`. Each image runs the eleven named
regression, read-only, PSDrive, documentation and operational suites, followed
by separate native race/review and report-handoff steps. It verifies the exact
four ZIP members and runs the same process checks on standalone and extracted
script copies. The workflow checks a PowerShell 7.x version string; the actual
hosted runtime version must be recorded with each run rather than inferred
from the recommended serviced-runtime guidance above.
The workflow is [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

Recorded successful runs are reproducibility evidence for their exact checkout
and OS/runtime versions. The current release must identify those runs. This
does not claim that an unsupported PowerShell version, a remote/UNC path, an
elevated policy, or an arbitrary filesystem provider has the same semantics. It
also does not turn a virtual runner result into a guarantee about every physical
device, storage driver, ACL provider, or enterprise policy.

Native child tests have finite timeouts and retain timed-out trials with a null
product exit. A timeout, incomplete stream capture or host startup error is not
converted into a product pass. The process adapter cannot sanitize host errors
that occur before PowerShell loads the script (for example a damaged script or
execution-policy rejection); do not change global policy to bypass such errors.

The named-file dynamic comparison excludes access timestamps and makes no
whole-metadata claim. Original Boundary B `FixtureUnchanged=false` and control
`Identical=false` observations remain preserved; original directory-write-time
attribution remains UNKNOWN.

Sources: [Microsoft support lifecycle](https://github.com/microsoftdocs/powershell-docs/blob/main/reference/docs-conceptual/install/PowerShell-Support-Lifecycle.md),
[official historical 7.0.13 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.0.13).
