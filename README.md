# Boundary Lens

Read-only Windows path, reparse-point and ACL evidence for one declared
workspace and one failed path. **Experimental open source, Apache-2.0.**
This is a diagnostic aid, not an authorization check, security certificate or
repair tool. An exit of zero means a report was produced, not that access is safe.

Requires Windows x64 and a serviced PowerShell 7 runtime. Local NTFS/ReFS paths
are accepted; actual ReFS and every enterprise policy are not certified.
No installer, service, administrator session or runtime dependency installation
is required. Native interop blocked by policy produces an explicit failure;
do not weaken policy or use a name-based fallback.

## Download the experimental release

Release: [v0.2.0-experimental.1](https://github.com/nowwcastle-sudo/boundary-lens/releases/tag/v0.2.0-experimental.1).
The public download does not require a GitHub account. In PowerShell 7:

```powershell
$boundaryAssets = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-download-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $boundaryAssets -ErrorAction Stop | Out-Null
$boundaryRelease = 'https://github.com/nowwcastle-sudo/boundary-lens/releases/download/v0.2.0-experimental.1'
$boundaryZip = Join-Path $boundaryAssets 'boundary-lens-0.2.0-experimental.1.zip'
Invoke-WebRequest -Uri "$boundaryRelease/boundary-lens-0.2.0-experimental.1.zip" -OutFile $boundaryZip -ErrorAction Stop
Get-FileHash -LiteralPath $boundaryZip -Algorithm SHA256
```

Compare the complete ZIP SHA-256 with this release's notes before continuing.
Never substitute an older release's checksum. Preserve a failed directory and
logs; do not retry with an overwrite/--clobber option. A matching checksum
identifies bytes, not their safety.

## Verify and extract

The archive has exactly four members: script, LICENSE, README and SHA256SUMS.
Check the names before extraction, then check all three payload hashes:

```powershell
$boundaryArchive = [IO.Compression.ZipFile]::OpenRead($boundaryZip)
try {
    $expectedMembers = @('BoundaryLens.ps1', 'LICENSE', 'README.md', 'SHA256SUMS.txt')
    $actualMembers = @($boundaryArchive.Entries | ForEach-Object FullName | Sort-Object)
    if (($actualMembers -join ',') -cne (($expectedMembers | Sort-Object) -join ',')) {
        throw 'Unexpected archive member set; preserve the ZIP and stop.'
    }
} finally { $boundaryArchive.Dispose() }
$extractDir = Join-Path $boundaryAssets ('extracted-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $extractDir) { throw 'Extraction directory already exists; stop.' }
New-Item -ItemType Directory -Path $extractDir -ErrorAction Stop | Out-Null
Expand-Archive -LiteralPath $boundaryZip -DestinationPath $extractDir -ErrorAction Stop
$sums = @(Get-Content -LiteralPath (Join-Path $extractDir 'SHA256SUMS.txt') -ErrorAction Stop)
if ($sums.Count -ne 3) { throw 'Expected exactly three checksum entries.' }
$seenNames = @{}
foreach ($line in $sums) {
    if ($line -notmatch '^([A-Fa-f0-9]{64})  (BoundaryLens\.ps1|LICENSE|README\.md)$') { throw 'Unexpected checksum entry.' }
    $expected = $Matches[1]
    $name = $Matches[2]
    if ($seenNames.ContainsKey($name)) { throw 'Duplicate checksum entry.' }
    $seenNames[$name] = $true
    if ((Get-FileHash -LiteralPath (Join-Path $extractDir $name) -Algorithm SHA256 -ErrorAction Stop).Hash -ine $expected) {
        throw 'Checksum mismatch; stop use.'
    }
}
Set-Location -LiteralPath $extractDir
```

## Build from source

From a clone of this repository, use the existing packager. Its output must be
a fresh direct child of the system temporary directory with the shown prefix:

```powershell
$boundaryCandidate = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-package-candidate-' + [guid]::NewGuid().ToString('N'))
pwsh -NoProfile -NonInteractive -File .\tests\package.ps1 -OutputDirectory $boundaryCandidate
if ($LASTEXITCODE -ne 0) { throw 'Package preparation failed; preserve the directory.' }
Set-Location -LiteralPath $boundaryCandidate
```

The result includes the ZIP and standalone script with identical script bytes.
Follow the synthetic first use below. Do not compare a source build against a
different release's archive hash; build timestamps and README bytes can differ.

## First use with a synthetic example

Stay in the directory containing the verified script. The following setup
writes one new synthetic directory and file. This is operator preparation,
separate from the read-only diagnostic. It uses no existing incident data, and
the product does not delete anything afterward.

```powershell
$demo = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-demo-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $demo) { throw 'Synthetic directory already exists; stop.' }
New-Item -ItemType Directory -Path $demo -ErrorAction Stop | Out-Null
Set-Content -LiteralPath (Join-Path $demo 'synthetic.txt') -Value 'Boundary Lens synthetic example only.' -Encoding utf8
```

Run the diagnostic and capture its native process exit immediately:

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Text
$existingExit = $LASTEXITCODE
$existingExit
```

## Save JSON reports for handoff

Run each line below in the directory containing the verified
`BoundaryLens.ps1`. The diagnostic reads the declared inputs; your PowerShell
session creates the report files. Keep the output directory outside the
investigated input (`$demo` here) and outside any original incident directory.

1. Bind a separate output directory and two fresh report names. A guarded
   evaluator may replace only the right-hand side of the `$boundaryOutput`
   assignment with its assigned ENVIRONMENT output directory. The remaining
   lines stay the same.

```powershell
$boundaryOutput = Join-Path ([IO.Path]::GetTempPath()) ('boundary-reports-' + [guid]::NewGuid().ToString('N'))
if (-not (Test-Path -LiteralPath $boundaryOutput -PathType Container)) { New-Item -ItemType Directory -Path $boundaryOutput -ErrorAction Stop | Out-Null }
$reportRun = [guid]::NewGuid().ToString('N')
$existingReport = Join-Path $boundaryOutput ("boundary-existing-$reportRun.json")
$missingReport = Join-Path $boundaryOutput ("boundary-missing-$reportRun.json")
```

2. Produce the existing-file JSON, capture the diagnostic process exit
   immediately, then save only after exit `0`.

```powershell
$existingJson = & pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Json
$existingExit = $LASTEXITCODE
$existingExit
if ($existingExit -ne 0) { throw "Existing-file diagnostic failed with exit $existingExit; preserve the output directory and stop." }
$existingJson | Out-File -LiteralPath $existingReport -Encoding utf8 -NoClobber -ErrorAction Stop
```

3. Produce the missing-file JSON separately. Do not create the missing input
   and do not reuse the existing report path.

```powershell
$missingJson = & pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'missing.txt') -Format Json
$missingExit = $LASTEXITCODE
$missingExit
if ($missingExit -ne 0) { throw "Missing-file diagnostic failed with exit $missingExit; preserve the output directory and stop." }
$missingJson | Out-File -LiteralPath $missingReport -Encoding utf8 -NoClobber -ErrorAction Stop
```

4. Read both saved files back as JSON and review the interpretation and next
   observation fields locally before any handoff.

```powershell
$existingSaved = Get-Content -Raw -LiteralPath $existingReport | ConvertFrom-Json -ErrorAction Stop
$missingSaved = Get-Content -Raw -LiteralPath $missingReport | ConvertFrom-Json -ErrorAction Stop
$existingSaved.results | Select-Object status, code, next_observation
$missingSaved.results | Select-Object status, code, next_observation
$existingReport
$missingReport
```

Both reports should keep `RUNTIME_ENFORCEMENT_UNKNOWN`; static evidence does
not establish runtime enforcement. Full JSON can contain paths and environment
details. In particular, review `incident.workspace_input`,
`incident.failed_path_input`, and `incident.observed_at`. Preserve these saved
evidence files, make a separate minimized copy if sharing is authorized, and
review and minimize that copy locally before handoff. These commands do not
transmit a report or claim it is safe to share.

### Standalone format

Use the verified script directly. Keep LICENSE with redistributed copies.

### ZIP format

The release ZIP includes BoundaryLens.ps1, LICENSE, README.md and SHA256SUMS.txt.
Do not reuse historical private-release filenames, hashes or three-member
layouts. This repository starts with a new public history; private development
records and artifacts are not part of its releases.

## How to read results

- observed: the named probe collected that evidence.
- cause-candidate: evidence is consistent with a bounded cause class, not a confirmed root cause.
- collection-failure: a probe could not obtain its intended observation; this does not mean the property is absent or normal.
- unknown: available evidence does not establish the fact.

The current collector holds native handles, traverses validated local
components and compares volume-qualified object identities with observed
ancestry. Contradictory captured controls or failed revalidation leave final
containment null. It never follows a newly observed target during refresh.

Final/reparse/nearest paths use NT device notation, such as
\Device\HarddiskVolumeN\folder\file; original and lexical inputs remain alongside
them. Identity fingerprints hash SID strings, not old account display names.
Do not compare fingerprints across these implementations.

ACL rows are selected identity/access-mask metadata, not effective-access or
complete inheritance evaluation. Generic masks may appear as numeric rights.
Unsupported null/absent DACL, conditional/callback or object-specific ACE shapes
remain explicit collection gaps. existing_segment_count counts declared
lexical segments, not internal native opens or expanded target depth.

The operator controls local report retention. The product does not save, upload
or transmit reports. Native queried state is read-only, but access timestamps
can change due to observation; no whole-machine non-mutation guarantee is made.
Kernel/device namespace and configured mappings are trusted. Atomic whole-report
snapshots, all filesystem filters and every transient change are not covered.
For required network isolation, use a separately verified externally enforced
environment; visible remote-input rejection alone does not certify network silence.

Use a fresh PowerShell process when changing collector versions. The loaded
native type must match the collector contract. This prevents accidental mixed
versions, not hostile code already executing in the same process.

See [native design](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/adr/0005-native-identity-collection.md)
and [Windows compatibility](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/compatibility/windows.md).

## Read the example and preserve the original incident

The existing-file report should show four observed records and
`RUNTIME_ENFORCEMENT_UNKNOWN`, with exit `0`. The count describes collection;
static path and ACL observations cannot establish runtime enforcement.

Now observe a deliberately missing synthetic filename without creating it:

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'missing.txt') -Format Text
$missingExit = $LASTEXITCODE
$missingExit
```

Expected exit is still `0`, because a report was produced. Expect
`TARGET_NOT_OBSERVED`, `FINAL_PATH_UNKNOWN`, `FINAL_CONTAINMENT_UNKNOWN`, and
`RUNTIME_ENFORCEMENT_UNKNOWN`. Four unknown rows are an expected evidence limit.
The missing file remains missing. An existing-file comparison does not resolve
an original missing-file incident: keep its original path and report, verify
spelling and which application should create the target, and record the
product/version and original error code/time locally. Obtain separately
authorized runtime evidence when static observations cannot narrow the cause.

## Help and fixed support errors

The direct process entry accepts exactly `-Workspace`, `-FailedPath`, and
optional `-Format Text` or `-Format Json`, in any order or case. Both paths are
required and nonblank. Abbreviated, duplicate, unknown, positional and
colon-joined options are rejected. Relative and unsupported path forms are
rejected before collection.

The existing dot-source API remains available for local callers:

```powershell
. .\BoundaryLens.ps1
Get-Help Invoke-BoundaryLens -Full
Invoke-BoundaryLens -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Json
```

Use the direct process entry to obtain fixed support errors. This intentional
invalid synthetic input produces no investigated-path report:

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace relative -FailedPath (Join-Path $demo 'synthetic.txt')
$supportExit = $LASTEXITCODE
$supportExit
```

Stderr is only `BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2`. Invalid
input and rejected remote input exit `2`; unexpected product defects emit only
`BOUNDARY_INTERNAL_ERROR` and exit `3`. Reports, including expected collection
failures and unknowns, exit `0`. Share only the fixed code, process exit,
release/runtime version and approved hashes through private support. Keep real
arguments, reports, investigated documents and ACL output local until reviewed
and minimized. Dot-sourced calls retain normal terminating PowerShell errors.

This handling begins after PowerShell loads a valid script. Missing/damaged
scripts, execution-policy rejection and invalid `pwsh` startup options can emit
host errors containing local details before product code runs. Keep those
errors private; do not change global policy or error preferences to hide them.
Stop invoking the script if identity checks fail or the owner withdraws it.
There is no installed service or database to remove.

## Metadata evidence has a bounded scope

The dynamic comparison covers the named synthetic file's content hash, length,
refreshed last-write time, attributes and ACL SDDL. It is not whole-machine
mutation monitoring or proof that every metadata value remains unchanged.
Observation can affect access-time evidence; directory metadata can settle
after setup. Preserve unequal snapshots and investigate attribution separately.

The original Boundary B trial recorded `FixtureUnchanged=false`; its
no-product control recorded `Identical=false`. Both remain unchanged. Content,
ACL and membership preservation was observed; strict whole-metadata
non-mutation and the original directory-write-time cause remain `UNKNOWN`.
Later successful checks do not replace that failure evidence. Real pilot reuse
and willingness to pay remain unproven by these synthetic exercises.


## Contributing and reporting

Synthetic-only issues and pull requests are welcome. Read
[CONTRIBUTING](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/CONTRIBUTING.md),
[SECURITY](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/SECURITY.md) and
[CODE_OF_CONDUCT](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/CODE_OF_CONDUCT.md).
Use private vulnerability reporting for sensitive security information; never
paste real incident paths, ACL output, account identities or credentials into
public issues. Maintainer response is best-effort.

This experimental source release does not establish real-user adoption,
prospective accuracy, legal correctness or universal environment support.
Apache License 2.0: see [LICENSE](LICENSE).
