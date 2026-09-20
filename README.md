# Boundary Lens

English | [한국어](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/README.ko.md)

Read-only Windows path, reparse-point and ACL evidence for one declared
workspace and one failed path. Experimental open source, Apache-2.0.
This is a diagnostic aid, not an authorization check, security certificate or
repair tool. An exit of zero means a report was produced, not that access is safe.

Requires Windows x64 and a serviced PowerShell 7 runtime. Local NTFS/ReFS paths
are accepted; actual ReFS and every enterprise policy are not certified.
No installer, service, administrator session or runtime dependency installation
is required. Native interop blocked by policy produces an explicit failure;
do not weaken policy or use a name-based fallback.

Use Boundary Lens when a Windows application cannot access a local path and
you need evidence to discuss with its maintainer. You provide the workspace
root and the path that failed. The report keeps the path you supplied, the
observed target and collection gaps separate. ACL means access control list:
the permission entries attached to a file or directory. A reparse point is a
filesystem entry, such as a junction or symbolic link, that can redirect a path.

## Features and command reference

| Feature | Input or option | What you get | Limit |
|---|---|---|---|
| Inspect one incident | Required `-Workspace` and `-FailedPath` | Path and ACL evidence for the two declared paths | No recursive workspace inventory or file-content analysis |
| Accept local paths | Nonblank, one-letter drive-qualified absolute paths on local NTFS/ReFS | Original and normalized lexical paths retained separately | Rejects relative/provider-qualified paths, reserved DOS device components, UNC, remote URI/WSL forms and detected UNC-backed drives |
| Observe path redirection | Existing path components, including supported reparse points | Final paths, reparse observations and logical/final workspace relations | Missing targets, unsupported targets and changed topology remain explicit gaps; no automatic repair |
| Observe ACL metadata | Security descriptor from the held object | Selected identity fingerprints and access masks | No effective-access decision or complete inheritance evaluation; unsupported ACL shapes remain gaps |
| Read a terminal report | `-Format Text` (default) | Counts for four evidence records, then status, code, evidence references and next observation | Counts describe collection, not whether access is safe |
| Preserve detailed evidence | `-Format Json` | Compressed JSON with `schema_version = 1`, `incident`, `evidence` and `results` | Printed to stdout; the operator must save and review it |
| Suggest the next observation | Result rows | A `REPARSE_TARGET_MISMATCH` cause candidate when the observed relations support it, plus failures and unknowns | A candidate is not a confirmed cause; `RUNTIME_ENFORCEMENT_UNKNOWN` remains |
| Call from PowerShell | Dot-source the script, then `Invoke-BoundaryLens` | The same report formats and local help | Normal terminating PowerShell errors; fixed support errors belong to the direct process entry |

`-Workspace` and `-FailedPath` name the incident inputs, not output folders.
The direct process entry accepts the three full option names in any order or
case. It rejects abbreviated, duplicate, unknown, positional and colon-joined
options. There is no output-file option; use the guarded saving steps below.

## Start here

Open PowerShell 7 (`pwsh`) on Windows x64 as your ordinary user. Windows
PowerShell 5.1 is outside this runtime contract. The script needs native interop;
policy that blocks it can prevent collection. Use your approved serviced
PowerShell 7 installation and keep policy restrictions in place.

For a first run, follow **Download → Verify and extract → First use** in the
same PowerShell session, one line at a time. The examples retain variables
between steps. Skip **Build from source** unless you want to package a clone.
Then read the result before saving or sharing anything. The download step uses
the network to retrieve the ZIP from GitHub; the diagnostic has no report-upload
feature. See the network-isolation limit under **How to read results**.

These English and Korean files are repository documentation. They may be newer
than the README inside the fixed `v0.2.0-experimental.1` ZIP. That release still
contains four members and does not include `README.ko.md`; these documentation
changes do not replace its script, archive or published checksums.

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

This **new source-build candidate** has exactly eight ZIP members:
`BoundaryLens.ps1`, `BoundaryIncident.ps1`, `IncidentInput.psm1`,
`IncidentObservations.psm1`, `IncidentHandoff.psm1`, `LICENSE`, `README.md`,
and `SHA256SUMS.txt`. The published `v0.2.0-experimental.1` ZIP above still has
four members. This source-build change does not replace that release or its
checksums.

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

## Make a minimized local handoff (source-build candidate only)

Keep the eight candidate files together. First run the original diagnostic and
save its full JSON as `$existingReport` with the guarded steps above. The
companion reads that file; it does not run the diagnostic or another product.
Create a separate incident file with only the fields you choose to supply:

```powershell
$incidentPath = Join-Path $boundaryOutput ("incident-$([guid]::NewGuid().ToString('N')).json")
if (Test-Path -LiteralPath $incidentPath) { throw 'Incident file already exists; stop.' }
[IO.File]::WriteAllText($incidentPath, '{"schema":"boundary-incident/1","product":"synthetic example"}', [Text.UTF8Encoding]::new($false))
$handoffPath = Join-Path $boundaryOutput ("handoff-$([guid]::NewGuid().ToString('N')).json")
pwsh -NoProfile -NonInteractive -File .\BoundaryIncident.ps1 -CoreReport $existingReport -Incident $incidentPath -Output $handoffPath -Format Json
$handoffExit = $LASTEXITCODE
$handoffExit
```

Use repeated `-LogPath FILE` pairs to select local `.json` or `.jsonl` logs;
none are discovered automatically. `-Format Html` writes a static HTML file
instead. Exit `0` means the requested handoff was written with no unavailable
optional observation, `1` means collection/export failed or an incomplete
handoff was written, and `2` means usage, schema or path rejection. An
incomplete file, if present, remains for review. The destination must be a
fresh local file outside investigated paths; existing files are never replaced.

If the companion cannot establish the current physical workspace boundary, it
refuses the export before creating a file. A missing failed target requires a
verified existing parent directory. This can prevent a handoff for an
unverified workspace; keep the original diagnostic JSON for investigation.

The handoff keeps known result/status codes, path labels, provenance and
UNKNOWN. It replaces arbitrary product, version, error, process, filter,
runtime and log strings with local aliases. Those raw strings stay only in
your separate incident/core/log inputs. This is a deliberate loss of detail:
the default shared handoff cannot identify a product from its alias. It is
minimized, not anonymous; timestamps and filesystem size can identify a case.
Review the actual file before sharing it. Generic strings cannot be guaranteed
secret-free if copied outside this allowlist. See the [local incident guide](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/local-incident.md).

## How to read results

| Process exit | Meaning | Next action |
|---|---|---|
| `0` | A report was produced, even with collection failures or unknowns | Read `results` and `next_observation`; do not close the incident on the exit alone |
| `2` | Invalid input (`BOUNDARY_INPUT_INVALID`) or rejected remote input (`BOUNDARY_REMOTE_UNSUPPORTED`) | Check full option names and the original local absolute paths; preserve the original error |
| `3` | Unexpected product failure (`BOUNDARY_INTERNAL_ERROR`) | Keep local evidence and report the fixed code, exit and approved version/hash details privately |

JSON `evidence` contains `workspace_path`, `failed_path`, `workspace_acl`,
`failed_path_acl` and `path_relation`. JSON `results` contains classified
failures, cause candidates and unknowns; observed records live in `evidence`.
A Text report summarizes those records before printing the result rows.

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
