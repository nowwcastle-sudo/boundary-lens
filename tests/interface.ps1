#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Interface {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("RED: $Message")
    exit 1
}

function Assert-Interface {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        Stop-Interface $Message
    }
}

function Assert-BoundaryError {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$ExpectedId,
        [Parameter(Mandatory)][string]$Label
    )

    try {
        & $Action
        Stop-Interface "$Label was accepted"
    }
    catch {
        $expectedPattern = '^(?:' + [regex]::Escape($ExpectedId) + ')(?:,|$)'
        if ($_.FullyQualifiedErrorId -notmatch $expectedPattern) {
            Stop-Interface "$Label error identifier mismatch: $($_.FullyQualifiedErrorId)"
        }
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$failedPath = Join-Path $PSScriptRoot 'fixtures\logical-final-mismatch.json'
$sourcePath = Join-Path $repoRoot 'src\BoundaryLens.ps1'

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Stop-Interface "analyzer entrypoint missing: $sourcePath"
}
if (-not (Test-Path -LiteralPath $failedPath -PathType Leaf)) {
    Stop-Interface "fixture missing: $failedPath"
}

. $sourcePath

try {
    $json = Invoke-BoundaryLens -Workspace $repoRoot -FailedPath $failedPath -Format Json
    $report = $json | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Stop-Interface "public JSON interface failed: $($_.Exception.Message)"
}

# A fresh, bounded observation distinguishes generic directory ACEs in CI.
# It never replaces the report under test and emits no identities or descriptors.
$descriptorProbe = $null
try {
    $descriptorProbe = Get-BoundaryObservation -RawPath $repoRoot -Role workspace
    $descriptorBytes = if ($null -ne $descriptorProbe.session) { $descriptorProbe.session.Complete().Security } else { $null }
    $descriptorPresent = $null -ne $descriptorBytes -and $descriptorBytes.Length -gt 0
    $genericMaskAces = 'unknown'
    if ($descriptorPresent) {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$descriptorBytes, 0)
        $genericMaskAces = @($descriptor.DiscretionaryAcl | Where-Object { $_ -is [Security.AccessControl.KnownAce] -and ($_.AccessMask -band -268435456) -ne 0 }).Count
    }
    [Console]::Error.WriteLine("BOUNDARY_TEST_DIAGNOSTIC descriptor_present=$descriptorPresent generic_mask_aces=$genericMaskAces")
}
catch { [Console]::Error.WriteLine('BOUNDARY_TEST_DIAGNOSTIC descriptor_present=unknown generic_mask_aces=unknown') }
finally { if ($null -ne $descriptorProbe -and $null -ne $descriptorProbe.session) { $descriptorProbe.session.Dispose() } }

Assert-Interface -Condition ($report.schema_version -eq 1) -Message 'schema mismatch'
Assert-Interface -Condition ($report.incident.runtime_kind -eq 'windows-local') -Message 'runtime kind mismatch'
Assert-Interface -Condition ($null -ne $report.evidence.workspace_path) -Message 'workspace path evidence missing'
Assert-Interface -Condition ($null -ne $report.evidence.failed_path) -Message 'failed path evidence missing'
Assert-Interface -Condition ($report.evidence.workspace_path.raw_input -eq $repoRoot) -Message 'workspace raw input was not preserved'
Assert-Interface -Condition ($report.evidence.failed_path.raw_input -eq $failedPath) -Message 'failed path raw input was not preserved'
if ($report.evidence.workspace_acl.status -ne 'observed' -or $report.evidence.failed_path_acl.status -ne 'observed') {
    # Preserve the original failing report. Only fixed codes/counts are logged;
    # no paths, SIDs, account names, security descriptors, or exception text.
    foreach ($role in @('workspace', 'failed_path')) {
        $pathRecord = if ($role -eq 'workspace') { $report.evidence.workspace_path } else { $report.evidence.failed_path }
        $aclRecord = if ($role -eq 'workspace') { $report.evidence.workspace_acl } else { $report.evidence.failed_path_acl }
        $pathCode = if ($null -eq $pathRecord.failure) { 'none' } else { $pathRecord.failure.error_id }
        $aclCode = if ($null -eq $aclRecord.failure) { 'none' } else { $aclRecord.failure.error_id }
        [Console]::Error.WriteLine("BOUNDARY_TEST_DIAGNOSTIC role=$role path_status=$($pathRecord.status) path_code=$pathCode acl_status=$($aclRecord.status) acl_code=$aclCode segments=$($pathRecord.observations.existing_segment_count) reparses=$(@($pathRecord.reparse_segments).Count) native_loaded=$($null -ne ('BoundaryLensNative.Session' -as [type]))")
    }
}
Assert-Interface -Condition ($report.evidence.workspace_acl.status -eq 'observed') -Message 'workspace ACL status mismatch'
Assert-Interface -Condition ($report.evidence.failed_path_acl.status -eq 'observed') -Message 'failed-path ACL status mismatch'
Assert-Interface -Condition ($report.evidence.workspace_acl.owner_fingerprint -match '^[0-9a-fA-F]{12}$') -Message 'workspace ACL owner fingerprint mismatch'
Assert-Interface -Condition ($report.evidence.failed_path_acl.owner_fingerprint -match '^[0-9a-fA-F]{12}$') -Message 'failed-path ACL owner fingerprint mismatch'
Assert-Interface -Condition ($report.evidence.workspace_acl.protected -is [bool]) -Message 'workspace ACL protection state missing'
Assert-Interface -Condition ($report.evidence.failed_path_acl.protected -is [bool]) -Message 'failed-path ACL protection state missing'
Assert-Interface -Condition ($null -eq $report.evidence.workspace_acl.failure) -Message 'workspace ACL unexpectedly contains a failure'
Assert-Interface -Condition ($null -eq $report.evidence.failed_path_acl.failure) -Message 'failed-path ACL unexpectedly contains a failure'
Assert-Interface -Condition ($json -notmatch 'S-1-') -Message 'public JSON exposed a raw SID'
Assert-Interface -Condition ($null -ne $report.evidence.path_relation) -Message 'path relation evidence missing'
Assert-Interface -Condition ($report.evidence.path_relation.logical_within_workspace -eq $true) -Message 'logical containment mismatch'
Assert-Interface -Condition ($report.evidence.path_relation.reparse_segment_observed -eq $false) -Message 'ordinary fixture unexpectedly has reparse evidence'
Assert-Interface -Condition ($report.evidence.path_relation.final_workspace_observed -eq $true -and $report.evidence.path_relation.final_path_observed -eq $true) -Message 'final path observations missing'
Assert-Interface -Condition ($report.evidence.path_relation.final_within_workspace -eq $true) -Message 'final containment mismatch'
Assert-Interface -Condition (Test-BoundaryContainment -Root 'C:\work' -Candidate 'C:\work\child') -Message 'segment-aware containment rejected a descendant'
Assert-Interface -Condition (-not (Test-BoundaryContainment -Root 'C:\work' -Candidate 'C:\workspace\child')) -Message 'segment-aware containment accepted a string-prefix sibling'

try {
    $firstText = Invoke-BoundaryLens -Workspace $repoRoot -FailedPath $failedPath -Format Text
    $secondText = Invoke-BoundaryLens -Workspace $repoRoot -FailedPath $failedPath -Format Text
}
catch {
    Stop-Interface "public Text interface failed: $($_.Exception.Message)"
}

$normalizeObservedAt = {
    param([string]$Text)
    $Text -replace 'observed_at=[^|\r\n]+', 'observed_at=<ignored>'
}
Assert-Interface -Condition ((& $normalizeObservedAt $firstText) -eq (& $normalizeObservedAt $secondText)) -Message 'Text output is not deterministic after observed_at normalization'

Assert-BoundaryError -Action { Invoke-BoundaryLens -Workspace '' -FailedPath $failedPath -Format Json -ErrorAction Stop | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'blank Workspace'
Assert-BoundaryError -Action { Invoke-BoundaryLens -Workspace 'vscode-remote://ssh-remote+example/workspace' -FailedPath $failedPath -Format Json -ErrorAction Stop | Out-Null } -ExpectedId 'BOUNDARY_REMOTE_UNSUPPORTED' -Label 'remote URI'
Assert-BoundaryError -Action { Test-BoundaryInput -Path '\\boundary-lens-invalid\share' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_REMOTE_UNSUPPORTED' -Label 'UNC path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path '//boundary-lens-invalid/share' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_REMOTE_UNSUPPORTED' -Label 'forward-slash UNC path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'smb://boundary-lens-invalid/share' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_REMOTE_UNSUPPORTED' -Label 'SMB URI'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'foo://boundary-lens-invalid/share' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_REMOTE_UNSUPPORTED' -Label 'arbitrary URI'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'Registry provider-qualified path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'HKLM:\SOFTWARE' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'Registry drive path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'Env:\PATH' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'Environment drive path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'relative\workspace' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'relative path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path '\rooted' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'current-drive-rooted path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path '/slash-root' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'slash-rooted path'
Assert-BoundaryError -Action { Test-BoundaryInput -Path " $repoRoot" -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'leading-whitespace path'

$tempDrive = Get-PSDrive -Name Temp -ErrorAction Stop
Assert-Interface -Condition ($tempDrive.Provider.Name -eq 'FileSystem') -Message 'Temp PSDrive is not a local FileSystem drive for the syntax-boundary RED'
Assert-BoundaryError -Action { Test-BoundaryInput -Path 'Temp:\boundary-lens-validation-only' -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'multi-character FileSystem drive path'

$customDriveName = 'BoundaryLensTemp'
try {
    New-PSDrive -Name $customDriveName -PSProvider Environment -Root '' -Scope Local -ErrorAction Stop | Out-Null
    Assert-BoundaryError -Action { Test-BoundaryInput -Path "$customDriveName`:\PATH" -ParameterName Workspace | Out-Null } -ExpectedId 'BOUNDARY_INPUT_INVALID' -Label 'custom non-filesystem drive path'
}
finally {
    Remove-PSDrive -Name $customDriveName -Scope Local -Force -ErrorAction SilentlyContinue
}

Assert-Interface -Condition (Test-BoundaryUncDriveMetadata -Root '\\boundary-lens-invalid\root' -DisplayRoot $null) -Message 'UNC Root was not recognized as remote drive metadata'
Assert-Interface -Condition (Test-BoundaryUncDriveMetadata -Root 'C:\local-root' -DisplayRoot '//boundary-lens-invalid/display-root') -Message 'UNC DisplayRoot was not recognized as remote drive metadata'
Assert-Interface -Condition (-not (Test-BoundaryUncDriveMetadata -Root 'C:\local-root' -DisplayRoot $null)) -Message 'local drive metadata was falsely classified as UNC'

$occupiedDriveNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($logicalDrive in [System.IO.Directory]::GetLogicalDrives()) {
    [void]$occupiedDriveNames.Add($logicalDrive.Substring(0, 1))
}
foreach ($psDrive in Get-PSDrive) {
    if ($psDrive.Name -match '^[A-Za-z]$') {
        [void]$occupiedDriveNames.Add($psDrive.Name)
    }
}
$unavailableDrive = @([char[]](90..68) | ForEach-Object { "$_`:" } | Where-Object { -not $occupiedDriveNames.Contains($_.Substring(0, 1)) } | Select-Object -First 1)[0]
if ([string]::IsNullOrWhiteSpace($unavailableDrive)) {
    Stop-Interface 'no unused drive letter is available for the unavailable-drive probe'
}
$unavailableWorkspace = "$unavailableDrive\boundary-lens-unavailable"
try {
    $unavailableReport = (Invoke-BoundaryLens -Workspace $unavailableWorkspace -FailedPath $failedPath -Format Json) | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Stop-Interface "unavailable drive became a terminating error: $($_.FullyQualifiedErrorId)"
}
Assert-Interface -Condition ($unavailableReport.evidence.workspace_path.status -eq 'collection-failure') -Message 'unavailable drive did not remain a workspace collection failure'
Assert-Interface -Condition ($unavailableReport.evidence.workspace_path.failure.error_id -eq 'WORKSPACE_NOT_FOUND') -Message 'unavailable drive failure code mismatch'
Assert-Interface -Condition ($null -eq $unavailableReport.evidence.workspace_path.exists) -Message 'unprobed unavailable workspace existence must be null'
Assert-Interface -Condition ($null -eq $unavailableReport.evidence.path_relation.final_workspace_observed) -Message 'unavailable drive final workspace relation must be null'
Assert-Interface -Condition ($null -eq $unavailableReport.evidence.path_relation.final_within_workspace) -Message 'unavailable drive final containment must be null'
Assert-Interface -Condition (@($unavailableReport.results | Where-Object { $_.status -eq 'unknown' -and $_.code -eq 'FINAL_WORKSPACE_UNKNOWN' }).Count -eq 1) -Message 'unavailable drive final workspace unknown missing'
Assert-Interface -Condition (@($unavailableReport.results | Where-Object { $_.status -eq 'unknown' -and $_.code -eq 'FINAL_CONTAINMENT_UNKNOWN' }).Count -eq 1) -Message 'unavailable drive final containment unknown missing'

[Console]::Out.WriteLine('GREEN: public JSON/Text interface retains complete bounded evidence and rejects unsafe path forms')
exit 0
