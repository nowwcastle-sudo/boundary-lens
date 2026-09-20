#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$failures = [System.Collections.Generic.List[string]]::new()

function Assert-LocalFinalChain {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        $script:failures.Add($Message)
    }
}

function Get-NativeRealPath {
    param(
        [Parameter(Mandatory)][string]$NodePath,
        [Parameter(Mandatory)][string]$Path
    )

    $output = @(& $NodePath -e "const fs=require('node:fs'); process.stdout.write(fs.realpathSync.native(process.argv[1]));" $Path)
    if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1 -or [string]::IsNullOrWhiteSpace($output[0])) {
        throw "Node native realpath oracle failed for the synthetic path: exit=$LASTEXITCODE"
    }
    return [System.IO.Path]::GetFullPath($output[0])
}

function Test-SamePath {
    param(
        [AllowNull()][string]$Left,
        [AllowNull()][string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    if ($Left -match '^\\Device\\HarddiskVolume[0-9]+\\' -and $Right -match '^[A-Za-z]:\\') {
        # Node supplies the independent physical DOS path; only its drive spelling
        # is converted to NT notation with the OS device mapping (no file traversal).
        $physical = [IO.Path]::GetFullPath($Right)
        $mappingSession = [BoundaryLensNative.Session]::new()
        try {
            $mappingMethod = $mappingSession.GetType().GetMethod('DeviceMapping', [Reflection.BindingFlags]'NonPublic,Instance')
            $device = [string]$mappingMethod.Invoke($mappingSession, [object[]]@($physical.Substring(0, 2)))
            return [string]::Equals($Left, ($device + '\' + $physical.Substring(3)), [StringComparison]::OrdinalIgnoreCase)
        } finally { $mappingSession.Dispose() }
    }
    return [string]::Equals([IO.Path]::GetFullPath($Left), [IO.Path]::GetFullPath($Right), [StringComparison]::OrdinalIgnoreCase)
}

function Get-SentinelSnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return [pscustomobject]@{
        Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Length = $item.Length
        LastWriteTimeUtc = $item.LastWriteTimeUtc
        Attributes = $item.Attributes
    }
}

function Assert-SentinelUnchanged {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][pscustomobject]$Before
    )

    $after = Get-SentinelSnapshot -Path $Path
    Assert-LocalFinalChain -Condition (
        $after.Hash -eq $Before.Hash -and
        $after.Length -eq $Before.Length -and
        $after.LastWriteTimeUtc -eq $Before.LastWriteTimeUtc -and
        $after.Attributes -eq $Before.Attributes
    ) -Message "diagnostic changed a sentinel: $Path"
}

function Assert-MismatchReport {
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$ExpectedWorkspace,
        [Parameter(Mandatory)][string]$ExpectedFailedPath,
        [Parameter(Mandatory)][string]$Label
    )

    $workspaceFailure = if ($null -eq $Report.evidence.workspace_path.failure) { '' } else { [string]$Report.evidence.workspace_path.failure.error_id }
    $failedPathFailure = if ($null -eq $Report.evidence.failed_path.failure) { '' } else { [string]$Report.evidence.failed_path.failure.error_id }
    Assert-LocalFinalChain -Condition ($Report.evidence.path_relation.logical_within_workspace -eq $true) -Message "$Label must remain logically inside the declared workspace"
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $Report.evidence.workspace_path.final_path -Right $ExpectedWorkspace) -Message "$Label workspace final path did not reach its physical terminal; status=$($Report.evidence.workspace_path.status) failure=$workspaceFailure observed=$($Report.evidence.workspace_path.final_path) expected=$ExpectedWorkspace"
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $Report.evidence.failed_path.final_path -Right $ExpectedFailedPath) -Message "$Label failed-path final path did not reach its physical terminal; status=$($Report.evidence.failed_path.status) failure=$failedPathFailure observed=$($Report.evidence.failed_path.final_path) expected=$ExpectedFailedPath"
    Assert-LocalFinalChain -Condition ($Report.evidence.path_relation.final_within_workspace -eq $false) -Message "$Label must report the physical failed path outside the physical workspace; observed=$($Report.evidence.path_relation.final_within_workspace)"
    Assert-LocalFinalChain -Condition (@($Report.results | Where-Object { $_.status -eq 'cause-candidate' -and $_.code -eq 'REPARSE_TARGET_MISMATCH' }).Count -eq 1) -Message "$Label omitted REPARSE_TARGET_MISMATCH"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repoRoot 'src\BoundaryLens.ps1'
$node = Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    [Console]::Error.WriteLine("RED: analyzer entrypoint missing: $sourcePath")
    exit 1
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('boundary-lens-local-final-chain-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $fixtureRoot) {
    [Console]::Error.WriteLine('RED: fresh fixture root unexpectedly already exists')
    exit 1
}

$junctions = [System.Collections.Generic.List[string]]::new()
$driveName = $null
try {
    $physicalWorkspace = Join-Path $fixtureRoot 'physical-workspace'
    $insideTerminal = Join-Path $physicalWorkspace 'inside-terminal'
    $outsideTerminal = Join-Path $fixtureRoot 'outside-terminal'
    foreach ($directory in @($fixtureRoot, $physicalWorkspace, $insideTerminal, $outsideTerminal)) {
        New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    }

    $insideFile = Join-Path $insideTerminal 'inside.txt'
    $outsideFile = Join-Path $outsideTerminal 'outside.txt'
    Set-Content -LiteralPath $insideFile -Value 'inside sentinel' -Encoding utf8 -NoNewline
    Set-Content -LiteralPath $outsideFile -Value 'outside sentinel' -Encoding utf8 -NoNewline

    $insideHop2 = Join-Path $physicalWorkspace 'inside-hop-2'
    $insideHop1 = Join-Path $physicalWorkspace 'inside-hop-1'
    $outsideHop2 = Join-Path $fixtureRoot 'outside-hop-2'
    $outsideHop1 = Join-Path $physicalWorkspace 'outside-hop-1'
    $workspace = Join-Path $fixtureRoot 'workspace'
    foreach ($link in @(
            @($insideHop2, $insideTerminal),
            @($insideHop1, $insideHop2),
            @($outsideHop2, $outsideTerminal),
            @($outsideHop1, $outsideHop2),
            @($workspace, $physicalWorkspace)
        )) {
        New-Item -ItemType Junction -Path $link[0] -Target $link[1] -ErrorAction Stop | Out-Null
        $junctions.Add($link[0])
    }

    $logicalInside = Join-Path $workspace 'inside-hop-1\inside.txt'
    $logicalOutside = Join-Path $workspace 'outside-hop-1\outside.txt'
    $nativeWorkspace = Get-NativeRealPath -NodePath $node.Source -Path $workspace
    $nativeInside = Get-NativeRealPath -NodePath $node.Source -Path $logicalInside
    $nativeOutside = Get-NativeRealPath -NodePath $node.Source -Path $logicalOutside
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $nativeWorkspace -Right $physicalWorkspace) -Message 'native oracle did not resolve the junctioned workspace to the explicit physical workspace'
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $nativeInside -Right $insideFile) -Message 'native oracle did not resolve the nested-inside chain to the explicit inside target'
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $nativeOutside -Right $outsideFile) -Message 'native oracle did not resolve the nested-outside chain to the explicit outside target'

    $insideBefore = Get-SentinelSnapshot -Path $insideFile
    $outsideBefore = Get-SentinelSnapshot -Path $outsideFile
    . $sourcePath

    $insideReport = (Invoke-BoundaryLens -Workspace $workspace -FailedPath $logicalInside -Format Json) | ConvertFrom-Json -ErrorAction Stop
    Assert-LocalFinalChain -Condition ($insideReport.evidence.path_relation.logical_within_workspace -eq $true) -Message 'nested-inside control must remain logically inside'
    Assert-LocalFinalChain -Condition ($insideReport.evidence.path_relation.final_within_workspace -eq $true) -Message 'nested-inside control must remain physically inside'
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $insideReport.evidence.workspace_path.final_path -Right $physicalWorkspace) -Message 'nested-inside workspace final path did not reach the physical workspace'
    Assert-LocalFinalChain -Condition (Test-SamePath -Left $insideReport.evidence.failed_path.final_path -Right $insideFile) -Message 'nested-inside failed path did not reach the physical inside target'
    Assert-LocalFinalChain -Condition (@($insideReport.results | Where-Object { $_.code -eq 'REPARSE_TARGET_MISMATCH' }).Count -eq 0) -Message 'nested-inside control emitted a mismatch candidate'

    $outsideReport = (Invoke-BoundaryLens -Workspace $workspace -FailedPath $logicalOutside -Format Json) | ConvertFrom-Json -ErrorAction Stop
    Assert-MismatchReport -Report $outsideReport -ExpectedWorkspace $physicalWorkspace -ExpectedFailedPath $outsideFile -Label 'nested-outside control'

    $driveName = @('Q','R','S','T','U','V','W','X','Y','Z') | Where-Object { $null -eq (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($driveName)) {
        throw 'No unused one-letter PSDrive name is available for the mixed-backing control.'
    }
    New-PSDrive -Name $driveName -PSProvider FileSystem -Root $workspace -Scope Script -ErrorAction Stop | Out-Null
    $driveWorkspace = "$driveName`:\"
    $driveOutside = "$driveName`:\outside-hop-1\outside.txt"
    $driveReport = (Invoke-BoundaryLens -Workspace $driveWorkspace -FailedPath $driveOutside -Format Json) | ConvertFrom-Json -ErrorAction Stop
    Assert-MismatchReport -Report $driveReport -ExpectedWorkspace $physicalWorkspace -ExpectedFailedPath $outsideFile -Label 'mixed local PSDrive control'

    Assert-SentinelUnchanged -Path $insideFile -Before $insideBefore
    Assert-SentinelUnchanged -Path $outsideFile -Before $outsideBefore
}
finally {
    if ($null -ne $driveName) {
        Remove-PSDrive -Name $driveName -Scope Script -Force -ErrorAction SilentlyContinue
    }
    # Preserve all synthetic inputs on both failure and success for inspection.
    [Console]::Out.WriteLine("Retained synthetic fixture: $fixtureRoot")
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        [Console]::Error.WriteLine("RED: $failure")
    }
    exit 1
}

[Console]::Out.WriteLine('GREEN: native oracle, nested inside/outside junction chains, junctioned workspace, mixed local PSDrive and sentinel immutability agree with public final-path evidence')
exit 0
