#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Assert-ReportHandoff {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw "Report handoff proof failed: $Message"
    }
}

function Get-NamedInputSnapshot {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $item = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    [pscustomobject]@{
        sha256 = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash
        length = $item.Length
        last_write_time_utc = $item.LastWriteTimeUtc.ToString('o')
        attributes = [string]$item.Attributes
    }
}

if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'OutputDirectory already exists; use a fresh proof path.'
}

$trialRoot = New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop
$packageRoot = New-Item -ItemType Directory -Path (Join-Path $trialRoot 'package') -ErrorAction Stop
$inputRoot = New-Item -ItemType Directory -Path (Join-Path $trialRoot 'input') -ErrorAction Stop
$reportRoot = Join-Path $trialRoot 'reports'
$existingInput = Join-Path $inputRoot 'synthetic.txt'
$missingInput = Join-Path $inputRoot 'missing.txt'
Set-Content -LiteralPath $existingInput -Value 'Boundary Lens synthetic report handoff proof.' -Encoding utf8
Copy-Item -LiteralPath (Join-Path $repoRoot 'src/BoundaryLens.ps1') -Destination $packageRoot -ErrorAction Stop

$readme = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'README.md')
$section = [regex]::Match(
    $readme,
    '(?s)## Save JSON reports for handoff\r?\n(?<body>.*?)\r?\n### Standalone format'
)
Assert-ReportHandoff $section.Success 'README report handoff section was not found'
$matches = [regex]::Matches(
    $section.Groups['body'].Value,
    '(?s)```powershell\r?\n(?<code>.*?)\r?\n```'
)
Assert-ReportHandoff ($matches.Count -eq 4) 'README report handoff route must contain four PowerShell blocks'
$steps = @($matches | ForEach-Object { $_.Groups['code'].Value })

$bindingLines = @($steps[0] -split '\r?\n')
$bindingIndexes = @(0..($bindingLines.Count - 1) | Where-Object {
        $bindingLines[$_] -match '^\$boundaryOutput = '
    })
Assert-ReportHandoff ($bindingIndexes.Count -eq 1) 'README output binding must be a single replaceable line'
$bindingLines[$bindingIndexes[0]] = '$boundaryOutput = ''' + $reportRoot.Replace("'", "''") + ''''
$steps[0] = $bindingLines -join [Environment]::NewLine

$demo = $inputRoot
$before = Get-NamedInputSnapshot -LiteralPath $existingInput
$missingBefore = Test-Path -LiteralPath $missingInput
Assert-ReportHandoff (-not $missingBefore) 'missing input exists before the diagnostic'

Push-Location -LiteralPath $packageRoot
try {
    foreach ($step in $steps) {
        . ([scriptblock]::Create($step))
    }
}
finally {
    Pop-Location
}

$after = Get-NamedInputSnapshot -LiteralPath $existingInput
$missingAfter = Test-Path -LiteralPath $missingInput
Assert-ReportHandoff (($before | ConvertTo-Json -Compress) -ceq ($after | ConvertTo-Json -Compress)) 'named existing input changed'
Assert-ReportHandoff (-not $missingAfter) 'missing input was created'
Assert-ReportHandoff ($existingExit -eq 0) 'existing diagnostic process exit was not zero'
Assert-ReportHandoff ($missingExit -eq 0) 'missing diagnostic process exit was not zero'
Assert-ReportHandoff ($existingSaved.schema_version -eq 1) 'existing report schema mismatch'
Assert-ReportHandoff ($missingSaved.schema_version -eq 1) 'missing report schema mismatch'
Assert-ReportHandoff (@($existingSaved.results | Where-Object code -eq 'RUNTIME_ENFORCEMENT_UNKNOWN').Count -eq 1) 'existing report lost runtime UNKNOWN'
foreach ($code in @('TARGET_NOT_OBSERVED', 'FINAL_PATH_UNKNOWN', 'FINAL_CONTAINMENT_UNKNOWN', 'RUNTIME_ENFORCEMENT_UNKNOWN')) {
    Assert-ReportHandoff (@($missingSaved.results | Where-Object code -eq $code).Count -eq 1) "missing report lost $code"
}
Assert-ReportHandoff ((Split-Path -Parent $existingReport) -ceq $reportRoot) 'existing report escaped the bound output folder'
Assert-ReportHandoff ((Split-Path -Parent $missingReport) -ceq $reportRoot) 'missing report escaped the bound output folder'

$saveLine = @($steps[1] -split '\r?\n' | Where-Object {
        $_ -ceq '$existingJson | Out-File -LiteralPath $existingReport -Encoding utf8 -NoClobber -ErrorAction Stop'
    })
Assert-ReportHandoff ($saveLine.Count -eq 1) 'README guarded save line was not found exactly once'
$collision = Join-Path $reportRoot 'existing-output-sentinel.json'
$sentinel = [Text.Encoding]::UTF8.GetBytes('preserve existing output sentinel')
[IO.File]::WriteAllBytes($collision, $sentinel)
$savedExistingReport = $existingReport
$existingReport = $collision
$rejected = $false
try {
    . ([scriptblock]::Create($saveLine[0]))
}
catch {
    $rejected = $true
}
Assert-ReportHandoff $rejected 'NoClobber accepted an existing report path'
Assert-ReportHandoff ([Convert]::ToBase64String([IO.File]::ReadAllBytes($collision)) -ceq [Convert]::ToBase64String($sentinel)) 'existing report sentinel changed'

$mutantLine = $saveLine[0].Replace(' -NoClobber', '')
Assert-ReportHandoff ($mutantLine -cne $saveLine[0]) 'overwrite-guard mutation was not applied'
$mutantCollision = Join-Path $reportRoot 'removed-overwrite-guard-sentinel.json'
[IO.File]::WriteAllBytes($mutantCollision, $sentinel)
$mutantBefore = (Get-FileHash -LiteralPath $mutantCollision -Algorithm SHA256).Hash
$existingReport = $mutantCollision
. ([scriptblock]::Create($mutantLine))
$mutantAfter = (Get-FileHash -LiteralPath $mutantCollision -Algorithm SHA256).Hash
$mutationVerificationFailed = $false
try {
    Assert-ReportHandoff ($mutantAfter -ceq $mutantBefore) 'existing report sentinel changed'
}
catch {
    $mutationVerificationFailed = $true
}
Assert-ReportHandoff $mutationVerificationFailed 'removed overwrite guard did not make the preservation check fail'

$summary = [ordered]@{
    schema_version = 1
    existing_process_exit = $existingExit
    missing_process_exit = $missingExit
    existing_input_before = $before
    existing_input_after = $after
    missing_input_present_before = $missingBefore
    missing_input_present_after = $missingAfter
    existing_report = [ordered]@{
        path = $savedExistingReport
        sha256 = (Get-FileHash -LiteralPath $savedExistingReport -Algorithm SHA256).Hash
    }
    missing_report = [ordered]@{
        path = $missingReport
        sha256 = (Get-FileHash -LiteralPath $missingReport -Algorithm SHA256).Hash
    }
    overwrite_negative = [ordered]@{
        rejected = $rejected
        sentinel_path = $collision
        sentinel_sha256 = (Get-FileHash -LiteralPath $collision -Algorithm SHA256).Hash
    }
    overwrite_guard_mutation = [ordered]@{
        copied_snippet_guard_removed = $true
        preservation_verification_failed = $mutationVerificationFailed
        sentinel_path = $mutantCollision
        before_sha256 = $mutantBefore
        after_sha256 = $mutantAfter
    }
    runtime_enforcement = 'UNKNOWN'
}
$summary | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $trialRoot 'proof-summary.json') -Encoding utf8 -NoClobber -ErrorAction Stop

[Console]::Out.WriteLine("GREEN: documented JSON handoff saved and parsed existing/missing reports; native exits=0/0; named input unchanged; missing input absent; NoClobber sentinel preserved; proof=$trialRoot")
exit 0
