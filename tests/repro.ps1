#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Repro {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("RED: $Message")
    exit 1
}

function Get-FixtureSnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    [pscustomobject]@{
        Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Length = $item.Length
        LastWriteTimeUtc = $item.LastWriteTimeUtc
        Attributes = $item.Attributes
    }
}

function Assert-FixtureUnchanged {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][pscustomobject]$Before
    )

    $after = Get-FixtureSnapshot -Path $Path
    if (
        $after.Hash -ne $Before.Hash -or
        $after.Length -ne $Before.Length -or
        $after.LastWriteTimeUtc -ne $Before.LastWriteTimeUtc -or
        $after.Attributes -ne $Before.Attributes
    ) {
        Stop-Repro "fixture changed: $Path"
    }
}

function Assert-ResultPair {
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$FixtureName
    )

    if (@($Results | Where-Object { $_.status -eq $Status -and $_.code -eq $Code }).Count -ne 1) {
        Stop-Repro "$FixtureName is missing exact result pair status=$Status code=$Code"
    }
}

$fixtureDirectory = Join-Path $PSScriptRoot 'fixtures'
$fixturePaths = @(
    (Join-Path $fixtureDirectory 'logical-final-mismatch.json'),
    (Join-Path $fixtureDirectory 'reparse-target-unresolved.json'),
    (Join-Path $fixtureDirectory 'same-final-boundary.json')
)
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\BoundaryLens.ps1'

foreach ($fixturePath in $fixturePaths) {
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        Stop-Repro "fixture missing: $fixturePath"
    }
}

$fixtureSnapshots = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
foreach ($fixturePath in $fixturePaths) {
    $fixtureSnapshots.Add($fixturePath, (Get-FixtureSnapshot -Path $fixturePath))
}

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Stop-Repro "analyzer entrypoint missing: $sourcePath"
}

. $sourcePath

foreach ($fixturePath in $fixturePaths) {
    $fixture = Get-Content -LiteralPath $fixturePath -Raw -Encoding utf8 | ConvertFrom-Json
    $fixtureName = Split-Path -Leaf $fixturePath
    $results = @(Classify-BoundaryEvidence -Evidence $fixture)
    $report = [pscustomobject]@{
        schema_version = $fixture.schema_version
        results = $results
    }
    $text = Format-BoundaryReport -Report $report -Format Text
    $json = Format-BoundaryReport -Report $report -Format Json

    try {
        $jsonReport = $json | ConvertFrom-Json
    }
    catch {
        Stop-Repro "$fixtureName JSON report did not parse: $($_.Exception.Message)"
    }

    if ($null -eq $jsonReport.results) {
        Stop-Repro "$fixtureName JSON report omitted results"
    }
    if ($text -match '(?<![A-Za-z0-9_])SAFE(?![A-Za-z0-9_])' -or $json -match '(?<![A-Za-z0-9_])SAFE(?![A-Za-z0-9_])') {
        Stop-Repro "$fixtureName emitted forbidden verdict SAFE"
    }
    if ($results.Count -ne $fixture.expected_codes.Count) {
        Stop-Repro "$fixtureName result count differs from expected_codes"
    }
    foreach ($code in $fixture.expected_codes) {
        if (@($results | Where-Object { $_.code -eq $code }).Count -ne 1) {
            Stop-Repro "$fixtureName missing expected code $code"
        }
    }

    switch ($fixtureName) {
        'logical-final-mismatch.json' {
            Assert-ResultPair -Results $results -Status 'cause-candidate' -Code 'REPARSE_TARGET_MISMATCH' -FixtureName $fixtureName
            Assert-ResultPair -Results $results -Status 'collection-failure' -Code 'VOLUME_FILTER_UNAVAILABLE' -FixtureName $fixtureName
            Assert-ResultPair -Results $results -Status 'unknown' -Code 'RUNTIME_ENFORCEMENT_UNKNOWN' -FixtureName $fixtureName
        }
        'reparse-target-unresolved.json' {
            Assert-ResultPair -Results $results -Status 'collection-failure' -Code 'REPARSE_TARGET_UNRESOLVED' -FixtureName $fixtureName
            Assert-ResultPair -Results $results -Status 'unknown' -Code 'FINAL_PATH_UNKNOWN' -FixtureName $fixtureName
            Assert-ResultPair -Results $results -Status 'unknown' -Code 'FINAL_CONTAINMENT_UNKNOWN' -FixtureName $fixtureName
            Assert-ResultPair -Results $results -Status 'unknown' -Code 'RUNTIME_ENFORCEMENT_UNKNOWN' -FixtureName $fixtureName
            if ($null -ne $fixture.path_relation.final_path_observed -or $null -ne $fixture.path_relation.final_within_workspace) {
                Stop-Repro "$fixtureName must use null for unobserved final relation fields"
            }
            if (@($results | Where-Object { $_.status -eq 'cause-candidate' }).Count -ne 0) {
                Stop-Repro "$fixtureName must not emit a cause candidate"
            }
        }
        'same-final-boundary.json' {
            if ($results.Count -ne 0) {
                Stop-Repro "$fixtureName must not emit a mismatch or safety result"
            }
        }
    }

}

foreach ($fixturePath in $fixturePaths) {
    Assert-FixtureUnchanged -Path $fixturePath -Before $fixtureSnapshots[$fixturePath]
}

[Console]::Out.WriteLine('GREEN: pure mismatch classification preserved structured failure and unknown results; unresolved and same-boundary fixtures emitted no unsupported cause; fixtures unchanged')
exit 0
