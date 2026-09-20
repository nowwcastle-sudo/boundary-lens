#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Assert-DocumentationContract {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw "Documentation contract failed: $Message"
    }
}

$readme = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'README.md')
$normalizedReadme = $readme -replace "`r`n", "`n"
$security = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'SECURITY.md')
$combined = "$readme`n$security"

Assert-DocumentationContract ($readme -match 'does not require a GitHub account') 'README anonymous public access'
Assert-DocumentationContract ($readme -match 'releases/tag/v0\.2\.0-experimental\.1') 'README exact release metadata'
Assert-DocumentationContract ($readme -match 'Invoke-WebRequest[\s\S]*-ErrorAction Stop') 'README failure-aware public release download'
Assert-DocumentationContract ($readme -match '--clobber') 'README failure-preserving download rule'
Assert-DocumentationContract ($readme -match 'expectedMembers') 'README exact extraction member check'
Assert-DocumentationContract ($readme -match 'Extraction directory already exists') 'README fresh extraction directory guard'
Assert-DocumentationContract ($readme -match 'private development\s+records and artifacts are not part') 'README historical private evidence boundary'
Assert-DocumentationContract ($readme -match '## Build from source') 'README source-build boundary'
Assert-DocumentationContract ($readme.Contains('$expectedMembers = @(''BoundaryLens.ps1'', ''LICENSE'', ''README.md'', ''SHA256SUMS.txt'')')) 'README current-source four-member contract'
Assert-DocumentationContract ($readme.Contains('if ($sums.Count -ne 3)')) 'README current-source three-checksum contract'
Assert-DocumentationContract ($readme.Contains('(BoundaryLens\.ps1|LICENSE|README\.md)')) 'README current-source checksum allowlist'
Assert-DocumentationContract ($readme -match 'Do not reuse historical private-release') 'README no historical-asset replacement boundary'
Assert-DocumentationContract ($readme -match '## Save JSON reports for handoff') 'README report handoff route'
Assert-DocumentationContract ($readme -match '\$boundaryOutput = Join-Path') 'README explicit report output binding'
Assert-DocumentationContract ($normalizedReadme.Contains("-Format Json`n`$existingExit = `$LASTEXITCODE")) 'README existing-report immediate process exit capture'
Assert-DocumentationContract ($normalizedReadme.Contains("-Format Json`n`$missingExit = `$LASTEXITCODE")) 'README missing-report immediate process exit capture'
Assert-DocumentationContract ($readme.Contains('$existingJson | Out-File -LiteralPath $existingReport -Encoding utf8 -NoClobber -ErrorAction Stop')) 'README existing-report guarded UTF-8 save'
Assert-DocumentationContract ($readme.Contains('$missingJson | Out-File -LiteralPath $missingReport -Encoding utf8 -NoClobber -ErrorAction Stop')) 'README missing-report guarded UTF-8 save'
Assert-DocumentationContract ($readme.Contains('Get-Content -Raw -LiteralPath $existingReport | ConvertFrom-Json -ErrorAction Stop')) 'README existing JSON readback'
Assert-DocumentationContract ($readme.Contains('Get-Content -Raw -LiteralPath $missingReport | ConvertFrom-Json -ErrorAction Stop')) 'README missing JSON readback'
Assert-DocumentationContract ($readme -match 'outside\s+the\s+investigated\s+input') 'README separate output boundary'
Assert-DocumentationContract ($readme -match 'review and minimize') 'README local minimization before sharing'
Assert-DocumentationContract ($readme -match 'incident\.workspace_input[\s\S]*incident\.failed_path_input[\s\S]*incident\.observed_at') 'README sensitive JSON incident fields'
Assert-DocumentationContract ($readme -match '(?i)failed directory and\s+logs') 'README failure preservation'
Assert-DocumentationContract ($readme -match 'RUNTIME_ENFORCEMENT_UNKNOWN') 'runtime unknown contract'
Assert-DocumentationContract ($readme -match 'Experimental open source') 'experimental public scope'
Assert-DocumentationContract ($combined -notmatch 'ghp_[A-Za-z0-9]{20,}') 'GitHub token pattern absent'
Assert-DocumentationContract ($combined -notmatch 'github_pat_[A-Za-z0-9_]{20,}') 'fine-grained token pattern absent'
Assert-DocumentationContract ($combined -notmatch '-----BEGIN [A-Z ]*PRIVATE KEY-----') 'private key pattern absent'

Write-Output 'GREEN: public release/package contracts, preserved private history, failure preservation, UNKNOWN and no-secret documentation boundaries are present'
