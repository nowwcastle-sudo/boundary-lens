#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Assert-RepositoryPrivacy {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )

    if (-not $Condition) {
        throw "Repository privacy check failed: $Message"
    }
}

$trackedFiles = @(& git -C $repoRoot ls-files)
$gitExit = $LASTEXITCODE
Assert-RepositoryPrivacy ($gitExit -eq 0) "git ls-files exited $gitExit"
Assert-RepositoryPrivacy ($trackedFiles.Count -gt 0) 'git ls-files returned no tracked files'

$fixtureFingerprint = '01234567' + '89ab'
$knownFingerprints = @(('ba7816bf' + '8f01'), ('e3b0c442' + '98fc'))
$knownFingerprintPattern = '(?:' + (($knownFingerprints | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
$violations = [System.Collections.Generic.List[string]]::new()
foreach ($relativePath in $trackedFiles) {
    $extension = [IO.Path]::GetExtension($relativePath)
    if ($extension -notin @('.json', '.md', '.ps1', '.txt', '.yml', '.yaml') -and $relativePath -notin @('LICENSE')) {
        continue
    }

    $fullPath = Join-Path $repoRoot $relativePath
    $lineNumber = 0
    foreach ($line in (Get-Content -LiteralPath $fullPath)) {
        $lineNumber++
        if ($line -match '(?i)(?:[A-Z]:[\\/]|\\\\\?\\[A-Z]:\\)Users[\\/]') {
            $violations.Add("user-profile-path:$relativePath`:$lineNumber")
        }

        $knownSyntheticVector = switch ($relativePath) {
            'tests/evidence-references.ps1' {
                $line -match ('^\s*owner_fingerprint = if \(\$failed\) \{ \$null \} else \{ ''' + [regex]::Escape($fixtureFingerprint) + ''' \}\s*$')
            }
            'tests/operational-ux.ps1' {
                $line -match ('^\s*Assert-Ux \(\(Get-BoundaryIdentityFingerprint -Identity ''(?:abc|)''\) -ceq ''' + $knownFingerprintPattern + '''\) ''fingerprint (?:known|empty) vector''\s*$')
            }
            'docs/superpowers/plans/2026-09-05-operational-ux.md' {
                $line -match ('^if \(\(Get-BoundaryIdentityFingerprint -Identity ''(?:abc|)''\) -cne ''' + $knownFingerprintPattern + '''\) \{ throw ''(?:SHA-256 prefix changed\.|Empty SHA-256 prefix changed\.)'' \}\s*$')
            }
            default { $false }
        }
        if (-not $knownSyntheticVector -and $line -match '(?i)(?:acl|owner|identity|sid)[^\r\n]{0,200}(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])') {
            $violations.Add("identity-derived-token:$relativePath`:$lineNumber")
        }
        if ($line -match '(?<![A-Za-z0-9])S-1-\d+(?:-\d+){2,}(?!\d)') {
            $violations.Add("raw-sid:$relativePath`:$lineNumber")
        }
    }
}

Assert-RepositoryPrivacy ($violations.Count -eq 0) ($violations -join ', ')
[Console]::Out.WriteLine("GREEN: $($trackedFiles.Count) tracked files contain no user-profile paths, raw SIDs, or concrete identity-derived tokens")
exit 0
