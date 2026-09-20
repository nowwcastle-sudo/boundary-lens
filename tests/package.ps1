#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Package {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("RED: $Message")
    exit 1
}

function Get-ValidatedPackageOutputDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char]'\', [char]'/' )
    $outputPath = [System.IO.Path]::GetFullPath($Path).TrimEnd([char]'\', [char]'/' )
    $repoRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd([char]'\', [char]'/' )
    $pathRoot = [System.IO.Path]::GetPathRoot($outputPath).TrimEnd([char]'\', [char]'/' )

    if ([string]::Equals($outputPath, $pathRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Package 'OutputDirectory must not be a filesystem root.'
    }
    if ([string]::Equals($outputPath, $repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Package 'OutputDirectory must not be the repository root.'
    }
    if (-not $outputPath.StartsWith("$tempRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Package 'OutputDirectory must be beneath the system temporary root.'
    }
    if (-not [string]::Equals((Split-Path -Parent $outputPath), $tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Package 'OutputDirectory must be a direct child of the system temporary root.'
    }
    if ((Split-Path -Leaf $outputPath) -notmatch '^boundary-lens-package-[A-Za-z0-9_-]+$') {
        Stop-Package 'OutputDirectory must use the test-owned boundary-lens-package-* name.'
    }
    if (Test-Path -LiteralPath $outputPath) {
        $item = Get-Item -LiteralPath $outputPath -Force
        if (-not $item.PSIsContainer) {
            Stop-Package 'OutputDirectory exists but is not a directory.'
        }
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-Package 'OutputDirectory must not be a reparse point.'
        }
    }

    return $outputPath
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Stop-IfOutputExists {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Stop-Package "OutputDirectory already exists and is not safe to overwrite: $Path"
    }
}

function Get-ZipEntryHash {
    param(
        [Parameter(Mandatory)][System.IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory)][string]$Name
    )

    $entry = $Archive.GetEntry($Name)
    if ($null -eq $entry) {
        Stop-Package "required archive member missing: $Name"
    }

    $stream = $entry.Open()
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Assert-ArchiveMemberSet {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][hashtable]$ExpectedHashes
    )

    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $expectedNames = @('BoundaryLens.ps1', 'BoundaryIncident.ps1', 'IncidentInput.psm1', 'IncidentObservations.psm1', 'IncidentHandoff.psm1', 'LICENSE', 'README.md', 'SHA256SUMS.txt')
        $actualNames = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        $difference = Compare-Object -ReferenceObject ($expectedNames | Sort-Object) -DifferenceObject $actualNames
        if ($null -ne $difference) {
            Stop-Package "archive member set differs from the required exact set: $($difference | Out-String)"
        }

        foreach ($name in $expectedNames) {
            $archiveHash = Get-ZipEntryHash -Archive $archive -Name $name
            if ($archiveHash -ne $ExpectedHashes[$name]) {
                Stop-Package "archive member hash differs from the standalone artifact: $name"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-Sha256Sums {
    param(
        [Parameter(Mandatory)][string]$SumsPath,
        [Parameter(Mandatory)][hashtable]$ExpectedHashes
    )

    $lines = @(Get-Content -LiteralPath $SumsPath -Encoding utf8)
    if ($lines.Count -ne 7) {
        Stop-Package 'SHA256SUMS.txt must contain exactly seven payload hashes.'
    }

    $actualHashes = @{}
    foreach ($line in $lines) {
        $match = [regex]::Match($line, '^(?<hash>[A-F0-9]{64})  (?<name>BoundaryLens\.ps1|BoundaryIncident\.ps1|IncidentInput\.psm1|IncidentObservations\.psm1|IncidentHandoff\.psm1|LICENSE|README\.md)$')
        if (-not $match.Success) {
            Stop-Package "SHA256SUMS.txt has an invalid entry: $line"
        }
        $name = $match.Groups['name'].Value
        if ($actualHashes.ContainsKey($name)) {
            Stop-Package "SHA256SUMS.txt repeats an entry: $name"
        }
        $actualHashes[$name] = $match.Groups['hash'].Value
    }

    foreach ($name in @('BoundaryLens.ps1', 'BoundaryIncident.ps1', 'IncidentInput.psm1', 'IncidentObservations.psm1', 'IncidentHandoff.psm1', 'LICENSE', 'README.md')) {
        if (-not $actualHashes.ContainsKey($name) -or $actualHashes[$name] -ne $ExpectedHashes[$name]) {
            Stop-Package "SHA256SUMS.txt does not validate $name"
        }
    }
}

function Assert-PublicPackageConsumer {
    param([Parameter(Mandatory)][string]$ReadmePath)

    if (-not (Test-Path -LiteralPath $ReadmePath -PathType Leaf)) {
        Stop-Package "package consumer guide missing: $ReadmePath"
    }

    $readme = Get-Content -LiteralPath $ReadmePath -Raw -Encoding utf8
    $buildMatch = [regex]::Match($readme, '(?s)## Build from source\r?\n.*?(?=\r?\n## )')
    if (-not $buildMatch.Success) {
        Stop-Package 'Public source-build section is missing from README.'
    }

    $build = $buildMatch.Value
    if ($build -notmatch '\[IO\.Path\]::GetTempPath\(\)') {
        Stop-Package 'README must derive the package directory from the system temporary root.'
    }
    if ($build -notmatch 'boundary-lens-package-') {
        Stop-Package 'README must use a boundary-lens-package-* direct-child name.'
    }
    if ($build -notmatch 'tests[\\/]package\.ps1\s+-OutputDirectory\s+\$boundaryCandidate') {
        Stop-Package 'README must pass the fresh temporary directory to package.ps1.'
    }
}

$outputPath = Get-ValidatedPackageOutputDirectory -Path $OutputDirectory
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repoRoot 'src\BoundaryLens.ps1'
$companionNames = @('BoundaryIncident.ps1','IncidentInput.psm1','IncidentObservations.psm1','IncidentHandoff.psm1')
$licensePath = Join-Path $repoRoot 'LICENSE'
$readmePath = Join-Path $repoRoot 'README.md'
$standalonePath = Join-Path $outputPath 'BoundaryLens.ps1'
$archivePath = Join-Path $outputPath 'boundary-lens-0.2.0-experimental.1.zip'
$packagedLicensePath = Join-Path $outputPath 'LICENSE'
$packagedReadmePath = Join-Path $outputPath 'README.md'
$sumsPath = Join-Path $outputPath 'SHA256SUMS.txt'

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Stop-Package "verified source script missing: $sourcePath"
}
if (-not (Test-Path -LiteralPath $readmePath -PathType Leaf)) {
    Stop-Package "package README missing: $readmePath"
}
if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
    Stop-Package "package LICENSE missing: $licensePath"
}
foreach ($name in $companionNames) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot "src\$name") -PathType Leaf)) { Stop-Package "package companion missing: $name" }
}

Assert-PublicPackageConsumer -ReadmePath $readmePath

Stop-IfOutputExists -Path $outputPath
New-Item -ItemType Directory -Path $outputPath -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $sourcePath -Destination $standalonePath -ErrorAction Stop
foreach ($name in $companionNames) { Copy-Item -LiteralPath (Join-Path $repoRoot "src\$name") -Destination (Join-Path $outputPath $name) -ErrorAction Stop }
Copy-Item -LiteralPath $licensePath -Destination $packagedLicensePath -ErrorAction Stop
Copy-Item -LiteralPath $readmePath -Destination $packagedReadmePath -ErrorAction Stop

$expectedHashes = @{
    'BoundaryLens.ps1' = Get-Sha256Hex -Path $standalonePath
    'LICENSE' = Get-Sha256Hex -Path $packagedLicensePath
    'README.md' = Get-Sha256Hex -Path $packagedReadmePath
}
foreach ($name in $companionNames) { $expectedHashes[$name] = Get-Sha256Hex -Path (Join-Path $outputPath $name) }
$payloadNames = @('BoundaryLens.ps1') + $companionNames + @('LICENSE','README.md')
$sums = @($payloadNames | ForEach-Object { "$($expectedHashes[$_])  $_" })
Set-Content -LiteralPath $sumsPath -Value $sums -Encoding utf8 -NoNewline:$false
$expectedHashes['SHA256SUMS.txt'] = Get-Sha256Hex -Path $sumsPath

$payloadPaths = @($payloadNames | ForEach-Object { Join-Path $outputPath $_ })
Compress-Archive -LiteralPath ($payloadPaths + @($sumsPath)) -DestinationPath $archivePath -CompressionLevel Optimal -ErrorAction Stop

foreach ($artifactPath in (@($standalonePath, $archivePath, $packagedLicensePath, $packagedReadmePath, $sumsPath) + @($companionNames | ForEach-Object { Join-Path $outputPath $_ }))) {
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        Stop-Package "required package artifact missing: $artifactPath"
    }
}

if ((Get-Sha256Hex -Path $sourcePath) -ne $expectedHashes['BoundaryLens.ps1']) {
    Stop-Package 'standalone script hash differs from the verified source script.'
}
if ((Get-Sha256Hex -Path $licensePath) -ne $expectedHashes['LICENSE']) {
    Stop-Package 'packaged LICENSE hash differs from the repository LICENSE.'
}
if ((Get-Sha256Hex -Path $readmePath) -ne $expectedHashes['README.md']) {
    Stop-Package 'packaged README hash differs from the repository README.'
}
foreach ($name in $companionNames) {
    if ((Get-Sha256Hex -Path (Join-Path $repoRoot "src\$name")) -ne $expectedHashes[$name]) { Stop-Package "packaged companion differs from source: $name" }
}
Assert-Sha256Sums -SumsPath $sumsPath -ExpectedHashes $expectedHashes
Assert-ArchiveMemberSet -ArchivePath $archivePath -ExpectedHashes $expectedHashes

[Console]::Out.WriteLine("GREEN: exact experimental package verified; script_sha256=$($expectedHashes['BoundaryLens.ps1']); output=$outputPath")
exit 0
