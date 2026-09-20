#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/BoundaryLens.ps1')

# These replacements return synthetic records; no investigated path reaches the OS.
function Test-BoundaryInput {
    param([string]$Path, [string]$ParameterName)
    return $Path
}

function Get-BoundaryPathEvidence {
    param([string]$RawPath, [string]$Role)
    $failed = $script:referenceScenario -eq 'path-failure' -and $Role -eq 'failed-path'
    return [pscustomobject]@{
        probe = 'path'
        status = if ($failed) { 'collection-failure' } else { 'observed' }
        raw_input = $RawPath
        lexical_path = $RawPath
        exists = if ($failed) { $null } else { $true }
        final_path = if ($failed) { $null } else { $RawPath }
        reparse_segments = @()
        observations = [pscustomobject]@{ role = $Role; reparse_observation_complete = -not $failed }
        failure = if ($failed) {
            [pscustomobject]@{ error_id = 'PATH_PROBE_UNAVAILABLE'; message = 'Synthetic unavailable path metadata.' }
        } else { $null }
    }
}

function Get-BoundaryAclEvidence {
    param([string]$RawPath, [string]$Role)
    $failed = $script:referenceScenario -eq 'acl-failure' -and $Role -eq 'failed-path'
    return [pscustomobject]@{
        probe = 'acl'
        status = if ($failed) { 'collection-failure' } else { 'observed' }
        raw_input = $RawPath
        role = $Role
        protected = if ($failed) { $null } else { $false }
        owner_fingerprint = if ($failed) { $null } else { '0123456789ab' }
        access_rules = @()
        failure = if ($failed) {
            [pscustomobject]@{ error_id = 'ACL_COLLECTION_FAILED'; message = 'Synthetic unavailable ACL metadata.' }
        } else { $null }
    }
}


# One native observation owns path and ACL together. The synthetic reporting seam
# retains the same failures without performing filesystem or native collection.
function Get-BoundaryObservation {
    param([string]$RawPath, [string]$Role)
    return [pscustomobject]@{
        path = Get-BoundaryPathEvidence -RawPath $RawPath -Role $Role
        acl = Get-BoundaryAclEvidence -RawPath $RawPath -Role $Role
        session = $null
        identity = if ($Role -eq 'workspace') { 'synthetic-root' } else { 'synthetic-leaf' }
        ancestors = @('synthetic-root','synthetic-leaf')
    }
}

function Test-ReportReference {
    param([pscustomobject]$Report, [string]$Reference)
    $segments = $Reference.Split('.')
    $cursor = if ($segments[0] -eq 'incident') { $Report } else { $Report.evidence }
    foreach ($segment in $segments) {
        if ($null -eq $cursor) { return $false }
        $property = $cursor.PSObject.Properties[$segment]
        if ($null -eq $property) { return $false }
        $cursor = $property.Value
    }
    # A present null observation is a valid reference, never an absent key.
    return $true
}

try {
    $dangling = [System.Collections.Generic.List[string]]::new()
    $referenceCount = 0
    foreach ($scenario in @('path-failure', 'acl-failure')) {
        $script:referenceScenario = $scenario
        $report = Invoke-BoundaryLens -Workspace 'C:\synthetic\workspace' -FailedPath 'C:\synthetic\workspace\failed.txt' -Format Json | ConvertFrom-Json
        $expectedCode = if ($scenario -eq 'path-failure') { 'PATH_PROBE_UNAVAILABLE' } else { 'ACL_COLLECTION_FAILED' }
        if (@($report.results | Where-Object { $_.status -eq 'collection-failure' -and $_.code -eq $expectedCode }).Count -ne 1) {
            throw [System.InvalidOperationException]::new('Synthetic scenario failed to emit its required collection failure.')
        }
        foreach ($result in @($report.results)) {
            if (@($result.evidence_refs).Count -eq 0) {
                throw [System.InvalidOperationException]::new('A synthetic result omitted evidence references.')
            }
            foreach ($reference in @($result.evidence_refs)) {
                $referenceCount++
                if (-not (Test-ReportReference -Report $report -Reference $reference)) {
                    $dangling.Add("${scenario}:$($result.code):$reference")
                }
            }
        }
    }
    if ($dangling.Count -gt 0) {
        [Console]::Error.WriteLine("RED: unresolved report evidence references: $($dangling -join ', ')")
        exit 1
    }
    [Console]::Out.WriteLine("GREEN: $referenceCount synthetic result references resolve, including present null observations; no investigated filesystem probes")
    exit 0
}
catch {
    [Console]::Error.WriteLine('RED: evidence-reference test harness could not complete; inspect locally without sharing exception details')
    exit 2
}
