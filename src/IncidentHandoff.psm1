Set-StrictMode -Version Latest

if (-not ('BoundaryHandoffPath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class BoundaryHandoffPath {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr templateFile);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    static string Final(SafeFileHandle handle, uint flags) {
        var path = new StringBuilder(32768);
        uint count = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, flags);
        if (count == 0 || count >= path.Capacity) throw new System.IO.IOException("Output identity unavailable.");
        return path.ToString();
    }
    public static string Final(SafeFileHandle handle) { return Final(handle, 0); }
    public static string NtFinal(SafeFileHandle handle) { return Final(handle, 2); }
    public static string DirectoryNtFinal(string path) {
        using (var handle = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new System.IO.IOException("Directory identity unavailable.");
            return NtFinal(handle);
        }
    }
}
'@ -ErrorAction Stop
}

function Test-HandoffCode([string]$Value) {
    return $Value -cin @('ACL_ACE_UNSUPPORTED','ACL_COLLECTION_FAILED','ACL_DACL_UNSUPPORTED','ACL_NOT_OBSERVED',
        'FINAL_CONTAINMENT_UNKNOWN','FINAL_PATH_UNKNOWN','FINAL_WORKSPACE_UNKNOWN','LOGICAL_CONTAINMENT_UNKNOWN',
        'NATIVE_COLLECTION_UNAVAILABLE','NATIVE_CONTRACT_MISMATCH','PATH_TOPOLOGY_CHANGED','PATH_TOPOLOGY_UNAVAILABLE',
        'REMOTE_REPARSE_TARGET_UNSUPPORTED','REPARSE_RELATION_UNKNOWN','REPARSE_TARGET_MISMATCH',
        'REPARSE_TARGET_UNRESOLVED','RUNTIME_ENFORCEMENT_UNKNOWN','TARGET_NOT_OBSERVED','WORKSPACE_NOT_FOUND',
        'PROCESS_EXITED','PROCESS_ACCESS_DENIED','PROCESS_NOT_FOUND','PROCESS_IDENTITY_CHANGED','PROCESS_UNAVAILABLE',
        'VOLUME_UNSUPPORTED','VOLUME_UNREADY','VOLUME_ACCESS_DENIED','VOLUME_UNAVAILABLE','URI_INVALID')
}
function Get-HandoffCode($Value) {
    if ($Value -is [string] -and (Test-HandoffCode $Value)) { return $Value }
    return 'UNRECOGNIZED_CODE'
}
function Get-HandoffStatus($Value) {
    if ($Value -is [string] -and $Value -cin @('observed','unknown','collection-failure','cause-candidate','supplied','unavailable')) { return $Value }
    return 'unknown'
}
function Get-HandoffTime($Value) {
    if ($Value -is [string] -and $Value -cmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)$') { return $Value }
    return $null
}

function New-IncidentHandoff {
    param([Parameter(Mandatory)][hashtable]$CoreReport, [Parameter(Mandatory)][hashtable]$Context,
        [Parameter()][AllowEmptyCollection()][object[]]$Observations=@())
    $results = [Collections.Generic.List[object]]::new()
    foreach ($row in @($CoreReport.results)) {
        $results.Add(@{status=(Get-HandoffStatus $row.status);code=(Get-HandoffCode $row.code)})
    }
    $coreEvidence = [Collections.Generic.List[object]]::new()
    foreach ($entry in @(@('workspace_path','workspace'),@('failed_path','failed-target'),@('workspace_acl','workspace'),@('failed_path_acl','failed-target'))) {
        $record = $CoreReport.evidence[$entry[0]]
        $coreEvidence.Add(@{probe= $(if ($entry[0].EndsWith('_acl')) {'acl'} else {'path'}); path=$entry[1];status=(Get-HandoffStatus $record.status);error_code=$(if ($null -ne $record.failure) { Get-HandoffCode $record.failure.error_id } else { $null })})
    }
    $incident = @{occurred_at=$(if ($Context.ContainsKey('occurred_at')) {Get-HandoffTime $Context['occurred_at']} else {$null});product=$(if ($Context.ContainsKey('product')) {'product-1'} else {$null});version=$(if ($Context.ContainsKey('version')) {'version-1'} else {$null});error_code=$(if ($Context.ContainsKey('error_code')) {'incident-error-1'} else {$null});runtime_uri_present=$Context.ContainsKey('runtime_uri');process_selected=$Context.ContainsKey('process_id');supplied_observation_count=$(if ($Context.ContainsKey('supplied_observations')) {@($Context.supplied_observations).Count} else {0})}
    $minimized = [Collections.Generic.List[object]]::new()
    $aliases = @{}
    $unavailable = 0
    foreach ($row in $Observations) {
        $kind = if ($row.kind -is [string] -and $row.kind -cin @('incident-context','runtime-uri','process','volume','filter','runtime','log')) { $row.kind } else { 'other' }
        $status = Get-HandoffStatus $row.status
        $provenance = if ($row.provenance -ceq 'local-query') {'local-query'} else {'operator-supplied'}
        if ($provenance -eq 'operator-supplied' -and $status -eq 'observed') { $status = 'supplied' }
        if ($provenance -eq 'local-query' -and $status -eq 'supplied') { $status = 'unavailable' }
        if ($status -eq 'unavailable') { $unavailable++ }
        $value = $null
        switch ($kind) {
            'process' {
                if ($status -eq 'observed' -and $row.value -is [hashtable]) {
                    $value = @{label='selected-process';incident_identity_unconfirmed=$true;start_time=(Get-HandoffTime $row.value.start_time)}
                }
            }
            'volume' {
                if ($status -eq 'observed' -and $row.value -is [hashtable]) {
                    $format = if ($row.value.filesystem_type -cin @('NTFS','ReFS')) {$row.value.filesystem_type} else {'other'}
                    $bytes = if ($row.value.available_bytes -is [long] -and $row.value.available_bytes -ge 0) {$row.value.available_bytes} else {$null}
                    $value = @{filesystem_type=$format;is_ready=($row.value.is_ready -eq $true);available_bytes=$bytes}
                }
            }
            'runtime-uri' {
                if ($status -eq 'supplied' -and $row.value -is [hashtable]) {
                    $scheme = if ($row.value.scheme -cin @('file','http','https','ssh','sftp','ftp')) {$row.value.scheme} else {'other'}
                    $representation = if ($row.value.representation -cin @('local','remote','unknown')) {$row.value.representation} else {'unknown'}
                    $value = @{scheme=$scheme;representation=$representation;relationship='unknown'}
                }
            }
            'log' {
                $aliases['log'] = 1 + [int]$aliases['log']
                $value = @{label="log-$($aliases['log'])";occurred_at=$(if ($row.value -is [hashtable] -and $row.value.ContainsKey('occurred_at')) {Get-HandoffTime $row.value['occurred_at']} else {$null});component_present=($row.value -is [hashtable] -and $row.value.ContainsKey('component'));error_code_present=($row.value -is [hashtable] -and $row.value.ContainsKey('error_code'))}
            }
            'filter' { $aliases['filter'] = 1 + [int]$aliases['filter']; $value = @{label="filter-$($aliases['filter'])"} }
            'runtime' { $aliases['runtime'] = 1 + [int]$aliases['runtime']; $value = @{label="runtime-$($aliases['runtime'])"} }
            'incident-context' { $value = @{label='incident-context'} }
        }
        $minimized.Add(@{kind=$kind;provenance=$provenance;status=$status;value=$value;observed_at=(Get-HandoffTime $row.observed_at);error_code=$(if ($null -ne $row.error_code) { Get-HandoffCode $row.error_code } else { $null })})
    }
    return @{core_summary=@{schema_version=$(if ($CoreReport.schema_version -eq 1) {1} else {$null});runtime_kind='windows-local';path_labels=@('workspace','failed-target');evidence=$coreEvidence.ToArray();results=$results.ToArray()};incident_context=$incident;observations=$minimized.ToArray();handoff_summary=@{status=$(if ($unavailable -gt 0) {'incomplete'} else {'complete'});unavailable_observation_count=$unavailable;runtime_enforcement='RUNTIME_ENFORCEMENT_UNKNOWN';next_observation='Review local original core report and unavailable evidence; runtime enforcement remains unknown.'}}
}

function Get-HandoffHtmlCell($Value) {
    if ($null -eq $Value) { return 'unavailable' }
    $printable=if ($Value -is [hashtable] -or $Value -is [array]) { $Value | ConvertTo-Json -Depth 16 -Compress } else { [string]$Value }
    return [Net.WebUtility]::HtmlEncode($printable)
}
function Add-HandoffHtmlRow([Text.StringBuilder]$Builder,[object[]]$Cells) {
    [void]$Builder.Append('<tr>')
    foreach ($cell in $Cells) {
        [void]$Builder.Append('<td>')
        [void]$Builder.Append((Get-HandoffHtmlCell $cell))
        [void]$Builder.Append('</td>')
    }
    [void]$Builder.Append('</tr>')
}
function ConvertTo-IncidentHtml {
    param([Parameter(Mandatory)][hashtable]$Handoff)
    $html=[Text.StringBuilder]::new()
    [void]$html.Append('<!doctype html><html lang="en"><meta charset="utf-8"><title>Boundary Lens incident handoff</title><style>body{font:16px system-ui;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#17212b}table{width:100%;border-collapse:collapse;margin:0 0 1.5rem}th,td{border:1px solid #cbd5dc;padding:.5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef2f5}caption{text-align:left;font-weight:700;margin:.5rem 0}</style><h1>Minimized incident handoff</h1><p>Evidence is labelled by source and availability. Runtime enforcement remains unknown.</p>')
    [void]$html.Append('<table><caption>Core summary</caption><thead><tr><th scope="col">Path</th><th scope="col">Probe</th><th scope="col">Status</th><th scope="col">Error</th></tr></thead><tbody>')
    foreach ($row in @($Handoff.core_summary.evidence)) { Add-HandoffHtmlRow $html @($row.path,$row.probe,$row.status,$row.error_code) }
    [void]$html.Append('</tbody></table><table><caption>Incident context</caption><thead><tr><th scope="col">Field</th><th scope="col">Minimized value</th></tr></thead><tbody>')
    foreach ($key in @('occurred_at','product','version','error_code','runtime_uri_present','process_selected','supplied_observation_count')) { Add-HandoffHtmlRow $html @($key,$Handoff.incident_context[$key]) }
    [void]$html.Append('</tbody></table><table><caption>Observations</caption><thead><tr><th scope="col">Kind</th><th scope="col">Provenance</th><th scope="col">Status</th><th scope="col">Value</th><th scope="col">Error</th></tr></thead><tbody>')
    foreach ($row in @($Handoff.observations)) { Add-HandoffHtmlRow $html @($row.kind,$row.provenance,$row.status,$row.value,$row.error_code) }
    [void]$html.Append('</tbody></table><table><caption>Handoff summary</caption><thead><tr><th scope="col">Status</th><th scope="col">Unavailable observations</th><th scope="col">Runtime enforcement</th><th scope="col">Next observation</th></tr></thead><tbody>')
    Add-HandoffHtmlRow $html @($Handoff.handoff_summary.status,$Handoff.handoff_summary.unavailable_observation_count,$Handoff.handoff_summary.runtime_enforcement,$Handoff.handoff_summary.next_observation)
    [void]$html.Append('</tbody></table></html>')
    return $html.ToString()
}

function Resolve-HandoffPhysicalPath([string]$Path,[bool]$RequireDirectory) {
    try {
        if ($Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[\\/](\.|\.\.)[\\/]' -or $Path -match '[\\/]\.\.?$') { throw 'path' }
        $pending=[IO.Path]::GetFullPath($Path)
        $links=0
        while ($true) {
            if ($links -gt 16) { throw 'link budget' }
            $root=[IO.Path]::GetPathRoot($pending)
            if ($root -cnotmatch '^[A-Za-z]:\\$' -or [IO.DriveInfo]::new($root).DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)) { throw 'drive' }
            $parts=@($pending.Substring($root.Length).Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries))
            if ($parts.Count -gt 256) { throw 'component budget' }
            $current=$root
            $restarted=$false
            for ($i=0;$i -lt $parts.Count;$i++) {
                $next=[IO.Path]::Combine($current,$parts[$i])
                try { $attributes=[IO.File]::GetAttributes($next) }
                catch [IO.FileNotFoundException] { $attributes=$null }
                catch [IO.DirectoryNotFoundException] { $attributes=$null }
                if ($null -eq $attributes) {
                    if ($RequireDirectory) { throw 'missing boundary' }
                    $tail=($parts[$i..($parts.Count-1)] -join '\')
                    $base=[BoundaryHandoffPath]::DirectoryNtFinal($current)
                    if ($base -notmatch '^\\Device\\HarddiskVolume[0-9]+(?:\\|$)') { throw 'nonlocal boundary' }
                    return ($base.TrimEnd([char]'\') + '\' + $tail)
                }
                if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'unsupported reparse' }
                    $target=[IO.DirectoryInfo]::new($next).LinkTarget
                    if ($target -cnotmatch '^[A-Za-z]:\\' -or $target.Substring(2).Contains(':') -or $target -match '[\\/](\.|\.\.)[\\/]' -or $target -match '[\\/]\.\.?$') { throw 'unverified link' }
                    $tail=if ($i+1 -lt $parts.Count) { $parts[($i+1)..($parts.Count-1)] -join '\' } else { '' }
                    $pending=if ($tail.Length -gt 0) { [IO.Path]::GetFullPath([IO.Path]::Combine($target,$tail)) } else { [IO.Path]::GetFullPath($target) }
                    $links++
                    $restarted=$true
                    break
                }
                if ($i -lt $parts.Count-1 -and ($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'nondirectory ancestor' }
                $current=$next
            }
            if ($restarted) { continue }
            $last=[IO.File]::GetAttributes($current)
            if (($last -band [IO.FileAttributes]::Directory) -eq 0) {
                if ($RequireDirectory) { throw 'not directory' }
                $base=[BoundaryHandoffPath]::DirectoryNtFinal([IO.Path]::GetDirectoryName($current))
                $physical=$base.TrimEnd([char]'\') + '\' + [IO.Path]::GetFileName($current)
            }
            else { $physical=[BoundaryHandoffPath]::DirectoryNtFinal($current) }
            if ($physical -notmatch '^\\Device\\HarddiskVolume[0-9]+(?:\\|$)') { throw 'nonlocal boundary' }
            return $physical.TrimEnd([char]'\')
        }
    }
    catch { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
}

function Test-HandoffWithin([string]$Candidate,[string]$Boundary) {
    return [string]::Equals($Candidate,$Boundary,[StringComparison]::OrdinalIgnoreCase) -or
        $Candidate.StartsWith($Boundary.TrimEnd([char]'\') + '\',[StringComparison]::OrdinalIgnoreCase)
}
function Assert-HandoffPhysicalBoundary([string]$Output,[string[]]$InvestigatedPaths) {
    $parent=[IO.Path]::GetDirectoryName($Output)
    $physicalParent=Resolve-HandoffPhysicalPath $parent $true
    $candidate=$physicalParent.TrimEnd([char]'\') + '\' + [IO.Path]::GetFileName($Output)
    for ($index=0;$index -lt $InvestigatedPaths.Count;$index++) {
        $investigated=$InvestigatedPaths[$index]
        if ($investigated -match '^\\Device\\') {
            if ($investigated -notmatch '^\\Device\\HarddiskVolume[0-9]+(?:\\[^\\:]+)*$' -or
                $investigated -match '[\\/]\.\.?([\\/]|$)') { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
            $boundary=$investigated.TrimEnd([char]'\')
        }
        else { $boundary=Resolve-HandoffPhysicalPath $investigated ($index -eq 0) }
        if (Test-HandoffWithin $candidate $boundary) { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
    }
    return $candidate
}

function Write-HandoffBytes([IO.FileStream]$Stream,[byte[]]$Bytes) { $Stream.Write($Bytes,0,$Bytes.Length) }

function Get-HandoffLocalPath([string]$Path, [bool]$MustExist) {
    try {
        if ($Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[\\/](\.|\.\.)[\\/]' -or $Path -match '[\\/]\.\.?$') { throw 'path' }
        $full = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($full)
        if ([IO.DriveInfo]::new($root).DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)) { throw 'drive' }
        $parent = [IO.Path]::GetDirectoryName($full)
        $current = $root
        foreach ($part in $parent.Substring($root.Length).Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)) {
            $current = [IO.Path]::Combine($current,$part)
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'ancestor' }
        }
        if ($MustExist) {
            $attributes = [IO.File]::GetAttributes($full)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'input' }
        }
        elseif ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full)) { throw 'collision' }
        return $full
    }
    catch { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
}

function Write-IncidentHandoff {
    param([Parameter(Mandatory)][string]$LiteralPath,[Parameter(Mandatory)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InputPaths,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InvestigatedPaths)
    if ($InvestigatedPaths.Count -eq 0 -or $InvestigatedPaths[0] -cnotmatch '^[A-Za-z]:\\') {
        throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID')
    }
    $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($Payload)
    $output = Get-HandoffLocalPath $LiteralPath $false
    foreach ($input in $InputPaths) {
        $qualified = Get-HandoffLocalPath $input $true
        if ([string]::Equals($output,$qualified,[StringComparison]::OrdinalIgnoreCase)) { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
    }
    foreach ($investigated in $InvestigatedPaths) {
        try {
            if ($investigated -match '^\\Device\\') { continue }
            if ($investigated -cnotmatch '^[A-Za-z]:\\' -or $investigated.Substring(2).Contains(':')) { throw 'path' }
            $boundary = [IO.Path]::GetFullPath($investigated).TrimEnd([char]'\',[char]'/')
            if ([string]::Equals($output,$boundary,[StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($boundary + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'inside' }
        }
        catch { throw [IO.InvalidDataException]::new('INCIDENT_OUTPUT_INVALID') }
    }
    $physicalCandidate=Assert-HandoffPhysicalBoundary $output $InvestigatedPaths
    $output = Get-HandoffLocalPath $output $false
    $physicalCandidate=Assert-HandoffPhysicalBoundary $output $InvestigatedPaths
    $stream = $null
    try {
        $stream = [IO.FileStream]::new($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $final = [BoundaryHandoffPath]::Final($stream.SafeFileHandle)
        if ($final.StartsWith('\\?\',[StringComparison]::Ordinal)) { $final = $final.Substring(4) }
        if (-not [string]::Equals($final,$output,[StringComparison]::OrdinalIgnoreCase)) { throw 'identity' }
        $finalNt=[BoundaryHandoffPath]::NtFinal($stream.SafeFileHandle)
        if (-not [string]::Equals($finalNt,$physicalCandidate,[StringComparison]::OrdinalIgnoreCase)) { throw 'physical identity' }
        Write-HandoffBytes $stream $bytes
        $stream.Flush($true)
    }
    catch { throw [IO.IOException]::new('INCIDENT_OUTPUT_FAILED') }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

Export-ModuleMember -Function New-IncidentHandoff,ConvertTo-IncidentHtml,Write-IncidentHandoff
