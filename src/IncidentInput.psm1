Set-StrictMode -Version Latest

if (-not ('BoundaryIncidentFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class BoundaryIncidentFileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ID_INFO {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)] public byte[] FileId;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out FILE_ID_INFO info, uint size);
    public static string Id(SafeFileHandle handle) {
        FILE_ID_INFO info;
        if (!GetFileInformationByHandleEx(handle, 18, out info, (uint)Marshal.SizeOf<FILE_ID_INFO>()))
            throw new System.IO.IOException("File identity unavailable.");
        return info.VolumeSerialNumber.ToString("X16") + Convert.ToHexString(info.FileId);
    }
}
'@ -ErrorAction Stop
}

function New-IncidentError([string]$Code) {
    return [IO.InvalidDataException]::new($Code)
}

function Convert-IncidentElement([System.Text.Json.JsonElement]$Element, [ref]$Nodes) {
    $Nodes.Value++
    if ($Nodes.Value -gt 100000) { throw (New-IncidentError 'INCIDENT_JSON_INVALID') }
    switch ($Element.ValueKind) {
        Object {
            $map = @{}
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($property in $Element.EnumerateObject()) {
                if ($property.Name.Length -gt 4096 -or -not $seen.Add($property.Name)) { throw (New-IncidentError 'INCIDENT_JSON_INVALID') }
                $map[$property.Name] = Convert-IncidentElement $property.Value $Nodes
            }
            return ,$map
        }
        Array {
            $items = [Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $items.Add((Convert-IncidentElement $item $Nodes)) }
            return ,$items.ToArray()
        }
        String {
            $value = $Element.GetString()
            if ($value.Length -gt 4096) { throw (New-IncidentError 'INCIDENT_JSON_INVALID') }
            return $value
        }
        Number {
            [long]$integer = 0
            if ($Element.TryGetInt64([ref]$integer)) { return $integer }
            [decimal]$decimal = 0
            if ($Element.TryGetDecimal([ref]$decimal)) { return $decimal }
            throw (New-IncidentError 'INCIDENT_JSON_INVALID')
        }
        True { return $true }
        False { return $false }
        Null { return $null }
        default { throw (New-IncidentError 'INCIDENT_JSON_INVALID') }
    }
}

function ConvertFrom-IncidentJson {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $value = $utf8.GetString($Bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 32
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $document = [System.Text.Json.JsonDocument]::Parse($value, $options)
        try {
            $nodes = 0
            return Convert-IncidentElement $document.RootElement ([ref]$nodes)
        }
        finally { $document.Dispose() }
    }
    catch { throw (New-IncidentError 'INCIDENT_JSON_INVALID') }
}

function Test-IncidentPath([string]$LiteralPath) {
    if ($LiteralPath -cnotmatch '^[A-Za-z]:\\' -or $LiteralPath.Substring(2).Contains(':') -or
        $LiteralPath -match '[\\/](\.|\.\.)[\\/]' -or $LiteralPath -match '[\\/]\.\.?$') {
        throw (New-IncidentError 'INCIDENT_PATH_INVALID')
    }
    try {
        $full = [IO.Path]::GetFullPath($LiteralPath)
        $root = [IO.Path]::GetPathRoot($full)
        $drive = [IO.DriveInfo]::new($root)
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { throw (New-IncidentError 'INCIDENT_PATH_INVALID') }
        $current = $root
        foreach ($part in $full.Substring($root.Length).Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)) {
            $current = [IO.Path]::Combine($current, $part)
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (New-IncidentError 'INCIDENT_PATH_INVALID') }
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw (New-IncidentError 'INCIDENT_PATH_INVALID') }
        return $full
    }
    catch { throw (New-IncidentError 'INCIDENT_PATH_INVALID') }
}

function Read-IncidentFile {
    param([Parameter(Mandatory)][string]$LiteralPath, [Parameter(Mandatory)][long]$MaxBytes)
    if ($MaxBytes -lt 0 -or $MaxBytes -gt 1048576) { throw (New-IncidentError 'INCIDENT_FILE_INVALID') }
    $path = Test-IncidentPath $LiteralPath
    try {
        $before = [IO.FileInfo]::new($path)
        $beforeLength = $before.Length
        $beforeModified = $before.LastWriteTimeUtc
        $beforeCreated = $before.CreationTimeUtc
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $heldId = [BoundaryIncidentFileIdentity]::Id($stream.SafeFileHandle)
            if ($stream.Length -gt $MaxBytes) { throw (New-IncidentError 'INCIDENT_FILE_INVALID') }
            $bytes = [byte[]]::new([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($count -le 0) { throw (New-IncidentError 'INCIDENT_FILE_INVALID') }
                $offset += $count
            }
            $after = [IO.FileInfo]::new((Test-IncidentPath $path))
            $pathStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $pathId = [BoundaryIncidentFileIdentity]::Id($pathStream.SafeFileHandle) }
            finally { $pathStream.Dispose() }
            if ($beforeLength -ne $after.Length -or $beforeLength -ne $stream.Length -or
                $heldId -cne $pathId -or
                $beforeModified -ne $after.LastWriteTimeUtc -or
                $beforeCreated -ne $after.CreationTimeUtc) { throw (New-IncidentError 'INCIDENT_FILE_INVALID') }
            return ,$bytes
        }
        finally { $stream.Dispose() }
    }
    catch {
        if ($_.Exception -is [IO.InvalidDataException] -and $_.Exception.Message -eq 'INCIDENT_FILE_INVALID') { throw }
        throw (New-IncidentError 'INCIDENT_FILE_IO_FAILED')
    }
}

function Assert-IncidentKeys([hashtable]$Map, [string[]]$Allowed) {
    foreach ($key in $Map.Keys) {
        if ($Allowed -cnotcontains $key) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    }
}

function Assert-IncidentShape([hashtable]$Map, [string[]]$Keys) {
    Assert-IncidentKeys $Map $Keys
    if ($Map.Count -ne $Keys.Count) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
}

function Assert-IncidentValue($Value, [string]$Type, [bool]$Nullable = $false) {
    if ($Nullable -and $null -eq $Value) { return }
    $good = switch ($Type) {
        string { $Value -is [string] }
        boolean { $Value -is [bool] }
        integer { $Value -is [long] -and $Value -ge 0 }
        array { $Value -is [array] }
        map { $Value -is [hashtable] }
    }
    if (-not $good) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
}

function Assert-IncidentFailure($Failure) {
    if ($null -eq $Failure) { return }
    Assert-IncidentValue $Failure map
    Assert-IncidentShape $Failure @('error_id','message')
    foreach ($key in @('error_id','message')) { Assert-IncidentValue $Failure[$key] string }
}

function Assert-IncidentCorePath([hashtable]$Record) {
    Assert-IncidentShape $Record @('probe','status','raw_input','lexical_path','exists','final_path','reparse_segments','observations','failure')
    Assert-IncidentValue $Record['probe'] string
    Assert-IncidentValue $Record['status'] string
    if ($Record['probe'] -cne 'path' -or $Record['status'] -cnotin @('observed','unknown','collection-failure')) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentValue $Record['raw_input'] string
    foreach ($key in @('lexical_path','final_path')) { Assert-IncidentValue $Record[$key] string $true }
    Assert-IncidentValue $Record['exists'] boolean $true
    Assert-IncidentValue $Record['reparse_segments'] array
    foreach ($segment in $Record['reparse_segments']) {
        Assert-IncidentValue $segment map
        Assert-IncidentShape $segment @('lexical_path','link_type','target')
        Assert-IncidentValue $segment['lexical_path'] string
        Assert-IncidentValue $segment['link_type'] string
        Assert-IncidentValue $segment['target'] array
        foreach ($target in $segment['target']) { Assert-IncidentValue $target string }
    }
    $obs = $Record['observations']
    Assert-IncidentValue $obs map
    Assert-IncidentShape $obs @('role','provider','existing_segment_count','nearest_existing_path','reparse_observation_complete')
    Assert-IncidentValue $obs['role'] string
    Assert-IncidentValue $obs['provider'] string
    if ($obs['role'] -cnotin @('workspace','failed-path') -or $obs['provider'] -cne 'FileSystem') { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentValue $obs['existing_segment_count'] integer
    Assert-IncidentValue $obs['nearest_existing_path'] string $true
    Assert-IncidentValue $obs['reparse_observation_complete'] boolean
    Assert-IncidentFailure $Record['failure']
}

function Assert-IncidentCoreAcl([hashtable]$Record) {
    Assert-IncidentShape $Record @('probe','status','raw_input','role','protected','owner_fingerprint','access_rules','failure')
    foreach ($key in @('probe','status','role')) { Assert-IncidentValue $Record[$key] string }
    if ($Record['probe'] -cne 'acl' -or $Record['status'] -cnotin @('observed','unknown','collection-failure') -or
        $Record['role'] -cnotin @('workspace','failed-path')) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentValue $Record['raw_input'] string
    Assert-IncidentValue $Record['protected'] boolean $true
    Assert-IncidentValue $Record['owner_fingerprint'] string $true
    Assert-IncidentValue $Record['access_rules'] array
    foreach ($rule in $Record['access_rules']) {
        Assert-IncidentValue $rule map
        Assert-IncidentShape $rule @('access_type','rights','inherited','identity_fingerprint')
        Assert-IncidentValue $rule['access_type'] string
        if ($rule['access_type'] -cnotin @('allow','deny')) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
        foreach ($key in @('rights','identity_fingerprint')) { Assert-IncidentValue $rule[$key] string }
        Assert-IncidentValue $rule['inherited'] boolean
    }
    Assert-IncidentFailure $Record['failure']
}

function Assert-IncidentUtc($Value, [bool]$Nullable = $false, [bool]$Core = $false) {
    if ($Nullable -and $null -eq $Value) { return }
    $suffix = if ($Core) { '(?:Z|\+00:00)' } else { 'Z' }
    if ($Value -isnot [string] -or $Value -cnotmatch ('^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?' + $suffix + '$')) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    [DateTimeOffset]$parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID')
    }
}

function Read-IncidentContext {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $data = ConvertFrom-IncidentJson -Bytes (Read-IncidentFile -LiteralPath $LiteralPath -MaxBytes 1048576)
    if ($data -isnot [hashtable]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentKeys $data @('schema','product','version','error_code','occurred_at','runtime_uri','process_id','supplied_observations')
    Assert-IncidentValue $data['schema'] string
    if ($data['schema'] -cne 'boundary-incident/1') { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    foreach ($key in @('product','version','error_code','occurred_at','runtime_uri')) {
        if ($data.ContainsKey($key) -and ($data[$key] -isnot [string] -or $data[$key].Length -eq 0)) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    }
    if ($data.ContainsKey('occurred_at')) { Assert-IncidentUtc $data['occurred_at'] }
    if ($data.ContainsKey('process_id') -and ($data['process_id'] -isnot [long] -or $data['process_id'] -lt 1 -or $data['process_id'] -gt [int]::MaxValue)) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    if ($data.ContainsKey('supplied_observations')) {
        if ($data['supplied_observations'] -isnot [array]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
        foreach ($entry in $data['supplied_observations']) {
            if ($entry -isnot [hashtable]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
            Assert-IncidentKeys $entry @('kind','value','observed_at')
            Assert-IncidentValue $entry['kind'] string
            if ($entry.Count -ne 3 -or $entry['kind'] -cnotin @('filter','runtime') -or $entry['value'] -isnot [string] -or $entry['value'].Length -eq 0) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
            Assert-IncidentUtc $entry['observed_at'] $true
        }
    }
    return $data
}

function Read-IncidentCoreReport {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $data = ConvertFrom-IncidentJson -Bytes (Read-IncidentFile -LiteralPath $LiteralPath -MaxBytes 1048576)
    if ($data -isnot [hashtable]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentKeys $data @('schema_version','incident','evidence','results')
    if ($data.Count -ne 4 -or $data['schema_version'] -isnot [long] -or $data['schema_version'] -ne 1 -or
        $data['incident'] -isnot [hashtable] -or $data['evidence'] -isnot [hashtable] -or $data['results'] -isnot [array]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    Assert-IncidentKeys $data['incident'] @('workspace_input','failed_path_input','runtime_kind','observed_at')
    Assert-IncidentValue $data['incident']['runtime_kind'] string
    if ($data['incident'].Count -ne 4 -or $data['incident']['runtime_kind'] -cne 'windows-local') { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    foreach ($key in @('workspace_input','failed_path_input')) { if ($data['incident'][$key] -isnot [string]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') } }
    Assert-IncidentUtc $data['incident']['observed_at'] $false $true
    Assert-IncidentKeys $data['evidence'] @('workspace_path','failed_path','workspace_acl','failed_path_acl','path_relation')
    if ($data['evidence'].Count -ne 5) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    foreach ($key in @('workspace_path','failed_path','workspace_acl','failed_path_acl','path_relation')) {
        if ($data['evidence'][$key] -isnot [hashtable]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
    }
    foreach ($key in @('workspace_path','failed_path')) { Assert-IncidentCorePath $data['evidence'][$key] }
    foreach ($key in @('workspace_acl','failed_path_acl')) { Assert-IncidentCoreAcl $data['evidence'][$key] }
    $relation = $data['evidence']['path_relation']
    Assert-IncidentShape $relation @('logical_within_workspace','reparse_segment_observed','final_workspace_observed','final_path_observed','final_within_workspace')
    foreach ($key in $relation.Keys) { Assert-IncidentValue $relation[$key] boolean $true }
    foreach ($item in $data['results']) {
        if ($item -isnot [hashtable]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
        Assert-IncidentKeys $item @('status','code','message','evidence_refs','next_observation')
        Assert-IncidentValue $item['status'] string
        if ($item.Count -ne 5 -or $item['status'] -cnotin @('unknown','collection-failure','cause-candidate') -or
            $item['code'] -isnot [string] -or $item['message'] -isnot [string] -or $item['next_observation'] -isnot [string] -or
            $item['evidence_refs'] -isnot [array]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') }
        foreach ($ref in $item['evidence_refs']) { if ($ref -isnot [string]) { throw (New-IncidentError 'INCIDENT_SCHEMA_INVALID') } }
    }
    return $data
}

function Read-IncidentLogs {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$LiteralPath)
    $records = [Collections.Generic.List[object]]::new()
    [long]$total = 0
    foreach ($path in $LiteralPath) {
        $jsonl = $path.EndsWith('.jsonl', [StringComparison]::OrdinalIgnoreCase)
        if (-not $jsonl -and -not $path.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
        $remaining = 4194304 - $total
        if ($remaining -lt 0) { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
        $bytes = Read-IncidentFile -LiteralPath $path -MaxBytes ([Math]::Min(1048576, $remaining))
        $total += $bytes.Length
        if ($jsonl) {
            try { $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) }
            catch { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
            $items = [Collections.Generic.List[object]]::new()
            $lines = $text -split '\r?\n'
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($line.Length -eq 0) {
                    if ($i -eq $lines.Count - 1) { continue }
                    throw (New-IncidentError 'INCIDENT_LOG_INVALID')
                }
                try { $items.Add((ConvertFrom-IncidentJson -Bytes ([Text.Encoding]::UTF8.GetBytes($line)))) }
                catch { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
                if ($items.Count + $records.Count -gt 10000) { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
            }
        }
        else {
            try { $parsed = ConvertFrom-IncidentJson -Bytes $bytes }
            catch { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
            $items = if ($parsed -is [array]) { $parsed } else { @($parsed) }
        }
        foreach ($item in $items) {
            if ($item -isnot [hashtable] -or $records.Count -ge 10000) { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
            $allowed = @{}
            foreach ($key in @('error_code','occurred_at','component','level')) {
                if ($item.ContainsKey($key)) {
                    if ($item[$key] -isnot [string]) { throw (New-IncidentError 'INCIDENT_LOG_INVALID') }
                    $allowed[$key] = $item[$key]
                }
            }
            if ($allowed.ContainsKey('occurred_at')) { try { Assert-IncidentUtc $allowed['occurred_at'] } catch { throw (New-IncidentError 'INCIDENT_LOG_INVALID') } }
            $records.Add($allowed)
        }
    }
    return $records.ToArray()
}

Export-ModuleMember -Function Read-IncidentFile,ConvertFrom-IncidentJson,Read-IncidentContext,Read-IncidentCoreReport,Read-IncidentLogs
