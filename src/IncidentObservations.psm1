Set-StrictMode -Version Latest

function New-IncidentObservation([string]$Kind, [string]$Provenance, [string]$Status,
    [object]$Value, [object]$ObservedAt, [object]$ErrorCode) {
    return @{ kind=$Kind; provenance=$Provenance; status=$Status; value=$Value
        observed_at=$ObservedAt; error_code=$ErrorCode }
}

# These small seams permit deterministic race/failure tests; production opens only the selected PID.
function Open-IncidentProcess([int]$ProcessId) {
    return [Diagnostics.Process]::GetProcessById($ProcessId)
}
function Read-IncidentProcessField([object]$Process, [string]$Field) {
    switch ($Field) {
        'start' { return $Process.StartTime }
        'name' { return $Process.ProcessName }
        'exited' { return $Process.HasExited }
    }
}
function Close-IncidentProcess([object]$Process) { $Process.Dispose() }
function Get-IncidentDriveInfo([string]$Root) { return [IO.DriveInfo]::new($Root) }

function Get-IncidentProcessObservation {
    param([Parameter(Mandatory)][int]$ProcessId, [Nullable[datetime]]$ExpectedStartTime)
    $result = New-IncidentObservation 'process' 'local-query' 'unavailable' $null $null 'PROCESS_UNAVAILABLE'
    if ($ProcessId -le 0) { $result.error_code = 'PROCESS_NOT_FOUND'; return $result }
    $process = $null
    try {
        $process = Open-IncidentProcess $ProcessId
        $first = [datetime](Read-IncidentProcessField $process 'start')
        $name = [string](Read-IncidentProcessField $process 'name')
        $exited = [bool](Read-IncidentProcessField $process 'exited')
        $last = [datetime](Read-IncidentProcessField $process 'start')
        if ($exited) { $result.error_code = 'PROCESS_EXITED'; return $result }
        if ($first -ne $last -or ($null -ne $ExpectedStartTime -and $first -ne [datetime]$ExpectedStartTime)) {
            $result.error_code = 'PROCESS_IDENTITY_CHANGED'
            return $result
        }
        $result.status = 'observed'
        $result.value = @{ process_id=$ProcessId; name=$name; start_time=$first.ToUniversalTime().ToString('o')
            incident_identity_unconfirmed=$true }
        $result.observed_at = [datetime]::UtcNow.ToString('o')
        $result.error_code = $null
    }
    catch {
        $error = $_.Exception
        while ($null -ne $error.InnerException) { $error = $error.InnerException }
        if ($error -is [UnauthorizedAccessException] -or
            ($error -is [ComponentModel.Win32Exception] -and $error.NativeErrorCode -eq 5)) {
            $result.error_code = 'PROCESS_ACCESS_DENIED'
        }
        elseif ($error -is [ArgumentException]) { $result.error_code = 'PROCESS_NOT_FOUND' }
        elseif ($error -is [InvalidOperationException]) { $result.error_code = 'PROCESS_EXITED' }
        else { $result.error_code = 'PROCESS_UNAVAILABLE' }
    }
    finally { if ($null -ne $process) { Close-IncidentProcess $process } }
    return $result
}

function Get-IncidentVolumeObservation {
    param([Parameter(Mandatory)][string]$LocalPath)
    $result = New-IncidentObservation 'volume' 'local-query' 'unavailable' $null $null 'VOLUME_UNSUPPORTED'
    if ($LocalPath -cnotmatch '^[A-Za-z]:\\' -or $LocalPath.Substring(2).Contains(':') -or
        $LocalPath -match '[\\/](\.|\.\.)[\\/]' -or $LocalPath -match '[\\/]\.\.?$') { return $result }
    try {
        $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($LocalPath))
        if ($root -cnotmatch '^[A-Za-z]:\\$') { return $result }
        $drive = Get-IncidentDriveInfo $root
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { return $result }
        if (-not $drive.IsReady) { $result.error_code = 'VOLUME_UNREADY'; return $result }
        $format = [string]$drive.DriveFormat
        $available = [long]$drive.AvailableFreeSpace
        $result.status = 'observed'
        $result.value = @{ filesystem_type=$format; is_ready=$true; available_bytes=$available }
        $result.observed_at = [datetime]::UtcNow.ToString('o')
        $result.error_code = $null
    }
    catch {
        $error = $_.Exception
        while ($null -ne $error.InnerException) { $error = $error.InnerException }
        if ($error -is [UnauthorizedAccessException] -or
            ($error -is [ComponentModel.Win32Exception] -and $error.NativeErrorCode -eq 5)) {
            $result.error_code = 'VOLUME_ACCESS_DENIED'
        }
        else { $result.error_code = 'VOLUME_UNAVAILABLE' }
    }
    return $result
}

function Get-IncidentUriObservation {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $result = New-IncidentObservation 'runtime-uri' 'operator-supplied' 'unavailable' $null $null 'URI_INVALID'
    [Uri]$uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $result }
    $representation = 'unknown'
    if ($uri.Scheme -eq 'file') {
        if ($uri.IsUnc) { $representation = 'remote' }
        else { $representation = 'local' }
    }
    elseif ($uri.Scheme -in @('http','https','ssh','sftp','ftp')) { $representation = 'remote' }
    $result.status = 'supplied'
    $result.value = @{ scheme=$uri.Scheme; representation=$representation; relationship='unknown' }
    $result.error_code = $null
    return $result
}

function Get-IncidentObservations {
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][hashtable]$CoreReport,
        [Parameter()][AllowEmptyCollection()][object[]]$Logs=@())
    $observations = [Collections.Generic.List[object]]::new()
    $contextValue = @{}
    foreach ($key in @('product','version','error_code','occurred_at')) {
        if ($Context.ContainsKey($key)) { $contextValue[$key] = $Context[$key] }
    }
    $observations.Add((New-IncidentObservation 'incident-context' 'operator-supplied' 'supplied' $contextValue $null $null))
    if ($Context.ContainsKey('runtime_uri')) { $observations.Add((Get-IncidentUriObservation -Value $Context['runtime_uri'])) }
    if ($Context.ContainsKey('process_id')) { $observations.Add((Get-IncidentProcessObservation -ProcessId $Context['process_id'])) }
    $observations.Add((Get-IncidentVolumeObservation -LocalPath $CoreReport['incident']['failed_path_input']))
    if ($Context.ContainsKey('supplied_observations')) {
        foreach ($item in $Context['supplied_observations']) {
            $observations.Add((New-IncidentObservation $item['kind'] 'operator-supplied' 'supplied' $item['value'] $item['observed_at'] $null))
        }
    }
    foreach ($log in $Logs) {
        $logValue = @{}
        foreach ($key in @('error_code','occurred_at','component','level')) {
            if ($log.ContainsKey($key)) { $logValue[$key] = $log[$key] }
        }
        $observations.Add((New-IncidentObservation 'log' 'operator-supplied' 'supplied' $logValue $null $null))
    }
    return $observations.ToArray()
}

Export-ModuleMember -Function Get-IncidentProcessObservation,Get-IncidentVolumeObservation,Get-IncidentUriObservation,Get-IncidentObservations
