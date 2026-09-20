Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot/../src/IncidentObservations.psm1" -Force
$checks = 0
function Check([bool]$Condition, [string]$Message) {
    $script:checks++
    if (-not $Condition) { throw $Message }
}
function Check-Shape([hashtable]$Observation) {
    Check ((@($Observation.Keys | Sort-Object) -join ',') -ceq 'error_code,kind,observed_at,provenance,status,value') 'Observation shape changed.'
    Check ($Observation.provenance -in @('local-query','operator-supplied')) 'Invalid provenance.'
    Check ($Observation.status -in @('observed','supplied','unavailable')) 'Invalid status.'
    if ($Observation.status -eq 'unavailable') {
        Check ($null -eq $Observation.value -and $null -eq $Observation.observed_at -and $Observation.error_code -is [string]) 'Failure fabricated a value or time.'
    }
}
$value = Get-IncidentUriObservation -Value 'ssh://example.invalid/private/file'
Check ($value.value.scheme -eq 'ssh') 'URI scheme missing.'
Check ($value.value.relationship -eq 'unknown') 'URI identity was guessed.'
Check ($value.provenance -eq 'operator-supplied' -and $value.status -eq 'supplied' -and $null -eq $value.observed_at) 'Supplied URI became measured evidence.'
Check-Shape $value
foreach ($case in @(
    @{ input='file:///C:/local/file.txt'; representation='local' },
    @{ input='file://example.invalid/share/file.txt'; representation='remote' },
    @{ input='https://example.invalid/path?token=PRIVATE#fragment'; representation='remote' },
    @{ input='custom:opaque'; representation='unknown' }
)) {
    $uri = Get-IncidentUriObservation -Value $case.input
    Check ($uri.value.representation -eq $case.representation -and $uri.value.relationship -eq 'unknown') 'URI representation or relationship changed.'
    Check (-not (($uri | ConvertTo-Json -Depth 8) -match 'example\.invalid|PRIVATE|fragment|/path|/share|/local')) 'URI authority or path leaked.'
    Check-Shape $uri
}
$invalidUri = Get-IncidentUriObservation -Value 'not a uri'
Check ($invalidUri.error_code -eq 'URI_INVALID') 'Malformed URI not rejected.'
Check-Shape $invalidUri

$real = Get-IncidentProcessObservation -ProcessId $PID
Check ($real.status -eq 'observed' -and $real.value.process_id -eq $PID -and $real.value.name -is [string]) 'Selected current process not observed.'
Check ($real.value.incident_identity_unconfirmed -is [bool] -and $real.value.incident_identity_unconfirmed) 'Incident-time process identity was assumed.'
Check ($real.value.start_time -is [string] -and $real.observed_at -is [string]) 'Process timestamps missing.'
Check-Shape $real
$missing = Get-IncidentProcessObservation -ProcessId 2147483647
Check ($missing.error_code -eq 'PROCESS_NOT_FOUND') 'Missing PID not fixed failure.'
Check-Shape $missing
$module = Get-Module IncidentObservations
& $module {
    $script:Mode = 'exit'
    $script:Opened = 0
    $script:Closed = 0
    function script:Open-IncidentProcess([int]$ProcessId) {
        if ($ProcessId -ne 99) { throw 'Unexpected PID.' }
        $script:Opened++
        if ($script:Mode -eq 'denied') { throw [UnauthorizedAccessException]::new('private') }
        if ($script:Mode -eq 'second-missing' -and $script:Opened -eq 2) { throw [ArgumentException]::new('ended') }
        if ($script:Mode -eq 'second-denied' -and $script:Opened -eq 2) { throw [UnauthorizedAccessException]::new('private') }
        return [pscustomobject]@{ marker='synthetic'; instance=$script:Opened }
    }
    function script:Read-IncidentProcessField([object]$Process, [string]$Field) {
        if ($Field -eq 'start') {
            if ($script:Mode -eq 'reuse' -and $Process.instance -eq 2) { return [datetime]'2026-09-20T01:00:00Z' }
            return [datetime]'2026-09-20T00:00:00Z'
        }
        if ($Field -eq 'name') { return 'synthetic' }
        if ($Field -eq 'exited') { return ($script:Mode -eq 'exit' -or ($script:Mode -eq 'second-exited' -and $Process.instance -eq 2)) }
    }
    function script:Close-IncidentProcess([object]$Process) { $script:Closed++ }
}
$exited = Get-IncidentProcessObservation -ProcessId 99
Check ($exited.error_code -eq 'PROCESS_EXITED') 'Exited PID not fixed failure.'
Check-Shape $exited
& $module { $script:Mode='reuse'; $script:Opened=0; $script:Closed=0 }
$reuse = Get-IncidentProcessObservation -ProcessId 99
Check ($reuse.error_code -eq 'PROCESS_IDENTITY_CHANGED') 'Changed start time not detected.'
Check-Shape $reuse
Check ((& $module { $script:Closed }) -eq 2) 'Both process handles were not closed.'
& $module { $script:Mode='stable'; $script:Opened=0; $script:Closed=0 }
$wrongPin = Get-IncidentProcessObservation -ProcessId 99 -ExpectedStartTime ([datetime]'2026-09-19T00:00:00Z')
Check ($wrongPin.error_code -eq 'PROCESS_IDENTITY_CHANGED') 'Prior identity pin not enforced.'
Check-Shape $wrongPin
foreach ($mode in @('second-missing','second-exited','second-denied')) {
    & $module { param($testMode) $script:Mode=$testMode; $script:Opened=0; $script:Closed=0 } $mode
    $changed = Get-IncidentProcessObservation -ProcessId 99
    $expected = if ($mode -eq 'second-denied') { 'PROCESS_ACCESS_DENIED' } else { 'PROCESS_EXITED' }
    Check ($changed.error_code -eq $expected) "Second process query $mode not unavailable as $expected."
    Check-Shape $changed
}
& $module { $script:Mode='denied'; $script:Opened=0 }
$denied = Get-IncidentProcessObservation -ProcessId 99
Check ($denied.error_code -eq 'PROCESS_ACCESS_DENIED') 'Process denial not fixed failure.'
Check-Shape $denied

$driveRoot = [IO.Path]::GetPathRoot($PSScriptRoot)
$realVolume = Get-IncidentVolumeObservation -LocalPath (Join-Path $PSScriptRoot 'synthetic.txt')
Check ($realVolume.status -eq 'observed' -and $realVolume.value.filesystem_type -is [string] -and $realVolume.value.available_bytes -is [long]) 'Declared local volume unavailable.'
Check (-not (($realVolume | ConvertTo-Json -Depth 8) -match 'volume_label|serial|host|[A-Za-z]:\\')) 'Volume identity leaked.'
Check-Shape $realVolume
$unsupported = Get-IncidentVolumeObservation -LocalPath '\\example.invalid\share\file'
Check ($unsupported.error_code -eq 'VOLUME_UNSUPPORTED') 'UNC path accepted as local volume.'
Check-Shape $unsupported
& $module {
    $script:DriveMode='unready'
    function script:Get-IncidentDriveInfo([string]$Root) {
        if ($script:DriveMode -eq 'denied') { throw [UnauthorizedAccessException]::new('private') }
        if ($script:DriveMode -eq 'unsupported') { return [pscustomobject]@{ DriveType=[IO.DriveType]::Network } }
        return [pscustomobject]@{ DriveType=[IO.DriveType]::Fixed; IsReady=$false }
    }
}
$local = Join-Path $driveRoot 'synthetic.txt'
$unready = Get-IncidentVolumeObservation -LocalPath $local
Check ($unready.error_code -eq 'VOLUME_UNREADY') 'Unready volume not fixed failure.'
Check-Shape $unready
& $module { $script:DriveMode='unsupported' }
$unsupportedDrive = Get-IncidentVolumeObservation -LocalPath $local
Check ($unsupportedDrive.error_code -eq 'VOLUME_UNSUPPORTED') 'Network drive accepted.'
Check-Shape $unsupportedDrive
& $module { $script:DriveMode='denied' }
$deniedDrive = Get-IncidentVolumeObservation -LocalPath $local
Check ($deniedDrive.error_code -eq 'VOLUME_ACCESS_DENIED') 'Volume denial not fixed failure.'
Check-Shape $deniedDrive

$context = @{ product='SAFE'; supplied_observations=@(@{kind='filter';value='SAFE';observed_at=$null},@{kind='runtime';value='SAFE';observed_at='2026-09-20T00:00:00Z'}) }
$core = @{ incident=@{failed_path_input=$local}; results=@(@{code='RUNTIME_ENFORCEMENT_UNKNOWN'}) }
$coreBefore = $core | ConvertTo-Json -Depth 8 -Compress
$observations = @(Get-IncidentObservations -Context $context -CoreReport $core -Logs @(@{error_code='SAFE';component='synthetic';message='PRIVATE'}))
Check ($observations.Count -eq 5) 'Wrong composed observation count.'
foreach ($observation in $observations) { Check-Shape $observation }
Check (($core | ConvertTo-Json -Depth 8 -Compress) -ceq $coreBefore) 'Core report was changed.'
Check (@($core.results | Where-Object code -eq 'RUNTIME_ENFORCEMENT_UNKNOWN').Count -eq 1) 'Core UNKNOWN removed.'
Check (@($observations | Where-Object { $_.provenance -eq 'local-query' -and (($_ | ConvertTo-Json -Depth 8) -match 'SAFE') }).Count -eq 0) 'Supplied SAFE claim became local evidence.'
Check (@($observations | Where-Object { $_.kind -in @('filter','runtime','log','incident-context') -and $_.status -ne 'supplied' }).Count -eq 0) 'Supplied evidence became observed.'
Check (-not (($observations | ConvertTo-Json -Depth 8) -match 'PRIVATE')) 'Log message copied.'
$empty = @(Get-IncidentObservations -Context @{} -CoreReport $core -Logs @())
Check ($empty.Count -eq 2 -and $empty[0].value.Count -eq 0) 'Empty optional context or logs failed.'

$source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '../src/IncidentObservations.psm1'))
function Find-ForbiddenAst([string]$Code) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Code, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'AST parse failure.' }
    $forbiddenCommands = @('Invoke-WebRequest','Invoke-RestMethod','Test-Path','Start-Process','Stop-Process','Get-Process','Get-CimInstance','Invoke-Command','Remove-Item','Set-Item','Set-Acl','Invoke-Expression')
    $forbiddenMembers = @('Start','Kill','GetProcesses','GetProcessByName','GetEnvironmentVariables','GetCommandLineArgs','GetResponse','GetResponseAsync','WriteAllText','WriteAllBytes','Delete','Move','Copy')
    $forbiddenProperties = @('StartInfo','Environment','WorkingSet','WorkingSet64','VirtualMemorySize64','MainModule','Modules','CommandLine')
    return @($ast.FindAll({ param($node)
        if ($node -is [Management.Automation.Language.CommandAst]) { return $node.GetCommandName() -in $forbiddenCommands }
        if ($node -is [Management.Automation.Language.MemberExpressionAst]) { return $node.Member.Value -in ($forbiddenMembers + $forbiddenProperties) }
        if ($node -is [Management.Automation.Language.TypeExpressionAst]) { return $node.TypeName.FullName -match '^(System\.)?Net\.(Http|Sockets|WebClient|Dns|WebRequest|FtpWebRequest|TcpClient)' }
        return $false
    }, $true))
}
Check (@(Find-ForbiddenAst $source).Count -eq 0) 'Forbidden network/process-mutation AST found.'
Check (@(Find-ForbiddenAst 'Start-Process notepad; [Diagnostics.Process]::GetProcesses()').Count -eq 2) 'Forbidden AST positive control failed.'
Check (@(Find-ForbiddenAst '[Net.Http.HttpClient]::new()').Count -eq 1) 'Network type AST positive control failed.'
Write-Output "incident-observations assertions=$checks"
