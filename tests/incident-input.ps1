Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot/../src/IncidentInput.psm1" -Force
$duplicate = [Text.Encoding]::UTF8.GetBytes('{"schema":"boundary-incident/1","product":"a","product":"b"}')
$rejected = $false
try { ConvertFrom-IncidentJson -Bytes $duplicate | Out-Null }
catch { $rejected = $_.Exception.Message -eq 'INCIDENT_JSON_INVALID' }
if (-not $rejected) { throw 'Duplicate key was accepted.' }
$checks = 1
function Reject-Json([string]$Json) {
    $script:checks++
    try { ConvertFrom-IncidentJson -Bytes ([Text.Encoding]::UTF8.GetBytes($Json)) | Out-Null }
    catch { if ($_.Exception.Message -eq 'INCIDENT_JSON_INVALID') { return }; throw }
    throw "Accepted invalid JSON"
}
function Check([bool]$Condition, [string]$Message) {
    $script:checks++
    if (-not $Condition) { throw $Message }
}
Reject-Json '{"schema":"boundary-incident/1","Product":"a","product":"b"}'
Reject-Json '{"schema":"boundary-incident/1","p\u0072oduct":"a","product":"b"}'
Reject-Json '{"value":NaN}'
Reject-Json ('[' * 33 + '0' + ']' * 33)
Reject-Json ('{"value":"' + ('x' * 4097) + '"}')
$valid = ConvertFrom-IncidentJson -Bytes ([Text.Encoding]::UTF8.GetBytes('{"schema":"boundary-incident/1","product":"a"}'))
Check ($valid['product'] -ceq 'a') 'Valid JSON changed.'
$atLimit = ConvertFrom-IncidentJson -Bytes ([Text.Encoding]::UTF8.GetBytes('{"value":"' + ('x' * 4096) + '"}'))
Check ($atLimit['value'].Length -eq 4096) 'Exact string limit rejected.'
try { ConvertFrom-IncidentJson -Bytes ([byte[]]@(123,34,120,34,58,34,255,34,125)) | Out-Null; throw 'Invalid UTF-8 accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_JSON_INVALID') 'Wrong UTF-8 failure.' }

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-input-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$incident = Join-Path $fixture 'incident.json'
$log = Join-Path $fixture 'log.jsonl'
$good = '{"schema":"boundary-incident/1","product":"demo","occurred_at":"2026-09-20T00:00:00Z","process_id":123,"supplied_observations":[{"kind":"filter","value":"given","observed_at":null}]}'
[IO.File]::WriteAllText($incident,$good)
$originalHash = (Get-FileHash -LiteralPath $incident -Algorithm SHA256).Hash
$output = @(Read-IncidentContext -LiteralPath $incident)
Check ($output.Count -eq 1 -and $output[0].schema -ceq 'boundary-incident/1') 'Context contract failed or stdout spilled.'
Check ((Get-FileHash -LiteralPath $incident -Algorithm SHA256).Hash -eq $originalHash) 'Incident changed.'
foreach ($bad in @('{"schema":"boundary-incident/1","status":"SAFE"}', '{"schema":"boundary-incident/1","process_id":true}', '{"schema":"boundary-incident/1","occurred_at":"2026-09-20T09:00:00+09:00"}', '{"schema":"boundary-incident/1","supplied_observations":[{"kind":"filter","value":"x","observed_at":null,"provenance":"local-query"}]}')) {
    [IO.File]::WriteAllText($incident,$bad)
    try { Read-IncidentContext -LiteralPath $incident | Out-Null; throw 'Invalid context accepted.' }
    catch { Check ($_.Exception.Message -eq 'INCIDENT_SCHEMA_INVALID') 'Wrong context failure.' }
}
[IO.File]::WriteAllText($incident,$good)
[IO.File]::WriteAllBytes($log,[Text.Encoding]::UTF8.GetBytes('{"error_code":"E1","message":"PRIVATE","component":"c"}' + "`n"))
$logs = @(Read-IncidentLogs -LiteralPath @($log))
Check ($logs.Count -eq 1 -and $logs[0].error_code -eq 'E1' -and -not $logs[0].ContainsKey('message')) 'Log allowlist failed.'
[IO.File]::WriteAllText($log, "{}`nnot-json")
try { Read-IncidentLogs -LiteralPath @($log) | Out-Null; throw 'Malformed log batch accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_LOG_INVALID') 'Wrong malformed batch failure.' }
[IO.File]::WriteAllText($log, ('{}' + "`n") * 10000)
Check (@(Read-IncidentLogs -LiteralPath @($log)).Count -eq 10000) 'Exact record bound rejected.'
[IO.File]::AppendAllText($log, '{}')
try { Read-IncidentLogs -LiteralPath @($log) | Out-Null; throw 'Record overflow accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_LOG_INVALID') 'Wrong record overflow failure.' }
[IO.File]::WriteAllBytes($log, [byte[]]::new(1048576))
Check ((Read-IncidentFile -LiteralPath $log -MaxBytes 1048576).Length -eq 1048576) 'Exact byte bound rejected.'
try { Read-IncidentFile -LiteralPath $log -MaxBytes 1048575 | Out-Null; throw 'Byte overflow accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_FILE_INVALID') 'Wrong byte overflow failure.' }
foreach ($badPath in @('\\server\share\file.json', 'Z:\missing\file.json')) {
    try { Read-IncidentFile -LiteralPath $badPath -MaxBytes 1048576 | Out-Null; throw 'Remote/missing path accepted.' }
    catch { Check ($_.Exception.Message -in @('INCIDENT_PATH_INVALID','INCIDENT_FILE_INVALID')) 'Wrong path failure.' }
}
$held = [IO.FileStream]::new($incident,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try {
    try { Read-IncidentFile -LiteralPath $incident -MaxBytes 1048576 | Out-Null; throw 'Locked input accepted.' }
    catch { Check ($_.Exception.Message -eq 'INCIDENT_FILE_INVALID') 'Wrong locked input failure.' }
}
finally { $held.Dispose() }
$junction = Join-Path $fixture 'junction'
New-Item -ItemType Junction -Path $junction -Target $fixture -ErrorAction Stop | Out-Null
try { Read-IncidentFile -LiteralPath (Join-Path $junction 'incident.json') -MaxBytes 1048576 | Out-Null; throw 'Parent junction accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_PATH_INVALID') 'Wrong parent junction failure.' }

. "$PSScriptRoot/../src/BoundaryLens.ps1"
$corePath = Join-Path $fixture 'core.json'
$coreJson = Invoke-BoundaryLens -Workspace $fixture -FailedPath $incident -Format Json
[IO.File]::WriteAllText($corePath,$coreJson)
$coreHash = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash
$core = @(Read-IncidentCoreReport -LiteralPath $corePath)
Check ($core.Count -eq 1 -and $core[0].schema_version -eq 1 -and @($core[0].results | Where-Object code -eq 'RUNTIME_ENFORCEMENT_UNKNOWN').Count -eq 1) 'Actual core report rejected or output spilled.'
Check ((Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash -eq $coreHash) 'Core input changed.'
$spoof = $coreJson | ConvertFrom-Json -AsHashtable
$spoof['evidence']['workspace_path']['observations']['unsafe'] = 'SAFE'
[IO.File]::WriteAllText($corePath,($spoof | ConvertTo-Json -Depth 32))
try { Read-IncidentCoreReport -LiteralPath $corePath | Out-Null; throw 'Nested extra core field accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_SCHEMA_INVALID') 'Wrong nested core failure.' }
Write-Output "incident-input assertions=$checks"
