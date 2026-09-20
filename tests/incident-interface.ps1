#Requires -Version 7.0
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../src/BoundaryIncident.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$checks=0
function Check([bool]$Condition,[string]$Message) { $script:checks++; if (-not $Condition) { throw $Message } }
. "$PSScriptRoot/../src/BoundaryLens.ps1"
$root=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-interface-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$target=Join-Path $root 'synthetic.txt'
[IO.File]::WriteAllText($target,'synthetic only')
$core=Join-Path $root 'core.json'
$incident=Join-Path $root 'incident.json'
$log=Join-Path $root 'selected.json'
[IO.File]::WriteAllText($core,(Invoke-BoundaryLens -Workspace $root -FailedPath $target -Format Json))
[IO.File]::WriteAllText($incident,'{"schema":"boundary-incident/1","product":"<script>token-secret-sentinel</script>","runtime_uri":"ssh://example.invalid/private"}')
[IO.File]::WriteAllText($log,'{"component":"host-secret-sentinel","error_code":"SAFE","message":"private"}')
$script=$ScriptPath
$output=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-output-' + [guid]::NewGuid().ToString('N') + '.json')
$stdout=@(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $core -Incident $incident -LogPath $log -Output $output -Format Json)
$exit=$LASTEXITCODE
Check ($exit -eq 0) 'Companion JSON process failed.'
Check ($stdout.Count -eq 0) 'Companion spilled stdout.'
Check ([IO.File]::Exists($output)) 'No handoff output.'
$body=[IO.File]::ReadAllText($output)
Check ($body.Contains('RUNTIME_ENFORCEMENT_UNKNOWN')) 'Unknown lost.'
Check (-not $body.Contains('token-secret-sentinel') -and -not $body.Contains('host-secret-sentinel')) 'Sensitive string leaked.'
$repeat=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-repeat-' + [guid]::NewGuid().ToString('N') + '.html')
@(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $core -Incident $incident -LogPath $log -LogPath $log -Output $repeat -Format Html) | Out-Null
Check ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($repeat)) 'Repeated log or HTML failed.'
$html=[IO.File]::ReadAllText($repeat)
Check ($html -notmatch '<script|<iframe|<img|<link|<form') 'HTML active resource.'
foreach ($argsToTry in @(@('-Unknown','x'),@('-Format','Xml'),@('-Format','Json','-Format','Html'),@('-Output'))) {
    $bad=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-bad-' + [guid]::NewGuid().ToString('N') + '.json')
    @(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $core -Incident $incident -Output $bad @argsToTry 2>$null) | Out-Null
    Check ($LASTEXITCODE -eq 2 -and -not [IO.File]::Exists($bad)) 'Malformed flags accepted.'
}
$unavailable=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-unavailable-' + [guid]::NewGuid().ToString('N') + '.json')
[IO.File]::WriteAllText($incident,'{"schema":"boundary-incident/1","process_id":2147483647}')
@(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $core -Incident $incident -Output $unavailable -Format Json 2>$null) | Out-Null
Check ($LASTEXITCODE -eq 1 -and [IO.File]::Exists($unavailable)) 'Unavailable optional evidence hidden.'
Check (([IO.File]::ReadAllText($unavailable)).Contains('incomplete')) 'Incomplete summary missing.'
Write-Output "incident-interface assertions=$checks"
