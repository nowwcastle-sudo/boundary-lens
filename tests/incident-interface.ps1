#Requires -Version 7.0
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../src/BoundaryIncident.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$checks=0
function Check([bool]$Condition,[string]$Message) { $script:checks++; if (-not $Condition) { throw $Message } }
function Invoke-CapturedIncident([string[]]$Tokens) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName='pwsh'
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    foreach ($token in @('-NoProfile','-NonInteractive','-File',$script)+$Tokens) { $info.ArgumentList.Add($token) }
    $child=[Diagnostics.Process]::new()
    $child.StartInfo=$info
    try {
        if (-not $child.Start()) { throw 'Companion test process did not start.' }
        $outTask=$child.StandardOutput.ReadToEndAsync()
        $errTask=$child.StandardError.ReadToEndAsync()
        $child.WaitForExit()
        return @{exit=$child.ExitCode;stdout=$outTask.GetAwaiter().GetResult();stderr=$errTask.GetAwaiter().GetResult().Trim()}
    } finally { $child.Dispose() }
}
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
Check (($html -split '<table').Count -ge 4) 'HTML has no separate summary, context and observations tables.'
Check ($html.Contains('<th scope="col">Provenance</th>') -and $html.Contains('<th scope="col">Status</th>')) 'HTML does not distinguish evidence source and availability.'
Check ($html.Contains('<caption>Core results</caption>') -and $html.Contains('<th scope="col">Observed at</th>')) 'HTML result and observation-time columns are absent.'
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
$lockedOut=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-locked-' + [guid]::NewGuid().ToString('N') + '.json')
$hold=[IO.FileStream]::new($core,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try {
    $lockedResult=Invoke-CapturedIncident @('-CoreReport',$core,'-Incident',$incident,'-Output',$lockedOut,'-Format','Json')
    Check ($lockedResult.exit -eq 1 -and $lockedResult.stderr -eq 'INCIDENT_FILE_IO_FAILED' -and -not [IO.File]::Exists($lockedOut)) 'Locked valid core was classified as usage rather than collection failure.'
} finally { $hold.Dispose() }
$invalidOut=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-invalid-' + [guid]::NewGuid().ToString('N') + '.json')
$invalidResult=Invoke-CapturedIncident @('-CoreReport','\\server\share\core.json','-Incident',$incident,'-Output',$invalidOut,'-Format','Json')
Check ($invalidResult.exit -eq 2 -and $invalidResult.stderr -eq 'INCIDENT_PATH_INVALID' -and -not [IO.File]::Exists($invalidOut)) 'Invalid core path was not usage/path error.'
$real=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-real-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($real) | Out-Null
$realFile=Join-Path $real 'synthetic.txt'
[IO.File]::WriteAllText($realFile,'synthetic only')
$alias=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-alias-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Junction -Path $alias -Target $real -ErrorAction Stop | Out-Null
$aliasCore=Join-Path $root 'core-alias.json'
[IO.File]::WriteAllText($aliasCore,(Invoke-BoundaryLens -Workspace $alias -FailedPath (Join-Path $alias 'synthetic.txt') -Format Json))
$aliasSafeOutput=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-alias-outside-' + [guid]::NewGuid().ToString('N') + '.json')
@(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $aliasCore -Incident $incident -Output $aliasSafeOutput -Format Json 2>$null) | Out-Null
Check ($LASTEXITCODE -eq 1 -and [IO.File]::Exists($aliasSafeOutput)) 'Physical alias check blocked an outside incomplete handoff.'
$aliasReport=Join-Path $real 'cli-alias-output.json'
$aliasResult=Invoke-CapturedIncident @('-CoreReport',$aliasCore,'-Incident',$incident,'-Output',$aliasReport,'-Format','Json')
Check ($aliasResult.exit -eq 2 -and $aliasResult.stderr -eq 'INCIDENT_OUTPUT_INVALID' -and -not [IO.File]::Exists($aliasReport)) 'Physical investigated junction target accepted as output.'
$missingCore=Join-Path $root 'core-missing.json'
[IO.File]::WriteAllText($missingCore,(Invoke-BoundaryLens -Workspace $root -FailedPath (Join-Path $root 'missing.txt') -Format Json))
$missingSafeOutput=Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-missing-outside-' + [guid]::NewGuid().ToString('N') + '.json')
@(& pwsh -NoProfile -NonInteractive -File $script -CoreReport $missingCore -Incident $incident -Output $missingSafeOutput -Format Json 2>$null) | Out-Null
Check ($LASTEXITCODE -eq 1 -and [IO.File]::Exists($missingSafeOutput)) 'Verified missing failed target blocked an outside incomplete handoff.'
Write-Output "incident-interface assertions=$checks"
