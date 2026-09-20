#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$checks = 0
function Check([bool]$Condition, [string]$Message) { $script:checks++; if (-not $Condition) { throw $Message } }

Import-Module "$PSScriptRoot/../src/IncidentHandoff.psm1" -Force
. "$PSScriptRoot/../src/BoundaryLens.ps1"
$root = Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$file = Join-Path $root 'synthetic.txt'
[IO.File]::WriteAllText($file, 'synthetic incident test only')
$inputHash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$core = Invoke-BoundaryLens -Workspace $root -FailedPath $file -Format Json | ConvertFrom-Json -AsHashtable
$sensitive = @(('C:\' + 'Users\secret-sentinel\private'), ('S-' + '1-5-21-12345-67890'), 'host-secret-sentinel', 'token-secret-sentinel', '<script>secret-sentinel</script>')
$core['results'][0]['message'] = $sensitive -join ' '
$core['results'][0]['next_observation'] = $sensitive -join ' '
$core['evidence']['workspace_path']['raw_input'] = $sensitive[0]
$core['evidence']['failed_path_acl']['raw_input'] = $sensitive[0]
$context = @{schema='boundary-incident/1';product=$sensitive[4];version=$sensitive[2];error_code=$sensitive[3];occurred_at='2026-09-20T00:00:00Z'; supplied_observations=@(@{kind='filter';value=$sensitive[1];observed_at=$null})}
$observations = @(@{kind='process';provenance='local-query';status='observed';value=@{process_id=123;name=$sensitive[2];start_time='2026-09-20T00:00:00Z';incident_identity_unconfirmed=$true};observed_at='2026-09-20T00:00:00Z';error_code=$null},@{kind='log';provenance='operator-supplied';status='supplied';value=@{component=$sensitive[3];error_code=$sensitive[4];occurred_at='2026-09-20T00:00:00Z'};observed_at=$null;error_code=$null},@{kind='filter';provenance='operator-supplied';status='supplied';value=$sensitive[1];observed_at=$null;error_code=$null})
$handoff = New-IncidentHandoff -CoreReport $core -Context $context -Observations $observations
$json = $handoff | ConvertTo-Json -Depth 32
$html = ConvertTo-IncidentHtml -Handoff $handoff
Check (@($handoff.Keys).Count -eq 4) 'Unexpected export envelope.'
Check (-not $json.Contains('core_report')) 'Raw core was exported.'
Check ($json.Contains('RUNTIME_ENFORCEMENT_UNKNOWN')) 'Runtime unknown was lost.'
foreach ($secret in $sensitive) { Check (-not $json.Contains($secret)) 'Sensitive JSON string leaked.'; Check (-not $html.Contains($secret)) 'Sensitive HTML string leaked.' }
Check ($html -notmatch '<script|<iframe|<img|<link|<form') 'Active or remote HTML resource.'
Check (($html -split '<table').Count -ge 4) 'HTML lacks separate readable tables.'
$poisoned=$handoff.Clone()
$poisoned['observations']=@(@{kind='log';provenance='operator-supplied';status='supplied';value='<script>alert(1)</script>';error_code=$null})
$encodedHtml=ConvertTo-IncidentHtml -Handoff $poisoned
Check ($encodedHtml.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') -and -not $encodedHtml.Contains('<script>alert(1)</script>')) 'HTML observation cell was not encoded.'
Check ($handoff.incident_context.product -eq 'product-1') 'Product was not aliased.'
Check ($handoff.observations[0].value.label -eq 'selected-process') 'Process identity leaked.'
Check ($html.Contains('operator-supplied')) 'Supplied provenance missing in HTML.'
Check ($handoff.handoff_summary.runtime_enforcement -eq 'RUNTIME_ENFORCEMENT_UNKNOWN') 'Unknown summary lost.'

$output = Join-Path ([IO.Path]::GetTempPath()) ('boundary-handoff-' + [guid]::NewGuid().ToString('N') + '.json')
Write-IncidentHandoff -LiteralPath $output -Payload $json -InputPaths @($file) -InvestigatedPaths @($root)
Check ([IO.File]::ReadAllText($output).Contains('RUNTIME_ENFORCEMENT_UNKNOWN')) 'New handoff not written.'
try { Write-IncidentHandoff -LiteralPath $output -Payload 'bad' -InputPaths @($file) -InvestigatedPaths @($root); throw 'Collision accepted.' } catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID') 'Collision error not fixed.' }
try { Write-IncidentHandoff -LiteralPath (Join-Path $root 'report.json') -Payload 'bad' -InputPaths @($file) -InvestigatedPaths @($root); throw 'Investigated descendant accepted.' } catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID') 'Investigated descendant error not fixed.' }
try { Write-IncidentHandoff -LiteralPath $file -Payload 'bad' -InputPaths @($file) -InvestigatedPaths @($root); throw 'Input alias accepted.' } catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID') 'Input alias error not fixed.' }
Check ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -eq $inputHash) 'Original input bytes changed.'
Check ([IO.File]::ReadAllText($output) -eq $json) 'Existing output changed after collision.'
$hard=Join-Path ([IO.Path]::GetTempPath()) ('boundary-hardlink-' + [guid]::NewGuid().ToString('N') + '.json')
New-Item -ItemType HardLink -Path $hard -Value $output -ErrorAction Stop | Out-Null
try { Write-IncidentHandoff -LiteralPath $hard -Payload 'bad' -InputPaths @($file) -InvestigatedPaths @($root); throw 'Hardlink accepted.' } catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID') 'Hardlink error not fixed.' }
$junction=Join-Path ([IO.Path]::GetTempPath()) ('boundary-output-junction-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Junction -Path $junction -Target ([IO.Path]::GetTempPath()) -ErrorAction Stop | Out-Null
try { Write-IncidentHandoff -LiteralPath (Join-Path $junction 'report.json') -Payload 'bad' -InputPaths @($file) -InvestigatedPaths @($root); throw 'Parent junction accepted.' } catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID') 'Parent junction error not fixed.' }
$sibling=$root+'-sibling'
[IO.Directory]::CreateDirectory($sibling) | Out-Null
$siblingOut=Join-Path $sibling 'report.json'
Write-IncidentHandoff -LiteralPath $siblingOut -Payload 'sibling-safe' -InputPaths @($file) -InvestigatedPaths @($root)
Check ([IO.File]::ReadAllText($siblingOut) -eq 'sibling-safe') 'Component-boundary sibling rejected.'
$unknownCore=$core.Clone()
$unknownCore['results']=@(@{status='unknown';code='RUNTIME_ENFORCEMENT_UNKNOWN';message='private';evidence_refs=@();next_observation='private'})
$unknownCore['evidence']=$core.evidence.Clone()
$unknownCore['evidence']['workspace_path']=$core.evidence.workspace_path.Clone()
$unknownCore['evidence']['workspace_path']['status']='unknown'
$unknownCore['evidence']['workspace_path']['failure']=$null
$unknown=New-IncidentHandoff -CoreReport $unknownCore -Context @{schema='boundary-incident/1'} -Observations @()
Check ($unknown.core_summary.evidence[0].status -eq 'unknown') 'Missing core observation became observed.'
$forged=New-IncidentHandoff -CoreReport $core -Context @{schema='boundary-incident/1'} -Observations @(@{kind='filter';provenance='operator-supplied';status='observed';value='SAFE';observed_at=$null;error_code=$null})
Check ($forged.observations[0].status -eq 'supplied' -and $forged.observations[0].provenance -eq 'operator-supplied') 'Forged supplied observation became measured.'
$privateScheme=New-IncidentHandoff -CoreReport $core -Context @{schema='boundary-incident/1'} -Observations @(@{kind='runtime-uri';provenance='operator-supplied';status='supplied';value=@{scheme='secretmarker';representation='remote';relationship='unknown'};observed_at=$null;error_code=$null})
Check ($privateScheme.observations[0].value.scheme -eq 'other' -and -not (($privateScheme | ConvertTo-Json -Depth 32).Contains('secretmarker'))) 'User-controlled URI scheme escaped the public allowlist.'
$failureOutput=Join-Path ([IO.Path]::GetTempPath()) ('boundary-handoff-partial-' + [guid]::NewGuid().ToString('N') + '.json')
$module=Get-Module IncidentHandoff
& $module {
    function script:Write-HandoffBytes([IO.FileStream]$Stream,[byte[]]$Bytes) {
        $Stream.Write([byte[]]@(65),0,1)
        throw [IO.IOException]::new('synthetic write failure')
    }
}
try { Write-IncidentHandoff -LiteralPath $failureOutput -Payload $json -InputPaths @($file) -InvestigatedPaths @($root); throw 'Injected write failure was ignored.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_FAILED') 'Post-open write failure lacked fixed error.' }
Check ([IO.File]::Exists($failureOutput) -and [IO.File]::ReadAllText($failureOutput) -eq 'A') 'Failed partial artifact was not retained.'
$unknownWorkspace=Join-Path ([IO.Path]::GetTempPath()) ('boundary-unverified-workspace-' + [guid]::NewGuid().ToString('N'))
$unknownOutput=Join-Path ([IO.Path]::GetTempPath()) ('boundary-unverified-output-' + [guid]::NewGuid().ToString('N') + '.json')
try { Write-IncidentHandoff -LiteralPath $unknownOutput -Payload $json -InputPaths @($file) -InvestigatedPaths @($unknownWorkspace); throw 'Unverified workspace accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID' -and -not [IO.File]::Exists($unknownOutput)) 'Unverified workspace did not fail closed before create.' }
$emptyBoundaryOutput=Join-Path ([IO.Path]::GetTempPath()) ('boundary-empty-boundary-' + [guid]::NewGuid().ToString('N') + '.json')
try { Write-IncidentHandoff -LiteralPath $emptyBoundaryOutput -Payload $json -InputPaths @($file) -InvestigatedPaths @(); throw 'Empty investigated boundary accepted.' }
catch { Check ($_.Exception.Message -eq 'INCIDENT_OUTPUT_INVALID' -and -not [IO.File]::Exists($emptyBoundaryOutput)) 'Empty boundary did not fail closed before create.' }
Write-Output "incident-handoff assertions=$checks"
