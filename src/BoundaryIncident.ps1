#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Stop-Incident([string]$Code,[int]$ExitCode) {
    [Console]::Error.WriteLine($Code)
    exit $ExitCode
}

$options=@{}
$logs=[Collections.Generic.List[string]]::new()
if ($args.Count -eq 0 -or ($args.Count % 2) -ne 0) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }
for ($i=0;$i -lt $args.Count;$i+=2) {
    $flag=$args[$i]
    $value=$args[$i+1]
    if ($flag -isnot [string] -or $value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('-')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }
    switch -CaseSensitive ($flag.ToLowerInvariant()) {
        '-corereport' { if ($options.ContainsKey('core')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }; $options['core']=$value }
        '-incident' { if ($options.ContainsKey('incident')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }; $options['incident']=$value }
        '-logpath' { $logs.Add($value) }
        '-output' { if ($options.ContainsKey('output')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }; $options['output']=$value }
        '-format' { if ($options.ContainsKey('format')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }; $options['format']=$value }
        default { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }
    }
}
foreach ($key in @('core','incident','output','format')) { if (-not $options.ContainsKey($key)) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 } }
if ($options.format -cnotin @('Json','Html')) { Stop-Incident 'INCIDENT_USAGE_INVALID' 2 }

try {
    Import-Module (Join-Path $PSScriptRoot 'IncidentInput.psm1') -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot 'IncidentObservations.psm1') -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot 'IncidentHandoff.psm1') -ErrorAction Stop
    $core=Read-IncidentCoreReport -LiteralPath $options.core
    $context=Read-IncidentContext -LiteralPath $options.incident
    $records=@(Read-IncidentLogs -LiteralPath $logs.ToArray())
    $observations=@(Get-IncidentObservations -Context $context -CoreReport $core -Logs $records)
    $handoff=New-IncidentHandoff -CoreReport $core -Context $context -Observations $observations
    $payload=if ($options.format -ceq 'Html') { ConvertTo-IncidentHtml -Handoff $handoff } else { $handoff | ConvertTo-Json -Depth 32 -Compress }
    $inputPaths=@($options.core,$options.incident)+$logs.ToArray()
    $boundaries=[Collections.Generic.List[string]]::new()
    $boundaries.Add($core.incident.workspace_input)
    $boundaries.Add($core.incident.failed_path_input)
    foreach ($key in @('workspace_path','failed_path')) {
        $savedFinal=$core.evidence[$key].final_path
        if ($null -ne $savedFinal) { $boundaries.Add($savedFinal) }
    }
    Write-IncidentHandoff -LiteralPath $options.output -Payload $payload -InputPaths $inputPaths -InvestigatedPaths $boundaries.ToArray()
    if ($handoff.handoff_summary.status -eq 'incomplete') { Stop-Incident 'INCIDENT_HANDOFF_INCOMPLETE' 1 }
    exit 0
}
catch {
    $code=$_.Exception.Message
    if ($code -in @('INCIDENT_JSON_INVALID','INCIDENT_SCHEMA_INVALID','INCIDENT_PATH_INVALID','INCIDENT_FILE_INVALID','INCIDENT_LOG_INVALID','INCIDENT_OUTPUT_INVALID')) { Stop-Incident $code 2 }
    if ($code -eq 'INCIDENT_FILE_IO_FAILED') { Stop-Incident $code 1 }
    Stop-Incident 'INCIDENT_EXPORT_FAILED' 1
}
