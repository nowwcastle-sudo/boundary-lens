#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$PowerShellPath = 'pwsh',
    [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/BoundaryLens.ps1'),
    # The harness budget accommodates observed host variance; a longer-budget pass does not identify its cause.
    # This is a harness limit only; the product has no matching sleep/retry behavior.
    [ValidateRange(1, 600)][int]$ChildTimeoutSeconds = 60,
    [switch]$RelativeOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$fixturePath = Join-Path $PSScriptRoot 'fixtures/logical-final-mismatch.json'
$trialName = 'boundary-lens-ux-' + [guid]::NewGuid().ToString('N')
$trialRoot = Join-Path ([IO.Path]::GetTempPath()) $trialName
New-Item -ItemType Directory -Path $trialRoot -ErrorAction Stop | Out-Null
$script:processCount = 0

function Stop-Ux {
    param([string]$Message)
    [Console]::Error.WriteLine("RED: $Message; retained_trial=$trialName")
    exit 1
}

function Assert-Ux {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { Stop-Ux $Message }
}

function Invoke-CapturedBoundaryProcess {
    param(
        [string]$Label,
        [string[]]$ArgumentTokens,
        [string[]]$EntryTokens = @('-File', ([IO.Path]::GetFullPath($ScriptPath)))
    )
    $started = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $PowerShellPath
    $info.WorkingDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($ScriptPath))
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Environment['POWERSHELL_TELEMETRY_OPTOUT'] = '1'
    $info.Environment['POWERSHELL_UPDATECHECK'] = 'Off'
    foreach ($token in @('-NoProfile', '-NonInteractive') + $EntryTokens + $ArgumentTokens) { $info.ArgumentList.Add($token) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Test process did not start.' }
        $afterStartUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $childPid = $process.Id
        $childStartTimeUtc = $null
        $childStartTimeErrorType = $null
        try { $childStartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o') }
        catch { $childStartTimeErrorType = $_.Exception.GetType().FullName }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $exited = $process.WaitForExit($ChildTimeoutSeconds * 1000)
        $nativeExit = $null
        $timeoutOsObservation = $null
        $preKillHasExited = $null
        $preKillObservationErrorType = $null
        $postKillWaitFinished = $null
        if ($exited) { $nativeExit = $process.ExitCode }
        else {
            $timeoutOsObservation = [pscustomobject]@{ at=[DateTimeOffset]::UtcNow.ToString('o'); status='unknown'; identity_match=$null; has_exited=$null; reason='initial-start-time-unavailable'; exception_type=$null }
            if ($null -ne $childStartTimeUtc) {
                $freshProcess = $null
                try {
                    $freshProcess = [Diagnostics.Process]::GetProcessById($childPid)
                    if ($freshProcess.StartTime.ToUniversalTime().ToString('o') -ceq $childStartTimeUtc) {
                        $freshHasExited = $freshProcess.HasExited
                        $timeoutOsObservation.status = 'observed'
                        $timeoutOsObservation.identity_match = $true
                        $timeoutOsObservation.has_exited = $freshHasExited
                        $timeoutOsObservation.reason = 'same-pid-and-start-time'
                    } else { $timeoutOsObservation.reason = 'identity-mismatch' }
                }
                catch {
                    $timeoutOsObservation.reason = 'unavailable'
                    $timeoutOsObservation.exception_type = $_.Exception.GetType().FullName
                }
                finally { if ($null -ne $freshProcess) { $freshProcess.Dispose() } }
            }
            try { $preKillHasExited = $process.HasExited }
            catch { $preKillObservationErrorType = $_.Exception.GetType().FullName }
            $process.Kill($true)
            $postKillWaitFinished = $process.WaitForExit(5000)
        }
        $streamWaitExceptionType = $null
        try { $streamsCompleted = [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 5000) }
        catch { $streamsCompleted = $false; $streamWaitExceptionType = $_.Exception.GetType().FullName }
        $timer.Stop()
        $stdout = if ($stdoutTask.Status -eq 'RanToCompletion') { $stdoutTask.GetAwaiter().GetResult() } else { $null }
        $stderr = if ($stderrTask.Status -eq 'RanToCompletion') { $stderrTask.GetAwaiter().GetResult() } else { $null }
        $result = [pscustomobject][ordered]@{
            label = $Label
            start_utc = $started.ToString('o')
            after_start_utc = $afterStartUtc
            child_pid = $childPid
            child_start_time_utc = $childStartTimeUtc
            child_start_time_error_type = $childStartTimeErrorType
            end_utc = [DateTimeOffset]::UtcNow.ToString('o')
            duration_ms = $timer.ElapsedMilliseconds
            timeout_seconds = $ChildTimeoutSeconds
            timed_out = -not $exited
            timeout_os_observation = $timeoutOsObservation
            pre_kill_has_exited = $preKillHasExited
            pre_kill_observation_error_type = $preKillObservationErrorType
            post_kill_wait_finished = $postKillWaitFinished
            streams_completed = $streamsCompleted
            stream_wait_exception_type = $streamWaitExceptionType
            stdout_task_status = [string]$stdoutTask.Status
            stderr_task_status = [string]$stderrTask.Status
            stdout_task_error_types = @(if ($null -ne $stdoutTask.Exception) { $stdoutTask.Exception.Flatten().InnerExceptions | ForEach-Object { $_.GetType().FullName } })
            stderr_task_error_types = @(if ($null -ne $stderrTask.Exception) { $stderrTask.Exception.Flatten().InnerExceptions | ForEach-Object { $_.GetType().FullName } })
            native_exit = $nativeExit
            stdout = $stdout
            stderr = $stderr
        }
        $script:processCount++
        $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $trialRoot ($Label + '.json')) -Encoding utf8
        Assert-Ux -Condition $exited -Message "child timeout: $Label (not a product exit)"
        Assert-Ux -Condition ($null -ne $stdout -and $null -ne $stderr) -Message "child stream capture incomplete: $Label"
        return $result
    } finally { $process.Dispose() }
}

function Get-FixtureState {
    $item = Get-Item -LiteralPath $fixturePath -Force
    $item.Refresh()
    return [pscustomobject]@{
        hash = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash
        length = $item.Length
        write_time = $item.LastWriteTimeUtc
        attributes = $item.Attributes
        sddl = (Get-Acl -LiteralPath $fixturePath).Sddl
    }
}

function Invoke-RelativeTextCheck {
    $relativeText = Invoke-CapturedBoundaryProcess -Label 'relative-existing-text' -EntryTokens @('-File', '.\BoundaryLens.ps1') -ArgumentTokens @('-Workspace', $repoRoot, '-FailedPath', $fixturePath, '-Format', 'Text')
    Assert-Ux ($relativeText.native_exit -eq 0 -and $relativeText.stderr -eq '') 'relative File entry process status'
    Assert-Ux ($relativeText.stdout -match '^Observations: 4/4 records observed; 0 collection failures; 0 records unobserved\.' -and $relativeText.stdout -match 'RUNTIME_ENFORCEMENT_UNKNOWN') 'relative File entry observation/runtime contract'
    return $relativeText
}

$invalidCases = @(
    @{ label = 'no-arguments'; tokens = @() },
    @{ label = 'missing-value'; tokens = @('-Workspace') },
    @{ label = 'unknown-option'; tokens = @('-Unexpected', 'synthetic') },
    @{ label = 'positional'; tokens = @('C:\synthetic', 'C:\synthetic\file') },
    @{ label = 'duplicate'; tokens = @('-Workspace', 'C:\synthetic', '-Workspace', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'abbreviation'; tokens = @('-W', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'colon-option'; tokens = @('-Workspace:C:\synthetic', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'invalid-format'; tokens = @('-Workspace', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file', '-Format', 'Xml') },
    @{ label = 'blank-format'; tokens = @('-Workspace', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file', '-Format', '') },
    @{ label = 'blank-workspace'; tokens = @('-Workspace', '', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'whitespace-workspace'; tokens = @('-Workspace', '  ', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'blank-failed-path'; tokens = @('-Workspace', 'C:\synthetic', '-FailedPath', '') },
    @{ label = 'whitespace-failed-path'; tokens = @('-Workspace', 'C:\synthetic', '-FailedPath', '  ') },
    @{ label = 'relative'; tokens = @('-Workspace', 'relative', '-FailedPath', 'C:\synthetic\file') },
    @{ label = 'provider'; tokens = @('-Workspace', 'FileSystem::C:\synthetic', '-FailedPath', 'C:\synthetic\file') }
)

try {
    if ($RelativeOnly) {
        $before = Get-FixtureState
        $absoluteText = Invoke-CapturedBoundaryProcess -Label 'existing-text' -ArgumentTokens @('-Workspace', $repoRoot, '-FailedPath', $fixturePath, '-Format', 'Text')
        Assert-Ux ($absoluteText.native_exit -eq 0 -and $absoluteText.stderr -eq '') 'absolute Text process status'
        $relativeText = Invoke-RelativeTextCheck
        Assert-Ux ($relativeText.stdout -ceq $absoluteText.stdout) 'relative and absolute Text differ'
        $after = Get-FixtureState
        foreach ($property in @('hash', 'length', 'write_time', 'attributes', 'sddl')) { Assert-Ux ($before.$property -eq $after.$property) "named synthetic fixture changed: $property" }
        [Console]::Out.WriteLine("GREEN: relative-entry delta only; $script:processCount bounded absolute/relative Text processes and named-fixture preservation; retained_trial=$trialName")
        exit 0
    }
    foreach ($case in $invalidCases) {
        $captured = Invoke-CapturedBoundaryProcess -Label $case.label -ArgumentTokens $case.tokens
        Assert-Ux ($captured.native_exit -eq 2 -and $captured.stdout -eq '' -and $captured.stderr.Trim() -ceq 'BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2') "fixed input error contract: $($case.label)"
    }
    $remote = Invoke-CapturedBoundaryProcess -Label 'remote-uri' -ArgumentTokens @('-Workspace', 'ssh://synthetic.invalid/work', '-FailedPath', 'C:\synthetic\file')
    Assert-Ux ($remote.native_exit -eq 2 -and $remote.stdout -eq '' -and $remote.stderr.Trim() -ceq 'BOUNDARY_ERROR code=BOUNDARY_REMOTE_UNSUPPORTED exit=2') 'fixed remote error contract'

    foreach ($fileOption in @('-f', '-fi', '-fil', '-FiLe')) {
        $aliasCase = Invoke-CapturedBoundaryProcess -Label ('host-file' + $fileOption.ToLowerInvariant()) -EntryTokens @($fileOption, ([IO.Path]::GetFullPath($ScriptPath))) -ArgumentTokens @('-Workspace:C:\synthetic', '-FailedPath', 'C:\synthetic\file')
        Assert-Ux ($aliasCase.native_exit -eq 2 -and $aliasCase.stdout -eq '' -and $aliasCase.stderr.Trim() -ceq 'BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2') "native File option preserves invalid colon input: $fileOption"
    }
    $wrapperPath = Join-Path $trialRoot 'synthetic-wrapper.ps1'
    Set-Content -LiteralPath $wrapperPath -Encoding utf8 -Value '& $args[0] -Workspace relative -FailedPath C:\synthetic\file; exit $LASTEXITCODE'
    $wrapper = Invoke-CapturedBoundaryProcess -Label 'other-file-wrapper' -EntryTokens @('-File', $wrapperPath) -ArgumentTokens @(([IO.Path]::GetFullPath($ScriptPath)), '-File', ([IO.Path]::GetFullPath($ScriptPath)), '-Workspace', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file')
    Assert-Ux ($wrapper.native_exit -eq 2 -and $wrapper.stdout -eq '' -and $wrapper.stderr.Trim() -ceq 'BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2') 'wrapper invocation must not consume parent argv tail'
    $escapedScriptPath = ([IO.Path]::GetFullPath($ScriptPath)).Replace("'", "''")
    $command = Invoke-CapturedBoundaryProcess -Label 'command-caller' -EntryTokens @('-Command', "& '$escapedScriptPath' -Workspace relative -FailedPath C:\synthetic\file; exit `$LASTEXITCODE") -ArgumentTokens @()
    Assert-Ux ($command.native_exit -eq 2 -and $command.stdout -eq '' -and $command.stderr.Trim() -ceq 'BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2') 'Command invocation must preserve caller arguments'

    $before = Get-FixtureState
    $normalArguments = @('-WORKSPACE', $repoRoot, '-failedpath', $fixturePath)
    $json = Invoke-CapturedBoundaryProcess -Label 'existing-json' -ArgumentTokens ($normalArguments + @('-Format', 'jSoN'))
    Assert-Ux ($json.native_exit -eq 0 -and $json.stderr -eq '') 'JSON process status'
    $report = $json.stdout | ConvertFrom-Json
    Assert-Ux ($report.schema_version -eq 1 -and @($report.results | Where-Object code -eq 'RUNTIME_ENFORCEMENT_UNKNOWN').Count -eq 1) 'JSON schema/runtime UNKNOWN'
    $text = Invoke-CapturedBoundaryProcess -Label 'existing-text' -ArgumentTokens $normalArguments
    Assert-Ux ($text.native_exit -eq 0 -and $text.stderr -eq '') 'Text process status'
    Assert-Ux ($text.stdout -match '^Observations: 4/4 records observed; 0 collection failures; 0 records unobserved\.') 'neutral observation summary'
    Assert-Ux ($text.stdout -match 'RUNTIME_ENFORCEMENT_UNKNOWN') 'Text runtime UNKNOWN'
    $relativeText = Invoke-RelativeTextCheck
    Assert-Ux ($relativeText.stdout -ceq $text.stdout) 'relative and absolute Text differ'
    $missing = Invoke-CapturedBoundaryProcess -Label 'missing-json' -ArgumentTokens @('-Workspace', $repoRoot, '-FailedPath', "$fixturePath.synthetic-missing", '-Format', 'Json')
    Assert-Ux ($missing.native_exit -eq 0 -and $missing.stderr -eq '') 'expected missing-target report exit'
    $missingReport = $missing.stdout | ConvertFrom-Json
    foreach ($code in @('TARGET_NOT_OBSERVED', 'FINAL_PATH_UNKNOWN', 'FINAL_CONTAINMENT_UNKNOWN', 'RUNTIME_ENFORCEMENT_UNKNOWN')) {
        Assert-Ux (@($missingReport.results | Where-Object { $_.status -eq 'unknown' -and $_.code -eq $code }).Count -eq 1) "missing-target UNKNOWN: $code"
    }
    Assert-Ux (-not (Test-Path -LiteralPath "$fixturePath.synthetic-missing")) 'missing target was created'
    $after = Get-FixtureState
    foreach ($property in @('hash', 'length', 'write_time', 'attributes', 'sddl')) { Assert-Ux ($before.$property -eq $after.$property) "named synthetic fixture changed: $property" }

    $loadOutput = @(. $ScriptPath)
    Assert-Ux ($loadOutput.Count -eq 0) 'dot-source emitted output'
    $help = Get-Help Invoke-BoundaryLens -Full
    Assert-Ux (@($help.examples.example).Count -ge 2) 'public help examples missing'
    foreach ($name in @('Workspace', 'FailedPath', 'Format')) {
        $parameter = @($help.parameters.parameter | Where-Object name -eq $name)
        Assert-Ux ($parameter.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace(($parameter[0].description.Text -join ' '))) "public help description: $name"
    }
    Assert-Ux ((Get-BoundaryIdentityFingerprint -Identity 'abc') -ceq 'ba7816bf8f01') 'fingerprint known vector'
    Assert-Ux ((Get-BoundaryIdentityFingerprint -Identity '') -ceq 'e3b0c44298fc') 'fingerprint empty vector'
    $unicodeAlgorithm = [Security.Cryptography.SHA256]::Create()
    try { $unicodeExpected = [BitConverter]::ToString($unicodeAlgorithm.ComputeHash([byte[]]@(0xC3, 0xA9))).Replace('-', '').Substring(0, 12).ToLowerInvariant() }
    finally { $unicodeAlgorithm.Dispose() }
    Assert-Ux ((Get-BoundaryIdentityFingerprint -Identity ([string][char]0x00E9)) -ceq $unicodeExpected) 'fingerprint explicit Unicode UTF-8 bytes'
    $unobservedReport = [pscustomobject]@{
        evidence = [pscustomobject]@{
            workspace_path = [pscustomobject]@{ status = 'collection-failure'; final_path = $null }
            failed_path = [pscustomobject]@{ status = 'unknown'; final_path = $null }
            workspace_acl = [pscustomobject]@{ status = 'collection-failure'; owner_fingerprint = $null }
            failed_path_acl = [pscustomobject]@{ status = 'unknown'; owner_fingerprint = $null }
        }
        results = @()
    }
    Assert-Ux ((Format-BoundaryReport -Report $unobservedReport -Format Text) -ceq 'Observations: 0/4 records observed; 2 collection failures; 2 records unobserved.') 'neutral summary preserves unavailable and null evidence'
    $originalFunction = ${function:Invoke-BoundaryLens}
    try {
        function Invoke-BoundaryLens { throw 'SYNTHETIC_PRIVATE_MARKER C:\synthetic\hidden.txt' }
        $internal = Invoke-BoundaryProcess -Arguments @('-Workspace', 'C:\synthetic', '-FailedPath', 'C:\synthetic\file')
        Assert-Ux ($internal.exit_code -eq 3 -and $internal.error_code -ceq 'BOUNDARY_INTERNAL_ERROR' -and $null -eq $internal.output) 'internal failure outcome'
        Assert-Ux (($internal | ConvertTo-Json) -notmatch 'SYNTHETIC_PRIVATE_MARKER') 'internal exception detail leaked'
    } finally { ${function:Invoke-BoundaryLens} = $originalFunction }
    Assert-Ux ($text.stdout -notmatch '(?i)(?<![A-Za-z0-9_])SAFE(?![A-Za-z0-9_])|sandbox guaranteed|permissions fully normal|problem free') 'forbidden Text verdict'
    [Console]::Out.WriteLine("GREEN: $script:processCount bounded process cases, fixed private errors, help, observations, fingerprints and named-fixture preservation; retained_trial=$trialName")
    exit 0
}
catch {
    [Console]::Error.WriteLine("RED: operational UX harness did not complete; retained_trial=$trialName")
    [pscustomobject]@{ exception_type=$_.Exception.GetType().FullName; category=[string]$_.CategoryInfo.Category; hresult=$_.Exception.HResult; script_line=$_.InvocationInfo.ScriptLineNumber } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $trialRoot 'harness-failure.json') -Encoding utf8
    exit 2
}
