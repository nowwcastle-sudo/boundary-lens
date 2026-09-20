#Requires -Version 7.0

[CmdletBinding()]
param([switch]$StaticOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-ReadOnly {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("RED: $Message")
    exit 1
}

function Assert-ReadOnly {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        Stop-ReadOnly $Message
    }
}

function Get-ObservedState {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject][ordered]@{
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        length = $item.Length
        last_write_time_utc = $item.LastWriteTimeUtc
        attributes = $item.Attributes
        sddl = $acl.Sddl
    }
}

function Assert-StateEqual {
    param(
        [Parameter(Mandatory)][pscustomobject]$Before,
        [Parameter(Mandatory)][pscustomobject]$After,
        [Parameter(Mandatory)][string]$Label
    )

    foreach ($property in @('sha256', 'length', 'last_write_time_utc', 'attributes', 'sddl')) {
        if ($Before.$property -ne $After.$property) {
            Stop-ReadOnly "$Label changed property $property"
        }
    }
}

function Assert-AclRecord {
    param(
        [Parameter(Mandatory)][pscustomobject]$Record,
        [Parameter(Mandatory)][string]$Role
    )

    Assert-ReadOnly -Condition ($Record.probe -eq 'acl') -Message "$Role ACL probe mismatch"
    Assert-ReadOnly -Condition ($Record.status -eq 'observed') -Message "$Role ACL evidence was not observed"
    Assert-ReadOnly -Condition ($Record.role -eq $Role) -Message "$Role ACL role mismatch"
    Assert-ReadOnly -Condition ($Record.protected -is [bool]) -Message "$Role ACL protection state missing"
    Assert-ReadOnly -Condition ($Record.owner_fingerprint -match '^[0-9a-fA-F]{12}$') -Message "$Role ACL owner fingerprint is not 12 hex characters"
    Assert-ReadOnly -Condition ($null -eq $Record.failure) -Message "$Role ACL observed record contains a failure"
    Assert-ReadOnly -Condition (@($Record.access_rules).Count -gt 0) -Message "$Role ACL access rules are missing"

    foreach ($ace in @($Record.access_rules)) {
        Assert-ReadOnly -Condition ($ace.access_type -in @('allow', 'deny')) -Message "$Role ACL access type is outside allow/deny"
        Assert-ReadOnly -Condition (-not [string]::IsNullOrWhiteSpace([string]$ace.rights)) -Message "$Role ACL rights are missing"
        Assert-ReadOnly -Condition ($ace.inherited -is [bool]) -Message "$Role ACL inherited flag is missing"
        Assert-ReadOnly -Condition ($ace.identity_fingerprint -match '^[0-9a-fA-F]{12}$') -Message "$Role ACL identity fingerprint is not 12 hex characters"
    }
}

function Get-ProofGateViolations {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory)][string[]]$AllowedCommands,
        [Parameter(Mandatory)][string[]]$AllowedStaticMembers,
        [Parameter(Mandatory)][string[]]$AllowedInstanceMembers,
        [string[]]$AllowedMemberAssignments = @()
    )

    $violations = [System.Collections.Generic.List[object]]::new()
    $entryGuard = $null
    $rootStatements = @($Ast.EndBlock.Statements)
    if ($rootStatements.Count -gt 0) {
        $lastStatement = $rootStatements[-1]
        if ($lastStatement -is [System.Management.Automation.Language.IfStatementAst] -and
            $lastStatement.Clauses.Count -eq 1 -and
            $lastStatement.Clauses[0].Item1.Extent.Text -ceq '$MyInvocation.InvocationName -ne ''.''') {
            $entryGuard = $lastStatement
        }
    }
    foreach ($redirectionAst in @($Ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.RedirectionAst]
                }, $true))) {
        $violations.Add($redirectionAst)
    }

    foreach ($commandAst in @($Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true))) {
        $commandName = $commandAst.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($commandName)) {
            $violations.Add($commandAst)
            continue
        }

        if ($commandName.Contains([char]'\') -or $null -ne (Get-Alias -Name $commandName -ErrorAction SilentlyContinue) -or $commandName -notin $AllowedCommands) {
            $violations.Add($commandAst)
        }
    }

    foreach ($memberAst in @($Ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
                }, $true))) {
        if ($memberAst.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $violations.Add($memberAst)
            continue
        }

        $memberName = [string]$memberAst.Member.Value
        if ($memberAst.Static) {
            if ($memberAst.Expression -isnot [System.Management.Automation.Language.TypeExpressionAst]) {
                $violations.Add($memberAst)
                continue
            }
            $memberKey = "$($memberAst.Expression.TypeName.FullName)|$memberName"
            if ($memberKey -eq 'Environment|GetCommandLineArgs') {
                $insideEntry = $null -ne $entryGuard -and $memberAst.Extent.StartOffset -ge $entryGuard.Extent.StartOffset -and $memberAst.Extent.EndOffset -le $entryGuard.Extent.EndOffset
                if (-not $insideEntry -or $memberAst.Extent.Text -cne '[Environment]::GetCommandLineArgs()') {
                    $violations.Add($memberAst)
                    continue
                }
            }
            if ($memberKey -notin $AllowedStaticMembers) {
                $violations.Add($memberAst)
            }
            continue
        }

        $memberKey = "$($memberAst.Expression.Extent.Text)|$memberName"
        if ($memberKey -in @('[Console]::Out|WriteLine', '[Console]::Error|WriteLine')) {
            $insideEntry = $null -ne $entryGuard -and $memberAst.Extent.StartOffset -ge $entryGuard.Extent.StartOffset -and $memberAst.Extent.EndOffset -le $entryGuard.Extent.EndOffset
            $expectedConsole = if ($memberKey -eq '[Console]::Out|WriteLine') {
                '[Console]::Out.WriteLine($processOutcome.output)'
            } else {
                '[Console]::Error.WriteLine("BOUNDARY_ERROR code=$($processOutcome.error_code) exit=$($processOutcome.exit_code)")'
            }
            if (-not $insideEntry -or $memberAst.Extent.Text -cne $expectedConsole) {
                $violations.Add($memberAst)
                continue
            }
        }
        if ($memberKey -notin $AllowedInstanceMembers) {
            $violations.Add($memberAst)
        }
    }

    foreach ($assignmentAst in @($Ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst]
                }, $true))) {
        if ($assignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $assignedVariable = $assignmentAst.Left.VariablePath.UserPath
            if ($assignedVariable -match '^(?:(?:global|script|local):)?(?:ErrorView|ErrorActionPreference|PSDefaultParameterValues|PSNativeCommandUseErrorActionPreference)$' -or $assignedVariable -match '^(?:global|env):') {
                $violations.Add($assignmentAst)
            }
        }
        $assignedMembers = @($assignmentAst.Left.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.MemberExpressionAst]
                }, $true))
        $approvedTerminalOutput = $false
        if (
            $assignmentAst.Left.Extent.Text -ceq '$TerminalPath.Value' -and
            $assignmentAst.Right.Extent.Text -in @('$null', '$normalizedTarget')
        ) {
            $owner = $assignmentAst.Parent
            while ($null -ne $owner -and $owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $owner = $owner.Parent
            }
            $approvedTerminalOutput = $null -ne $owner -and $owner.Name -ceq 'Test-BoundaryTargetChain'
        }
        if ($assignedMembers.Count -gt 0 -and $assignmentAst.Left.Extent.Text -notin $AllowedMemberAssignments) {
            $violations.Add($assignmentAst)
        }
    }

    foreach ($unaryAst in @($Ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.UnaryExpressionAst] -and
                    $node.TokenKind -in @(
                        [System.Management.Automation.Language.TokenKind]::PlusPlus,
                        [System.Management.Automation.Language.TokenKind]::MinusMinus,
                        [System.Management.Automation.Language.TokenKind]::PostfixPlusPlus,
                        [System.Management.Automation.Language.TokenKind]::PostfixMinusMinus
                    )
                }, $true))) {
        if ($unaryAst.Child -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $assignedVariable = $unaryAst.Child.VariablePath.UserPath
            if ($assignedVariable -match '^(?:(?:global|script|local):)?(?:ErrorView|ErrorActionPreference|PSDefaultParameterValues|PSNativeCommandUseErrorActionPreference)$' -or $assignedVariable -match '^(?:global|env):') {
                $violations.Add($unaryAst)
            }
        }
        $assignedMembers = @($unaryAst.Child.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.MemberExpressionAst]
                }, $true))
        if ($assignedMembers.Count -gt 0 -and $unaryAst.Child.Extent.Text -notin $AllowedMemberAssignments) {
            $violations.Add($unaryAst)
        }
    }

    foreach ($exitAst in @($Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))) {
        $insideEntry = $null -ne $entryGuard -and $exitAst.Extent.StartOffset -ge $entryGuard.Extent.StartOffset -and $exitAst.Extent.EndOffset -le $entryGuard.Extent.EndOffset
        if (-not $insideEntry -or $exitAst.Extent.Text -cne 'exit $processOutcome.exit_code') { $violations.Add($exitAst) }
    }
    if ($null -ne $entryGuard) {
        foreach ($nestedFunction in @($entryGuard.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
            $violations.Add($nestedFunction)
        }
    }
    return @($violations)
}

function Get-TestAst {
    param([Parameter(Mandatory)][string]$Source)

    $tokens = $null
    $errors = $null
    $parsedAst = [System.Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0) {
        Stop-ReadOnly "AST gate self-test parser errors: $(@($errors).Count)"
    }
    return $parsedAst
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$fixturePath = Join-Path $PSScriptRoot 'fixtures\logical-final-mismatch.json'
$sourcePath = Join-Path $repoRoot 'src\BoundaryLens.ps1'

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Stop-ReadOnly "analyzer entrypoint missing: $sourcePath"
}
if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
    Stop-ReadOnly "fixture missing: $fixturePath"
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    Stop-ReadOnly "product parser errors: $(@($parseErrors).Count)"
}

$allowedCommands = @(
    'Classify-BoundaryEvidence', 'ConvertTo-Json', 'ForEach-Object', 'Format-BoundaryReport',
    'Add-Type', 'Initialize-BoundaryNative', 'ConvertFrom-BoundaryNativeAcl', 'Get-BoundaryObservation', 'Resolve-BoundaryDrivePath', 'Get-BoundaryEvidence',
    'Get-BoundaryIdentityFingerprint', 'Get-PSDrive',
    'Get-BoundaryDriveMetadata',
    'Invoke-BoundaryLens', 'Invoke-BoundaryProcess',
    'New-BoundaryAclUnknownEvidence', 'Test-BoundaryContainment',
    'Test-BoundaryInput', 'Test-BoundaryUncDriveMetadata',
    'Test-BoundaryUncPath', 'Where-Object'
)
$allowedStaticMembers = @(
    'BoundaryLensNative.Session|new',
    'Environment|GetCommandLineArgs',
    'string|Equals',
    'string|IsNullOrEmpty',
    'string|IsNullOrWhiteSpace',
    'System.ArgumentException|new',
    'System.BitConverter|ToString',
    'System.Enum|ToObject',
    'System.Collections.Generic.HashSet[string]|new',
    'System.Collections.Generic.List[object]|new',
    'System.Collections.Generic.List[string]|new',
    'System.InvalidOperationException|new',
    'System.IO.Path|GetFullPath',
    'System.IO.Path|GetPathRoot',
    'System.IO.Path|IsPathFullyQualified',
    'System.Management.Automation.ErrorRecord|new',
    'System.Security.AccessControl.RawSecurityDescriptor|new',
    'System.Security.Cryptography.SHA256|Create'
    'System.Text.RegularExpressions.Regex|IsMatch'
)
$allowedInstanceMembers = @(
    '[Console]::Error|WriteLine',
    '[Console]::Out|WriteLine',
    '[DateTimeOffset]::UtcNow|ToString',
    '[System.BitConverter]::ToString($digest)|Replace',
    '[System.IO.Path]::GetFullPath($value)|TrimEnd',
    '[System.Text.Encoding]::UTF8|GetBytes',
    '$algorithm|ComputeHash',
    '$algorithm|Dispose',
    '$collectionFailures|Add',
    '$capturedDriveMappings|ContainsKey',
    '$current|Substring',
    '$failedObservation.session|Dispose',
    '$hex.Substring(0, 12)|ToLowerInvariant',
    '$hex|Substring',
    '$identityRoot|TrimEnd',
    '$lines|Add',
    '$Mappings|Add',
    '$lexical|Substring',
    '$normalizedCandidate|StartsWith',
    '$normalizedCandidate|TrimEnd',
    '$normalizedRoot|EndsWith',
    '$normalizedRoot|TrimEnd',
    '$observation.session|Dispose',
    '$observation.session|Refresh',
    '$options|ContainsKey',
    '$Path|Substring',
    '$result.status|ToUpperInvariant',
    '$results|Add',
    '$rules|Add',
    '$session|Complete',
    '$session|Dispose',
    '$session|OpenPath',
    '$unknowns|Add',
    '$visited|Add',
    '$workspaceObservation.session|Dispose',
    '$workspaceObservation.session|Reconcile'
)
$allowedMemberAssignments = @(
    '$acl.status', '$acl.failure', '$capturedDriveMappings[$capturedMapping.name]',
    '$observation.topology_code', '$observation.path.final_path',
    '$pathRecord.exists', '$pathRecord.final_path', '$pathRecord.reparse_segments', '$pathRecord.status', '$pathRecord.failure',
    '$pathRecord.observations.existing_segment_count', '$pathRecord.observations.nearest_existing_path', '$pathRecord.observations.reparse_observation_complete',
    '$record.access_rules', '$record.exists', '$record.failure', '$record.final_path',
    '$record.observations.existing_segment_count', '$record.observations.nearest_existing_path',
    '$record.observations.reparse_observation_complete', '$record.owner_fingerprint',
    '$record.protected', '$record.reparse_segments', '$record.status'
)
$commandAsts = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))
$knownAlias = Get-Alias -Name 'ni' -ErrorAction Stop
Assert-ReadOnly -Condition ($knownAlias.Definition -eq 'New-Item') -Message 'AST gate alias self-test prerequisite changed'
$item = [pscustomobject]@{ IsReadOnly = $false }
$gateSelfTests = @(
    [pscustomobject]@{
        label = 'output redirection'
        source = 'Get-Item -LiteralPath test.txt > written.txt'
    },
    [pscustomobject]@{
        label = '.NET file write member'
        source = '[IO.File]::WriteAllText(''written.txt'', ''blocked'')'
    },
    [pscustomobject]@{
        label = 'unlisted external command'
        source = 'cmd.exe /c echo blocked'
    },
    [pscustomobject]@{
        label = 'module-qualified forbidden command'
        source = 'Microsoft.PowerShell.Management\Set-Content -LiteralPath test.txt -Value blocked'
    },
    [pscustomobject]@{
        label = 'known alias resolving to forbidden command'
        source = 'ni -Path test.txt -ItemType File'
    },
    [pscustomobject]@{
        label = 'dynamic unresolved command invocation'
        source = '& $commandName -LiteralPath test.txt'
    },
    [pscustomobject]@{
        label = 'filesystem item property assignment'
        source = '$item.IsReadOnly = $true'
    },
    [pscustomobject]@{
        label = 'terminal output assignment outside its resolver'
        source = '$TerminalPath.Value = $normalizedTarget'
    },
    [pscustomobject]@{
        label = 'terminal output assignment with an unapproved value'
        source = 'function Test-BoundaryTargetChain { $TerminalPath.Value = $untrustedTarget }'
    },
    [pscustomobject]@{
        label = 'suffix reconstruction from provider-returned physical spelling'
        source = '$lexicalPath.Substring($item.FullName.Length).TrimStart([char]''\'')'
    },
    [pscustomobject]@{
        label = 'console output inside a collector'
        source = 'function Probe { [Console]::Out.WriteLine($processOutcome.output) }'
    },
    [pscustomobject]@{
        label = 'exit inside a collector'
        source = 'function Probe { exit $processOutcome.exit_code }'
    },
    [pscustomobject]@{
        label = 'global error view modification'
        source = '$ErrorView = ''NormalView'''
    },
    [pscustomobject]@{
        label = 'global error preference modification'
        source = '$ErrorActionPreference = ''SilentlyContinue'''
    },
    [pscustomobject]@{
        label = 'stdout redirection through Console'
        source = '[Console]::SetOut($writer)'
    },
    [pscustomobject]@{
        label = 'stderr redirection through Console'
        source = '[Console]::SetError($writer)'
    },
    [pscustomobject]@{
        label = 'arbitrary text inside direct guard'
        source = 'if ($MyInvocation.InvocationName -ne ''.'') { [Console]::Out.WriteLine(''arbitrary'') }'
    },
    [pscustomobject]@{
        label = 'global variable assignment'
        source = '$global:BoundaryPreference = ''changed'''
    },
    [pscustomobject]@{
        label = 'error preference increment'
        source = '$ErrorActionPreference++'
    },
    [pscustomobject]@{
        label = 'environment setting assignment'
        source = '$env:BOUNDARY_SYNTHETIC_SETTING = ''changed'''
    },
    [pscustomobject]@{
        label = 'process argv read inside a collector'
        source = 'function Probe { [Environment]::GetCommandLineArgs() }'
    },
    [pscustomobject]@{
        label = 'unapproved environment read'
        source = 'if ($MyInvocation.InvocationName -ne ''.'') { [Environment]::GetEnvironmentVariables() }'
    }
)
$gateSelfTestFailures = [System.Collections.Generic.List[string]]::new()
foreach ($selfTest in $gateSelfTests) {
    $selfTestAst = Get-TestAst -Source $selfTest.source
    $selfTestHits = @(Get-ProofGateViolations -Ast $selfTestAst -AllowedCommands $allowedCommands -AllowedStaticMembers $allowedStaticMembers -AllowedInstanceMembers $allowedInstanceMembers -AllowedMemberAssignments $allowedMemberAssignments)
    if ($selfTestHits.Count -lt 1) {
        $gateSelfTestFailures.Add($selfTest.label)
    }
}
if ($gateSelfTestFailures.Count -gt 0) {
    Stop-ReadOnly "AST gate self-test misses: $($gateSelfTestFailures -join ', ')"
}
Assert-ReadOnly -Condition (-not $item.IsReadOnly) -Message 'AST gate executed the filesystem property-assignment attack snippet'

$testLocalAssignmentAst = Get-TestAst -Source '$proofLocal.status = ''observed'''
$testLocalAssignmentHits = @(Get-ProofGateViolations -Ast $testLocalAssignmentAst -AllowedCommands $allowedCommands -AllowedStaticMembers $allowedStaticMembers -AllowedInstanceMembers $allowedInstanceMembers -AllowedMemberAssignments @('$proofLocal.status'))
if ($testLocalAssignmentHits.Count -ne 0) {
    Stop-ReadOnly 'AST gate rejected its explicitly allowlisted test-local property assignment'
}

$proofGateViolations = @(Get-ProofGateViolations -Ast $ast -AllowedCommands $allowedCommands -AllowedStaticMembers $allowedStaticMembers -AllowedInstanceMembers $allowedInstanceMembers -AllowedMemberAssignments $allowedMemberAssignments)
if ($proofGateViolations.Count -gt 0) {
    Stop-ReadOnly "product AST is outside the strict read-only allowlists at line $($proofGateViolations[0].Extent.StartLineNumber)"
}
Assert-ReadOnly -Condition ($null -eq $ast.ParamBlock) -Message 'product has a top-level parameter binder outside the safe process adapter'
$consoleCalls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Expression.Extent.Text -in @('[Console]::Out', '[Console]::Error') }, $true))
Assert-ReadOnly -Condition ($consoleCalls.Count -eq 2) -Message 'product console output must remain exactly two guarded calls'
$productExits = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
Assert-ReadOnly -Condition ($productExits.Count -eq 1) -Message 'product exit must remain one guarded process exit'


# Review identity gate for the ENTIRE native body; not a proof that arbitrary C# is read-only.
# Any helper edit requires native source review and a deliberate digest update.
$expectedNativeSha256 = 'CB4A818DB885A6021F0EF6A40113B39BCF5DF996089E634234AA90F387EF9182'
$expectedImports = @(
    'advapi32.dll|GetSecurityDescriptorLength', 'advapi32.dll|GetSecurityInfo',
    'kernel32.dll|DeviceIoControl', 'kernel32.dll|GetFileInformationByHandle',
    'kernel32.dll|GetFileInformationByHandleEx', 'kernel32.dll|GetFinalPathNameByHandleW',
    'kernel32.dll|GetVolumeInformationByHandleW', 'kernel32.dll|LocalFree',
    'kernel32.dll|QueryDosDeviceW', 'ntdll.dll|NtCreateFile'
)
function Test-NativeBody([string]$Code) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Code.Replace([string][char]13, '')
        $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    } finally { $sha.Dispose() }
    if ($digest -cne $expectedNativeSha256) { return $false }
    $imports = @([regex]::Matches($Code, '\[DllImport\("([^"]+)"[^\]]+\]\s*static extern \S+\s+(\w+)\(') | ForEach-Object { $_.Groups[1].Value + '|' + $_.Groups[2].Value } | Sort-Object)
    return ($imports -join ',') -ceq (($expectedImports | Sort-Object) -join ',')
}
$nativeCalls = @($commandAsts | Where-Object { $_.GetCommandName() -eq 'Add-Type' })
Assert-ReadOnly ($nativeCalls.Count -eq 1) 'native compilation must be a single reviewed call'
$nativeCall = $nativeCalls[0]
$nativeOwner = $nativeCall.Parent
while ($null -ne $nativeOwner -and $nativeOwner -isnot [Management.Automation.Language.FunctionDefinitionAst]) { $nativeOwner = $nativeOwner.Parent }
Assert-ReadOnly ($null -ne $nativeOwner -and $nativeOwner.Name -ceq 'Initialize-BoundaryNative') 'native compilation escaped its initializer'
$nativeElements = @($nativeCall.CommandElements)
Assert-ReadOnly ($nativeElements.Count -eq 5 -and
    $nativeElements[1].Extent.Text -ceq '-TypeDefinition' -and
    $nativeElements[2] -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $nativeElements[2].StringConstantType -eq 'SingleQuotedHereString' -and
    $nativeElements[3].Extent.Text -ceq '-ErrorAction' -and $nativeElements[4].Extent.Text -ceq 'Stop') 'native compilation allows dynamic source or output assembly writes'
$nativeCode = $nativeElements[2].Value
Assert-ReadOnly (Test-NativeBody $nativeCode) 'embedded native body/imports differ from the reviewed candidate'
$nativeAttacks = @(
    $nativeCode.Replace('OpenExisting = 1', 'OpenExisting = 3'),
    $nativeCode.Replace('ReadAttributes = 0x80', 'ReadAttributes = 0x180'),
    $nativeCode.Replace('GetReparsePoint = 0x900A8', 'GetReparsePoint = 0x900A4'),
    $nativeCode.Replace('GetSecurityInfo(', 'SetSecurityInfo('),
    ($nativeCode + [Environment]::NewLine + 'class WriteAttack { void Run() { System.IO.File.WriteAllText("attack", "blocked"); } }')
)
foreach ($attack in $nativeAttacks) { Assert-ReadOnly (-not (Test-NativeBody $attack)) 'native review gate accepted a write/create/access/import mutation' }
Assert-ReadOnly (@($commandAsts | Where-Object { $_.GetCommandName() -in @('Get-Acl','Get-Item','Resolve-Path') }).Count -eq 0) 'name-based probe remains in native product'

if ($StaticOnly) {
    [Console]::Out.WriteLine("GREEN: source parser, exact allowlists, guarded console/exit and $($gateSelfTests.Count) PowerShell + $($nativeAttacks.Count) native proof attacks; dynamic fixture checks not run")
    exit 0
}

$before = Get-ObservedState -Path $fixturePath
. $sourcePath

try {
    $json = Invoke-BoundaryLens -Workspace $repoRoot -FailedPath $fixturePath -Format Json
    $report = $json | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Stop-ReadOnly "public invocation failed: $($_.FullyQualifiedErrorId)"
}

$after = Get-ObservedState -Path $fixturePath
Assert-StateEqual -Before $before -After $after -Label 'fixture'

Assert-ReadOnly -Condition ($null -ne $report.evidence.workspace_acl) -Message 'workspace ACL evidence missing'
Assert-ReadOnly -Condition ($null -ne $report.evidence.failed_path_acl) -Message 'failed-path ACL evidence missing'
Assert-AclRecord -Record $report.evidence.workspace_acl -Role 'workspace'
Assert-AclRecord -Record $report.evidence.failed_path_acl -Role 'failed-path'

$getAclCommands = @($commandAsts | Where-Object { $_.GetCommandName() -eq 'Get-Acl' })
Assert-ReadOnly -Condition ($getAclCommands.Count -eq 0) -Message "product must not reopen ACLs by name; observed $($getAclCommands.Count)"

Assert-ReadOnly -Condition ($json -notmatch 'S-1-') -Message 'public JSON exposed a raw SID'
Assert-ReadOnly -Condition ($json -notmatch 'ACL_NOT_COLLECTED') -Message 'public JSON retained the ACL placeholder'
$fixedStatuses = @('cause-candidate', 'collection-failure', 'unknown')
foreach ($result in @($report.results)) {
    Assert-ReadOnly -Condition ($result.status -in $fixedStatuses) -Message "result status is outside the fixed vocabulary: $($result.status)"
}

$missingAcl = Get-BoundaryAclEvidence -RawPath "$fixturePath.missing" -Role 'failed-path'
Assert-ReadOnly -Condition ($missingAcl.status -eq 'collection-failure') -Message 'ACL access failure was not returned as a structured collection failure'
Assert-ReadOnly -Condition ($missingAcl.failure.error_id -eq 'ACL_COLLECTION_FAILED') -Message 'ACL access failure identifier mismatch'
Assert-ReadOnly -Condition (($missingAcl | ConvertTo-Json -Depth 10 -Compress) -notmatch 'S-1-') -Message 'ACL failure exposed a raw SID'

[Console]::Out.WriteLine("GREEN: fixture SHA-256=$($after.sha256) length=$($after.length) last-write=$($after.last_write_time_utc.ToString('o')) attributes=$($after.attributes) SDDL unchanged; minimized ACL evidence observed; exact command/member/assignment and guarded output/exit checks rejected all $($gateSelfTests.Count) proof attacks")
exit 0
