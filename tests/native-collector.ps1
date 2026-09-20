#Requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('all','paths','reparse','psdrive','race')][string]$Group = 'all')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/BoundaryLens.ps1')
$checks = 0
function Assert-Native([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "RED: $Message" }
    $script:checks++
}
function Native-Report([string]$Root, [string]$Path) {
    return Invoke-BoundaryLens -Workspace $Root -FailedPath $Path -Format Json | ConvertFrom-Json
}
Initialize-BoundaryNative
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('boundary-native-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixture -ErrorAction Stop
$workspace = Join-Path $fixture 'workspace'
$outside = Join-Path $fixture 'outside'
$null = New-Item -ItemType Directory -Path $workspace,$outside -ErrorAction Stop
$file = Join-Path $workspace '유니코드 space.txt'
[IO.File]::WriteAllText($file, 'synthetic native collector fixture')
[IO.File]::WriteAllText((Join-Path $outside 'target.txt'), 'outside fixture')
try {
    if ($Group -in @('all','paths')) {
        $before = @((Get-FileHash -LiteralPath $file).Hash, (Get-Item -LiteralPath $file).LastWriteTimeUtc.Ticks, (Get-Acl -LiteralPath $file).Sddl)
        $report = Native-Report $workspace $file
        Assert-Native ($report.evidence.failed_path.status -eq 'observed') 'Unicode/spaces path was not observed'
        Assert-Native ($report.evidence.failed_path_acl.status -eq 'observed') 'same-handle ACL was not observed'
        Assert-Native ($report.evidence.path_relation.final_within_workspace -eq $true) 'identity ancestry did not establish containment'
        Assert-Native ($report.evidence.failed_path.final_path -match '^\\Device\\HarddiskVolume[0-9]+\\') 'final name is not a supported local NT path'
        $after = @((Get-FileHash -LiteralPath $file).Hash, (Get-Item -LiteralPath $file).LastWriteTimeUtc.Ticks, (Get-Acl -LiteralPath $file).Sddl)
        Assert-Native (($before -join '|') -ceq ($after -join '|')) 'fixture content, write time or ACL changed'
        Assert-Native (($report | ConvertTo-Json -Depth 12) -notmatch 'S-1-\d') 'report leaked an SID'
        $missing = Native-Report $workspace (Join-Path $workspace 'missing.txt')
        Assert-Native ($missing.evidence.failed_path.exists -eq $false -and $missing.evidence.failed_path.status -eq 'unknown') 'missing leaf semantics changed'
        $missingParent = Native-Report $workspace (Join-Path $workspace 'missing-parent\child.txt')
        Assert-Native ($null -eq $missingParent.evidence.failed_path.exists) 'unprobed descendant was asserted absent'
        $aclFailure = ConvertFrom-BoundaryNativeAcl -Security $null -RawPath $file -Role 'failed-path'
        Assert-Native ($aclFailure.status -eq 'collection-failure' -and $aclFailure.failure.error_id -eq 'ACL_COLLECTION_FAILED') 'missing READ_CONTROL data did not remain an ACL-only failure'
        # A dedicated test-owned denial fixture is retained with its intentional ACL.
        $deniedFile = Join-Path $workspace 'acl-denied.txt'
        [IO.File]::WriteAllText($deniedFile, 'intentional READ_CONTROL denial fixture')
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $restrictedAcl = [Security.AccessControl.FileSecurity]::new()
            $restrictedAcl.SetOwner($identity.User)
            $restrictedAcl.SetAccessRuleProtection($true, $false)
            $ownerRights = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WinCreatorOwnerRightsSid, $null)
            $restrictedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ownerRights, [Security.AccessControl.FileSystemRights]::ReadPermissions, [Security.AccessControl.AccessControlType]::Deny))
            $restrictedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity.User, [Security.AccessControl.FileSystemRights]'ReadAttributes,Synchronize,ChangePermissions', [Security.AccessControl.AccessControlType]::Allow))
            Set-Acl -LiteralPath $deniedFile -AclObject $restrictedAcl
            $denied = Native-Report $workspace $deniedFile
            Assert-Native ($denied.evidence.failed_path.status -eq 'observed' -and $denied.evidence.failed_path_acl.status -eq 'collection-failure') 'real READ_CONTROL denial erased metadata or read ACL anyway'
        } finally { $identity.Dispose() }
        # An explicitly denied attribute ACE does not force a query-only NT open
        # to fail on every Windows host. A file in an ancestor position reliably
        # exercises collection failure without assuming the host's permission rules.
        $metadataBlocked = Join-Path $workspace 'non-directory-parent'
        [IO.File]::WriteAllText($metadataBlocked, 'not a directory')
        $metadataReport = Native-Report $workspace (Join-Path $metadataBlocked 'unprobed.txt')
        Assert-Native ($metadataReport.evidence.failed_path.failure.error_id -eq 'PATH_PROBE_UNAVAILABLE') 'invalid ancestor did not remain a path collection failure'
        Assert-Native ($null -eq $metadataReport.evidence.failed_path.exists -and $null -eq $metadataReport.evidence.path_relation.reparse_segment_observed -and $null -eq $metadataReport.evidence.path_relation.final_within_workspace) 'metadata failure converted unobserved facts to false'
        Assert-Native ($metadataReport.evidence.failed_path_acl.status -eq 'unknown') 'ACL was collected after path acquisition failed'
        foreach ($bad in @('\\boundary-native-invalid\share', '//boundary-native-invalid/share', 'ssh://invalid/path', '\\?\UNC\boundary-native-invalid\share', '\\.\pipe\boundary-native-invalid')) {
            $blocked = $false
            try { $null = Test-BoundaryInput -Path $bad -ParameterName Workspace }
            catch { $blocked = $_.FullyQualifiedErrorId -match '^BOUNDARY_(REMOTE_UNSUPPORTED|INPUT_INVALID)' }
            Assert-Native $blocked 'remote/device input was not rejected before acquisition'
        }
        $nativeType = [BoundaryLensNative.Session]
        $parse = $nativeType.GetMethod('ParseReparse', [Reflection.BindingFlags]'NonPublic,Static')
        foreach ($bytes in @([byte[]]@(0,0), [byte[]]::new(20))) {
            $blocked = $false
            try { $null = $parse.Invoke($null, [object[]]@($bytes, $bytes.Length, $false, $null)) }
            catch { $blocked = $true }
            Assert-Native $blocked 'malformed/unsupported reparse buffer was accepted'
        }
        $malformed = [byte[]]::new(20)
        [BitConverter]::GetBytes([uint32]2684354572).CopyTo($malformed, 0)
        [BitConverter]::GetBytes([uint16]12).CopyTo($malformed, 4)
        [BitConverter]::GetBytes([uint16]65534).CopyTo($malformed, 8)
        [BitConverter]::GetBytes([uint16]2).CopyTo($malformed, 10)
        $blocked = $false
        try { $null = $parse.Invoke($null, [object[]]@($malformed, $malformed.Length, $false, $null)) } catch { $blocked = $true }
        Assert-Native $blocked 'out-of-range substitute-name bytes were accepted'
        foreach ($remote in @('\??\UNC\boundary-native-invalid\share', '\Device\Mup\invalid', '\Device\LanmanRedirector\invalid', 'https://invalid/path')) {
            $session = [BoundaryLensNative.Session]::new()
            try {
                $snapshot = $session.OpenPath($remote)
                Assert-Native ($snapshot.Failure -eq 'REMOTE_REPARSE_TARGET_UNSUPPORTED' -and $snapshot.Count -eq 0) 'native remote rejection reached an object open'
            } finally { $session.Dispose() }
        }
        $nativeInitializer = (Get-Command Initialize-BoundaryNative).ScriptBlock
        try {
            function Initialize-BoundaryNative { throw 'Synthetic interop policy refusal.' }
            $blockedInterop = Native-Report $workspace $file
            Assert-Native ($blockedInterop.evidence.failed_path.failure.error_id -eq 'NATIVE_COLLECTION_UNAVAILABLE' -and $null -eq $blockedInterop.evidence.failed_path.final_path) 'interop refusal did not fail closed'
        } finally { Set-Item -LiteralPath Function:Initialize-BoundaryNative -Value $nativeInitializer }
    }
    if ($Group -in @('all','reparse')) {
        $link = Join-Path $workspace 'junction'
        $null = New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop
        $escaped = Native-Report $workspace (Join-Path $link 'target.txt')
        Assert-Native ($escaped.evidence.failed_path.status -eq 'observed') 'junction descendant unavailable'
        Assert-Native (@($escaped.results | Where-Object code -eq 'REPARSE_TARGET_MISMATCH').Count -eq 1) 'junction escape candidate missing'
        Assert-Native (@($escaped.evidence.failed_path.reparse_segments).Count -eq 1) 'junction evidence count incorrect'
        $flagSession = [BoundaryLensNative.Session]::new()
        $targetSession = [BoundaryLensNative.Session]::new()
        try {
            $null = $flagSession.OpenPath($workspace)
            $targetSnapshot = $targetSession.OpenPath($outside)
            $privateFlags = [Reflection.BindingFlags]'NonPublic,Instance'
            $parentFrame = $flagSession.GetType().GetField('final', $privateFlags).GetValue($flagSession)
            $openMethod = $flagSession.GetType().GetMethod('Open', $privateFlags)
            $linkFrame = $openMethod.Invoke($flagSession, [object[]]@($parentFrame, 'junction', $false))
            Assert-Native ($linkFrame.Identity -ne $targetSnapshot.Identity) 'FILE_OPEN_REPARSE_POINT followed the leaf target'
            $combinationSafe = $false
            try {
                $combined = $openMethod.Invoke($flagSession, [object[]]@($parentFrame, 'junction', $true))
                $combinationSafe = $combined.Identity -ne $targetSnapshot.Identity
            } catch { $combinationSafe = $_.Exception.ToString() -match 'PATH_PROBE_UNAVAILABLE' }
            Assert-Native $combinationSafe 'OBJ_DONT_REPARSE plus leaf-open neither refused nor retained the link'
        } finally { $flagSession.Dispose(); $targetSession.Dispose() }
        $nested = Join-Path $workspace 'nested'
        $null = New-Item -ItemType Junction -Path $nested -Target $link -ErrorAction Stop
        $nestedReport = Native-Report $workspace (Join-Path $nested 'target.txt')
        Assert-Native ($nestedReport.evidence.failed_path.status -eq 'observed' -and @($nestedReport.evidence.failed_path.reparse_segments).Count -eq 2) 'nested local junction chain failed'
        $cycleA = Join-Path $workspace 'cycle-a'
        $cycleB = Join-Path $workspace 'cycle-b'
        Assert-Native ([IO.Path]::GetFullPath($cycleB).StartsWith($fixture + '\')) 'cycle fixture replacement escaped its owned directory'
        $null = New-Item -ItemType Directory -Path $cycleB
        $null = New-Item -ItemType Junction -Path $cycleA -Target $cycleB
        # Only this empty, newly created fixture directory is replaced.
        Remove-Item -LiteralPath $cycleB -Force
        $null = New-Item -ItemType Junction -Path $cycleB -Target $cycleA
        $cycle = Native-Report $workspace (Join-Path $cycleA 'child.txt')
        Assert-Native ($cycle.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED' -and $null -eq $cycle.evidence.failed_path.final_path) 'junction cycle did not fail closed'
        $chain = $outside
        for ($index = 17; $index -ge 1; $index--) {
            $current = Join-Path $workspace "depth-$index"
            $null = New-Item -ItemType Junction -Path $current -Target $chain
            $chain = $current
        }
        $depth = Native-Report $workspace (Join-Path $chain 'target.txt')
        Assert-Native ($depth.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED') 'junction hop limit not enforced'
        $depthControl = Native-Report $workspace (Join-Path $workspace 'depth-2\target.txt')
        Assert-Native ($depthControl.evidence.failed_path.status -eq 'observed') 'supported 16-hop positive control failed'
        $brokenTarget = Join-Path $fixture 'broken-target'
        $brokenLink = Join-Path $workspace 'broken-link'
        $null = New-Item -ItemType Directory -Path $brokenTarget
        $null = New-Item -ItemType Junction -Path $brokenLink -Target $brokenTarget
        if (-not [IO.Path]::GetFullPath($brokenTarget).StartsWith($fixture + '\')) { throw 'Broken target escaped its owned fixture' }
        Remove-Item -LiteralPath $brokenTarget
        $broken = Native-Report $workspace $brokenLink
        Assert-Native ($broken.evidence.failed_path.exists -eq $true -and $broken.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED') 'observed broken link lost its observed existence or failed-open boundary'
        $brokenChild = Native-Report $workspace (Join-Path $brokenLink 'child.txt')
        Assert-Native ($null -eq $brokenChild.evidence.failed_path.exists -and $null -eq $brokenChild.evidence.failed_path.final_path) 'broken-link descendant was asserted observed'
        $symbolic = Join-Path $workspace 'relative-link'
        try {
            $null = New-Item -ItemType SymbolicLink -Path $symbolic -Target '..\outside' -ErrorAction Stop
        }
        catch {
            throw 'Relative symlink fixture requires Windows Developer Mode or the symlink privilege; verification is incomplete.'
        }
        $relative = Native-Report $workspace (Join-Path $symbolic 'target.txt')
        Assert-Native ($relative.evidence.failed_path.status -eq 'observed' -and $relative.evidence.path_relation.final_within_workspace -eq $false) 'relative symlink parent semantics failed'
    }
    if ($Group -in @('all','psdrive')) {
        $letter = @('Q','R','S','T','U','V','W','X','Y','Z') | Where-Object { $null -eq (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
        Assert-Native ($null -ne $letter) 'no unused test PSDrive letter'
        $null = New-PSDrive -Name $letter -PSProvider FileSystem -Root $workspace -Scope Script
        try {
            $alias = $letter + ':\'
            $resolved = Resolve-BoundaryDrivePath -Path ($alias + '유니코드 space.txt')
            Assert-Native ([string]::Equals($resolved, $file, [StringComparison]::OrdinalIgnoreCase)) 'PSDrive backing resolution lost suffix'
            $report = Native-Report $alias ($alias + '유니코드 space.txt')
            Assert-Native ($report.evidence.failed_path.status -eq 'observed' -and $report.evidence.path_relation.final_within_workspace -eq $true) 'PSDrive did not use its native backing'
            $session = [BoundaryLensNative.Session]::new()
            try {
                $first = $session.OpenPath($resolved)
                $oldIdentity = $first.Identity
                Remove-PSDrive -Name $letter -Scope Script
                $null = New-PSDrive -Name $letter -PSProvider FileSystem -Root $outside -Scope Script
                $last = $session.Complete()
                Assert-Native ($last.Identity -eq $oldIdentity -and $null -ne $last.Security) 'PSDrive retarget substituted an acquired object'
            } finally { $session.Dispose() }
        } finally { Remove-PSDrive -Name $letter -Scope Script -ErrorAction SilentlyContinue }
        # Seed only mapping metadata; remote/cycle controls cannot reach the OS resolver.
        foreach ($mappingCase in @(
            @{ first = '\Device\Mup\invalid'; second = $null; code = 'REMOTE_REPARSE_TARGET_UNSUPPORTED' },
            @{ first = '\Device\UnsupportedDevice'; second = $null; code = 'NATIVE_VOLUME_UNSUPPORTED' },
            @{ first = '\??\R:\'; second = '\??\Q:\'; code = 'REPARSE_TARGET_UNRESOLVED' }
        )) {
            $mapped = [BoundaryLensNative.Session]::new()
            try {
                $cache = $mapped.GetType().GetField('deviceMappings', [Reflection.BindingFlags]'NonPublic,Instance').GetValue($mapped)
                $cache.Add('Q:', $mappingCase.first)
                if ($null -ne $mappingCase.second) { $cache.Add('R:', $mappingCase.second) }
                $result = $mapped.OpenPath('Q:\child.txt')
                Assert-Native ($result.Failure -eq $mappingCase.code -and $result.Count -eq 0) 'DOS alias metadata boundary failed'
            } finally { $mapped.Dispose() }
        }
        $script:mockDriveMode = ''
        $script:mockDriveLookups = [Collections.Generic.List[string]]::new()
        try {
            function Get-PSDrive {
                param([string]$Name)
                $script:mockDriveLookups.Add($Name)
                $root = $Name + ':\'
                $display = $null
                if ($script:mockDriveMode -eq 'depth') {
                    $chain = @('Q','R','S','T','U','V','W','X','Y','Z','A','B','D','E','F','G','H','I')
                    $position = [array]::IndexOf($chain, $Name)
                    if ($position -ge 0 -and $position -lt ($chain.Count - 1)) { $root = $chain[$position + 1] + ':\' }
                }
                if ($Name -eq 'Q') {
                    switch ($script:mockDriveMode) {
                        'display' { $display = 'C:\display-root' }
                        'equivalent' { $root = 'C:\display-root\'; $display = 'C:\display-root' }
                        'conflict' { $root = 'C:\one'; $display = 'C:\two' }
                        'remote' { $display = '\\boundary-native-invalid\share' }
                        'cycle' { $root = 'R:\' }
                        'nested' { $root = 'R:\nested' }
                        'empty' { $root = '' }
                    }
                }
                if ($Name -eq 'R' -and $script:mockDriveMode -ne 'depth') { $root = if ($script:mockDriveMode -eq 'cycle') { 'Q:\' } else { 'C:\base' } }
                return [pscustomobject]@{ Provider = [pscustomobject]@{Name='FileSystem'}; Root=$root; DisplayRoot=$display }
            }
            foreach ($case in @(@('display','C:\display-root\child'), @('equivalent','C:\display-root\child'), @('nested','C:\base\nested\child'))) {
                $script:mockDriveMode = $case[0]
                Assert-Native ((Resolve-BoundaryDrivePath 'Q:\child') -eq $case[1]) 'local PSDrive metadata composition failed'
            }
            foreach ($mode in @('conflict','remote','cycle','empty','depth')) {
                $script:mockDriveMode = $mode
                $script:mockDriveLookups.Clear()
                $blocked = $false
                try { $null = Resolve-BoundaryDrivePath 'Q:\child' } catch { $blocked = $true }
                Assert-Native $blocked 'ambiguous/remote/cyclic PSDrive metadata was accepted'
                if ($mode -eq 'depth') { Assert-Native ($script:mockDriveLookups.Count -eq 17 -and -not $script:mockDriveLookups.Contains('I')) 'PSDrive metadata crossed its fixed depth limit' }
            }
        } finally { Remove-Item -LiteralPath Function:Get-PSDrive }
    }
    if ($Group -in @('all','race')) {
        $session = [BoundaryLensNative.Session]::new()
        $moved = Join-Path $workspace 'retained.txt'
        Assert-Native ([IO.Path]::GetFullPath($file).StartsWith($fixture + '\') -and [IO.Path]::GetFullPath($moved).StartsWith($fixture + '\')) 'race move escaped the owned fixture'
        try {
            $first = $session.OpenPath($file)
            Assert-Native ($null -eq $first.Failure) 'race prerequisite acquisition failed'
            $identity = $first.Identity
            Move-Item -LiteralPath $file -Destination $moved -ErrorAction Stop
            [IO.File]::WriteAllText($file, 'replacement object')
            $last = $session.Complete()
            Assert-Native ($last.Identity -eq $identity -and $last.Final.EndsWith('\retained.txt')) 'name replacement substituted final object'
            Assert-Native ($null -ne $last.Security) 'ACL was not collected from retained object'
            $replacement = [BoundaryLensNative.Session]::new()
            try {
                $new = $replacement.OpenPath($file)
                Assert-Native ($new.Identity -ne $identity) 'positive control failed: replacement identity did not differ'
            } finally { $replacement.Dispose() }
        } finally { $session.Dispose() }
        $disposedFailed = $false
        try { $null = $session.Complete() } catch { $disposedFailed = $true }
        Assert-Native $disposedFailed 'disposed session permitted handle reuse'
        $parentRace = Join-Path $workspace 'parent-race'
        $oldParent = Join-Path $workspace 'retained-parent'
        $null = New-Item -ItemType Directory -Path $parentRace
        [IO.File]::WriteAllText((Join-Path $parentRace 'target.txt'), 'retained parent fixture')
        $parentSession = [BoundaryLensNative.Session]::new()
        try {
            $null = $parentSession.OpenPath($parentRace)
            $privateFlags = [Reflection.BindingFlags]'NonPublic,Instance'
            $heldParent = $parentSession.GetType().GetField('final', $privateFlags).GetValue($parentSession)
            Assert-Native ([IO.Path]::GetFullPath($parentRace).StartsWith($fixture + '\') -and [IO.Path]::GetFullPath($oldParent).StartsWith($fixture + '\')) 'parent move escaped its owned fixture'
            Move-Item -LiteralPath $parentRace -Destination $oldParent
            $null = New-Item -ItemType Junction -Path $parentRace -Target $outside
            $openMethod = $parentSession.GetType().GetMethod('Open', $privateFlags)
            $heldChild = $openMethod.Invoke($parentSession, [object[]]@($heldParent, 'target.txt', $false))
            $nameMethod = $parentSession.GetType().GetMethod('FinalName', [Reflection.BindingFlags]'NonPublic,Static')
            $childName = [string]$nameMethod.Invoke($null, [object[]]@($heldChild))
            Assert-Native ($childName.EndsWith('\retained-parent\target.txt')) 'parent name replacement redirected a handle-relative child open'
        } finally { $parentSession.Dispose() }
        # Inspect the exact native handles, not process-wide lazy runtime allocations.
        foreach ($candidate in @($file, (Join-Path $workspace 'missing.txt'))) {
            $cleanup = [BoundaryLensNative.Session]::new()
            $handles = @()
            try {
                $null = $cleanup.OpenPath($candidate)
                $ownedField = $cleanup.GetType().GetField('owned', [Reflection.BindingFlags]'NonPublic,Instance')
                $handles = @($ownedField.GetValue($cleanup))
                Assert-Native ($handles.Count -gt 0 -and @($handles | Where-Object IsClosed).Count -eq 0) 'cleanup positive control did not hold live handles'
            } finally { $cleanup.Dispose() }
            Assert-Native (@($handles | Where-Object { -not $_.IsClosed }).Count -eq 0) 'successful/failed traversal retained native handles after disposal'
        }
    }
    [Console]::Out.WriteLine("GREEN: native $Group group; $checks assertions; fixture retained at $fixture")
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    [Console]::Error.WriteLine("Failure line: $($_.InvocationInfo.ScriptLineNumber); error: $($_.FullyQualifiedErrorId)")
    [Console]::Error.WriteLine("Fixture retained for inspection: $fixture")
    exit 1
}
