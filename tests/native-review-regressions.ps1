#Requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('all','drift','repeated','dacl','remote','bounds','volume-identity','volume-alias','reserved','ace-shapes','segment-count','type-contract','psdrive-drift','dosmap-drift','declared-nearest','malformed-utf16','declared-missing','interop-failure','reparse-control','captured-coherence')][string]$Group = 'all', [switch]$StaleTypeFixture)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/BoundaryLens.ps1'
if ($StaleTypeFixture) {
    Add-Type 'namespace BoundaryLensNative { public sealed class Session { public const string ContractId = "stale-test-contract"; public static int Created; public Session() { Created++; } } }'
}
. $sourcePath
$checks = 0
function Assert-Review([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "RED: $Message" }
    $script:checks++
}
function Report-Review([string]$Workspace, [string]$FailedPath) {
    Invoke-BoundaryLens -Workspace $Workspace -FailedPath $FailedPath -Format Json | ConvertFrom-Json
}
function New-NativeBoundaryFixtureProduct {
    # Only native imports are substituted. The path walker, reparse decoder,
    # snapshot logic and public PowerShell report pipeline are the production code.
    $product = [IO.File]::ReadAllText($sourcePath)
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($product, [ref]$tokens, [ref]$errors)
    $addType = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type' }, $true))
    Assert-Review ($errors.Count -eq 0 -and $addType.Count -eq 1) 'fixture extraction did not identify the single native source'
    $literal = $addType[0].CommandElements[2]
    $native = $literal.Value
    $importPattern = '\[DllImport\("[^"]+"[^\r\n]*\)\]\s*static extern [^;]+;'
    Assert-Review ([regex]::Matches($native, $importPattern).Count -eq 10) 'fixture must replace exactly the reviewed ten native imports'
    $native = [regex]::Replace($native, $importPattern, '')
    $native = $native.Replace('namespace BoundaryLensNative {', 'namespace BoundaryLensNativeFixture {')
    $shim = @'
        // Test-only, memory-only native boundary. There are no native imports here.
        sealed class FixtureNode {
            public string Path;
            public uint Attributes;
            public long Identity;
            public byte[] Reparse;
        }
        const string FixtureRoot = @"\Device\HarddiskVolume999";
        const string FixtureOtherRoot = @"\Device\HarddiskVolume1000";
        static readonly Dictionary<string, string> fixtureMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, FixtureNode> fixtureNodes = new Dictionary<string, FixtureNode>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<long, FixtureNode> fixtureHandles = new Dictionary<long, FixtureNode>();
        static readonly Dictionary<long, uint> fixtureCapturedAttributes = new Dictionary<long, uint>();
        static readonly Dictionary<long, byte[]> fixtureCapturedReparse = new Dictionary<long, byte[]>();
        public static readonly List<string> FixtureOpens = new List<string>();
        public static readonly List<string> FixtureAclQueries = new List<string>();
        public static readonly List<string> FixtureMappingQueries = new List<string>();
        public static int FixtureRemoteOpens, FixtureContractViolations;
        public static string FixtureThrowAt, FixtureThrowKind;
        public static bool FixtureReplayControls;
        public static string FixtureUnavailable, FixtureRetargetOnRead;
        static long fixtureId, fixtureHandle;

        public static void FixtureReset() {
            fixtureNodes.Clear(); fixtureHandles.Clear(); FixtureOpens.Clear(); FixtureAclQueries.Clear();
            FixtureMappingQueries.Clear();
            fixtureMappings.Clear();
            fixtureCapturedAttributes.Clear(); fixtureCapturedReparse.Clear();
            FixtureReplayControls = false; FixtureUnavailable = FixtureRetargetOnRead = null;
            fixtureMappings.Add("C:", FixtureRoot); fixtureMappings.Add("D:", FixtureOtherRoot);
            fixtureMappings.Add("Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", FixtureRoot);
            FixtureRemoteOpens = 0; FixtureContractViolations = 0; fixtureId = 0; fixtureHandle = 1000;
            FixtureThrowAt = FixtureThrowKind = null;
            fixtureNodes.Add(FixtureRoot + "\\", new FixtureNode { Path = FixtureRoot + "\\", Attributes = 0x10, Identity = ++fixtureId });
        }
        public static void FixtureMap(string alias, string target) { fixtureMappings[alias] = target; }
        static void FixtureThrow(string stage) {
            if (FixtureThrowAt != stage) return;
            switch (FixtureThrowKind) {
                case "dll": throw new DllNotFoundException("FIXTURE_PRIVATE_RUNTIME_DETAIL");
                case "entry": throw new EntryPointNotFoundException("FIXTURE_PRIVATE_RUNTIME_DETAIL");
                case "platform": throw new PlatformNotSupportedException("FIXTURE_PRIVATE_RUNTIME_DETAIL");
                case "policy": throw new System.Security.SecurityException("FIXTURE_PRIVATE_RUNTIME_DETAIL");
                default: throw new InvalidOperationException("FIXTURE_PRIVATE_RUNTIME_DETAIL");
            }
        }
        public static void FixtureUnmap(string alias) { fixtureMappings.Remove(alias); }
        public static void FixtureBadUtf16(string relative) {
            var node = fixtureNodes[FixtureRoot + "\\" + relative];
            node.Attributes |= 0x400;
            node.Reparse = new byte[18];
            BitConverter.GetBytes(0xA0000003U).CopyTo(node.Reparse, 0);
            BitConverter.GetBytes((ushort)10).CopyTo(node.Reparse, 4);
            BitConverter.GetBytes((ushort)2).CopyTo(node.Reparse, 10);
            node.Reparse[17] = 0xD8; // Lone high surrogate, not a real filesystem fixture.
        }
        public static void FixtureCloneVolume() {
            foreach (var pair in new List<KeyValuePair<string, FixtureNode>>(fixtureNodes)) {
                string name = pair.Key.Replace(FixtureRoot, FixtureOtherRoot);
                var node = pair.Value;
                fixtureNodes.Add(name, new FixtureNode { Path = name, Attributes = node.Attributes, Identity = node.Identity, Reparse = node.Reparse });
            }
        }
        public static void FixtureAdd(string relative, bool directory, string target) {
            string current = FixtureRoot;
            string[] parts = relative.Split('\\');
            for (int i = 0; i < parts.Length; i++) {
                current += "\\" + parts[i];
                FixtureNode node;
                if (!fixtureNodes.TryGetValue(current, out node)) {
                    node = new FixtureNode { Path = current, Attributes = 0x10, Identity = ++fixtureId };
                    fixtureNodes.Add(current, node);
                }
                if (i == parts.Length - 1) {
                    node.Attributes = directory ? 0x10U : 0U;
                    node.Reparse = null;
                    if (!String.IsNullOrEmpty(target)) {
                        node.Attributes |= 0x400;
                        byte[] path = Encoding.Unicode.GetBytes(target);
                        node.Reparse = new byte[16 + path.Length];
                        BitConverter.GetBytes(0xA0000003U).CopyTo(node.Reparse, 0);
                        BitConverter.GetBytes(checked((ushort)(8 + path.Length))).CopyTo(node.Reparse, 4);
                        BitConverter.GetBytes(checked((ushort)path.Length)).CopyTo(node.Reparse, 10);
                        path.CopyTo(node.Reparse, 16);
                    }
                }
            }
        }
        static uint QueryDosDeviceW(string name, char[] target, int length) {
            FixtureThrow("mapping");
            FixtureMappingQueries.Add(name);
            string value;
            if (!fixtureMappings.TryGetValue(name, out value)) return 0;
            value += "\0\0";
            value.CopyTo(0, target, 0, value.Length);
            return (uint)value.Length;
        }
        static uint NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength) {
            handle = null; status = new IoStatus();
            var us = (UnicodeString)Marshal.PtrToStructure(attributes.ObjectName, typeof(UnicodeString));
            string name = Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
            string path;
            if (attributes.RootDirectory == IntPtr.Zero) path = name;
            else path = fixtureHandles[attributes.RootDirectory.ToInt64()].Path.TrimEnd('\\') + "\\" + name;
            FixtureOpens.Add(path);
            if (!path.StartsWith(FixtureRoot + "\\", StringComparison.Ordinal) && !path.StartsWith(FixtureOtherRoot + "\\", StringComparison.Ordinal)) { FixtureRemoteOpens++; return AccessDenied; }
            if ((access & ~(ReadAttributes | ReadControl | Synchronize)) != 0 || disposition != OpenExisting ||
                share != ShareReadWriteDelete || (options & OpenReparse) == 0) FixtureContractViolations++;
            FixtureNode node;
            if (!fixtureNodes.TryGetValue(path, out node)) return NameMissing;
            long token = ++fixtureHandle;
            fixtureHandles.Add(token, node);
            // ownsHandle=false prevents fabricated tokens from reaching CloseHandle.
            handle = new SafeFileHandle(new IntPtr(token), false);
            return 0;
        }
        static bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo information) {
            FixtureThrow("information");
            long token = handle.DangerousGetHandle().ToInt64();
            uint attributes = fixtureHandles[token].Attributes;
            if (!fixtureCapturedAttributes.ContainsKey(token)) fixtureCapturedAttributes.Add(token, attributes);
            information = new FileInfo { Attributes = FixtureReplayControls ? fixtureCapturedAttributes[token] : attributes };
            return FixtureUnavailable != "information";
        }
        static bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out FileIdentity information, uint size) {
            var id = new byte[16];
            BitConverter.GetBytes(fixtureHandles[handle.DangerousGetHandle().ToInt64()].Identity).CopyTo(id, 0);
            information = new FileIdentity { VolumeSerial = 1, Id = id };
            return true;
        }
        static uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags) {
            FixtureThrow("name");
            string value = fixtureHandles[handle.DangerousGetHandle().ToInt64()].Path;
            if (value.Length + 1 > length) return (uint)value.Length + 1;
            path.Append(value);
            return (uint)value.Length;
        }
        static bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder volume, uint volumeLength, out uint serial, out uint maximumComponent, out uint flags, StringBuilder filesystem, uint filesystemLength) {
            serial = 1; maximumComponent = 255; flags = 0; filesystem.Append("NTFS"); return true;
        }
        static bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputLength, byte[] output, uint outputLength, out uint returned, IntPtr overlapped) {
            FixtureThrow("reparse");
            if (code != GetReparsePoint) FixtureContractViolations++;
            long token = handle.DangerousGetHandle().ToInt64();
            byte[] value = fixtureHandles[token].Reparse;
            if (value != null && !fixtureCapturedReparse.ContainsKey(token)) fixtureCapturedReparse.Add(token, (byte[])value.Clone());
            if (FixtureReplayControls && fixtureCapturedReparse.ContainsKey(token)) value = fixtureCapturedReparse[token];
            returned = value == null ? 0U : (uint)value.Length;
            if (value == null || FixtureUnavailable == "reparse") return false;
            value.CopyTo(output, 0);
            if (FixtureRetargetOnRead != null && fixtureHandles[token].Path == FixtureRoot + "\\J") {
                string target = FixtureRetargetOnRead; FixtureRetargetOnRead = null;
                FixtureAdd("J", true, target);
            }
            return true;
        }
        static uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor) {
            FixtureThrow("acl");
            FixtureAclQueries.Add(fixtureHandles[handle.DangerousGetHandle().ToInt64()].Path);
            if (objectType != 1 || information != 5) FixtureContractViolations++;
            owner = group = dacl = sacl = descriptor = IntPtr.Zero;
            return 5;
        }
        static uint GetSecurityDescriptorLength(IntPtr descriptor) { return 0; }
        static IntPtr LocalFree(IntPtr memory) { return IntPtr.Zero; }

'@
    $native = $native.Replace('        static BoundaryFailure Fail', ($shim + '        static BoundaryFailure Fail'))
    Assert-Review ($native -notmatch 'DllImport|static extern') 'memory fixture retained a native entry point'
    $replacement = "@'" + [Environment]::NewLine + $native + [Environment]::NewLine + "'@"
    $product = $product.Substring(0, $literal.Extent.StartOffset) + $replacement + $product.Substring($literal.Extent.EndOffset)
    return $product.Replace('BoundaryLensNative.Session', 'BoundaryLensNativeFixture.Session')
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('boundary-native-review-' + [guid]::NewGuid().ToString('N'))
$workspace = Join-Path $fixture 'workspace'
$outside = Join-Path $fixture 'outside'
$null = New-Item -ItemType Directory -Path $workspace,$outside -ErrorAction Stop
$file = Join-Path $workspace 'held.txt'
[IO.File]::WriteAllText($file, 'pinned object')
try {
    if ($Group -in @('all','type-contract')) {
        if ($StaleTypeFixture) {
            $report = Report-Review $workspace $file
            Assert-Review ([BoundaryLensNative.Session]::Created -eq 0) 'stale native type was instantiated'
            Assert-Review ($report.evidence.workspace_path.failure.error_id -eq 'NATIVE_COLLECTION_UNAVAILABLE') 'stale native type did not fail closed'
        } else {
            Initialize-BoundaryNative
            . $sourcePath
            Initialize-BoundaryNative
            $report = Report-Review $workspace $file
            Assert-Review ($report.evidence.failed_path.status -eq 'observed') 'matching native contract was not reusable'
            $runner = (Get-Process -Id $PID).Path
            & $runner -NoProfile -File $PSCommandPath -Group type-contract -StaleTypeFixture
            Assert-Review ($LASTEXITCODE -eq 0) 'stale native type child failed'
        }
    }
    if ($Group -in @('all','reserved')) {
        foreach ($name in @('NUL','con.txt','COM1.log',('COM'+[char]0x00b9+'.txt'),('LPT'+[char]0x00b3),'NUL.tar.gz','NUL .txt','CONIN$','CONOUT$')) {
            $blocked = $false
            try { $null = Test-BoundaryInput -Path ('C:\synthetic\'+$name) -ParameterName Workspace } catch { $blocked = $_.FullyQualifiedErrorId -match '^BOUNDARY_INPUT_INVALID' }
            Assert-Review $blocked 'reserved DOS component was accepted as a literal file'
        }
        foreach ($name in @('console.txt','COM10.txt','null.txt')) { Assert-Review ((Test-BoundaryInput -Path ('C:\synthetic\'+$name) -ParameterName Workspace) -eq ('C:\synthetic\'+$name)) 'ordinary lookalike was rejected' }
    }
    if ($Group -in @('all','ace-shapes')) {
        $owner = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $world = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WorldSid, $null)
        foreach ($shape in @('callback','object')) {
            $acl = [Security.AccessControl.RawAcl]::new(4, 1)
            if ($shape -eq 'callback') {
                $ace = [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None, [Security.AccessControl.AceQualifier]::AccessAllowed, 1, $world, $true, [byte[]]@(0,0,0,0))
            } else {
                $ace = [Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None, [Security.AccessControl.AceQualifier]::AccessAllowed, 1, $world, [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent, [guid]::Empty, [guid]::Empty, $false, $null)
            }
            $acl.InsertAce(0, $ace)
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new([Security.AccessControl.ControlFlags]'SelfRelative,DiscretionaryAclPresent', $owner, $null, $null, $acl)
            $bytes = [byte[]]::new($descriptor.BinaryLength); $descriptor.GetBinaryForm($bytes, 0)
            $record = ConvertFrom-BoundaryNativeAcl -Security $bytes -RawPath 'C:\synthetic' -Role workspace
            Assert-Review ($record.status -eq 'collection-failure' -and $record.failure.error_id -eq 'ACL_ACE_UNSUPPORTED') 'restricted ACE was flattened into an unconditional summary'
            Assert-Review (($record | ConvertTo-Json -Depth 8) -notmatch 'S-1-\d') 'unsupported ACE leaked an identity'
        }
    }
    if ($Group -in @('all','drift')) {
        Initialize-BoundaryNative
        $session = [BoundaryLensNative.Session]::new()
        try {
            $first = $session.OpenPath($file)
            $originalId = $first.Identity
            $destination = Join-Path $outside 'moved.txt'
            Assert-Review ([IO.Path]::GetFullPath($file).StartsWith($fixture + '\') -and [IO.Path]::GetFullPath($destination).StartsWith($fixture + '\')) 'move escaped owned fixture'
            Move-Item -LiteralPath $file -Destination $destination
            $completed = $session.Complete()
            Assert-Review ($completed.Identity -eq $originalId -and $null -ne $completed.Security -and $completed.Final.EndsWith('\outside\moved.txt')) 'pinned object evidence was lost on a cross-boundary move'
            $driftProperty = $completed.PSObject.Properties['TopologyFailure']
            Assert-Review ($null -ne $driftProperty -and $driftProperty.Value -eq 'PATH_TOPOLOGY_CHANGED') 'cross-boundary move left stale ancestry usable'
        } finally { $session.Dispose() }
        $lateFile = Join-Path $workspace 'late.txt'
        [IO.File]::WriteAllText($lateFile, 'move after the first observations')
        $script:lateMoveSource = $lateFile
        $script:lateMoveTarget = Join-Path $outside 'late.txt'
        $script:originalObservation = (Get-Command Get-BoundaryObservation).ScriptBlock
        try {
            function Get-BoundaryObservation {
                param([string]$RawPath, [string]$Role)
                $observed = & $script:originalObservation -RawPath $RawPath -Role $Role
                if ($Role -eq 'failed-path') { Move-Item -LiteralPath $script:lateMoveSource -Destination $script:lateMoveTarget }
                return $observed
            }
            $report = Report-Review $workspace $lateFile
            Assert-Review ($report.evidence.failed_path.status -eq 'observed' -and $report.evidence.failed_path_acl.status -eq 'observed') 'late move erased pinned path or ACL evidence'
            Assert-Review ($report.evidence.failed_path.final_path.EndsWith('\outside\late.txt') -and $null -eq $report.evidence.path_relation.final_within_workspace) 'public comparison retained stale containment after second input collection'
            Assert-Review (@($report.results | Where-Object { $_.status -eq 'unknown' -and $_.code -eq 'PATH_TOPOLOGY_CHANGED' }).Count -eq 1) 'public drift reason was not explicit'
        } finally { Set-Item -LiteralPath Function:Get-BoundaryObservation -Value $script:originalObservation }
        $script:moveWorkspace = $workspace
        $script:movedWorkspace = Join-Path $outside 'workspace-moved'
        $script:replacementFile = Join-Path $workspace 'replacement.txt'
        try {
            function Get-BoundaryObservation {
                param([string]$RawPath, [string]$Role)
                $observed = & $script:originalObservation -RawPath $RawPath -Role $Role
                if ($Role -eq 'workspace') {
                    Move-Item -LiteralPath $script:moveWorkspace -Destination $script:movedWorkspace
                    $null = New-Item -ItemType Directory -Path $script:moveWorkspace
                    [IO.File]::WriteAllText($script:replacementFile, 'new workspace object')
                }
                return $observed
            }
            Assert-Review ([IO.Path]::GetFullPath($script:moveWorkspace).StartsWith($fixture + '\') -and [IO.Path]::GetFullPath($script:movedWorkspace).StartsWith($fixture + '\')) 'workspace move escaped owned fixture'
            $report = Report-Review $workspace $script:replacementFile
            Assert-Review ($report.evidence.workspace_path.final_path.EndsWith('\outside\workspace-moved') -and $report.evidence.failed_path.status -eq 'observed') 'first-input drift was not refreshed after second acquisition'
            Assert-Review ($null -eq $report.evidence.path_relation.final_within_workspace -and @($report.results | Where-Object code -eq 'PATH_TOPOLOGY_CHANGED').Count -eq 1) 'mixed input generations produced a definite containment answer'
        } finally { Set-Item -LiteralPath Function:Get-BoundaryObservation -Value $script:originalObservation }
    }
    if ($Group -in @('all','repeated')) {
        $again = Join-Path $workspace 'again'
        $null = New-Item -ItemType Junction -Path $again -Target $workspace
        $target = Join-Path $workspace 'finite.txt'
        [IO.File]::WriteAllText($target, 'finite repeated link target')
        $report = Report-Review $workspace (Join-Path $again 'again\finite.txt')
        Assert-Review ($report.evidence.failed_path.status -eq 'observed') 'finite repeated link was rejected as a cycle'
        Assert-Review (@($report.evidence.failed_path.reparse_segments).Count -eq 2 -and $report.evidence.path_relation.final_within_workspace -eq $true) 'finite repeated link lost its evidence or ancestry'
    }
    if ($Group -in @('all','dacl')) {
        $owner = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $world = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WorldSid, $null)
        foreach ($kind in @('null','absent','empty','ordinary','generic-all','generic-read','generic-mixed')) {
            $flags = [Security.AccessControl.ControlFlags]::SelfRelative
            if ($kind -ne 'absent') { $flags = $flags -bor [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent }
            $dacl = $null
            if ($kind -notin @('null','absent')) { $dacl = [Security.AccessControl.RawAcl]::new(2, 1) }
            if ($kind -notin @('null','absent','empty')) {
                $mask = switch ($kind) {
                    'generic-all' { 268435456 }
                    'generic-read' { [int]::MinValue }
                    'generic-mixed' { -1073741696 }
                    default { [int][Security.AccessControl.FileSystemRights]::Read }
                }
                $aceFlags = if ($kind -like 'generic-*') { [Security.AccessControl.AceFlags]'ObjectInherit,ContainerInherit,InheritOnly' } else { [Security.AccessControl.AceFlags]::None }
                $ace = [Security.AccessControl.CommonAce]::new($aceFlags, [Security.AccessControl.AceQualifier]::AccessAllowed, $mask, $world, $false, $null)
                $dacl.InsertAce(0, $ace)
            }
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($flags, $owner, $null, $null, $dacl)
            $bytes = [byte[]]::new($descriptor.BinaryLength)
            $descriptor.GetBinaryForm($bytes, 0)
            $record = ConvertFrom-BoundaryNativeAcl -Security $bytes -RawPath 'C:\synthetic' -Role 'failed-path'
            if ($kind -in @('null','absent')) {
                Assert-Review ($record.status -eq 'collection-failure' -and $null -ne $record.failure -and $record.failure.error_id -eq 'ACL_DACL_UNSUPPORTED') 'null/absent DACL was presented like an empty DACL'
            } else {
                Assert-Review ($record.status -eq 'observed' -and @($record.access_rules).Count -eq $(if ($kind -eq 'empty') { 0 } else { 1 })) "supported $kind DACL evidence changed"
            }
            if ($kind -like 'generic-*') { Assert-Review ($record.access_rules[0].rights -ceq [string]$mask) 'valid generic access-mask bits were lost or remapped' }
            if ($kind -eq 'ordinary') { Assert-Review ($record.access_rules[0].rights -ceq 'Read') 'ordinary rights lost their named representation' }
            Assert-Review (($record | ConvertTo-Json -Depth 8) -notmatch 'S-1-\d') 'descriptor fixture leaked a SID'
        }
    }
    if ($Group -in @('all','remote','bounds','volume-identity','volume-alias','segment-count','reserved','psdrive-drift','dosmap-drift','declared-nearest','malformed-utf16','declared-missing','interop-failure','reparse-control','captured-coherence')) {
        $fixtureProduct = New-NativeBoundaryFixtureProduct
        & {
            param($FixtureProduct, $SelectedGroup)
            . ([scriptblock]::Create($FixtureProduct))
            Initialize-BoundaryNative
            if ($SelectedGroup -in @('all','reparse-control','captured-coherence')) {
                # The same product collector is used; only in-memory native responses vary.
                $modes = if ($SelectedGroup -eq 'captured-coherence') { @('captured-cross','captured-repeat') } else { @('stable','payload','add-bit','remove-bit','unavailable-info','unavailable-data','captured-cross','captured-repeat') }
                foreach ($mode in $modes) {
                    [BoundaryLensNativeFixture.Session]::FixtureReset()
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('A\file', $false, $null)
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('B\file', $false, $null)
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('B\back', $true, '\??\C:\A')
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, '\??\C:\A')
                    if ($mode -eq 'add-bit') { [BoundaryLensNativeFixture.Session]::FixtureAdd('J\file', $false, $null); [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, $null) }
                    if ($mode -eq 'captured-repeat') {
                        [BoundaryLensNativeFixture.Session]::FixtureAdd('A\again', $true, '\??\C:\J')
                        [BoundaryLensNativeFixture.Session]::FixtureReplayControls = $true
                    }
                    if ($mode -eq 'captured-cross') { [BoundaryLensNativeFixture.Session]::FixtureReplayControls = $true }
                    $script:controlMode = $mode
                    $script:controlOriginal = (Get-Command Get-BoundaryObservation).ScriptBlock
                    function Get-BoundaryObservation {
                        param([string]$RawPath, [string]$Role)
                        if ($Role -eq 'failed-path' -and $script:controlMode -eq 'captured-cross') { [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, '\??\C:\B') }
                        if ($Role -eq 'failed-path' -and $script:controlMode -eq 'captured-repeat') { [BoundaryLensNativeFixture.Session]::FixtureRetargetOnRead = '\??\C:\B' }
                        $observation = & $script:controlOriginal -RawPath $RawPath -Role $Role
                        if ($Role -eq 'failed-path') {
                            switch ($script:controlMode) {
                                'payload' { [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, '\??\C:\B') }
                                'add-bit' { [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, '\??\C:\B') }
                                'remove-bit' { [BoundaryLensNativeFixture.Session]::FixtureAdd('J', $true, $null) }
                                'unavailable-info' { [BoundaryLensNativeFixture.Session]::FixtureUnavailable = 'information' }
                                'unavailable-data' { [BoundaryLensNativeFixture.Session]::FixtureUnavailable = 'reparse' }
                            }
                            $script:controlOpenCount = [BoundaryLensNativeFixture.Session]::FixtureOpens.Count
                        }
                        return $observation
                    }
                    try {
                        $workspaceInput = if ($mode -eq 'captured-repeat') { 'C:\A' } else { 'C:\J' }
                        $failedInput = switch ($mode) { 'captured-cross' { 'C:\J\back\file' }; 'captured-repeat' { 'C:\J\again\file' }; default { 'C:\J\file' } }
                        $report = Invoke-BoundaryLens -Workspace $workspaceInput -FailedPath $failedInput -Format Json | ConvertFrom-Json
                        Assert-Review ($report.evidence.workspace_path.status -eq 'observed' -and $report.evidence.failed_path.status -eq 'observed') 'control refresh erased pinned path observations'
                        if ($mode -eq 'stable') {
                            Assert-Review ($report.evidence.path_relation.final_within_workspace -eq $true) 'stable control lost definite containment'
                        } else {
                            $expected = if ($mode -like 'unavailable-*') { 'PATH_TOPOLOGY_UNAVAILABLE' } else { 'PATH_TOPOLOGY_CHANGED' }
                            Assert-Review ($null -eq $report.evidence.path_relation.final_within_workspace -and @($report.results | Where-Object code -eq $expected).Count -eq 1) ('reparse control change retained definite containment: '+$mode)
                            Assert-Review (@($report.results | Where-Object code -eq 'REPARSE_TARGET_MISMATCH').Count -eq 0) 'control change produced a mismatch cause candidate'
                        }
                        Assert-Review ([BoundaryLensNativeFixture.Session]::FixtureOpens.Count -eq $script:controlOpenCount -and [BoundaryLensNativeFixture.Session]::FixtureRemoteOpens -eq 0 -and [BoundaryLensNativeFixture.Session]::FixtureContractViolations -eq 0) 'control reconciliation opened a new target or changed query-only access'
                        if ($mode -eq 'captured-cross') { Assert-Review ($report.evidence.failed_path.final_path.EndsWith('\A\file')) 'captured contradiction did not exercise the formerly definite positive path' }
                    } finally { Set-Item -LiteralPath Function:Get-BoundaryObservation -Value $script:controlOriginal }
                }
            }
            if ($SelectedGroup -in @('all','declared-missing')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('target\present.txt', $false, $null)
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\link', $true, '\??\C:\target')
                foreach ($suffix in @('missing.txt','missing-parent\child.txt')) {
                    $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath ('C:\workspace\link\'+$suffix) -Format Json | ConvertFrom-Json
                    Assert-Review ($report.evidence.failed_path.status -eq 'unknown' -and $report.evidence.failed_path.failure.error_id -eq 'TARGET_NOT_OBSERVED') 'resolved reparse converted a declared missing suffix into link failure'
                    Assert-Review (($suffix -eq 'missing.txt' -and $report.evidence.failed_path.exists -eq $false) -or ($suffix -ne 'missing.txt' -and $null -eq $report.evidence.failed_path.exists)) 'declared missing leaf/parent distinction was lost'
                }
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\broken', $true, '\??\C:\absent-target')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\broken' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.status -eq 'collection-failure' -and $report.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED' -and $report.evidence.failed_path.exists -eq $true) 'missing target expansion was incorrectly treated as a missing declared leaf'
            }
            if ($SelectedGroup -in @('all','interop-failure')) {
                foreach ($kind in @('dll','entry','platform','policy','unexpected')) {
                    [BoundaryLensNativeFixture.Session]::FixtureReset()
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\item.txt', $false, $null)
                    [BoundaryLensNativeFixture.Session]::FixtureThrowAt = 'mapping'
                    [BoundaryLensNativeFixture.Session]::FixtureThrowKind = $kind
                    $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\item.txt' -Format Json | ConvertFrom-Json
                    $expected = if ($kind -eq 'unexpected') { 'NATIVE_COLLECTION_FAILED' } else { 'NATIVE_COLLECTION_UNAVAILABLE' }
                    Assert-Review ($report.evidence.workspace_path.failure.error_id -eq $expected) 'managed native runtime failure was classified as a filesystem probe failure'
                    Assert-Review (($report | ConvertTo-Json -Depth 10) -notmatch 'FIXTURE_PRIVATE_RUNTIME_DETAIL') 'native exception details escaped the fixed failure boundary'
                }
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\item.txt', $false, $null)
                [BoundaryLensNativeFixture.Session]::FixtureThrowAt = 'acl'
                [BoundaryLensNativeFixture.Session]::FixtureThrowKind = 'entry'
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\item.txt' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.status -eq 'observed' -and $report.evidence.failed_path_acl.failure.error_id -eq 'NATIVE_COLLECTION_UNAVAILABLE') 'ACL interop failure erased pinned path evidence or lost its runtime classification'
            }
            if ($SelectedGroup -in @('all','psdrive-drift','dosmap-drift')) {
                $kinds = if ($SelectedGroup -eq 'psdrive-drift') { @('ps') } elseif ($SelectedGroup -eq 'dosmap-drift') { @('dos') } else { @('ps','dos') }
                foreach ($kind in $kinds) {
                    foreach ($mode in @('stable','changed','unavailable','remote-after')) {
                        [BoundaryLensNativeFixture.Session]::FixtureReset()
                        [BoundaryLensNativeFixture.Session]::FixtureAdd('one\item.txt', $false, $null)
                        [BoundaryLensNativeFixture.Session]::FixtureAdd('two\item.txt', $false, $null)
                        [BoundaryLensNativeFixture.Session]::FixtureMap('S:', '\??\C:\one')
                        $script:mappingKind = $kind; $script:mappingMode = $mode
                        $script:mappingPsRoot = 'C:\one'; $script:mappingPsUnavailable = $false
                        $script:mappingOriginal = (Get-Command Get-BoundaryObservation).ScriptBlock
                        $script:mappingWorkspaceSession = $null
                        function Get-PSDrive {
                            param([string]$Name)
                            if ($Name -eq 'Q' -and $script:mappingPsUnavailable) { throw 'Synthetic metadata unavailable' }
                            $root = if ($Name -eq 'Q') { $script:mappingPsRoot } else { $Name + ':\' }
                            [pscustomobject]@{ Provider=[pscustomobject]@{Name='FileSystem'};Root=$root;DisplayRoot=$null }
                        }
                        function Get-BoundaryObservation {
                            param([string]$RawPath, [string]$Role)
                            if ($Role -eq 'failed-path' -and $script:mappingMode -eq 'changed') {
                                if ($script:mappingKind -eq 'ps') { $script:mappingPsRoot = 'C:\two' }
                                else { [BoundaryLensNativeFixture.Session]::FixtureMap('S:', '\??\C:\two') }
                            }
                            $observation = & $script:mappingOriginal -RawPath $RawPath -Role $Role
                            if ($Role -eq 'workspace') { $script:mappingWorkspaceSession = $observation.session }
                            if ($Role -eq 'failed-path') {
                                if ($script:mappingMode -eq 'unavailable') {
                                    if ($script:mappingKind -eq 'ps') { $script:mappingPsUnavailable = $true }
                                    else { [BoundaryLensNativeFixture.Session]::FixtureUnmap('S:') }
                                }
                                if ($script:mappingMode -eq 'remote-after') {
                                    if ($script:mappingKind -eq 'ps') { $script:mappingPsRoot = '\\boundary-native-invalid\share' }
                                    else { [BoundaryLensNativeFixture.Session]::FixtureMap('S:', '\??\UNC\boundary-native-invalid\share') }
                                }
                            }
                            return $observation
                        }
                        try {
                            $alias = if ($kind -eq 'ps') { 'Q:\' } else { 'S:\' }
                            $report = Invoke-BoundaryLens -Workspace $alias -FailedPath ($alias+'item.txt') -Format Json | ConvertFrom-Json
                            Assert-Review ($report.evidence.workspace_path.status -eq 'observed' -and $report.evidence.failed_path.status -eq 'observed') 'mapping recheck erased pinned observations'
                            if ($mode -eq 'stable') {
                                Assert-Review ($report.evidence.path_relation.final_within_workspace -eq $true) 'stable mapping lost its definite positive control'
                            } else {
                                $expected = if ($mode -eq 'unavailable') { 'PATH_TOPOLOGY_UNAVAILABLE' } else { 'PATH_TOPOLOGY_CHANGED' }
                                Assert-Review ($null -eq $report.evidence.path_relation.final_within_workspace -and @($report.results | Where-Object code -eq $expected).Count -eq 1) 'incomparable drive mappings produced definite containment'
                                Assert-Review (@($report.results | Where-Object code -eq 'REPARSE_TARGET_MISMATCH').Count -eq 0) 'mapping drift emitted a mismatch cause candidate'
                            }
                            Assert-Review ([BoundaryLensNativeFixture.Session]::FixtureOpens.Count -eq 5 -and [BoundaryLensNativeFixture.Session]::FixtureRemoteOpens -eq 0) 'mapping recheck opened a new target'
                            if ($kind -eq 'dos') {
                                $cache = $script:mappingWorkspaceSession.GetType().GetField('deviceMappings', [Reflection.BindingFlags]'NonPublic,Instance').GetValue($script:mappingWorkspaceSession)
                                Assert-Review ($cache['S:'] -ceq '\??\C:\one') 'mapping recheck replaced initial cached evidence'
                                Assert-Review (@([BoundaryLensNativeFixture.Session]::FixtureMappingQueries | Where-Object { $_ -eq 'S:' }).Count -gt 2) 'mapping recheck did not bypass the per-session cache'
                            }
                        } finally {
                            Set-Item -LiteralPath Function:Get-BoundaryObservation -Value $script:mappingOriginal
                            Remove-Item -LiteralPath Function:Get-PSDrive
                        }
                    }
                }
            }
            if ($SelectedGroup -in @('all','declared-nearest')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\broken', $true, '\??\C:\missing\target')
                foreach ($suffix in @('', '\child.txt')) {
                    $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath ('C:\workspace\broken'+$suffix) -Format Json | ConvertFrom-Json
                    Assert-Review ($report.evidence.failed_path.observations.nearest_existing_path.EndsWith('\workspace\broken') -and $report.evidence.failed_path.observations.existing_segment_count -eq 3) 'target reset discarded the nearest declared segment'
                    Assert-Review (($suffix -eq '' -and $report.evidence.failed_path.exists -eq $true) -or ($suffix -ne '' -and $null -eq $report.evidence.failed_path.exists)) 'endpoint and missing descendant existence were collapsed'
                }
                function Get-PSDrive {
                    param([string]$Name)
                    $root = if ($Name -eq 'Q') { 'C:\missing\backing' } else { $Name+':\' }
                    [pscustomobject]@{ Provider=[pscustomobject]@{Name='FileSystem'};Root=$root;DisplayRoot=$null }
                }
                try {
                    [BoundaryLensNativeFixture.Session]::FixtureMap('S:', '\??\C:\missing\backing')
                    foreach ($alias in @('Q','S')) {
                        $report = Invoke-BoundaryLens -Workspace ($alias+':\') -FailedPath ($alias+':\child') -Format Json | ConvertFrom-Json
                        Assert-Review ($report.evidence.workspace_path.observations.existing_segment_count -eq 0 -and $null -eq $report.evidence.workspace_path.observations.nearest_existing_path) 'an unreached logical root reported a nearest path'
                    }
                } finally { Remove-Item -LiteralPath Function:Get-PSDrive }
            }
            if ($SelectedGroup -in @('all','malformed-utf16')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\broken', $true, '\??\C:\placeholder')
                [BoundaryLensNativeFixture.Session]::FixtureBadUtf16('workspace\broken')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\broken' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED') 'malformed UTF-16 lost its target-resolution error classification'
                Assert-Review ($report.evidence.failed_path.exists -eq $true -and $report.evidence.path_relation.reparse_segment_observed -eq $true -and $null -eq $report.evidence.failed_path.final_path) 'malformed target lost the observed local link boundary'
                Assert-Review ([BoundaryLensNativeFixture.Session]::FixtureOpens.Count -eq 5 -and [BoundaryLensNativeFixture.Session]::FixtureRemoteOpens -eq 0) 'malformed target advanced traversal'
            }
            if ($SelectedGroup -in @('all','reserved')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                $session = [BoundaryLensNativeFixture.Session]::new()
                try {
                    $snapshot = $session.OpenPath('C:\synthetic\NUL.txt')
                    Assert-Review ($snapshot.Failure -eq 'REPARSE_TARGET_UNRESOLVED' -and [BoundaryLensNativeFixture.Session]::FixtureOpens.Count -eq 0) 'reserved native component reached an open'
                } finally { $session.Dispose() }
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\link', $true, '\??\C:\NUL.txt')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\link' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.failure.error_id -eq 'REPARSE_TARGET_UNRESOLVED' -and @([BoundaryLensNativeFixture.Session]::FixtureOpens | Where-Object { $_.EndsWith('\NUL.txt') }).Count -eq 0) 'reserved reparse target was opened'
            }
            if ($SelectedGroup -in @('all','volume-identity')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\item.txt', $false, $null)
                [BoundaryLensNativeFixture.Session]::FixtureCloneVolume()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\other', $true, '\??\D:\workspace')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\other\item.txt' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.final_path.StartsWith('\Device\HarddiskVolume1000\')) 'clone fixture did not reach its second native volume'
                Assert-Review ($report.evidence.path_relation.final_within_workspace -eq $false) 'matching cloned serial/file IDs collapsed different native volumes'
            }
            if ($SelectedGroup -in @('all','volume-alias')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\item.txt', $false, $null)
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\alias', $true, '\??\volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\workspace')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\alias\item.txt' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.failed_path.status -eq 'observed' -and $report.evidence.path_relation.final_within_workspace -eq $true) 'lowercase volume GUID alias was rejected'
            }
            if ($SelectedGroup -in @('all','segment-count')) {
                [BoundaryLensNativeFixture.Session]::FixtureReset()
                [BoundaryLensNativeFixture.Session]::FixtureAdd('physical\long\deep\item.txt', $false, $null)
                [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\link', $true, '\??\C:\physical\long\deep')
                $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\link\item.txt' -Format Json | ConvertFrom-Json
                Assert-Review ($report.evidence.workspace_path.observations.existing_segment_count -eq 2 -and $report.evidence.failed_path.observations.existing_segment_count -eq 4) 'target traversal inflated declared segment counts'
                $missing = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath 'C:\workspace\link\missing.txt' -Format Json | ConvertFrom-Json
                Assert-Review ($missing.evidence.failed_path.observations.existing_segment_count -eq 3 -and $missing.evidence.failed_path.exists -eq $false) 'missing suffix counted unobserved declared components or lost observed absence'
                function Get-PSDrive {
                    param([string]$Name)
                    $root = switch ($Name) { 'Q' { 'C:\physical\long\deep' }; 'R' { 'C:\missing\backing' }; default { $Name + ':\' } }
                    [pscustomobject]@{ Provider=[pscustomobject]@{Name='FileSystem'};Root=$root;DisplayRoot=$null }
                }
                try {
                    $report = Invoke-BoundaryLens -Workspace 'Q:\' -FailedPath 'Q:\item.txt' -Format Json | ConvertFrom-Json
                    Assert-Review ($report.evidence.workspace_path.observations.existing_segment_count -eq 1 -and $report.evidence.failed_path.observations.existing_segment_count -eq 2) 'PSDrive backing inflated declared segment counts'
                    [BoundaryLensNativeFixture.Session]::FixtureMap('S:', '\??\C:\missing\backing')
                    foreach ($alias in @('R','S')) {
                        $report = Invoke-BoundaryLens -Workspace ($alias+':\') -FailedPath ($alias+':\item.txt') -Format Json | ConvertFrom-Json
                        Assert-Review ($report.evidence.workspace_path.observations.existing_segment_count -eq 0 -and $report.evidence.failed_path.observations.existing_segment_count -eq 0) 'native volume root was counted before the declared alias root existed'
                    }
                } finally { Remove-Item -LiteralPath Function:Get-PSDrive }
            }
            if ($SelectedGroup -in @('all','remote')) {
                foreach ($case in @(@('workspace\outer', $true), @('workspace\outer\child.txt', $null))) {
                    [BoundaryLensNativeFixture.Session]::FixtureReset()
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace', $true, $null)
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('workspace\outer', $true, '\??\C:\landing\remote')
                    [BoundaryLensNativeFixture.Session]::FixtureAdd('landing\remote', $true, '\??\UNC\boundary-native-invalid\share')
                    $report = Invoke-BoundaryLens -Workspace 'C:\workspace' -FailedPath ('C:\' + $case[0]) -Format Json | ConvertFrom-Json
                    Assert-Review ($report.evidence.failed_path.status -eq 'collection-failure' -and $report.evidence.failed_path.failure.error_id -eq 'REMOTE_REPARSE_TARGET_UNSUPPORTED') 'common collector did not reject the nested remote target'
                    Assert-Review ($report.evidence.failed_path.exists -ceq $case[1]) 'endpoint/descendant existence was collapsed'
                    Assert-Review (@($report.evidence.failed_path.reparse_segments).Count -eq 2 -and $report.evidence.path_relation.reparse_segment_observed -eq $true) 'nested reparse observations were lost'
                    Assert-Review ($null -eq $report.evidence.failed_path.final_path -and $null -eq $report.evidence.path_relation.final_within_workspace -and $report.evidence.failed_path_acl.status -eq 'unknown') 'remote target produced final containment or ACL evidence'
                    Assert-Review (@($report.results | Where-Object { $_.status -eq 'unknown' -and $_.code -eq 'FINAL_CONTAINMENT_UNKNOWN' }).Count -eq 1) 'public remote failure omitted containment UNKNOWN'
                    Assert-Review ([BoundaryLensNativeFixture.Session]::FixtureRemoteOpens -eq 0 -and [BoundaryLensNativeFixture.Session]::FixtureContractViolations -eq 0) 'native boundary recorded a forbidden open or access mode'
                    Assert-Review (@([BoundaryLensNativeFixture.Session]::FixtureAclQueries).Count -eq 1 -and @([BoundaryLensNativeFixture.Session]::FixtureOpens | Where-Object { $_.EndsWith('\landing\remote\child.txt') }).Count -eq 0) 'collector probed the remote descendant or its ACL'
                }
            }
            if ($SelectedGroup -in @('all','bounds')) {
                $components = [BoundaryLensNativeFixture.Session].GetMethod('Components', [Reflection.BindingFlags]'NonPublic,Static')
                $atLimit = (('a' * 254 + '\') * 128) + ('b' * 120)
                Assert-Review ($atLimit.Length -eq 32760 -and @($components.Invoke($null, [object[]]@($atLimit))).Count -gt 0) '32760-character parser positive boundary failed'
                foreach ($invalid in @(($atLimit + 'b'), ('x' * 256), ((@('a') * 257) -join '\'))) {
                    $blocked = $false
                    try { $null = $components.Invoke($null, [object[]]@($invalid)) } catch { $blocked = $true }
                    Assert-Review $blocked 'length/component overflow was accepted'
                }
                foreach ($count in @(255,256,257)) {
                    [BoundaryLensNativeFixture.Session]::FixtureReset()
                    $relative = (@('a') * $count) -join '\'
                    [BoundaryLensNativeFixture.Session]::FixtureAdd($relative, $false, $null)
                    $session = [BoundaryLensNativeFixture.Session]::new()
                    $held = @()
                    try {
                        $snapshot = $session.OpenPath('C:\' + $relative)
                        $owned = $session.GetType().GetField('owned', [Reflection.BindingFlags]'NonPublic,Instance')
                        $held = @($owned.GetValue($session))
                        if ($count -eq 255) {
                            $snapshot = $session.Complete()
                            Assert-Review ($null -eq $snapshot.Failure -and $snapshot.Exists -eq $true -and $held.Count -eq 256) '256-owned-handle positive boundary failed'
                        } else {
                            $expectedOpens = if ($count -eq 256) { 256 } else { 0 }
                            Assert-Review ($snapshot.Failure -eq 'REPARSE_TARGET_UNRESOLVED' -and [BoundaryLensNativeFixture.Session]::FixtureOpens.Count -eq $expectedOpens) 'component/owned-handle overflow opened beyond its bound'
                        }
                        Assert-Review ([BoundaryLensNativeFixture.Session]::FixtureContractViolations -eq 0) 'bounded open used an unapproved mode'
                    } finally { $session.Dispose() }
                    Assert-Review (@($held | Where-Object { -not $_.IsClosed }).Count -eq 0) 'bounded traversal did not dispose its handles'
                }
            }
        } $fixtureProduct $Group
        if ($Group -in @('all','bounds')) {
            $longDirectory = $workspace
            for ($index = 0; $index -lt 8; $index++) { $longDirectory = Join-Path $longDirectory ('segment-' + ('x' * 30) + $index) }
            $null = [IO.Directory]::CreateDirectory($longDirectory)
            $longFile = Join-Path $longDirectory 'long.txt'
            [IO.File]::WriteAllText($longFile, 'long local path fixture')
            $report = Report-Review $workspace $longFile
            Assert-Review ($longFile.Length -gt 260 -and $report.evidence.failed_path.status -eq 'observed' -and $report.evidence.path_relation.final_within_workspace -eq $true) 'real local path beyond MAX_PATH failed'
        }
    }
    [Console]::Out.WriteLine("GREEN: review $Group group; $checks assertions; retained fixture $fixture")
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    [Console]::Error.WriteLine("Failure line $($_.InvocationInfo.ScriptLineNumber); retained fixture $fixture")
    exit 1
}
