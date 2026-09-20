function Classify-BoundaryEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Evidence)

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($failure in @($Evidence.collection_failures)) {
        if ($null -eq $failure) {
            continue
        }

        $results.Add([pscustomobject][ordered]@{
                status = 'collection-failure'
                code = [string]$failure.code
                message = [string]$failure.message
                evidence_refs = @($failure.evidence_refs)
                next_observation = [string]$failure.next_observation
            })
    }

    $relation = $Evidence.path_relation
    if (
        $relation.logical_within_workspace -eq $true -and
        $relation.reparse_segment_observed -eq $true -and
        $relation.final_workspace_observed -eq $true -and
        $relation.final_path_observed -eq $true -and
        $relation.final_within_workspace -eq $false
    ) {
        $results.Add([pscustomobject][ordered]@{
                status = 'cause-candidate'
                code = 'REPARSE_TARGET_MISMATCH'
                message = 'The observed logical and final boundary relations are consistent with a reparse target mismatch.'
                evidence_refs = @(
                    'path_relation.logical_within_workspace',
                    'path_relation.reparse_segment_observed',
                    'path_relation.final_workspace_observed',
                    'path_relation.final_path_observed',
                    'path_relation.final_within_workspace'
                )
                next_observation = 'Compare the observed reparse target with the operator-declared final workspace boundary.'
            })
    }

    foreach ($unknown in @($Evidence.unknowns)) {
        if ($null -eq $unknown) {
            continue
        }

        $results.Add([pscustomobject][ordered]@{
                status = 'unknown'
                code = [string]$unknown.code
                message = [string]$unknown.message
                evidence_refs = @($unknown.evidence_refs)
                next_observation = [string]$unknown.next_observation
            })
    }

    return $results
}

function Format-BoundaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report,
        [Parameter(Mandatory)][ValidateSet('Text','Json')][string]$Format
    )

    if ($Format -eq 'Json') {
        return ($Report | ConvertTo-Json -Depth 10 -Compress)
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $Report.PSObject.Properties['evidence']) {
        $records = @(
            foreach ($name in @('workspace_path', 'failed_path', 'workspace_acl', 'failed_path_acl')) {
                if ($null -ne $Report.evidence.PSObject.Properties[$name]) { $Report.evidence.$name }
            }
        )
        if ($records.Count -gt 0) {
            $observedCount = @($records | Where-Object { $_.status -eq 'observed' }).Count
            $failureCount = @($records | Where-Object { $_.status -eq 'collection-failure' }).Count
            $unknownCount = @($records | Where-Object { $_.status -eq 'unknown' }).Count
            $lines.Add("Observations: $observedCount/$($records.Count) records observed; $failureCount collection failures; $unknownCount records unobserved.")
        }
    }
    foreach ($result in @($Report.results)) {
        $references = @($result.evidence_refs) -join ','
        $lines.Add("[$($result.status.ToUpperInvariant())] $($result.code) | $($result.message) | evidence_refs=$references | next_observation=$($result.next_observation)")
    }

    return ($lines -join [Environment]::NewLine)
}

function Test-BoundaryUncPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    return -not [string]::IsNullOrEmpty($Path) -and $Path -match '^(?:\\\\|//)'
}

function Test-BoundaryUncDriveMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Root,
        [AllowNull()][AllowEmptyString()][string]$DisplayRoot
    )

    return (Test-BoundaryUncPath -Path $Root) -or ($null -ne $DisplayRoot -and (Test-BoundaryUncPath -Path $DisplayRoot))
}

function Get-BoundaryDriveMetadata {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    try { $drive = Get-PSDrive -Name $Name -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.DriveNotFoundException]) { $drive = $null }
        else { throw }
    }
    return [pscustomobject]@{
        name = $Name; present = $null -ne $drive
        provider = if ($null -ne $drive) { [string]$drive.Provider.Name } else { $null }
        root = if ($null -ne $drive) { [string]$drive.Root } else { $null }
        display = if ($null -ne $drive) { [string]$drive.DisplayRoot } else { $null }
    }
}

function Resolve-BoundaryDrivePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [AllowNull()][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Mappings)
    $current = $Path
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    for ($depth = 0; $depth -le 16; $depth++) {
        if (-not $visited.Add($current)) { throw 'REPARSE_TARGET_UNRESOLVED' }
        $name = $current.Substring(0, 1)
        $mapping = Get-BoundaryDriveMetadata -Name $name
        if ($null -ne $Mappings) { $Mappings.Add($mapping) }
        if (-not $mapping.present) { return $current }
        if ($mapping.provider -ne 'FileSystem') { throw 'REPARSE_TARGET_UNRESOLVED' }
        $root = $mapping.root
        $display = $mapping.display
        if ([string]::IsNullOrWhiteSpace($root)) { throw 'REPARSE_TARGET_UNRESOLVED' }
        if (Test-BoundaryUncDriveMetadata -Root $root -DisplayRoot $display) { throw 'REMOTE_REPARSE_TARGET_UNSUPPORTED' }
        $identityRoot = $name + ':\'
        $backing = $null
        foreach ($value in @($root, $display)) {
            if ([string]::IsNullOrEmpty($value)) { continue }
            if ($value -notmatch '^[A-Za-z]:[\\/]') { throw 'REPARSE_TARGET_UNRESOLVED' }
            $normalized = [System.IO.Path]::GetFullPath($value).TrimEnd([char]'\')
            if ([string]::Equals($normalized, $identityRoot.TrimEnd([char]'\'), [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($null -ne $backing -and -not [string]::Equals($backing, $normalized, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'REPARSE_TARGET_UNRESOLVED' }
            $backing = $normalized
        }
        if ($null -eq $backing) { return $current }
        $current = [System.IO.Path]::GetFullPath("$backing\$($current.Substring(3))")
    }
    throw 'REPARSE_TARGET_UNRESOLVED'
}

function Initialize-BoundaryNative {
    [CmdletBinding()]
    param()

    if ('BoundaryLensNative.Session' -as [type]) {
        if ([BoundaryLensNative.Session]::ContractId -cne 'boundary-lens-native-20260920-v6') { throw 'NATIVE_CONTRACT_MISMATCH' }
        return
    }
    # Exact embedded source and native call contract are checked by tests/read-only.ps1.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace BoundaryLensNative {
    public sealed class ReparseObservation {
        public string lexical_path;
        public string link_type;
        public string[] target;
    }
    public sealed class Snapshot {
        public bool? Exists;
        public bool Complete;
        public int Count;
        public int DeclaredCount;
        public string Nearest;
        public string DeclaredNearest;
        public string Final;
        public string Identity;
        public string[] Ancestors = new string[0];
        public string Failure;
        public string TopologyFailure;
        public string AclFailure;
        public byte[] Security;
        public readonly List<ReparseObservation> Reparses = new List<ReparseObservation>();
    }
    public sealed class BoundaryFailure : Exception {
        public readonly string Code;
        public BoundaryFailure(string code) : base(code) { Code = code; }
    }
    public sealed class Session : IDisposable {
        // Accidental cross-version reuse guard, not protection from hostile in-process code.
        public const string ContractId = "boundary-lens-native-20260920-v6";
        // All opens are existing-only, query-only, and non-following. No API accepts
        // an arbitrary access mask, disposition, native function or control code.
        const uint ReadAttributes = 0x80, ReadControl = 0x20000, Synchronize = 0x100000;
        const uint OpenExisting = 1, ShareReadWriteDelete = 7;
        const uint OpenReparse = 0x200000, OpenNoRecall = 0x400000, Synchronous = 0x20;
        const uint CaseInsensitive = 0x40, DontReparse = 0x1000;
        const uint GetReparsePoint = 0x900A8;
        const int MaxHops = 16, MaxComponents = 256;
        const uint AccessDenied = 0xC0000022, NameMissing = 0xC0000034, PathMissing = 0xC000003A;
        static readonly Regex LocalVolume = new Regex(@"^\\Device\\HarddiskVolume[0-9]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex DrivePath = new Regex(@"^[A-Za-z]:\\", RegexOptions.CultureInvariant);
        static readonly Regex VolumePath = new Regex(@"^Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex ReservedDevice = new Regex(@"^(?:(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3]) *(?:[.:]|$)|CONIN\$ *$|CONOUT\$ *$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        [StructLayout(LayoutKind.Sequential)]
        struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)]
        struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [StructLayout(LayoutKind.Sequential)]
        struct IoStatus { public IntPtr Status, Information; }
        [StructLayout(LayoutKind.Sequential)]
        struct FileInfo { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write; public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
        [StructLayout(LayoutKind.Sequential)]
        struct FileIdentity { public ulong VolumeSerial; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Id; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern uint QueryDosDeviceW(string name, [Out] char[] target, int length);
        [DllImport("ntdll.dll", ExactSpelling = true)]
        static extern uint NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo information);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out FileIdentity information, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder volume, uint volumeLength, out uint serial, out uint maximumComponent, out uint flags, StringBuilder filesystem, uint filesystemLength);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputLength, [Out] byte[] output, uint outputLength, out uint returned, IntPtr overlapped);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        static extern IntPtr LocalFree(IntPtr memory);

        sealed class Frame {
            public SafeFileHandle Handle;
            public bool CanReadAcl;
            public FileInfo Information;
            public string Identity;
            public string NameAtOpen;
            public string VolumeIdentity;
            public byte[] ReparseData;
        }
        sealed class Location {
            public string Device;
            public List<string> Components;
        }
        sealed class PendingPart {
            public string Name;
            public bool Declared;
        }
        readonly List<SafeFileHandle> owned = new List<SafeFileHandle>();
        readonly List<Frame> stack = new List<Frame>();
        readonly List<Frame> observedFrames = new List<Frame>();
        readonly Dictionary<string, string> deviceMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Snapshot result = new Snapshot();
        Frame final;
        bool disposed, opened;

        static BoundaryFailure Fail(string code) { return new BoundaryFailure(code); }
        static string RuntimeFailureCode(Exception error) {
            for (int depth = 0; depth < 8 && error.InnerException != null &&
                (error is TypeInitializationException || error is System.Reflection.TargetInvocationException); depth++)
                error = error.InnerException;
            return error is DllNotFoundException || error is EntryPointNotFoundException ||
                error is BadImageFormatException || error is PlatformNotSupportedException ||
                error is System.Security.SecurityException || error is MethodAccessException ||
                error is MarshalDirectiveException ? "NATIVE_COLLECTION_UNAVAILABLE" : "NATIVE_COLLECTION_FAILED";
        }
        static byte[] ReadReparseData(Frame frame) {
            var bytes = new byte[16384];
            uint count;
            if (!DeviceIoControl(frame.Handle, GetReparsePoint, IntPtr.Zero, 0, bytes, (uint)bytes.Length, out count, IntPtr.Zero) ||
                count < 8 || count > bytes.Length) throw Fail("REPARSE_TARGET_UNRESOLVED");
            Array.Resize(ref bytes, (int)count);
            return bytes;
        }
        static bool SameBytes(byte[] left, byte[] right) {
            if (left.Length != right.Length) return false;
            for (int i = 0; i < left.Length; i++) if (left[i] != right[i]) return false;
            return true;
        }
        // Compare captured controls, not names: distinct hard-link names are legitimate.
        // Contradictions stay unknown even if subsequent reads replay each old value.
        public void Reconcile(Session other) {
            if (disposed || (other != null && other.disposed)) throw Fail("PATH_PROBE_UNAVAILABLE");
            var captured = new Dictionary<string, Frame>(StringComparer.Ordinal);
            bool changed = false;
            foreach (Session session in other == null ? new Session[] { this } : new Session[] { this, other }) {
                foreach (Frame frame in session.observedFrames) {
                    Frame previous;
                    if (!captured.TryGetValue(frame.Identity, out previous)) { captured.Add(frame.Identity, frame); continue; }
                    if ((previous.Information.Attributes & 0x400) != (frame.Information.Attributes & 0x400) ||
                        (previous.ReparseData != null && frame.ReparseData != null && !SameBytes(previous.ReparseData, frame.ReparseData)))
                        changed = true;
                }
            }
            if (other != null) foreach (var mapping in deviceMappings) {
                string value;
                if (other.deviceMappings.TryGetValue(mapping.Key, out value) && !String.Equals(mapping.Value, value, StringComparison.Ordinal))
                    changed = true;
            }
            if (changed) {
                result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                if (other != null) other.result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
            }
        }

        // Pure rejection is performed before QueryDosDevice or any file open.
        static void CheckRemote(string value) {
            if (value.StartsWith(@"\\", StringComparison.Ordinal) &&
                !value.StartsWith(@"\\?\", StringComparison.Ordinal)) throw Fail("REMOTE_REPARSE_TARGET_UNSUPPORTED");
            if (value.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(@"\Device\Mup", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(@"\Device\LanmanRedirector", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(value, @"^[A-Za-z][A-Za-z0-9+.-]*://")) throw Fail("REMOTE_REPARSE_TARGET_UNSUPPORTED");
        }
        static List<string> Components(string value) {
            if (value.Length > 32760 || value.IndexOf('\0') >= 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
            var parts = new List<string>();
            foreach (string part in value.Split('\\')) {
                if (part.Length == 0 || part == ".") continue;
                if (ReservedDevice.IsMatch(part)) throw Fail("REPARSE_TARGET_UNRESOLVED");
                if (part != ".." && (part.Length > 255 || part.IndexOfAny(new char[] { ':', '*', '?', '"', '<', '>', '|', '/' }) >= 0 ||
                    part.EndsWith(" ", StringComparison.Ordinal) || part.EndsWith(".", StringComparison.Ordinal)))
                    throw Fail("REPARSE_TARGET_UNRESOLVED");
                parts.Add(part);
            }
            if (parts.Count > MaxComponents) throw Fail("REPARSE_TARGET_UNRESOLVED");
            return parts;
        }
        static string QueryDeviceMapping(string alias) {
            var buffer = new char[32768];
            uint length = QueryDosDeviceW(alias, buffer, buffer.Length);
            if (length == 0 && Marshal.GetLastWin32Error() == 2) throw Fail("TARGET_NOT_OBSERVED");
            if (length == 0 || length > buffer.Length) throw Fail("NATIVE_VOLUME_UNSUPPORTED");
            int end = Array.IndexOf(buffer, '\0', 0, (int)length);
            if (end < 1) throw Fail("NATIVE_VOLUME_UNSUPPORTED");
            // QueryDosDevice returns the current mapping first; later strings are old mappings.
            return new string(buffer, 0, end);
        }
        string DeviceMapping(string alias) {
            string value;
            if (deviceMappings.TryGetValue(alias, out value)) return value;
            value = QueryDeviceMapping(alias);
            deviceMappings.Add(alias, value);
            return value;
        }
        Location Locate(string value) {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            CheckRemote(value);
            value = value.Replace('/', '\\');
            for (int depth = 0; depth <= MaxHops; depth++) {
                CheckRemote(value);
                if (!visited.Add(value)) throw Fail("REPARSE_TARGET_UNRESOLVED");
                if (value.StartsWith(@"\??\", StringComparison.Ordinal) || value.StartsWith(@"\\?\", StringComparison.Ordinal))
                    value = value.Substring(4);
                string alias, suffix;
                if (DrivePath.IsMatch(value)) { alias = value.Substring(0, 2); suffix = value.Substring(3); }
                else {
                    Match volume = VolumePath.Match(value);
                    if (volume.Success) { alias = value.Substring(0, volume.Length - 1); suffix = value.Substring(volume.Length); }
                    else {
                        int separator = value.IndexOf('\\', @"\Device\".Length);
                        string device = separator < 0 ? value : value.Substring(0, separator);
                        if (!LocalVolume.IsMatch(device)) throw Fail("NATIVE_VOLUME_UNSUPPORTED");
                        return new Location { Device = device, Components = Components(separator < 0 ? "" : value.Substring(separator + 1)) };
                    }
                }
                value = DeviceMapping(alias).TrimEnd('\\') + "\\" + suffix;
            }
            throw Fail("REPARSE_TARGET_UNRESOLVED");
        }
        Frame Open(Frame parent, string name, bool root) {
            if (owned.Count >= MaxComponents) throw Fail("REPARSE_TARGET_UNRESOLVED");
            IntPtr text = IntPtr.Zero, unicode = IntPtr.Zero;
            try {
                if (name.Length == 0 || name.Length > 32760) throw Fail("REPARSE_TARGET_UNRESOLVED");
                text = Marshal.StringToHGlobalUni(name);
                var us = new UnicodeString { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2 + 2)), Buffer = text };
                unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(us, unicode, false);
                var oa = new ObjectAttributes {
                    Length = Marshal.SizeOf(typeof(ObjectAttributes)), ObjectName = unicode,
                    RootDirectory = parent == null ? IntPtr.Zero : parent.Handle.DangerousGetHandle(),
                    Attributes = CaseInsensitive | (root ? DontReparse : 0)
                };
                IoStatus io;
                SafeFileHandle handle;
                uint access = ReadAttributes | ReadControl | Synchronize;
                uint status = NtCreateFile(out handle, access, ref oa, out io, IntPtr.Zero, 0, ShareReadWriteDelete, OpenExisting, OpenReparse | OpenNoRecall | Synchronous, IntPtr.Zero, 0);
                bool canReadAcl = true;
                if (status == AccessDenied) {
                    if (handle != null) handle.Dispose();
                    canReadAcl = false;
                    status = NtCreateFile(out handle, ReadAttributes | Synchronize, ref oa, out io, IntPtr.Zero, 0, ShareReadWriteDelete, OpenExisting, OpenReparse | OpenNoRecall | Synchronous, IntPtr.Zero, 0);
                }
                if (status != 0 || handle == null || handle.IsInvalid) {
                    if (handle != null) handle.Dispose();
                    if (status == NameMissing || status == PathMissing) throw Fail("TARGET_NOT_OBSERVED");
                    throw Fail("PATH_PROBE_UNAVAILABLE");
                }
                owned.Add(handle);
                FileInfo info;
                FileIdentity identity;
                if (!GetFileInformationByHandle(handle, out info) ||
                    !GetFileInformationByHandleEx(handle, 18, out identity, (uint)Marshal.SizeOf(typeof(FileIdentity))))
                    throw Fail("PATH_PROBE_UNAVAILABLE");
                var frame = new Frame { Handle = handle, CanReadAcl = canReadAcl, Information = info,
                    Identity = identity.VolumeSerial.ToString("x16") + ":" + BitConverter.ToString(identity.Id) };
                frame.NameAtOpen = FinalName(frame);
                frame.VolumeIdentity = parent == null ? frame.NameAtOpen.TrimEnd('\\') : parent.VolumeIdentity;
                frame.Identity = frame.VolumeIdentity + "|" + frame.Identity;
                if (parent != null) {
                    int separator = frame.NameAtOpen.LastIndexOf('\\');
                    string observedParent = separator < 0 ? "" : frame.NameAtOpen.Substring(0, separator);
                    if (!String.Equals(observedParent, parent.NameAtOpen.TrimEnd('\\'), StringComparison.Ordinal))
                        result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                }
                observedFrames.Add(frame);
                return frame;
            }
            finally {
                if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
                if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
            }
        }
        static string FinalName(Frame frame) {
            var path = new StringBuilder(32768);
            uint count = GetFinalPathNameByHandleW(frame.Handle, path, (uint)path.Capacity, 2);
            if (count == 0 || count >= path.Capacity) throw Fail("PATH_RESOLUTION_FAILED");
            return path.ToString();
        }
        void Root(Location location) {
            // No DOS alias is opened. Device namespace is trusted by the declared threat model.
            if (!LocalVolume.IsMatch(location.Device)) throw Fail("NATIVE_VOLUME_UNSUPPORTED");
            Frame root = Open(null, location.Device + "\\", true);
            if ((root.Information.Attributes & 0x10) == 0 || (root.Information.Attributes & 0x400) != 0)
                throw Fail("NATIVE_VOLUME_UNSUPPORTED");
            uint serial, componentLength, flags;
            var filesystem = new StringBuilder(32);
            if (!GetVolumeInformationByHandleW(root.Handle, null, 0, out serial, out componentLength, out flags, filesystem, (uint)filesystem.Capacity) ||
                (filesystem.ToString() != "NTFS" && filesystem.ToString() != "ReFS"))
                throw Fail("NATIVE_VOLUME_UNSUPPORTED");
            stack.Clear();
            stack.Add(root);
            result.Count++;
            result.Nearest = FinalName(root);
        }
        static string ParseReparse(byte[] bytes, int count, out bool relative, out string kind) {
            relative = false;
            kind = null;
            if (count < 16 || count > bytes.Length) throw Fail("REPARSE_TARGET_UNRESOLVED");
            uint tag = BitConverter.ToUInt32(bytes, 0);
            int end = 8 + BitConverter.ToUInt16(bytes, 4);
            int start;
            if (tag == 0xA000000C) {
                if (count < 20) throw Fail("REPARSE_TARGET_UNRESOLVED");
                uint flags = BitConverter.ToUInt32(bytes, 16);
                if ((flags & ~1U) != 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
                relative = flags == 1; kind = "SymbolicLink"; start = 20;
            }
            else if (tag == 0xA0000003) { kind = "Junction"; start = 16; }
            else throw Fail("REPARSE_TARGET_UNRESOLVED");
            int offset = BitConverter.ToUInt16(bytes, 8), length = BitConverter.ToUInt16(bytes, 10);
            int printOffset = BitConverter.ToUInt16(bytes, 12), printLength = BitConverter.ToUInt16(bytes, 14);
            if (end != count || end < start || (offset | length | printOffset | printLength) % 2 != 0 ||
                length == 0 || start + offset + length > end || start + printOffset + printLength > end)
                throw Fail("REPARSE_TARGET_UNRESOLVED");
            string target;
            try { target = new UnicodeEncoding(false, false, true).GetString(bytes, start + offset, length); }
            catch (DecoderFallbackException) { throw Fail("REPARSE_TARGET_UNRESOLVED"); }
            if (target.IndexOf('\0') >= 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
            return target;
        }
        public Snapshot OpenPath(string canonicalDosPath, int declaredSuffixCount = -1) {
            if (disposed || opened) throw Fail("PATH_PROBE_UNAVAILABLE");
            opened = true;
            try {
                Location location = Locate(canonicalDosPath);
                string input = canonicalDosPath.Replace('/', '\\');
                int suffixCount = declaredSuffixCount < 0 ? (DrivePath.IsMatch(input) ? Components(input.Substring(3)).Count : location.Components.Count) : declaredSuffixCount;
                int backingCount = location.Components.Count - suffixCount;
                if (declaredSuffixCount < -1 || suffixCount > MaxComponents || backingCount < 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
                Root(location);
                // The logical root exists only after its PSDrive/SUBST backing is reached.
                if (backingCount == 0) { result.DeclaredCount = 1; result.DeclaredNearest = result.Nearest; }
                var pending = new List<PendingPart>();
                for (int i = 0; i < location.Components.Count; i++)
                    pending.Add(new PendingPart { Name = location.Components[i], Declared = i >= backingCount - 1 });
                int hops = 0, steps = 0;
                while (pending.Count > 0) {
                    if (++steps > MaxComponents) throw Fail("REPARSE_TARGET_UNRESOLVED");
                    PendingPart part = pending[0]; pending.RemoveAt(0);
                    Frame parent = stack[stack.Count - 1];
                    if ((parent.Information.Attributes & 0x10) == 0) throw Fail("PATH_PROBE_UNAVAILABLE");
                    if (part.Name == "..") {
                        if (stack.Count > 1) stack.RemoveAt(stack.Count - 1);
                        if (part.Declared) { result.DeclaredCount++; result.DeclaredNearest = stack[stack.Count - 1].NameAtOpen; }
                        continue;
                    }
                    Frame child;
                    try { child = Open(parent, part.Name, false); }
                    catch (BoundaryFailure failure) {
                        if (failure.Code == "TARGET_NOT_OBSERVED") {
                            if (!part.Declared && result.Reparses.Count > 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
                            result.Complete = true;
                            if (part.Declared && pending.Count == 0) result.Exists = false;
                        }
                        throw;
                    }
                    result.Count++;
                    if (part.Declared) { result.DeclaredCount++; result.DeclaredNearest = child.NameAtOpen; }
                    if (pending.Count == 0) result.Exists = true;
                    result.Nearest = FinalName(child);
                    if ((child.Information.Attributes & 0x400) != 0) {
                        // The reparse attribute is already observed even if its data
                        // is unsupported, unavailable, malformed, or over the hop limit.
                        var observedLink = new ReparseObservation { lexical_path = result.Nearest, link_type = null, target = new string[0] };
                        result.Reparses.Add(observedLink);
                        // A repeated link can consume a finite pending suffix. The hard
                        // hop/component/handle bounds terminate cycles without rejecting it.
                        if (++hops > MaxHops) throw Fail("REPARSE_TARGET_UNRESOLVED");
                        child.ReparseData = ReadReparseData(child);
                        bool relative; string kind;
                        string target = ParseReparse(child.ReparseData, child.ReparseData.Length, out relative, out kind);
                        observedLink.link_type = kind;
                        observedLink.target = new string[] { target };
                        CheckRemote(target);
                        List<string> prefix;
                        if (relative) {
                            if (target.StartsWith(@"\", StringComparison.Ordinal) || target.StartsWith("/", StringComparison.Ordinal) || target.IndexOf(':') >= 0) throw Fail("REPARSE_TARGET_UNRESOLVED");
                            prefix = Components(target.Replace('/', '\\'));
                        }
                        else {
                            try { location = Locate(target); Root(location); }
                            catch (BoundaryFailure failure) {
                                if (failure.Code == "TARGET_NOT_OBSERVED") throw Fail("REPARSE_TARGET_UNRESOLVED");
                                throw;
                            }
                            prefix = location.Components;
                        }
                        var expanded = new List<PendingPart>();
                        foreach (string name in prefix) expanded.Add(new PendingPart { Name = name, Declared = false });
                        expanded.AddRange(pending);
                        if (expanded.Count > MaxComponents) throw Fail("REPARSE_TARGET_UNRESOLVED");
                        pending = expanded;
                    }
                    else { stack.Add(child); }
                }
                final = stack[stack.Count - 1];
                result.Exists = true;
                result.Complete = true;
                result.Identity = final.Identity;
                var ancestors = new List<string>();
                foreach (Frame frame in stack) ancestors.Add(frame.Identity);
                result.Ancestors = ancestors.ToArray();
            }
            catch (BoundaryFailure failure) { result.Failure = failure.Code; }
            catch (Exception error) { result.Failure = RuntimeFailureCode(error); }
            return result;
        }
        // Revalidate observed names through retained handles. A detected change is sticky;
        // this does not claim an atomic snapshot or rule out unobserved intervening moves.
        public Snapshot Refresh() {
            if (disposed || !opened) throw Fail("PATH_PROBE_UNAVAILABLE");
            Reconcile(null);
            if (final == null || result.Failure != null) return result;
            // Query only the original aliases. Do not replace their captured values,
            // resolve the new value, or open any newly selected target.
            foreach (var mapping in deviceMappings) {
                try {
                    if (!String.Equals(QueryDeviceMapping(mapping.Key), mapping.Value, StringComparison.Ordinal))
                        result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                }
                catch {
                    if (result.TopologyFailure == null) result.TopologyFailure = "PATH_TOPOLOGY_UNAVAILABLE";
                }
            }
            foreach (Frame frame in observedFrames) {
                try {
                    FileInfo current;
                    if (!GetFileInformationByHandle(frame.Handle, out current)) throw Fail("PATH_PROBE_UNAVAILABLE");
                    if ((current.Attributes & 0x400) != (frame.Information.Attributes & 0x400))
                        result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                    else if (frame.ReparseData != null && !SameBytes(frame.ReparseData, ReadReparseData(frame)))
                        result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                    string currentName = FinalName(frame);
                    if (!String.Equals(currentName, frame.NameAtOpen, StringComparison.Ordinal))
                        result.TopologyFailure = "PATH_TOPOLOGY_CHANGED";
                    if (Object.ReferenceEquals(frame, final)) result.Final = currentName;
                }
                catch {
                    if (result.TopologyFailure == null) result.TopologyFailure = "PATH_TOPOLOGY_UNAVAILABLE";
                }
            }
            return result;
        }
        // Completion only reads the already-owned final object. Names are never reopened.
        public Snapshot Complete() {
            if (disposed || !opened) throw Fail("PATH_PROBE_UNAVAILABLE");
            if (final == null || result.Failure != null) return result;
            try { result.Final = FinalName(final); }
            catch (BoundaryFailure failure) { result.Failure = failure.Code; return result; }
            catch (Exception error) { result.Failure = RuntimeFailureCode(error); return result; }
            Refresh();
            if (!final.CanReadAcl) return result;
            IntPtr owner, group, dacl, sacl, descriptor = IntPtr.Zero;
            try {
                if (GetSecurityInfo(final.Handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor) != 0 || descriptor == IntPtr.Zero)
                    return result;
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length < 20 || length > 1048576) return result;
                var security = new byte[(int)length];
                Marshal.Copy(descriptor, security, 0, security.Length);
                result.Security = security;
            }
            catch (Exception error) { result.AclFailure = RuntimeFailureCode(error); }
            finally {
                if (descriptor != IntPtr.Zero) {
                    try { LocalFree(descriptor); }
                    catch (Exception error) { result.AclFailure = RuntimeFailureCode(error); }
                }
            }
            return result;
        }
        public void Dispose() {
            if (disposed) return;
            disposed = true;
            for (int i = owned.Count - 1; i >= 0; i--) owned[i].Dispose();
            owned.Clear();
        }
    }
}
'@ -ErrorAction Stop
}

function Test-BoundaryInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$ParameterName
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $exception = [System.ArgumentException]::new("$ParameterName must be a nonblank Windows filesystem path.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if (
        $Path -match '^(?i:(vscode-remote|ssh|wsl|sftp|ftp|http|https):)' -or
        (Test-BoundaryUncPath -Path $Path)
    ) {
        $exception = [System.ArgumentException]::new("$ParameterName uses a remote or WSL path form outside the Windows-local scope.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_REMOTE_UNSUPPORTED', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if ($Path -match '^[A-Za-z][A-Za-z0-9_.-]*::') {
        $exception = [System.ArgumentException]::new("$ParameterName must use the FileSystem provider, not a provider-qualified path.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if ($Path -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
        $exception = [System.ArgumentException]::new("$ParameterName uses a URI form outside the Windows-local scope.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_REMOTE_UNSUPPORTED', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if ($Path -match '^[A-Za-z][A-Za-z0-9_-]*:[\\/]' -and $Path -notmatch '^[A-Za-z]:[\\/]') {
        $exception = [System.ArgumentException]::new("$ParameterName uses unsupported multi-character PowerShell drive syntax.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if ($Path -match '^[A-Za-z][A-Za-z0-9+.-]*:' -and $Path -notmatch '^[A-Za-z]:') {
        $exception = [System.ArgumentException]::new("$ParameterName uses a URI form outside the Windows-local scope.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_REMOTE_UNSUPPORTED', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if ($Path -notmatch '^[A-Za-z]:[\\/]') {
        $exception = [System.ArgumentException]::new("$ParameterName must be a raw one-letter drive-qualified absolute path.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    $reservedDevice = '^(?:(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3]) *(?:[.:]|$)|CONIN\$ *$|CONOUT\$ *$)'
    foreach ($component in ($Path.Substring(3) -split '[\\/]')) {
        if ([System.Text.RegularExpressions.Regex]::IsMatch($component, $reservedDevice, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            $exception = [System.ArgumentException]::new('Reserved DOS device components are outside the supported filesystem path syntax.')
            throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
        }
    }

    $driveName = $Path.Substring(0, 1)
    $drive = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
    if ($null -ne $drive -and $drive.Provider.Name -ne 'FileSystem') {
        $exception = [System.ArgumentException]::new("$ParameterName must use the FileSystem provider.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }
    if ($null -ne $drive -and (Test-BoundaryUncDriveMetadata -Root $drive.Root -DisplayRoot $drive.DisplayRoot)) {
        $exception = [System.ArgumentException]::new("$ParameterName resolves through a UNC-backed drive outside the Windows-local scope.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_REMOTE_UNSUPPORTED', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    try {
        $lexicalPath = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        $exception = [System.ArgumentException]::new("$ParameterName is not a valid Windows filesystem path.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if (Test-BoundaryUncPath -Path $lexicalPath) {
        $exception = [System.ArgumentException]::new("$ParameterName normalized to a UNC path outside the Windows-local scope.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_REMOTE_UNSUPPORTED', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    if (-not [System.IO.Path]::IsPathFullyQualified($lexicalPath)) {
        $exception = [System.ArgumentException]::new("$ParameterName must be a raw one-letter drive-qualified absolute path.")
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path)
    }

    return $lexicalPath
}

function Get-BoundaryObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][ValidateSet('workspace','failed-path')][string]$Role
    )
    $lexical = Test-BoundaryInput -Path $RawPath -ParameterName $Role
    $pathRecord = [pscustomobject][ordered]@{
        probe = 'path'; status = 'collection-failure'; raw_input = $RawPath
        lexical_path = $lexical; exists = $null; final_path = $null; reparse_segments = @()
        observations = [pscustomobject][ordered]@{
            role = $Role; provider = 'FileSystem'; existing_segment_count = 0
            nearest_existing_path = $null; reparse_observation_complete = $false
        }
        failure = $null
    }
    $session = $null
    $snapshot = $null
    $driveMappings = [System.Collections.Generic.List[object]]::new()
    $code = 'NATIVE_COLLECTION_UNAVAILABLE'
    try {
        $canonical = Resolve-BoundaryDrivePath -Path $lexical -Mappings $driveMappings
        Initialize-BoundaryNative
        $session = [BoundaryLensNative.Session]::new()
        $declaredSuffixCount = @($lexical.Substring(3) -split '[\\/]' | Where-Object { $_.Length -gt 0 }).Count
        $snapshot = $session.OpenPath($canonical, $declaredSuffixCount)
        $snapshot = $session.Complete()
        $code = $snapshot.Failure
        $pathRecord.exists = $snapshot.Exists
        $pathRecord.final_path = $snapshot.Final
        $pathRecord.reparse_segments = @($snapshot.Reparses | ForEach-Object {
            [pscustomobject][ordered]@{ lexical_path = $_.lexical_path; link_type = $_.link_type; target = @($_.target) }
        })
        $pathRecord.observations.existing_segment_count = $snapshot.DeclaredCount
        $pathRecord.observations.nearest_existing_path = $snapshot.DeclaredNearest
        $pathRecord.observations.reparse_observation_complete = $snapshot.Complete
        $pathRecord.status = if ($null -eq $code) { 'observed' } elseif ($code -eq 'TARGET_NOT_OBSERVED' -and $Role -eq 'failed-path') { 'unknown' } else { 'collection-failure' }
        if ($code -eq 'TARGET_NOT_OBSERVED' -and $Role -eq 'workspace') { $code = 'WORKSPACE_NOT_FOUND' }
    }
    catch {
        if ($_.Exception.Message -in @('REPARSE_TARGET_UNRESOLVED', 'REMOTE_REPARSE_TARGET_UNSUPPORTED')) { $code = $_.Exception.Message }
        if ($null -ne $session) { $session.Dispose(); $session = $null }
    }
    if ($null -ne $code) {
        $pathRecord.failure = [pscustomobject][ordered]@{
            error_id = $code
            message = 'The requested local observation could not be completed within the supported native collection boundary.'
        }
    }
    $acl = New-BoundaryAclUnknownEvidence -RawPath $RawPath -Role $Role
    if ($pathRecord.status -eq 'observed') {
        $acl = ConvertFrom-BoundaryNativeAcl -Security $snapshot.Security -RawPath $RawPath -Role $Role
        if ($null -ne $snapshot.AclFailure) {
            $acl.status = 'collection-failure'
            $acl.failure = [pscustomobject][ordered]@{ error_id = $snapshot.AclFailure; message = 'The native ACL observation could not be completed.' }
        }
    }
    return [pscustomobject]@{
        path = $pathRecord; acl = $acl; session = $session
        identity = if ($null -ne $snapshot) { $snapshot.Identity } else { $null }
        ancestors = if ($null -ne $snapshot) { @($snapshot.Ancestors) } else { @() }
        topology_code = if ($null -ne $snapshot) { $snapshot.TopologyFailure } else { $null }
        drive_mappings = @($driveMappings)
    }
}

function Get-BoundaryPathEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RawPath, [Parameter(Mandatory)][string]$Role)
    $observation = Get-BoundaryObservation -RawPath $RawPath -Role $Role
    try { return $observation.path }
    finally { if ($null -ne $observation.session) { $observation.session.Dispose() } }
}

function Get-BoundaryIdentityFingerprint {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Identity)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Identity))
        $hex = [System.BitConverter]::ToString($digest).Replace('-', '')
        return $hex.Substring(0, 12).ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function ConvertFrom-BoundaryNativeAcl {
    [CmdletBinding()]
    param(
        [AllowNull()][byte[]]$Security,
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][ValidateSet('workspace','failed-path')][string]$Role
    )
    $record = [pscustomobject][ordered]@{
        probe = 'acl'; status = 'collection-failure'; raw_input = $RawPath; role = $Role
        protected = $null; owner_fingerprint = $null; access_rules = @()
        failure = [pscustomobject][ordered]@{ error_id = 'ACL_COLLECTION_FAILED'; message = 'The ACL could not be observed with the current process access.' }
    }
    try {
        if ($null -eq $Security -or $Security.Length -eq 0) { return $record }
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Security, 0)
        if ($null -eq $descriptor.DiscretionaryAcl -or ($descriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) {
            $record.failure = [pscustomobject][ordered]@{
                error_id = 'ACL_DACL_UNSUPPORTED'
                message = 'A null or absent DACL cannot be represented by the supported ACL summary.'
            }
            return $record
        }
        if ($null -eq $descriptor.Owner) { return $record }
        $rules = [System.Collections.Generic.List[object]]::new()
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.OpaqueLength -ne 0 -or $ace.AceQualifier -notin @('AccessAllowed', 'AccessDenied')) {
                $record.failure = [pscustomobject][ordered]@{
                    error_id = 'ACL_ACE_UNSUPPORTED'
                    message = 'An ACE shape contains restrictions that the supported ACL summary cannot represent.'
                }
                return $record
            }
            $rules.Add([pscustomobject][ordered]@{
                access_type = if ($ace.AceQualifier -eq 'AccessAllowed') { 'allow' } else { 'deny' }
                # Inheritable ACEs can retain generic bits without a named FileSystemRights value.
                rights = [string]([System.Enum]::ToObject([System.Security.AccessControl.FileSystemRights], $ace.AccessMask))
                inherited = [bool]($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited)
                identity_fingerprint = Get-BoundaryIdentityFingerprint -Identity $ace.SecurityIdentifier.Value
            })
        }
        $record.owner_fingerprint = Get-BoundaryIdentityFingerprint -Identity $descriptor.Owner.Value
        $record.protected = [bool]($descriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        $record.access_rules = @($rules)
        $record.status = 'observed'
        $record.failure = $null
    }
    catch { }
    return $record
}

function Get-BoundaryAclEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RawPath, [Parameter(Mandatory)][string]$Role)
    $observation = Get-BoundaryObservation -RawPath $RawPath -Role $Role
    try {
        if ($observation.acl.status -eq 'unknown') { return ConvertFrom-BoundaryNativeAcl -Security $null -RawPath $RawPath -Role $Role }
        return $observation.acl
    }
    finally { if ($null -ne $observation.session) { $observation.session.Dispose() } }
}

function New-BoundaryAclUnknownEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][ValidateSet('workspace','failed-path')][string]$Role
    )

    return [pscustomobject][ordered]@{
        probe = 'acl'
        status = 'unknown'
        raw_input = $RawPath
        role = $Role
        protected = $null
        owner_fingerprint = $null
        access_rules = @()
        failure = [pscustomobject][ordered]@{
            error_id = 'ACL_NOT_OBSERVED'
            message = 'ACL collection was skipped because a verified local final path was not established.'
        }
    }
}

function Test-BoundaryContainment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Candidate
    )

    $normalizedRoot = $Root -replace '/', '\'
    $normalizedCandidate = $Candidate -replace '/', '\'
    $rootRoot = [System.IO.Path]::GetPathRoot($normalizedRoot)
    if ($normalizedRoot.Length -gt $rootRoot.Length) {
        $normalizedRoot = $normalizedRoot.TrimEnd([char]'\')
    }
    $candidateRoot = [System.IO.Path]::GetPathRoot($normalizedCandidate)
    if ($normalizedCandidate.Length -gt $candidateRoot.Length) {
        $normalizedCandidate = $normalizedCandidate.TrimEnd([char]'\')
    }

    if ([string]::Equals($normalizedRoot, $normalizedCandidate, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    if ($normalizedRoot.EndsWith('\', [System.StringComparison]::Ordinal)) {
        return $normalizedCandidate.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)
    }
    return $normalizedCandidate.StartsWith("$normalizedRoot\", [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-BoundaryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Workspace,
        [Parameter(Mandatory)][AllowEmptyString()][string]$FailedPath
    )

    $workspaceObservation = $null
    $failedObservation = $null
    try {
    $workspaceObservation = Get-BoundaryObservation -RawPath $Workspace -Role 'workspace'
    $failedObservation = Get-BoundaryObservation -RawPath $FailedPath -Role 'failed-path'
    $topologyCode = $null
    if ($null -ne $workspaceObservation.session -and $null -ne $failedObservation.session) {
        $workspaceObservation.session.Reconcile($failedObservation.session)
    }
    # Reconcile captured provider mappings before any fresh queries can mask a contradiction.
    $capturedDriveMappings = @{}
    foreach ($observation in @($workspaceObservation, $failedObservation)) {
        if ($null -eq $observation.PSObject.Properties['drive_mappings']) { continue }
        foreach ($capturedMapping in $observation.drive_mappings) {
            if ($capturedDriveMappings.ContainsKey($capturedMapping.name)) {
                $previousMapping = $capturedDriveMappings[$capturedMapping.name]
                $changedMapping = $previousMapping.present -ne $capturedMapping.present
                foreach ($field in @('provider', 'root', 'display')) {
                    if (-not [string]::Equals($previousMapping.$field, $capturedMapping.$field, [System.StringComparison]::Ordinal)) { $changedMapping = $true }
                }
                if ($changedMapping) { $topologyCode = 'PATH_TOPOLOGY_CHANGED' }
            } else { $capturedDriveMappings[$capturedMapping.name] = $capturedMapping }
        }
    }
    foreach ($observation in @($workspaceObservation, $failedObservation)) {
        if ($null -ne $observation.PSObject.Properties['drive_mappings']) {
            foreach ($capturedMapping in $observation.drive_mappings) {
                try {
                    $currentMapping = Get-BoundaryDriveMetadata -Name $capturedMapping.name
                    $changedMapping = $currentMapping.present -ne $capturedMapping.present
                    foreach ($field in @('provider', 'root', 'display')) {
                        if (-not [string]::Equals($currentMapping.$field, $capturedMapping.$field, [System.StringComparison]::Ordinal)) { $changedMapping = $true }
                    }
                    if ($changedMapping) { $observation.topology_code = 'PATH_TOPOLOGY_CHANGED' }
                }
                catch { if ($null -eq $observation.topology_code) { $observation.topology_code = 'PATH_TOPOLOGY_UNAVAILABLE' } }
            }
        }
        if ($null -ne $observation.session) {
            $snapshot = $observation.session.Refresh()
            if ($null -ne $snapshot.TopologyFailure -and ($null -eq $observation.topology_code -or $snapshot.TopologyFailure -eq 'PATH_TOPOLOGY_CHANGED')) { $observation.topology_code = $snapshot.TopologyFailure }
            if ($null -ne $snapshot.Final) { $observation.path.final_path = $snapshot.Final }
        }
        if ($null -ne $observation.PSObject.Properties['topology_code'] -and $null -ne $observation.topology_code) {
            if ($null -eq $topologyCode -or $observation.topology_code -eq 'PATH_TOPOLOGY_CHANGED') { $topologyCode = $observation.topology_code }
        }
    }
    $workspacePathEvidence = $workspaceObservation.path
    $failedPathEvidence = $failedObservation.path
    $workspaceAcl = $workspaceObservation.acl
    $failedPathAcl = $failedObservation.acl

    $logicalWithinWorkspace = if ($null -ne $workspacePathEvidence.lexical_path -and $null -ne $failedPathEvidence.lexical_path) {
        Test-BoundaryContainment -Root $workspacePathEvidence.lexical_path -Candidate $failedPathEvidence.lexical_path
    }
    else {
        $null
    }
    $workspaceHasReparse = @($workspacePathEvidence.reparse_segments).Count -gt 0
    $failedPathHasReparse = @($failedPathEvidence.reparse_segments).Count -gt 0
    $reparseSegmentObserved = if ($workspaceHasReparse -or $failedPathHasReparse) {
        $true
    }
    elseif ($workspacePathEvidence.observations.reparse_observation_complete -eq $true -and $failedPathEvidence.observations.reparse_observation_complete -eq $true) {
        $false
    }
    else {
        $null
    }
    $finalWorkspaceObserved = if ($null -ne $workspacePathEvidence.final_path) { $true } else { $null }
    $finalPathObserved = if ($null -ne $failedPathEvidence.final_path) { $true } else { $null }
    $finalWithinWorkspace = if ($finalWorkspaceObserved -eq $true -and $finalPathObserved -eq $true -and $null -eq $topologyCode) {
        $null -ne $workspaceObservation.identity -and $workspaceObservation.identity -in $failedObservation.ancestors
    }
    else {
        $null
    }

    $collectionFailures = [System.Collections.Generic.List[object]]::new()
    foreach ($pathEvidence in @($workspacePathEvidence, $failedPathEvidence)) {
        if ($pathEvidence.status -eq 'collection-failure') {
            $collectionFailures.Add([pscustomobject][ordered]@{
                    code = $pathEvidence.failure.error_id
                    message = $pathEvidence.failure.message
                    evidence_refs = @(if ($pathEvidence.observations.role -eq 'workspace') { 'workspace_path' } else { 'failed_path' })
                    next_observation = 'Inspect the declared path with a local, read-only filesystem probe.'
            })
        }
    }
    foreach ($aclEvidence in @($workspaceAcl, $failedPathAcl)) {
        if ($aclEvidence.status -eq 'collection-failure') {
            $collectionFailures.Add([pscustomobject][ordered]@{
                    code = $aclEvidence.failure.error_id
                    message = $aclEvidence.failure.message
                    evidence_refs = @(if ($aclEvidence.role -eq 'workspace') { 'workspace_acl' } else { 'failed_path_acl' })
                    next_observation = 'Inspect ACL visibility for the declared local path without changing permissions.'
                })
        }
    }

    $unknowns = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $topologyCode) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = $topologyCode
                message = 'Path or ancestry observations changed or could not be revalidated through the retained handles; final containment is unknown.'
                evidence_refs = @('workspace_path', 'failed_path', 'path_relation.final_within_workspace')
                next_observation = 'Collect again while the selected paths are stable. Retained-object evidence is not an atomic topology snapshot.'
            })
    }
    if ($failedPathEvidence.status -eq 'unknown') {
        $unknowns.Add([pscustomobject][ordered]@{
                code = $failedPathEvidence.failure.error_id
                message = $failedPathEvidence.failure.message
                evidence_refs = @('failed_path')
                next_observation = 'Keep the original failed path and report; check spelling and which application should create it. An existing-file comparison does not resolve this missing target.'
            })
    }
    if ($null -eq $logicalWithinWorkspace) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = 'LOGICAL_CONTAINMENT_UNKNOWN'
                message = 'Logical containment could not be established from the validated lexical paths.'
                evidence_refs = @('path_relation.logical_within_workspace')
                next_observation = 'Provide both raw one-letter absolute paths for lexical comparison.'
            })
    }
    if ($null -eq $reparseSegmentObserved) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = 'REPARSE_RELATION_UNKNOWN'
                message = 'Reparse-segment presence could not be established for every existing local segment.'
                evidence_refs = @('path_relation.reparse_segment_observed')
                next_observation = 'Complete a local metadata-only walk of every existing segment.'
            })
    }
    if ($null -eq $finalWorkspaceObserved) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = 'FINAL_WORKSPACE_UNKNOWN'
                message = 'The final workspace identity was not observed.'
                evidence_refs = @('path_relation.final_workspace_observed')
                next_observation = 'Observe the final local workspace identity without crossing a remote target.'
            })
    }
    if ($null -eq $finalPathObserved) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = 'FINAL_PATH_UNKNOWN'
                message = 'The final failed-path identity was not observed.'
                evidence_refs = @('path_relation.final_path_observed')
                next_observation = 'Observe the final local failed-path identity without crossing a remote target.'
            })
    }
    if ($null -eq $finalWithinWorkspace) {
        $unknowns.Add([pscustomobject][ordered]@{
                code = 'FINAL_CONTAINMENT_UNKNOWN'
                message = if ($null -ne $topologyCode) { 'Final containment could not be established because topology observations changed or could not be revalidated.' } else { 'Final containment could not be established without both final identities.' }
                evidence_refs = @('path_relation.final_within_workspace')
                next_observation = 'Observe both final identities before comparing the final boundary.'
            })
    }
    $unknowns.Add([pscustomobject][ordered]@{
            code = 'RUNTIME_ENFORCEMENT_UNKNOWN'
            message = 'Static path evidence cannot establish runtime enforcement.'
            evidence_refs = @('incident.runtime_kind')
            next_observation = 'Record the affected product/version and original error code/time locally; obtain separately authorized runtime evidence when needed. Review and minimize before sharing.'
        })

    return [pscustomobject][ordered]@{
        workspace_path = $workspacePathEvidence
        failed_path = $failedPathEvidence
        workspace_acl = $workspaceAcl
        failed_path_acl = $failedPathAcl
        path_relation = [pscustomobject][ordered]@{
            logical_within_workspace = $logicalWithinWorkspace
            reparse_segment_observed = $reparseSegmentObserved
            final_workspace_observed = $finalWorkspaceObserved
            final_path_observed = $finalPathObserved
            final_within_workspace = $finalWithinWorkspace
        }
        collection_failures = @($collectionFailures)
        unknowns = @($unknowns)
    }
    }
    finally {
        if ($null -ne $failedObservation -and $null -ne $failedObservation.session) { $failedObservation.session.Dispose() }
        if ($null -ne $workspaceObservation -and $null -ne $workspaceObservation.session) { $workspaceObservation.session.Dispose() }
    }
}

function Invoke-BoundaryLens {
    <#
    .SYNOPSIS
    Collect bounded, read-only Windows-local path and ACL evidence.
    .DESCRIPTION
    Observe one declared workspace and one failed path without modifying the
    investigated state. Expected collection failures and UNKNOWN facts are report
    values. Static observations cannot establish runtime enforcement. Reports
    may contain sensitive paths; review and minimize them before sharing.
    For fixed private-support errors use the script's direct -File process entry.
    .PARAMETER Workspace
    The original workspace as a nonblank raw one-letter absolute local path.
    Relative, provider-qualified, UNC and remote forms are not accepted.
    .PARAMETER FailedPath
    The original failed local path. A missing target remains an observation gap;
    keep its report even if a separate existing-file comparison succeeds.
    .PARAMETER Format
    Text adds neutral collection counts and result rows. Json preserves the
    version-1 evidence model. The default is Text.
    .EXAMPLE
    $demo = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-demo-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $demo) { throw 'Synthetic directory already exists; stop.' }
    New-Item -ItemType Directory -Path $demo -ErrorAction Stop | Out-Null
    Set-Content -LiteralPath (Join-Path $demo 'synthetic.txt') -Value 'Boundary Lens synthetic example only.' -Encoding utf8
    Invoke-BoundaryLens -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Text

    Operator setup writes a new harmless synthetic directory and file. The
    diagnostic reads it. Four observed records and runtime UNKNOWN are expected.
    .EXAMPLE
    Invoke-BoundaryLens -Workspace $demo -FailedPath (Join-Path $demo 'missing.txt') -Format Text

    After the first example, observe a deliberately missing filename without
    creating it. Target/final-path/final-containment/runtime unknowns are expected.
    For a real incident, retain the original failed path and report, check its
    spelling and expected creator, and obtain separately authorized runtime
    evidence when needed. This comparison does not resolve the original incident.
    .NOTES
    Private prototype 0.2.0. No elevation, remote adapter, automatic repair or
    safety verdict. Metadata equality is only a scoped test observation; it is
    not a whole-machine or whole-metadata guarantee.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Workspace,
        [Parameter(Mandatory)][AllowEmptyString()][string]$FailedPath,
        [ValidateSet('Text','Json')][string]$Format = 'Text'
    )

    try {
        $null = Test-BoundaryInput -Path $Workspace -ParameterName 'Workspace'
        $null = Test-BoundaryInput -Path $FailedPath -ParameterName 'FailedPath'
        $evidence = Get-BoundaryEvidence -Workspace $Workspace -FailedPath $FailedPath
        $report = [pscustomobject][ordered]@{
            schema_version = 1
            incident = [pscustomobject][ordered]@{
                workspace_input = $Workspace
                failed_path_input = $FailedPath
                runtime_kind = 'windows-local'
                observed_at = [DateTimeOffset]::UtcNow.ToString('o')
            }
            evidence = [pscustomobject][ordered]@{
                workspace_path = $evidence.workspace_path
                failed_path = $evidence.failed_path
                workspace_acl = $evidence.workspace_acl
                failed_path_acl = $evidence.failed_path_acl
                path_relation = $evidence.path_relation
            }
            results = @(Classify-BoundaryEvidence -Evidence $evidence)
        }
        return Format-BoundaryReport -Report $report -Format $Format
    }
    catch {
        if ($_.FullyQualifiedErrorId -match '^BOUNDARY_(INPUT_INVALID|REMOTE_UNSUPPORTED)') {
            throw
        }

        $exception = [System.InvalidOperationException]::new('Boundary Lens could not produce a complete report.')
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'BOUNDARY_INTERNAL_ERROR', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
    }
}

function Invoke-BoundaryProcess {
    param([AllowEmptyCollection()][string[]]$Arguments = @())

    try {
        $options = @{}
        if ($Arguments.Count -eq 0 -or $Arguments.Count % 2 -ne 0) {
            throw [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('Invalid process arguments.'), 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
        }
        for ($index = 0; $index -lt $Arguments.Count; $index += 2) {
            $key = switch ($Arguments[$index]) {
                '-Workspace' { 'Workspace' }
                '-FailedPath' { 'FailedPath' }
                '-Format' { 'Format' }
                default { '' }
            }
            if ($key -eq '' -or $options.ContainsKey($key)) {
                throw [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('Invalid process arguments.'), 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
            }
            $options[$key] = $Arguments[$index + 1]
        }
        if (-not $options.ContainsKey('Workspace') -or -not $options.ContainsKey('FailedPath')) {
            throw [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('Invalid process arguments.'), 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
        }
        if ([string]::IsNullOrWhiteSpace($options['Workspace']) -or [string]::IsNullOrWhiteSpace($options['FailedPath'])) {
            throw [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('Invalid process arguments.'), 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
        }
        if (-not $options.ContainsKey('Format')) { $options['Format'] = 'Text' }
        if ($options['Format'] -notin @('Text', 'Json')) {
            throw [System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('Invalid process arguments.'), 'BOUNDARY_INPUT_INVALID', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
        }
        $output = Invoke-BoundaryLens -Workspace $options['Workspace'] -FailedPath $options['FailedPath'] -Format $options['Format']
        return [pscustomobject]@{ output = $output; error_code = $null; exit_code = 0 }
    }
    catch {
        $code = switch (($_.FullyQualifiedErrorId -split ',')[0]) {
            'BOUNDARY_INPUT_INVALID' { 'BOUNDARY_INPUT_INVALID' }
            'BOUNDARY_REMOTE_UNSUPPORTED' { 'BOUNDARY_REMOTE_UNSUPPORTED' }
            default { 'BOUNDARY_INTERNAL_ERROR' }
        }
        $nativeExit = if ($code -eq 'BOUNDARY_INTERNAL_ERROR') { 3 } else { 2 }
        return [pscustomobject]@{ output = $null; error_code = $code; exit_code = $nativeExit }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $processArguments = $args
        if ([string]::IsNullOrEmpty($MyInvocation.ScriptName) -and [string]::IsNullOrEmpty($MyInvocation.Line)) {
            $hostArguments = [Environment]::GetCommandLineArgs()
            for ($hostIndex = 1; $hostIndex -lt $hostArguments.Count; $hostIndex++) {
                if ($hostArguments[$hostIndex] -in @('-f', '-fi', '-fil', '-file')) {
                    if ($hostIndex + 1 -lt $hostArguments.Count -and [string]::Equals([System.IO.Path]::GetFullPath($hostArguments[$hostIndex + 1]), $PSCommandPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $processArguments = @(for ($tailIndex = $hostIndex + 2; $tailIndex -lt $hostArguments.Count; $tailIndex++) { $hostArguments[$tailIndex] })
                    }
                    break
                }
            }
        }
        $processOutcome = Invoke-BoundaryProcess -Arguments $processArguments
    }
    catch { $processOutcome = [pscustomobject]@{ output = $null; error_code = 'BOUNDARY_INTERNAL_ERROR'; exit_code = 3 } }
    if ($null -eq $processOutcome.error_code) {
        [Console]::Out.WriteLine($processOutcome.output)
    }
    else {
        [Console]::Error.WriteLine("BOUNDARY_ERROR code=$($processOutcome.error_code) exit=$($processOutcome.exit_code)")
    }
    exit $processOutcome.exit_code
}
