using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.SnapshotPublication;

// CurrentUser store and LOGON_NETCREDENTIALS_ONLY, as sli_collect.powershell.
// Passwords reach only CryptUnprotectData / CreateProcessWithLogonW, never argv.
[SupportedOSPlatform("windows")]
internal sealed class AdCoordinatorIdentity : IDisposable
{
    internal Process Process { get; }
    readonly SafeFileHandle job;
    AdCoordinatorIdentity(Process process, SafeFileHandle job) { Process = process; this.job = job; }
    static WorkerFailure Failure(string reason) => new("source_identity", reason);
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Length; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] struct FileInfo { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written; public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct Startup { public int Size; public IntPtr Reserved, Desktop, Title; public uint X, Y, Width, Height, XChars, YChars, Fill, Flags; public short Show, ReservedSize; public IntPtr Reserved2, Input, Output, Error; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint Pid, Tid; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorking, MaxWorking; public uint Processes; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct Limits { public BasicLimits Basic; public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfo info);
    [DllImport("advapi32", SetLastError = true)] static extern uint GetSecurityInfo(SafeFileHandle file, int type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("crypt32", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32", SetLastError = true)] static extern bool SetInformationJobObject(SafeFileHandle job, int type, ref Limits limits, int size);
    [DllImport("kernel32", SetLastError = true)] static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [DllImport("kernel32", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32")] static extern bool TerminateProcess(IntPtr handle, uint exit);
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessWithLogonW(string user, string? domain, IntPtr password, uint logon, string application, StringBuilder command, uint flags, IntPtr environment, string directory, ref Startup startup, out ProcessInfo info);
    internal static string Quote(string text) {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in text) { if (c == '\\') { slashes++; continue; } result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); result.Append(c); slashes = 0; }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    static SafeFileHandle Open(string path, bool directory, SecurityIdentifier sid) {
        var file = CreateFileW(path, 0x80020000, 1, IntPtr.Zero, 3, 0x00200000 | (directory ? 0x02000000u : 0), IntPtr.Zero);
        try {
            if (file.IsInvalid || !GetFileInformationByHandle(file, out var info) || (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || !directory && info.Links != 1) throw Failure("ad_source_credentials_unsafe_path");
            if (GetSecurityInfo(file, 1, 5, out _, out _, out _, out _, out var descriptor) != 0) throw Failure("ad_source_credentials_unsafe_acl");
            try {
                byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                var sd = new RawSecurityDescriptor(bytes, 0); var acl = sd.DiscretionaryAcl;
                var expected = new HashSet<string> { sid.Value, "S-1-5-18" }; var actual = new HashSet<string>();
                if (sd.Owner != sid || (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 || acl is null || acl.Count != expected.Count) throw Failure("ad_source_credentials_unsafe_acl");
                foreach (GenericAce ace in acl) {
                    if (ace is not CommonAce a || a.AceQualifier != AceQualifier.AccessAllowed || a.IsCallback || a.AccessMask != 0x1f01ff || a.AceFlags != (directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None)) throw Failure("ad_source_credentials_unsafe_acl");
                    actual.Add(a.SecurityIdentifier.Value);
                }
                if (!actual.SetEquals(expected)) throw Failure("ad_source_credentials_unsafe_acl");
            } finally { LocalFree(descriptor); }
            return file;
        } catch { file.Dispose(); throw; }
    }
    internal static AdCoordinatorIdentity Start(ProcessStartInfo start, string dataRoot) {
        if (Path.GetFileName(start.FileName).ToLowerInvariant() != "powershell.exe") throw Failure("ad_source_process_command_invalid");
        string store = Path.GetFullPath(Path.Combine(dataRoot, "runtime/ad-source-credentials"));
        if (store.StartsWith("\\", StringComparison.Ordinal) || store.Length > 32700 || store.Length < 3 || store[1] != ':') throw Failure("ad_source_credentials_unsafe_path");
        // Hold the path components against rename/reparse substitution until creation.
        var parents = new List<SafeFileHandle>();
        IntPtr password = IntPtr.Zero, environment = IntPtr.Zero; byte[] clear = []; var process = new ProcessInfo(); SafeFileHandle? job = null;
        try {
            using var identity = WindowsIdentity.GetCurrent(); var sid = identity.User ?? throw Failure("ad_source_credentials_owner_missing");
            for (var dir = Directory.GetParent(store); dir is not null; dir = dir.Parent) {
                var handle = CreateFileW(dir.FullName, 0x20000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                parents.Add(handle); if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info) || (info.Attributes & 0x400) != 0) throw Failure("ad_source_credentials_unsafe_path");
            }
            using var folder = Open(store, true, sid); using var file = Open(Path.Combine(store, "credentials.dpapi"), false, sid);
            using var stream = new FileStream(file, FileAccess.Read); if (stream.Length is <= 0 or > 65536) throw Failure("ad_source_credentials_invalid_size");
            byte[] encrypted = new byte[stream.Length]; stream.ReadExactly(encrypted);
            var pinned = GCHandle.Alloc(encrypted, GCHandleType.Pinned); Blob output = default; IntPtr description = IntPtr.Zero;
            try {
                var input = new Blob { Length = encrypted.Length, Data = pinned.AddrOfPinnedObject() };
                if (!CryptUnprotectData(ref input, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output) || Marshal.PtrToStringUni(description) != "sli.ad-source-credentials" || output.Length is <= 0 or > 32768) throw Failure("ad_source_credentials_unavailable");
                clear = new byte[output.Length]; Marshal.Copy(output.Data, clear, 0, clear.Length);
            } finally {
                if (output.Data != IntPtr.Zero) { for (int i = 0; i < output.Length; i++) Marshal.WriteByte(output.Data, i, 0); LocalFree(output.Data); }
                if (description != IntPtr.Zero) LocalFree(description); pinned.Free();
            }
            using var json = JsonDocument.Parse(clear); var value = json.RootElement;
            if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != 5 || !value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["version", "purpose", "owner_sid", "username", "password"]) || value.GetProperty("version").GetInt32() != 1 || value.GetProperty("purpose").GetString() != "sli.ad-source-credentials" || value.GetProperty("owner_sid").GetString() != sid.Value) throw Failure("ad_source_credentials_invalid_payload");
            string username = value.GetProperty("username").GetString()!, secret = value.GetProperty("password").GetString()!;
            if (username.Length is < 1 or > 1024 || username.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || "/:\"<>|?*;=,[]".Contains(c)) || secret.Length is < 1 or > 4096 || secret.Contains('\0')) throw Failure("ad_source_credentials_invalid_payload");
            string? domain = null; string user = username;
            if (username.Count(c => c == '\\') == 1 && !username.Contains('@')) { var parts = username.Split('\\'); domain = parts[0]; user = parts[1]; }
            else if (username.Count(c => c == '@') != 1 || username.Contains('\\')) throw Failure("ad_source_credentials_invalid_payload");
            if (string.IsNullOrEmpty(user) || domain is "" or "." or ".." || user is "." or ".." || domain is null && username.Split('@').Any(p => p.Length == 0 || p is "." or "..")) throw Failure("ad_source_credentials_invalid_payload");
            string command = string.Join(' ', new[] { start.FileName }.Concat(start.ArgumentList).Select(Quote));
            if (command.Length >= 32767) throw Failure("ad_source_process_command_too_long");
            var names = new[] { "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "SystemDrive", "ComSpec" };
            environment = Marshal.StringToHGlobalUni(string.Join('\0', names.Where(n => start.Environment.ContainsKey(n) && start.Environment[n] is not null).Select(n => n + "=" + start.Environment[n])) + "\0\0");
            password = Marshal.StringToHGlobalUni(secret);
            job = CreateJobObjectW(IntPtr.Zero, null); var limits = new Limits { Basic = new BasicLimits { Flags = 0x2000 } };
            if (job.IsInvalid || !SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf<Limits>())) throw Failure("ad_source_process_job_failed");
            var startup = new Startup { Size = Marshal.SizeOf<Startup>(), Flags = 1, Show = 0 };
            if (!CreateProcessWithLogonW(user, domain, password, 2, start.FileName, new StringBuilder(command), 0x08000404, environment, start.WorkingDirectory, ref startup, out process)) throw Failure("ad_source_process_failed");
            if (!AssignProcessToJobObject(job, process.Process) || ResumeThread(process.Thread) == uint.MaxValue) throw Failure("ad_source_process_job_failed");
            var result = new AdCoordinatorIdentity(Process.GetProcessById(checked((int)process.Pid)), job); job = null; return result;
        } catch (WorkerFailure) { if (process.Process != IntPtr.Zero) TerminateProcess(process.Process, 1); throw; }
        catch { if (process.Process != IntPtr.Zero) TerminateProcess(process.Process, 1); throw Failure("ad_source_credentials_unavailable"); }
        finally {
            if (password != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(password); if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment); CryptographicOperations.ZeroMemory(clear);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread); if (process.Process != IntPtr.Zero) CloseHandle(process.Process); job?.Dispose(); foreach (var handle in parents) handle.Dispose();
        }
    }
    public void Dispose() { job.Dispose(); Process.Dispose(); }
}
