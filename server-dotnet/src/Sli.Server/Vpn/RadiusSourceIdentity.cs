using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Vpn;

// Source: windows_runtime_identity.py and vpn_source_auth.py. Source credentials
// are decrypted only in the child and impersonation surrounds only the SMB read.
[SupportedOSPlatform("windows")]
internal static class RadiusSourceIdentity
{
    internal static void Verify()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!Matches(identity.Name, identity.User?.Value, Process.GetCurrentProcess().SessionId,
            Environment.GetEnvironmentVariable("ADLOG_COLLECTION_PRINCIPAL"), Environment.GetEnvironmentVariable("ADLOG_COLLECTION_PRINCIPAL_SID")))
            throw new UnauthorizedAccessException("current_windows_account_is_not_approved_owner");
    }

    internal static bool Matches(string principal, string? sid, int session, string? expectedPrincipal, string? expectedSid) =>
        session != 0 && !string.IsNullOrWhiteSpace(expectedPrincipal) && !string.IsNullOrWhiteSpace(expectedSid) &&
        string.Equals(principal, expectedPrincipal.Trim(), StringComparison.OrdinalIgnoreCase) && string.Equals(sid, expectedSid.Trim(), StringComparison.OrdinalIgnoreCase);

    internal static T Read<T>(RadiusAcquisitionSource source, Func<T> read)
    {
        string mode = Environment.GetEnvironmentVariable("ADLOG_VPN_SOURCE_CREDENTIAL_MODE") ?? "process";
        if (mode == "process") return read();
        if (mode != "dpapi_current_user") throw new InvalidOperationException("vpn_source_credential_mode_invalid");
        using var thread = WindowsIdentity.GetCurrent(true);
        if (thread is not null) throw new InvalidOperationException("vpn_source_thread_impersonation_forbidden");
        var (username, password) = Credentials(Path.Combine(source.DataRoot, "runtime", "vpn-source-credentials"));
        string? domain = null; string user = username;
        if (username.Contains('\\')) { var parts = username.Split('\\', 2); domain = parts[0]; user = parts[1]; }
        if (!LogonUserW(user, domain, password, 9, 3, out var token)) throw new UnauthorizedAccessException("vpn_source_access_failed");
        using (token) return WindowsIdentity.RunImpersonated(token, read);
    }

    // Pin ancestors and credential handles against replacement. Reject reparse
    // points, hard links, unexpected owner and every ACL except owner/SYSTEM.
    private static (string Username, string Password) Credentials(string root)
    {
        root = Path.GetFullPath(root);
        string drive = Path.GetPathRoot(root)!;
        if (drive.Length != 3 || drive[1] != ':' || GetDriveTypeW(drive) != 3) throw new InvalidOperationException("vpn_source_credential_path_invalid");
        var handles = new List<SafeFileHandle>();
        try {
            var ancestors = new Stack<string>();
            for (var directory = new DirectoryInfo(root); directory is not null; directory = directory.Parent) ancestors.Push(directory.FullName);
            while (ancestors.TryPop(out string? directory)) {
                var handle = Open(directory, true, string.Equals(directory.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)); handles.Add(handle);
            }
            using var blob = Open(Path.Combine(root, "credentials.dpapi"), false, true);
            long size = RandomAccess.GetLength(blob);
            if (size is < 1 or > 65536) throw new InvalidOperationException("vpn_source_credential_size_invalid");
            byte[] encrypted = new byte[(int)size]; int count = 0;
            while (count < encrypted.Length) { int n = RandomAccess.Read(blob, encrypted.AsSpan(count), count); if (n == 0) throw new IOException(); count += n; }
            var input = new Blob { Length = encrypted.Length, Data = Marshal.AllocHGlobal(encrypted.Length) };
            Blob output = default; IntPtr description = IntPtr.Zero;
            try {
                Marshal.Copy(encrypted, 0, input.Data, encrypted.Length);
                if (!CryptUnprotectData(ref input, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)) throw new InvalidOperationException("vpn_source_dpapi_failed");
                if (Marshal.PtrToStringUni(description) != "sli.vpn-source-credentials" || output.Length is < 1 or > 32768) throw new InvalidOperationException("vpn_source_credential_payload_invalid");
                byte[] clear = new byte[output.Length]; Marshal.Copy(output.Data, clear, 0, clear.Length);
                try {
                    using var json = JsonDocument.Parse(clear); using var identity = WindowsIdentity.GetCurrent();
                    return ValidatePayload(json.RootElement, identity.User!.Value);
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(clear); }
            }
            finally {
                Marshal.FreeHGlobal(input.Data);
                if (output.Data != IntPtr.Zero) { for (int i = 0; i < output.Length; i++) Marshal.WriteByte(output.Data, i, 0); LocalFree(output.Data); }
                if (description != IntPtr.Zero) LocalFree(description);
            }
        }
        finally { foreach (var handle in handles) handle.Dispose(); }
    }

    internal static (string Username, string Password) ValidatePayload(JsonElement payload, string sid)
    {
        try {
            string[] keys = ["version", "purpose", "owner_sid", "username", "password"];
            var properties = payload.EnumerateObject().ToArray();
            if (properties.Length != keys.Length || !properties.Select(x => x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(keys) ||
                payload.GetProperty("version").GetInt32() != 1 || payload.GetProperty("purpose").GetString() != "sli.vpn-source-credentials" || payload.GetProperty("owner_sid").GetString() != sid) throw new ArgumentException();
            string user = payload.GetProperty("username").GetString()!, password = payload.GetProperty("password").GetString()!;
            _ = new System.Text.UTF8Encoding(false, true).GetByteCount(user); _ = new System.Text.UTF8Encoding(false, true).GetByteCount(password);
            if (user.EnumerateRunes().Count() is < 1 or > 1024 || user.EnumerateRunes().Any(c => System.Text.Rune.IsWhiteSpace(c) || System.Text.Rune.GetUnicodeCategory(c) is System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.Surrogate or System.Globalization.UnicodeCategory.PrivateUse or System.Globalization.UnicodeCategory.OtherNotAssigned) ||
                user.IndexOfAny("/:\"<>|?*;=,[]".ToCharArray()) >= 0 ||
                !(user.Count(c => c == '\\') == 1 && !user.Contains('@') || user.Count(c => c == '@') == 1 && !user.Contains('\\')) ||
                user.Split(['\\', '@']).Any(x => x is "" or "." or "..") || password.EnumerateRunes().Count() is < 1 or > 4096 || password.Contains('\0')) throw new ArgumentException();
            return (user, password);
        }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or KeyNotFoundException or NullReferenceException or FormatException) {
            throw new InvalidOperationException("vpn_source_credential_payload_invalid");
        }
    }

    private static SafeFileHandle Open(string path, bool directory, bool acl)
    {
        uint access = directory ? 0x80u : 0x80000000u;
        if (acl) access |= 0x20000;
        var handle = CreateFileW(path, access, 1 | 2, IntPtr.Zero, 3, 0x00200000u | (directory ? 0x02000000u : 0), IntPtr.Zero);
        try {
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info) || (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || !directory && info.Links != 1)
                throw new InvalidOperationException("vpn_source_credential_path_invalid");
            if (acl) {
                IntPtr descriptor = IntPtr.Zero;
                try {
                    if (GetSecurityInfo(handle, 1, 1 | 4, out _, out _, out _, out _, out descriptor) != 0) throw new InvalidOperationException("vpn_source_credential_acl_invalid");
                    byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                    var security = new RawSecurityDescriptor(bytes, 0); using var identity = WindowsIdentity.GetCurrent();
                    ValidateAcl(security, identity.User!, directory);
                }
                finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
            }
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    internal static void ValidateAcl(RawSecurityDescriptor descriptor, SecurityIdentifier owner, bool directory)
    {
        var expected = new HashSet<string>([owner.Value, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value], StringComparer.Ordinal);
        var acl = descriptor.DiscretionaryAcl;
        if (descriptor.Owner != owner || (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 || acl is null || acl.Count != expected.Count)
            throw new InvalidOperationException("vpn_source_credential_acl_invalid");
        AceFlags flags = directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None;
        foreach (GenericAce ace in acl)
            if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed || common.AceFlags != flags || common.IsCallback || common.AccessMask != 0x1f01ff || !expected.Remove(common.SecurityIdentifier.Value))
                throw new InvalidOperationException("vpn_source_credential_acl_invalid");
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] private struct Information { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUserW(string user, string? domain, string password, int type, int provider, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle file, out Information information);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint requested, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
}
