using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Agents.Radius;

// Deliberately not a record: diagnostics/ToString must never print credentials.
internal sealed class NpsSourceCredentials(string username, string password)
{
    internal string Username { get; } = username;
    internal string Password { get; } = password;

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);

    internal static void Validate(string username, string password)
    {
        static bool Control(char ch) => char.GetUnicodeCategory(ch) is UnicodeCategory.Control or UnicodeCategory.Format
            or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned;
        if (username.Length is < 1 or > 1024 || username.Any(ch => char.IsWhiteSpace(ch) || Control(ch))
            || username.Any(ch => "/:\"<>|?*;=,[]".Contains(ch))) throw new InvalidDataException();
        string[] parts;
        if (username.Count(ch => ch == '\\') == 1 && !username.Contains('@')) parts = username.Split('\\');
        else if (username.Count(ch => ch == '@') == 1 && !username.Contains('\\')) parts = username.Split('@');
        else throw new InvalidDataException();
        if (parts.Any(x => x.Length == 0 || x is "." or "..")) throw new InvalidDataException();
        if (password.Length is < 1 or > 4096 || password.Contains('\0')) throw new InvalidDataException();
        _ = new UTF8Encoding(false, true).GetByteCount(password);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void Verify(SafeFileHandle handle, SecurityIdentifier sid, bool directory, bool acl)
    {
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info)
            || (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory
            || (!directory && info.Links != 1)) throw new InvalidDataException();
        if (!acl) return;
        if (GetSecurityInfo(handle, 1, 5, out _, out _, out _, out _, out var descriptor) != 0) throw new InvalidDataException();
        try
        {
            byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var sd = new RawSecurityDescriptor(bytes, 0);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var expected = new HashSet<string> { sid.Value, system.Value };
            var actual = new HashSet<string>();
            if (sd.Owner != sid || (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0
                || sd.DiscretionaryAcl is null || sd.DiscretionaryAcl.Count != expected.Count) throw new InvalidDataException();
            var flags = directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None;
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (ace is not CommonAce allowed || allowed.AceType != AceType.AccessAllowed || allowed.IsCallback
                    || allowed.AceFlags != flags || allowed.AccessMask != 0x1f01ff) throw new InvalidDataException();
                actual.Add(allowed.SecurityIdentifier.Value);
            }
            if (!actual.SetEquals(expected)) throw new InvalidDataException();
        }
        finally { LocalFree(descriptor); }
    }

    internal static NpsSourceCredentials Load(string dataDirectory, string profile)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || profile != "vpn") throw new InvalidDataException();
            string root = Path.Combine(dataDirectory, "runtime", "vpn-source-credentials");
            if (!Path.IsPathFullyQualified(root) || root.Length > 32700 || root.Length < 3 || root[1] != ':'
                || !char.IsAsciiLetter(root[0]) || new DriveInfo(Path.GetPathRoot(root)!).DriveType != DriveType.Fixed
                || root[3..].Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x is "." or ".." || x.EndsWith(' ') || x.EndsWith('.') || x.IndexOfAny(":<>\"|?*".ToCharArray()) >= 0))
                throw new InvalidDataException();
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User ?? throw new InvalidDataException();
            var pinned = new List<SafeFileHandle>();
            byte[]? clear = null;
            try
            {
                // Pin every ancestor without share-delete; reject reparse paths
                // rather than following, repairing or adopting their ACLs.
                var ancestors = new List<string>();
                for (var path = new DirectoryInfo(root); path is not null; path = path.Parent) ancestors.Add(path.FullName);
                foreach (string path in ancestors.AsEnumerable().Reverse())
                {
                    bool last = path.Equals(root, StringComparison.OrdinalIgnoreCase);
                    var handle = CreateFile(path, 0x80u | (last ? 0x20000u : 0), 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    pinned.Add(handle); Verify(handle, sid, true, last);
                }
                var file = CreateFile(Path.Combine(root, "credentials.dpapi"), 0x80020000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                pinned.Add(file); Verify(file, sid, false, true);
                using var stream = new FileStream(file, FileAccess.Read);
                if (stream.Length is < 1 or > 65536) throw new InvalidDataException();
                byte[] encrypted = new byte[stream.Length]; stream.ReadExactly(encrypted);
                if (stream.Length != encrypted.Length) throw new InvalidDataException();
                var pin = GCHandle.Alloc(encrypted, GCHandleType.Pinned);
                IntPtr description = IntPtr.Zero;
                Blob result = default;
                try
                {
                    var input = new Blob { Length = encrypted.Length, Data = pin.AddrOfPinnedObject() };
                    if (!CryptUnprotectData(ref input, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out result)
                        || Marshal.PtrToStringUni(description) != "sli.vpn-source-credentials" || result.Length is < 1 or > 32768) throw new InvalidDataException();
                    clear = new byte[result.Length]; Marshal.Copy(result.Data, clear, 0, clear.Length);
                }
                finally
                {
                    if (result.Data != IntPtr.Zero)
                    {
                        for (int index = 0; index < result.Length; index++) Marshal.WriteByte(result.Data, index, 0);
                        LocalFree(result.Data);
                    }
                    if (description != IntPtr.Zero) LocalFree(description);
                    pin.Free();
                }
                using var json = JsonDocument.Parse(clear);
                var value = json.RootElement;
                string[] keys = ["version", "purpose", "owner_sid", "username", "password"];
                if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != keys.Length
                    || !value.EnumerateObject().Select(x => x.Name).ToHashSet().SetEquals(keys)
                    || value.GetProperty("version").GetRawText() != "1" || value.GetProperty("purpose").GetString() != "sli.vpn-source-credentials"
                    || value.GetProperty("owner_sid").GetString() != sid.Value) throw new InvalidDataException();
                string username = value.GetProperty("username").GetString()!, password = value.GetProperty("password").GetString()!;
                Validate(username, password);
                return new(username, password);
            }
            finally
            {
                if (clear is not null) CryptographicOperations.ZeroMemory(clear);
                foreach (var handle in pinned.AsEnumerable().Reverse()) handle.Dispose();
            }
        }
        catch { throw new InvalidOperationException("ad_source_credentials_unavailable"); }
    }
}
