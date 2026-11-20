using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Sli.Server.Agents.Deployment;

namespace Sli.Server.Agents.Radius;

// Read the Python VPN CurrentUser envelope; never create, repair or adopt a store.
[SupportedOSPlatform("windows")]
internal static class VpnSourceCredentialStore
{
    private const string Purpose = "sli.vpn-source-credentials";
    internal static VpnSourceCredentials Load(string root)
    {
        var pins = new List<SafeFileHandle>();
        byte[]? clear = null;
        try
        {
            if (!Path.IsPathFullyQualified(root) || root.Length > 32700 || root.Length < 3 || root[1] != ':' || !char.IsAsciiLetter(root[0])) throw new IOException();
            string[] parts = root[3..].Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parts.Length > 127 || parts.Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.IndexOfAny(":<>\"|?*".ToCharArray()) >= 0)) throw new IOException();
            if (GetDriveType(root[..3]) != 3) throw new IOException();
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User ?? throw new IOException();
            string path = root[..3];
            pins.Add(Open(path, directory: true));
            Verify(pins[^1], owner, directory: true, acl: false);
            for (int i = 0; i < parts.Length; i++)
            {
                path = Path.Combine(path, parts[i]);
                pins.Add(Open(path, directory: true));
                Verify(pins[^1], owner, directory: true, acl: i == parts.Length - 1);
            }
            using var file = Open(Path.Combine(root, "credentials.dpapi"), directory: false);
            Verify(file, owner, directory: false, acl: true);
            using var stream = new FileStream(file, FileAccess.Read);
            if (stream.Length is < 1 or > 65536) throw new IOException();
            byte[] blob = new byte[(int)stream.Length];
            stream.ReadExactly(blob);
            if (stream.Length != blob.Length) throw new IOException();
            clear = Unprotect(blob);
            return Decode(clear, owner.Value);
        }
        catch { throw new VpnSourceAuthException("vpn_source_access_failed"); }
        finally
        {
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
            for (int i = pins.Count - 1; i >= 0; i--) pins[i].Dispose();
        }
    }
    internal static VpnSourceCredentials Decode(byte[] clear, string owner)
    {
        using var document = JsonDocument.Parse(new UTF8Encoding(false, true).GetString(clear));
        var payload = document.RootElement;
        string[] fields = ["version", "purpose", "owner_sid", "username", "password"];
        if (clear.Length is < 1 or > 32768 || payload.ValueKind != JsonValueKind.Object || payload.EnumerateObject().Count() != fields.Length || !payload.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(fields)
            || payload.GetProperty("version").GetRawText() != "1" || payload.GetProperty("purpose").GetString() != Purpose
            || payload.GetProperty("owner_sid").GetString() != owner) throw new IOException();
        string username = payload.GetProperty("username").GetString() ?? throw new IOException();
        string password = payload.GetProperty("password").GetString() ?? throw new IOException();
        AdOperationCredentials.ValidateUsername(username);
        if (password.EnumerateRunes().Count() is < 1 or > 4096 || password.Contains('\0') || !ValidUtf16(password)) throw new IOException();
        return new(username, password);
    }
    private static bool ValidUtf16(string value)
    { try { _ = new UTF8Encoding(false, true).GetByteCount(value); return true; } catch (EncoderFallbackException) { return false; } }
    private static SafeFileHandle Open(string path, bool directory)
    {
        // No FILE_SHARE_DELETE: all ancestors and the blob stay pinned. Open reparse points themselves.
        var handle = CreateFile(path, directory ? 0x20080u : 0x80020000u, directory ? 3u : 1u, 0, 3, 0x02200000, 0);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException(); }
        return handle;
    }
    private static void Verify(SafeFileHandle handle, SecurityIdentifier owner, bool directory, bool acl)
    {
        if (!GetFileInformationByHandle(handle, out var info) || (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || !directory && info.Links != 1) throw new IOException();
        if (!acl) return;
        if (GetSecurityInfo(handle, 1, 5, out _, out _, out _, out _, out nint descriptor) != 0) throw new IOException();
        try
        {
            byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            VerifyAcl(bytes, owner, directory);
        }
        finally { LocalFree(descriptor); }
    }
    internal static void VerifyAcl(byte[] bytes, SecurityIdentifier owner, bool directory)
    {
        var sd = new RawSecurityDescriptor(bytes, 0);
        var expected = new HashSet<string>([owner.Value, "S-1-5-18"]);
        if (sd.Owner != owner || !sd.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) || sd.DiscretionaryAcl is null || sd.DiscretionaryAcl.Count != expected.Count) throw new IOException();
        foreach (GenericAce entry in sd.DiscretionaryAcl)
        {
            if (entry is not CommonAce ace || ace.IsCallback || ace.AceType != AceType.AccessAllowed || ace.AceFlags != (directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None)
                || ace.AccessMask != 0x1f01ff || !expected.Remove(ace.SecurityIdentifier.Value)) throw new IOException();
        }
        if (expected.Count != 0) throw new IOException();
    }
    internal static byte[] Unprotect(byte[] blob)
    {
        var pin = GCHandle.Alloc(blob, GCHandleType.Pinned);
        var input = new DataBlob { Size = blob.Length, Data = pin.AddrOfPinnedObject() };
        DataBlob output = default; nint description = 0;
        try
        {
            if (!CryptUnprotectData(ref input, out description, 0, 0, 0, 1, out output) || Marshal.PtrToStringUni(description) != Purpose || output.Size is < 1 or > 32768) throw new IOException();
            var clear = new byte[output.Size]; Marshal.Copy(output.Data, clear, 0, clear.Length); return clear;
        }
        finally
        {
            if (output.Data != 0)
            {
                for (int i = 0; i < output.Size; i++) Marshal.WriteByte(output.Data, i, 0);
                LocalFree(output.Data);
            }
            if (description != 0) LocalFree(description);
            pin.Free();
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Size; public nint Data; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo
    {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern uint GetDriveType(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint parts, out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(nint descriptor);
    [DllImport("kernel32.dll")] private static extern nint LocalFree(nint memory);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref DataBlob input, out nint description, nint entropy, nint reserved, nint prompt, uint flags, out DataBlob output);
}
