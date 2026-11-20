using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Sources;

// Pin every path component without delete sharing, inspect the opened object, and never repair ACLs.
internal class AdSourceCredentialWindows
{
    internal const uint DpapiFlags = 1; // UI forbidden, CurrentUser; LocalMachine is forbidden.
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { internal int Length; internal nint Descriptor; internal int Inherit; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { internal int Length; internal nint Data; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string name, ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint information, out nint owner, out nint group, out nint dacl, out nint sacl, out nint descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(nint descriptor);
    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string source, string destination, uint flags);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptProtectData(ref DataBlob input, string description, nint entropy, nint reserved, nint prompt, uint flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref DataBlob input, out nint description, nint entropy, nint reserved, nint prompt, uint flags, out DataBlob output);

    internal virtual string CurrentSid()
    {
        if (!OperatingSystem.IsWindows()) throw new AdCredentialStoreException("windows_required");
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new AdCredentialStoreException("owner_mismatch");
    }

    internal virtual uint DriveType(string root) => GetDriveTypeW(root);

    internal string RootPath(string path)
    {
        // Validate before normalization so aliases, UNC, devices and ADS cannot disappear.
        if (path.Length is < 3 or > 32700 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] is not ('\\' or '/'))
            throw new AdCredentialStoreException("unsafe_path");
        string[] parts = path[3..].Replace('/', '\\').Split('\\');
        if (parts.Length > 127 || parts.Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.IndexOfAny(":<>\"|?*\0".ToCharArray()) >= 0))
            throw new AdCredentialStoreException("unsafe_path");
        if (DriveType(path[..3]) != 3) throw new AdCredentialStoreException("unsafe_path");
        return Path.GetFullPath(path);
    }

    private sealed class Pins : IDisposable
    {
        internal readonly List<SafeFileHandle> Handles = [];
        public void Dispose() { for (int i = Handles.Count - 1; i >= 0; i--) Handles[i].Dispose(); }
    }

    internal IDisposable Directory(string path, string sid, bool create)
    {
        var pins = new Pins();
        try
        {
            var ancestors = new Stack<string>();
            for (string? item = path; item is not null; item = Path.GetDirectoryName(item)) ancestors.Push(item);
            foreach (string item in ancestors)
            {
                bool leaf = item == path;
                var handle = CreateFileW(item, 0x80u | (leaf ? 0x20000u : 0), 3, 0, 3, 0x02200000, 0);
                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastPInvokeError();
                    handle.Dispose();
                    if (error is not (2 or 3)) throw new Win32Exception(error);
                    if (!leaf || !create) throw new AdCredentialStoreException("missing");
                    WithSecurity(sid, directory: true, attributes =>
                    {
                        if (!CreateDirectoryW(item, ref attributes) && Marshal.GetLastPInvokeError() != 183) throw new Win32Exception();
                        return 0;
                    });
                    handle = CreateFileW(item, 0x20080, 3, 0, 3, 0x02200000, 0);
                    if (handle.IsInvalid) { handle.Dispose(); throw new AdCredentialStoreException("storage_failed"); }
                }
                pins.Handles.Add(handle);
                Verify(handle, sid, directory: true, enforceAcl: leaf);
            }
            return pins;
        }
        catch { pins.Dispose(); throw; }
    }

    internal SafeFileHandle BlobHandle(string path, string sid)
    {
        var handle = CreateFileW(path, 0x80020000, 1, 0, 3, 0x02200000, 0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError(); handle.Dispose();
            if (error is 2 or 3) throw new AdCredentialStoreException("missing");
            throw new Win32Exception(error);
        }
        try { Verify(handle, sid, directory: false); return handle; }
        catch { handle.Dispose(); throw; }
    }

    internal SafeFileHandle CreateBlob(string path, string sid) => WithSecurity(sid, directory: false, attributes =>
    {
        nint pointer = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityAttributes>());
        try
        {
            Marshal.StructureToPtr(attributes, pointer, false);
            var handle = CreateFileW(path, 0x40020000, 0, pointer, 1, 0x00200080, 0);
            if (handle.IsInvalid) { handle.Dispose(); throw new AdCredentialStoreException("storage_failed"); }
            return handle;
        }
        finally { Marshal.FreeHGlobal(pointer); }
    });

    private static T WithSecurity<T>(string sid, bool directory, Func<SecurityAttributes, T> action)
    {
        if (!OperatingSystem.IsWindows()) throw new AdCredentialStoreException("windows_required");
        string flags = directory ? "OICI" : "";
        string system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;
        var descriptor = new RawSecurityDescriptor($"O:{sid}D:P(A;{flags};FA;;;{sid})" + (sid == system ? "" : $"(A;{flags};FA;;;{system})"));
        byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try { return action(new() { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject() }); }
        finally { pinned.Free(); }
    }

    internal void Verify(SafeFileHandle handle, string sid, bool directory, bool enforceAcl = true)
    {
        if (!OperatingSystem.IsWindows()) throw new AdCredentialStoreException("windows_required");
        if (!GetFileInformationByHandle(handle, out var info)) throw new AdCredentialStoreException("storage_failed");
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || !directory && info.Links != 1)
            throw new AdCredentialStoreException("unsafe_path");
        if (!enforceAcl) return;
        if (GetSecurityInfo(handle, 1, 5, out _, out _, out _, out _, out var pointer) != 0) throw new AdCredentialStoreException("unsafe_acl");
        try
        {
            byte[] bytes = new byte[GetSecurityDescriptorLength(pointer)]; Marshal.Copy(pointer, bytes, 0, bytes.Length);
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            if (descriptor.Owner?.Value != sid) throw new AdCredentialStoreException("owner_mismatch");
            var expected = new HashSet<string> { sid, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value };
            var actual = new HashSet<string>();
            var acl = descriptor.DiscretionaryAcl;
            if (!descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) || acl is null || acl.Count != expected.Count)
                throw new AdCredentialStoreException("unsafe_acl");
            foreach (GenericAce entry in acl)
            {
                if (entry is not CommonAce ace || ace.AceType != AceType.AccessAllowed || ace.IsCallback || ace.AccessMask != 0x1f01ff
                    || ace.AceFlags != (directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None))
                    throw new AdCredentialStoreException("unsafe_acl");
                actual.Add(ace.SecurityIdentifier.Value);
            }
            if (!actual.SetEquals(expected)) throw new AdCredentialStoreException("unsafe_acl");
        }
        finally { LocalFree(pointer); }
    }

    internal virtual void Move(string source, string destination, bool replace)
    {
        if (MoveFileExW(source, destination, 8u | (replace ? 1u : 0))) return;
        int error = Marshal.GetLastPInvokeError();
        throw new AdCredentialStoreException(!replace && error is 80 or 183 ? "already_exists" : "storage_failed");
    }

    internal virtual byte[] Protect(byte[] clear, string purpose) => Crypt(clear, purpose, protect: true).Clear;
    internal virtual (byte[] Clear, string Description) Unprotect(byte[] blob) => Crypt(blob, "", protect: false);

    private static (byte[] Clear, string Description) Crypt(byte[] bytes, string purpose, bool protect)
    {
        var input = new DataBlob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        DataBlob output = default; nint description = 0;
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            // CRYPTPROTECT_UI_FORBIDDEN = 1, never CRYPTPROTECT_LOCAL_MACHINE (4).
            bool success = protect ? CryptProtectData(ref input, purpose, 0, 0, 0, DpapiFlags, out output)
                : CryptUnprotectData(ref input, out description, 0, 0, 0, DpapiFlags, out output);
            if (!success) throw new AdCredentialStoreException("dpapi_failed");
            byte[] result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length);
            return (result, protect ? purpose : Marshal.PtrToStringUni(description) ?? "");
        }
        finally
        {
            Marshal.Copy(new byte[bytes.Length], 0, input.Data, bytes.Length); Marshal.FreeHGlobal(input.Data);
            if (output.Data != 0) { Marshal.Copy(new byte[output.Length], 0, output.Data, output.Length); LocalFree(output.Data); }
            if (description != 0) LocalFree(description);
        }
    }
}
