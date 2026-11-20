using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Sources;

// Read the existing Python CurrentUser envelope. Never create/repair ACLs or stores.
public sealed class WindowsCredentialStore(string dataDirectory)
{
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public nint Data; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,nint security,uint disposition,uint flags,nint template);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] private static extern uint GetDriveType(string root);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
    [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint requested,out nint owner,out nint group,out nint dacl,out nint sacl,out nint descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(nint descriptor);
    [DllImport("kernel32.dll")] private static extern nint LocalFree(nint memory);
    [DllImport("crypt32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CryptUnprotectData(ref Blob input,out nint description,nint entropy,nint reserved,nint prompt,uint flags,out Blob output);

    public AdSourceLogin Load(string profile)
    {
        if (!OperatingSystem.IsWindows()) throw new CollectionSourceException("ad_source_credentials_unavailable");
        try { return LoadWindows(profile); }
        catch { throw new CollectionSourceException("ad_source_credentials_unavailable"); }
    }
    [SupportedOSPlatform("windows")]
    private AdSourceLogin LoadWindows(string profile)
    {
        if (profile is not ("ad" or "vpn")) throw new FormatException();
        string root = Path.Combine(dataDirectory,"runtime",profile + "-source-credentials");
        if (!Path.IsPathFullyQualified(root) || root.Length > 32700 || root.Length < 3 || root[1] != ':' || !char.IsAsciiLetter(root[0])
            || root.Split(Path.DirectorySeparatorChar).Skip(1).Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.IndexOfAny(":<>\"|?*".ToCharArray()) >= 0)
            || GetDriveType(Path.GetPathRoot(root)!) != 3) throw new FormatException();
        using var identity = WindowsIdentity.GetCurrent(); string sid = identity.User!.Value;
        var handles = new List<SafeFileHandle>();
        byte[]? clear = null;
        try {
            // Pin every ancestor without FILE_SHARE_DELETE, including the store.
            var paths = new Stack<string>();
            for (string? path=root; path is not null; path=Path.GetDirectoryName(path)) paths.Push(path);
            if (paths.Count > 128) throw new FormatException();
            while (paths.TryPop(out string? path)) {
                bool store = path == root;
                var h = CreateFile(path,0x80u | (store ? 0x20000u : 0),3,0,3,0x02000000 | 0x00200000,0); handles.Add(h);
                Verify(h,sid,true,store);
            }
            var file = CreateFile(Path.Combine(root,"credentials.dpapi"),0x80000000 | 0x20000,1,0,3,0x02000000 | 0x00200000,0); handles.Add(file);
            var info = Verify(file,sid,false,true);
            if (info.SizeHigh != 0 || info.SizeLow is 0 or >65536) throw new FormatException();
            byte[] blob = new byte[info.SizeLow];
            using (var stream = new FileStream(file,FileAccess.Read)) {
                stream.ReadExactly(blob);
                if (stream.ReadByte() != -1 || stream.Length != blob.Length) throw new FormatException();
                clear = Unprotect(blob,"sli." + profile + "-source-credentials");
            }
            return Decode(clear,sid,"sli." + profile + "-source-credentials");
        }
        finally {
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
            for (int i=handles.Count-1;i>=0;i--) handles[i].Dispose();
        }
    }
    [SupportedOSPlatform("windows")]
    private static FileInfo Verify(SafeFileHandle handle,string sid,bool directory,bool acl)
    {
        if (handle.IsInvalid || !GetFileInformationByHandle(handle,out var info) || (info.Attributes & 0x400) != 0
            || ((info.Attributes & 0x10) != 0) != directory || !directory && info.Links != 1) throw new FormatException();
        if (!acl) return info;
        if (GetSecurityInfo(handle,1,5,out _,out _,out _,out _,out nint descriptor) != 0) throw new FormatException();
        try {
            byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
            var sd = new RawSecurityDescriptor(bytes,0);
            var expected = new HashSet<string>([sid,"S-1-5-18"],StringComparer.Ordinal);
            if (sd.Owner?.Value != sid || !sd.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected)
                || sd.DiscretionaryAcl is null || sd.DiscretionaryAcl.Count != expected.Count) throw new FormatException();
            var actual = new HashSet<string>();
            foreach (GenericAce ace in sd.DiscretionaryAcl) {
                if (ace is not CommonAce a || a.IsCallback || a.AceType != AceType.AccessAllowed || a.AccessMask != 0x1f01ff
                    || a.AceFlags != (directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None)) throw new FormatException();
                actual.Add(a.SecurityIdentifier.Value);
            }
            if (!actual.SetEquals(expected)) throw new FormatException();
            return info;
        }
        finally { _ = LocalFree(descriptor); }
    }
    private static byte[] Unprotect(byte[] encrypted,string purpose)
    {
        nint input = Marshal.AllocHGlobal(encrypted.Length); var output = new Blob(); nint description = 0;
        try {
            Marshal.Copy(encrypted,0,input,encrypted.Length); var blob = new Blob { Size=encrypted.Length,Data=input };
            if (!CryptUnprotectData(ref blob,out description,0,0,0,1,out output)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (Marshal.PtrToStringUni(description) != purpose || output.Size is <1 or >32768) throw new FormatException();
            byte[] result = new byte[output.Size]; Marshal.Copy(output.Data,result,0,result.Length); return result;
        }
        finally {
            Marshal.FreeHGlobal(input);
            if (description != 0) _ = LocalFree(description);
            if (output.Data != 0) { for (int i=0;i<output.Size;i++) Marshal.WriteByte(output.Data,i,0); _ = LocalFree(output.Data); }
        }
    }
    internal static AdSourceLogin Decode(byte[] clear,string sid,string purpose)
    {
        // Strict UTF-8 and duplicate-key rejection match the existing envelope.
        using var json = JsonDocument.Parse(new UTF8Encoding(false,true).GetString(clear)); var value = json.RootElement;
        var fields = value.EnumerateObject().Select(x => x.Name).ToArray();
        if (fields.Length != 5 || !fields.ToHashSet().SetEquals(["version","purpose","owner_sid","username","password"])
            || value.GetProperty("version").GetRawText() != "1" || value.GetProperty("purpose").GetString() != purpose
            || value.GetProperty("owner_sid").GetString() != sid) throw new FormatException();
        string username = value.GetProperty("username").GetString()!, password = value.GetProperty("password").GetString()!;
        AdSourceAuth.ValidateUsername(username);
        _ = new UTF8Encoding(false,true).GetByteCount(password);
        if (password.EnumerateRunes().Count() is <1 or >4096 || password.Contains('\0')) throw new FormatException();
        return new(username,password);
    }
    public static CollectionIdentity CurrentIdentity()
    {
        if (!OperatingSystem.IsWindows()) return new("","",0,"windows_required");
        try {
            using var identity = WindowsIdentity.GetCurrent();
            return new(identity.Name,identity.User!.Value,System.Diagnostics.Process.GetCurrentProcess().SessionId);
        }
        catch { return new("","",0,"identity_probe_failed"); }
    }
}
