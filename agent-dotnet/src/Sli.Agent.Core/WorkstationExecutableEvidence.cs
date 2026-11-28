using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

internal static class WorkstationExecutableEvidence
{
    internal const int SignatureLimit = 2;
    private const int MaxFileSize = 64 * 1024 * 1024;
    private static readonly Guid Authenticode = new("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
    private static readonly Regex Reserved = new(@"\A(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Dictionary<(string Path, string Hash), Signature> Cache = new();

    private sealed record Signature(string Status, string? Signer);

    internal static bool SafeLocalPath(string path)
    {
        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\'
            || Encoding.UTF8.GetByteCount(path) > 512 || char.IsWhiteSpace(path[^1]) || path[^1] is >= '\u001c' and <= '\u001f')
            return false;
        return path[3..].Split('\\').All(part => part.Length > 0 && part is not ("." or "..")
            && !part.EndsWith(' ') && !part.EndsWith('.') && !part.Contains('~') && !Reserved.IsMatch(part)
            && !part.Any(c => c < 32 || c == 127 || "/:\"<>|?*%".Contains(c)));
    }

    internal static string? DriveType(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] is not ('\\' or '/')) return null;
        return GetDriveTypeW(path[..2] + "\\") switch { 2 => "removable", 4 => "network", _ => null };
    }

    internal static JsonObject? Measure(string path, string? launchTime, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows() || !SafeLocalPath(path)
            || GetDriveTypeW(path[..3]) != 3 || !DateTimeOffset.TryParse(launchTime,
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var launched))
            return null;
        try
        {
            using var handle = OpenWithoutReparse(path);
            if (handle is null) return null;
            using var file = new FileStream(handle, FileAccess.Read);
            var finalPath = new StringBuilder(1024);
            if (GetFinalPathNameByHandleW(file.SafeFileHandle, finalPath, (uint)finalPath.Capacity, 0) >= finalPath.Capacity
                || !string.Equals(finalPath.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase)
                || file.Length > MaxFileSize || File.GetLastWriteTimeUtc(file.SafeFileHandle) > launched
                || File.GetCreationTimeUtc(file.SafeFileHandle) > launched
                || !GetFileInformationByHandleEx(handle, 18, out var id, Marshal.SizeOf<FileId>()))
                return null;

            string hash = Convert.ToHexStringLower(SHA256.HashData(file));
            string identity = Convert.ToHexStringLower(SHA256.HashData(
                Encoding.UTF8.GetBytes(FormattableString.Invariant($"{id.Volume:x16}{id.Low:x16}{id.High:x16}"))));
            var key = (path.ToUpperInvariant(), hash);
            Signature? signature;
            lock (Cache) Cache.TryGetValue(key, out signature);
            if (signature is null)
            {
                signature = Verify(path, file.SafeFileHandle);
                if (signature is null) return null;
                file.Position = 0;
                if (hash != Convert.ToHexStringLower(SHA256.HashData(file))) return null;
                lock (Cache)
                {
                    if (Cache.Count >= 1024) Cache.Clear();
                    Cache[key] = signature;
                }
            }

            return new JsonObject {
                ["scope"] = "file_at_measurement", ["observed_at_utc"] = Iso8601.Format(now),
                ["status"] = signature.Status, ["reason"] = null, ["sha256_before"] = hash, ["sha256_after"] = hash,
                ["identity_before"] = identity, ["identity_after"] = identity,
                ["signer_sha256"] = signature.Signer, ["kind"] = signature.Signer is null ? "none" : "embedded",
            };
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static SafeFileHandle? OpenWithoutReparse(string path)
    {
        // Resolve the drive alias first. OBJ_DONT_REPARSE also rejects the DOS drive alias itself.
        var target = new StringBuilder(1024);
        if (QueryDosDeviceW(path[..2], target, (uint)target.Capacity) == 0) return null;
        string device = target.ToString();
        const string localVolume = @"\Device\HarddiskVolume";
        if (!device.StartsWith(localVolume, StringComparison.OrdinalIgnoreCase)
            || device.Length == localVolume.Length || !device[localVolume.Length..].All(char.IsAsciiDigit)) return null;
        string nativePath = device + path[2..];
        IntPtr name = Marshal.StringToHGlobalUni(nativePath);
        IntPtr unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            ushort length = checked((ushort)(nativePath.Length * 2));
            Marshal.StructureToPtr(new UnicodeString { Buffer = name, Length = length, Capacity = (ushort)(length + 2) }, unicode, false);
            var attributes = new ObjectAttributes { Size = Marshal.SizeOf<ObjectAttributes>(), Name = unicode,
                Flags = 0x40 | 0x1000 }; // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
            int status = NtOpenFile(out var handle, 0x100081, ref attributes, out _, 1, 0x60);
            if (status == 0 && !handle.IsInvalid) return handle;
            handle.Dispose();
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(unicode);
            Marshal.FreeHGlobal(name);
        }
    }

    private static Signature? Verify(string path, SafeFileHandle file)
    {
        var info = new TrustFile { Size = Marshal.SizeOf<TrustFile>(), Path = path, File = file.DangerousGetHandle() };
        IntPtr pointer = Marshal.AllocHGlobal(info.Size);
        Marshal.StructureToPtr(info, pointer, false);
        var data = new TrustData { Size = Marshal.SizeOf<TrustData>(), UiChoice = 2, UnionChoice = 1, File = pointer,
            StateAction = 1, Flags = 0x1000 }; // WTD_CACHE_ONLY_URL_RETRIEVAL
        try
        {
            int result = WinVerifyTrust(new IntPtr(-1), in Authenticode, ref data);
            if (result == unchecked((int)0x800B0100)) return new("unsigned", null); // TRUST_E_NOSIGNATURE
            if (result != 0 || data.State == IntPtr.Zero) return null;
            IntPtr provider = WTHelperProvDataFromStateData(data.State);
            if (provider == IntPtr.Zero) return null;
            IntPtr signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if (signer == IntPtr.Zero) return null;
            IntPtr cert = WTHelperGetProvCertFromChain(signer, 0);
            if (cert == IntPtr.Zero) return null;
            var context = Marshal.PtrToStructure<ProviderCert>(cert).Context;
            if (context == IntPtr.Zero) return null;
            var encoded = Marshal.PtrToStructure<CertContext>(context);
            if (encoded.Bytes == IntPtr.Zero || encoded.Length is < 1 or > 65536) return null;
            var bytes = new byte[encoded.Length];
            Marshal.Copy(encoded.Bytes, bytes, 0, bytes.Length);
            return new("signed", Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
        finally
        {
            if (data.State != IntPtr.Zero)
            {
                data.StateAction = 2;
                WinVerifyTrust(new IntPtr(-1), in Authenticode, ref data);
            }
            Marshal.DestroyStructure<TrustFile>(pointer);
            Marshal.FreeHGlobal(pointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustFile
    {
        internal int Size;
        internal string Path;
        internal IntPtr File, KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        internal int Size;
        internal IntPtr Policy, Sip;
        internal uint UiChoice, RevocationChecks, UnionChoice;
        internal IntPtr File;
        internal uint StateAction;
        internal IntPtr State, Url;
        internal uint Flags, UiContext;
        internal IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderCert { internal uint Size; internal IntPtr Context; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertContext { internal uint Encoding; internal IntPtr Bytes; internal int Length; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { internal ushort Length, Capacity; internal IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        internal int Size;
        internal IntPtr Root, Name;
        internal uint Flags;
        internal IntPtr Security, SecurityQuality;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus { internal IntPtr Status, Information; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId { internal ulong Volume, Low, High; }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtOpenFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
        out IoStatus ioStatus, uint share, uint options);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder target, uint capacity);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out FileId information, int size);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr window, in Guid action, ref TrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint index);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint index);
}
