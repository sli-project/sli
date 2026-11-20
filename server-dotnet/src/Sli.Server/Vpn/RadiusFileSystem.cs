using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Sli.Agent.Core;

namespace Sli.Server.Vpn;

/// <summary>Read-only local/SMB handles; reparse points and identity changes fail closed. No RADIUS configuration is read.</summary>
[SupportedOSPlatform("windows")]
internal sealed class RadiusFileSystem : IRadiusFileSystem
{
    public IEnumerable<RadiusFile> Inventory(string directory)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(directory))
        {
            var name = Path.GetFileName(path);
            if (!name.StartsWith("in", StringComparison.OrdinalIgnoreCase) || !name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)) continue;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new AgentException("tail_reparse_point_forbidden");
            using var file = OpenPath(path);
            yield return file.Metadata;
        }
    }
    public IRadiusReadFile Open(RadiusFile file) => OpenPath(file.Key);
    private static ReadFile OpenPath(string path)
    {
        // OPEN_REPARSE_POINT observes the link itself instead of following a swapped directory entry.
        var handle = CreateFileW(path, 0x80000000, 1 | 2 | 4, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException("radius_open_failed"); }
        try
        {
            if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("radius_stat_failed");
            if ((info.Attributes & 0x400) != 0) throw new AgentException("tail_reparse_point_forbidden");
            if ((info.Attributes & 0x10) != 0) throw new IOException("radius_not_file");
            static long Ns(uint high, uint low) => checked((((long)high << 32 | low) - 116444736000000000L) * 100);
            var metadata = new RadiusFile(path, Path.GetFileName(path), Ns(info.CreationHigh, info.CreationLow), Ns(info.WriteHigh, info.WriteLow),
                checked((long)((ulong)info.SizeHigh << 32 | info.SizeLow)), info.Volume.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ((ulong)info.IndexHigh << 32 | info.IndexLow).ToString(System.Globalization.CultureInfo.InvariantCulture));
            return new(handle, metadata);
        }
        catch { handle.Dispose(); throw; }
    }
    private sealed class ReadFile(SafeFileHandle handle, RadiusFile metadata) : IRadiusReadFile
    {
        public RadiusFile Metadata => metadata;
        public byte[] Read(long offset, int count)
        {
            var bytes = new byte[count];
            var read = 0;
            while (read < count)
            {
                var step = RandomAccess.Read(handle, bytes.AsSpan(read), offset + read);
                if (step == 0) break;
                read += step;
            }
            return bytes[..read];
        }
        public void Dispose() => handle.Dispose();
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Information
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out Information information);
}
