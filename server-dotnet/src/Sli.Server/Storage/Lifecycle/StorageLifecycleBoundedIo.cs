using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Storage.Lifecycle;

// Port of storage_lifecycle_bounded_io.read_bytes: inspect the pinned file,
// including its modification time, before returning any bytes to the caller.
internal static class StorageLifecycleBoundedIo
{
    internal readonly record struct Identity(ulong Device, ulong Inode, ulong Size, long ModifiedSeconds, uint ModifiedNanoseconds);

    internal static byte[] ReadBytes(string path, int maxBytes, string tooLarge,
        Func<SafeFileHandle, Identity>? metadata = null)
    {
        Identity before;
        try {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            before = FileIdentity(handle);
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException) {
            throw new LifecycleBlocked("bounded_file_stat_failed");
        }
        if (before.Size > (ulong)maxBytes) throw new LifecycleBlocked(tooLarge);
        metadata ??= FileIdentity;
        try {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (metadata(stream.SafeFileHandle) != before) throw new LifecycleBlocked("bounded_file_changed_during_open");
            byte[] bytes = new byte[checked(maxBytes + 1)]; int count = 0, read;
            while (count < bytes.Length && (read = stream.Read(bytes, count, bytes.Length - count)) != 0) count += read;
            if (metadata(stream.SafeFileHandle) != before) throw new LifecycleBlocked("bounded_file_changed_during_read");
            if (count > maxBytes) throw new LifecycleBlocked(tooLarge);
            return bytes[..count];
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException) {
            throw new LifecycleBlocked("bounded_file_read_failed");
        }
    }

    internal static Identity FileIdentity(SafeFileHandle handle)
    {
        if (OperatingSystem.IsLinux()) {
            // Same stable statx ABI as AdCredentialSecrets; AT_EMPTY_PATH pins
            // the opened inode. Keep nanoseconds: DateTime would round them away.
            bool retained = false;
            try {
                handle.DangerousAddRef(ref retained);
                if (Stat(handle.DangerousGetHandle().ToInt32(), "", 0x1000, 0x340, out var info) != 0 || (info.Mask & 0x340) != 0x340)
                    throw new IOException("bounded_file_metadata_failed");
                return new(((ulong)info.DeviceMajor << 32) | info.DeviceMinor, info.Inode, info.Size, info.ModifiedSeconds, info.ModifiedNanoseconds);
            } finally { if (retained) handle.DangerousRelease(); }
        }
        if (OperatingSystem.IsWindows()) {
            if (!GetInformation(handle, out var info)) throw new IOException("bounded_file_metadata_failed");
            ulong modified = ((ulong)info.ModifiedHigh << 32) | info.ModifiedLow;
            return new(info.Volume, ((ulong)info.InodeHigh << 32) | info.InodeLow,
                ((ulong)info.SizeHigh << 32) | info.SizeLow, (long)(modified / 10000000), (uint)(modified % 10000000 * 100));
        }
        throw new PlatformNotSupportedException("bounded_file_metadata_unsupported");
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(40)] public ulong Size;
        [FieldOffset(112)] public long ModifiedSeconds;
        [FieldOffset(120)] public uint ModifiedNanoseconds;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }
    [StructLayout(LayoutKind.Explicit, Size = 52)]
    struct WindowsInformation
    {
        [FieldOffset(20)] public uint ModifiedLow;
        [FieldOffset(24)] public uint ModifiedHigh;
        [FieldOffset(28)] public uint Volume;
        [FieldOffset(32)] public uint SizeHigh;
        [FieldOffset(36)] public uint SizeLow;
        [FieldOffset(44)] public uint InodeHigh;
        [FieldOffset(48)] public uint InodeLow;
    }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    static extern int Stat(int descriptor, string path, int flags, uint mask, out Statx info);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetInformation(SafeFileHandle handle, out WindowsInformation info);
}
