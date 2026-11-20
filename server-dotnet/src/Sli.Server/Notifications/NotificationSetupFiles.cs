using System.Runtime.InteropServices;

namespace Sli.Server.Notifications;

// Linux-only root writer, matching sli_secrets' root:10001 0750/0640 contract.
// statx with AT_SYMLINK_NOFOLLOW rejects links, including pre-existing targets.
public sealed class NotificationSetupFiles : INotificationSetupFiles
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(20)] public uint User;
        [FieldOffset(24)] public uint Group;
        [FieldOffset(28)] public ushort Mode;
    }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)] private static extern int Stat(int dir, string path, int flags, uint mask, out Statx data);
    [DllImport("libc", EntryPoint = "geteuid")] private static extern uint User();
    [DllImport("libc", EntryPoint = "chown", SetLastError = true)] private static extern int Chown(string path, uint uid, uint gid);
    [DllImport("libc", EntryPoint = "getxattr", SetLastError = true)] private static extern nint Xattr(string path, string name, IntPtr value, nuint size);
    [DllImport("libc", EntryPoint = "removexattr", SetLastError = true)] private static extern int RemoveXattr(string path, string name);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int Sync(int fd);
    [DllImport("libc", EntryPoint = "close")] private static extern int Close(int fd);
    private readonly string directory;
    private static readonly HashSet<string> Names = ["smtp.json", "smtp.ready", "notification_smtp_password", "telegram.json", "notification_telegram_token"];
    public NotificationSetupFiles(string path)
    {
        if (!OperatingSystem.IsLinux() || User() != 0 || !Path.IsPathFullyQualified(path)) throw new InvalidOperationException("notification_setup_root_required");
        directory = Path.GetFullPath(path);
        TrustedParents(Path.GetDirectoryName(directory)!);
        if (!ExistsPath(directory))
        {
            Directory.CreateDirectory(directory, (UnixFileMode)0x1c0); Protect(directory, 10001, (UnixFileMode)0x1e8);
        }
        Check(directory, true);
    }
    private static bool ExistsPath(string path)
    {
        if (Stat(-100, path, 0x100 | 0x800, 0x000f, out _) == 0) return true;
        if (Marshal.GetLastPInvokeError() == 2) return false;
        throw new IOException("notification_setup_path_invalid");
    }
    internal static void TrustedParents(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if (Stat(-100, current, 0x100 | 0x800, 0x000f, out var st) != 0 || st.User != 0 || (st.Mode & 0xf000) != 0x4000 || (st.Mode & 0x12) != 0)
                throw new IOException("notification_setup_path_invalid");
    }
    private static void Check(string path, bool directory)
    {
        int allowed = directory ? 0x1e8 : 0x1a0;
        if (Stat(-100, path, 0x100 | 0x800, 0x000f, out var st) != 0 || st.User != 0 || st.Group != 10001 ||
            (st.Mode & 0xf000) != (directory ? 0x4000 : 0x8000) || (st.Mode & 0xfff & ~allowed) != 0 || !directory && (st.Mode & 0x20) == 0)
            throw new IOException("notification_setup_acl_invalid");
        foreach (string attr in new[] { "system.posix_acl_access", "system.posix_acl_default" })
        {
            var length = Xattr(path, attr, IntPtr.Zero, 0);
            if (length >= 0 || Marshal.GetLastPInvokeError() is not (61 or 95)) throw new IOException("notification_setup_acl_invalid");
        }
    }
    internal static void Protect(string path, uint gid, UnixFileMode mode)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        foreach (string attr in new[] { "system.posix_acl_access", "system.posix_acl_default" })
            if (RemoveXattr(path, attr) != 0 && Marshal.GetLastPInvokeError() is not (61 or 95)) throw new IOException("notification_setup_acl_invalid");
        if (Chown(path, 0, gid) != 0) throw new IOException("notification_setup_acl_invalid");
        File.SetUnixFileMode(path, mode);
    }
    internal static void SyncDirectory(string path)
    {
        int fd = Open(path, 0x10000 | 0x80000); if (fd < 0) throw new IOException("notification_setup_sync_failed");
        try { if (Sync(fd) != 0) throw new IOException("notification_setup_sync_failed"); } finally { Close(fd); }
    }
    private string PathFor(string name)
    { if (!Names.Contains(name)) throw new IOException("notification_setup_path_invalid"); Check(directory, true); return Path.Combine(directory, name); }
    public bool Exists(string name) { string path = PathFor(name); if (!ExistsPath(path)) return false; Check(path, false); return true; }
    public byte[] Read(string name)
    {
        string path = PathFor(name); Check(path, false);
        using var stream = File.OpenRead(path); var bytes = new byte[65537]; int n = 0, read;
        while (n < bytes.Length && (read = stream.Read(bytes, n, bytes.Length - n)) > 0) n += read;
        if (n > 65536) throw new IOException("notification_setup_size_invalid"); return bytes[..n];
    }
    public void Remove(string name)
    { string path = PathFor(name); if (ExistsPath(path)) { Check(path, false); File.Delete(path); } SyncDirectory(directory); }
    public void Publish(string name, byte[] content)
    {
        if (content.Length > 65536) throw new IOException("notification_setup_size_invalid");
        string path = PathFor(name); if (ExistsPath(path)) Check(path, false);
        string temporary = Path.Combine(directory, ".sli-secret-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            using (var stream = new FileStream(temporary, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = (UnixFileMode)0x180 }))
            { stream.Write(content); stream.Flush(true); }
            Protect(temporary, 10001, (UnixFileMode)0x1a0); File.Move(temporary, path, true); SyncDirectory(directory);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    internal static void PrepareSocket(string path, uint gid)
    {
        string parent = Path.GetDirectoryName(path)!;
        TrustedParents(Path.GetDirectoryName(parent)!);
        if (!Directory.Exists(parent)) { Directory.CreateDirectory(parent); Protect(parent, gid, (UnixFileMode)0x1e8); }
        TrustedParents(parent);
        // systemd creates RuntimeDirectory as root:root 0700. Python changes
        // that trusted directory to root:sli-api 0750 before binding.
        if (Stat(-100, parent, 0x100 | 0x800, 0x000f, out _) != 0) throw new IOException("notification_setup_acl_invalid");
        Protect(parent, gid, (UnixFileMode)0x1e8);
        if (ExistsPath(path))
        {
            if (Stat(-100, path, 0x100 | 0x800, 0x000f, out var socket) != 0 || socket.User != 0 || (socket.Mode & 0xf000) != 0xc000) throw new IOException("notification_setup_path_invalid");
            File.Delete(path);
        }
    }
}
