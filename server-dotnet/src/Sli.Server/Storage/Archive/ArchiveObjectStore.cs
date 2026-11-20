using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sli.Server.Storage.Archive;

// Same-volume create-new/flush/immutable rename protocol. Directory fsync mirrors RadiusEvidenceStore.
internal sealed class ArchiveObjectStore
{
    readonly string root;
    readonly Action<string> syncDirectory;
    internal static bool SupportsRoot(string root) => Path.IsPathFullyQualified(root);
    internal ArchiveObjectStore(string root, Action<string>? syncDirectory = null,bool initialize=true)
    {
        this.syncDirectory = syncDirectory ?? Sync;
        if (!SupportsRoot(root)) throw new InvalidDataException("archive_root_absolute_required");
        this.root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        CheckAncestors(this.root);
        if(!initialize) return;
        Directory.CreateDirectory(this.root);
        foreach (var name in new[] { "staging", "published", "quarantine" })
        { string path = Path.Combine(this.root, name); CheckAncestors(path); Directory.CreateDirectory(path); this.syncDirectory(this.root); }
    }
    internal string Final(string name) => ObjectPath("published", name);
    internal string Partial(string name) => ObjectPath("staging", name + ".partial");
    string ObjectPath(string directory, string name)
    {
        if (string.IsNullOrWhiteSpace(name) || Path.GetFileName(name) != name || name.IndexOfAny(['/', '\\', ':']) >= 0 || name is "." or "..")
            throw new InvalidDataException("archive_object_name_invalid");
        string path = Path.Combine(root, directory, name); RequirePath(path); return path;
    }
    internal void RequirePath(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("archive_object_outside_root");
        var absolute = Path.GetFullPath(path);
        string relative = Path.GetRelativePath(root, absolute);
        if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathFullyQualified(relative))
            throw new InvalidDataException("archive_object_outside_root");
        CheckAncestors(absolute);
    }
    static void CheckAncestors(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            // GetAttributes observes dangling symlinks too; File.Exists would silently miss them.
            try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("archive_reparse_path_refused"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }
    internal static byte[] ReadBounded(string path, long size)
    {
        if (size is < 1 or > ArchiveCodec.MaxCompressedBytes) throw new InvalidDataException("archive_compressed_out_of_bounds");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length != size) throw new InvalidDataException("archive_compressed_size_mismatch");
        byte[] bytes = new byte[checked((int)size)]; input.ReadExactly(bytes);
        if (input.ReadByte() != -1) throw new InvalidDataException("archive_compressed_size_mismatch");
        return bytes;
    }
    internal void Verify(string path, byte[] expected)
    {
        RequirePath(path);
        var bytes = ReadBounded(path, expected.Length);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), SHA256.HashData(expected))) throw new InvalidDataException("archive_object_hash_mismatch");
    }
    internal void QuarantinePartial(string name)
    {
        string partial = Partial(name), quarantine = ObjectPath("quarantine", name + ".hash-mismatch");
        AtomicMove(partial, quarantine);
        syncDirectory(Path.GetDirectoryName(quarantine)!); syncDirectory(Path.GetDirectoryName(partial)!);
    }
    internal void SyncPublicationDirectories(string final)
    {
        RequirePath(final);
        string staging = Path.Combine(root,"staging"); RequirePath(staging);
        // A visible final object may be the result of a rename whose directory fsync failed.
        // Recovery must complete BOTH syncs before the database can expose it as published.
        syncDirectory(Path.GetDirectoryName(final)!); syncDirectory(staging);
    }
    internal string Prepare(string name, byte[] compressed)
    {
        var final = Final(name);
        if (File.Exists(final)) { Verify(final, compressed); return final; }
        string partial = ObjectPath("staging", name + ".partial");
        if (File.Exists(partial))
        {
            try { Verify(partial, compressed); }
            catch (InvalidDataException)
            {
                QuarantinePartial(name);
                throw;
            }
        }
        else
        {
            using (var file = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(compressed); file.Flush(true); }
            syncDirectory(Path.GetDirectoryName(partial)!);
            Verify(partial, compressed);
        }
        return partial;
    }
    internal void Publish(string prepared, string final, byte[] compressed)
    {
        Verify(prepared, compressed); RequirePath(final);
        if (prepared == final) { SyncPublicationDirectories(final); return; }
        try { AtomicMove(prepared, final); }
        catch (IOException) when (File.Exists(final))
        { Verify(final, compressed); File.Delete(prepared); }
        SyncPublicationDirectories(final);
        Verify(final, compressed);
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close", SetLastError = true)] static extern int Close(int fd);
    [DllImport("libc", EntryPoint = "renameat2", SetLastError = true)] static extern int RenameNoReplace(int oldDirectory, string oldPath, int newDirectory, string newPath, uint flags);
    static void AtomicMove(string source, string destination)
    {
        if (OperatingSystem.IsWindows()) { File.Move(source,destination,false); return; }
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("archive_atomic_rename_unsupported");
        // Do not permit File.Move's cross-device copy/delete fallback. EXDEV and unsupported
        // kernel/filesystem primitives fail closed, leaving the durable staging object intact.
        if (RenameNoReplace(-100,source,-100,destination,1) != 0)
            throw new IOException("archive_atomic_rename_failed errno=" + Marshal.GetLastPInvokeError());
    }
    static void Sync(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        int fd = Open(path, 0);
        if (fd < 0) throw new IOException("archive_directory_sync_failed");
        try { if (Fsync(fd) != 0) throw new IOException("archive_directory_sync_failed"); } finally { _ = Close(fd); }
    }
}
