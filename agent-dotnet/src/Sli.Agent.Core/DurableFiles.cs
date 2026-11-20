namespace Sli.Agent.Core;

/// <summary>
/// The only way the agent changes its state on disk. Every write is all-or-nothing: a crash leaves the old file or the new
/// one, never half of it. Tests replace it to inject failures between steps.
/// </summary>
public interface IDurableFiles
{
    void WriteAtomic(string path, ReadOnlySpan<byte> data);

    byte[]? ReadAll(string path);

    void Delete(string path);

    long Length(string path);

    IReadOnlyList<string> List(string directory, string searchPattern);

    void EnsureDirectory(string directory);
}

/// <summary>Hardens a state directory (Windows: a protected DACL for the service identity and SYSTEM). The default does nothing.</summary>
public interface IDirectorySecurity
{
    void Secure(string directory);
}

public sealed class NoDirectorySecurity : IDirectorySecurity
{
    public void Secure(string directory)
    {
    }
}

public sealed class PhysicalDurableFiles(IDirectorySecurity? security = null) : IDurableFiles
{
    private readonly IDirectorySecurity _security = security ?? new NoDirectorySecurity();
    private readonly HashSet<string> _secured = [];

    public void EnsureDirectory(string directory)
    {
        if (new DirectoryInfo(directory).LinkTarget is not null) throw new AgentException("agent_state_path_invalid");
        Directory.CreateDirectory(directory);
        // Once per process and directory: this runs at every start (so a damaged ACL is repaired) but not at every write.
        lock (_secured)
        {
            if (_secured.Add(Path.GetFullPath(directory))) _security.Secure(directory);
        }
    }

    public void WriteAtomic(string path, ReadOnlySpan<byte> data)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        EnsureDirectory(directory);
        var temporary = Path.Combine(directory, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public byte[]? ReadAll(string path)
    {
        // File.Exists also returns false for access failures. Never mistake an unreadable identity for a new host.
        try { return File.ReadAllBytes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    public void Delete(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    public long Length(string path) => new FileInfo(path).Length;

    public IReadOnlyList<string> List(string directory, string searchPattern) =>
        Directory.Exists(directory) ? Directory.EnumerateFiles(directory, searchPattern).Order(StringComparer.Ordinal).ToList() : [];
}
