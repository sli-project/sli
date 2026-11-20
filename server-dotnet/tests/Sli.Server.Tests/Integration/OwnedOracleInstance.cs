using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

namespace Sli.Server.Tests.Integration;

// Oracle harness only. Cleanup never signals a PID and retains markers and diagnostic files.
internal static class OwnedOracleInstance
{
    private const string Format = "sli.test.oracle-instance.v2";
    private const string Marker = "instance-owner.json";
    private static readonly string[] Pending = ["runtime-password.txt", "ready.json", "ready.tmp"];
    private sealed record Identity(int Pid, long Started);
    private sealed record Instance(string Path, byte[] MarkerBytes, Identity Identity);

    internal static string Record(string root, Guid runId, string side, Guid instanceId, Process process)
    {
        string directory = SideDirectory(root, runId, side);
        RequireUuid(instanceId);
        // Read the launched Process object, never rediscover ownership from a bare PID.
        if (process.HasExited) throw Refused();
        long started = process.StartTime.ToUniversalTime().Ticks;
        if (started <= 0 || process.HasExited) throw Refused();
        string instance = Path.Combine(directory, "oracle-" + instanceId.ToString("D"));
        if (Path.Exists(instance) || new DirectoryInfo(instance).LinkTarget is not null) throw Refused();
        Directory.CreateDirectory(instance);
        RequirePlainPath(instance);
        using var stream = new FileStream(Path.Combine(instance, Marker), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        JsonSerializer.Serialize(stream, new { format = Format, run_id = runId.ToString("D"),
            instance_id = instanceId.ToString("D"), pid = process.Id, process_start_utc_ticks = started });
        stream.Flush(flushToDisk: true);
        return instance;
    }

    // null means positively absent/exited. Identity/permission errors must throw, never mean absent.
    internal static long? ReadProcessStart(int pid)
    {
        if (pid <= 0 || !(OperatingSystem.IsWindows() || OperatingSystem.IsLinux())) throw Refused();
        Process process;
        try { process = Process.GetProcessById(pid); }
        catch (ArgumentException) { return null; }
        using (process)
        {
            try
            {
                if (process.HasExited) return null;
                long started = process.StartTime.ToUniversalTime().Ticks;
                if (started <= 0) throw Refused();
                return started;
            }
            catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException)
            { throw Refused(); }
        }
    }

    internal static void CleanupStopped(string root, Guid runId, string side, Func<int, long?>? readStart = null)
    {
        readStart ??= ReadProcessStart;
        string directory = SideDirectory(root, runId, side);
        var instances = new List<Instance>();
        // Admit every instance before deleting anything: an unknown/live sibling preserves the run.
        foreach (string instance in Directory.EnumerateFileSystemEntries(directory, "oracle-*"))
        {
            RequirePlainPath(instance);
            if (!Directory.Exists(instance)) throw Refused();
            string id = Path.GetFileName(instance)["oracle-".Length..];
            if (!Guid.TryParseExact(id, "D", out var instanceId) || instanceId.ToString("D") != id) throw Refused();
            RequireUuid(instanceId);
            string marker = Path.Combine(instance, Marker);
            RequirePlainPath(marker);
            byte[] bytes = File.ReadAllBytes(marker);
            Identity identity;
            try
            {
                using var doc = JsonDocument.Parse(bytes);
                var m = doc.RootElement;
                string[] fields = ["format", "run_id", "instance_id", "pid", "process_start_utc_ticks"];
                if (m.ValueKind != JsonValueKind.Object || m.EnumerateObject().Count() != fields.Length
                    || m.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != fields.Length
                    || !fields.All(f => m.TryGetProperty(f, out _))
                    || m.GetProperty("format").GetString() != Format
                    || m.GetProperty("run_id").GetString() != runId.ToString("D")
                    || m.GetProperty("instance_id").GetString() != id) throw Refused();
                identity = new(m.GetProperty("pid").GetInt32(), m.GetProperty("process_start_utc_ticks").GetInt64());
                if (identity.Pid <= 0 || identity.Started <= 0 || identity.Started > DateTime.MaxValue.Ticks) throw Refused();
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException or OverflowException)
            { throw Refused(); }
            var candidate = new Instance(instance, bytes, identity);
            Admit(candidate, readStart);
            instances.Add(candidate);
        }
        foreach (var instance in instances)
        {
            Admit(instance, readStart);
            foreach (string name in Pending)
            {
                // Revalidate immediately before each unlink; never recurse into diagnostics or other files.
                Admit(instance, readStart);
                string path = Path.Combine(instance.Path, name);
                if (PendingFile(path)) File.Delete(path);
            }
        }
    }

    private static void Admit(Instance instance, Func<int, long?> readStart)
    {
        RequirePlainPath(instance.Path);
        string marker = Path.Combine(instance.Path, Marker);
        RequirePlainPath(marker);
        if (!File.ReadAllBytes(marker).AsSpan().SequenceEqual(instance.MarkerBytes)) throw Refused();
        long? current;
        try { current = readStart(instance.Identity.Pid); }
        catch (Exception e) when (e is Win32Exception or UnauthorizedAccessException or IOException or InvalidOperationException)
        { throw Refused(); }
        // Exact creation identity only: no marker timestamps, age thresholds or PID-only fallback.
        if (current is <= 0 || current > DateTime.MaxValue.Ticks || current == instance.Identity.Started) throw Refused();
        foreach (string name in Pending)
            PendingFile(Path.Combine(instance.Path, name));
    }

    private static bool PendingFile(string path)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return false; }
        // File.Exists masks permission/IO failures as absence; those failures must propagate.
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) throw Refused();
        RequirePlainPath(path);
        return true;
    }

    private static string SideDirectory(string root, Guid runId, string side)
    {
        RequireUuid(runId);
        if (!Path.IsPathFullyQualified(root) || side is not ("python" or "dotnet")) throw Refused();
        string directory = Path.Combine(Path.GetFullPath(root), runId.ToString("D"), side);
        RequirePlainPath(directory);
        if (!Directory.Exists(directory)) throw Refused();
        return directory;
    }

    private static void RequirePlainPath(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw Refused();
    }

    private static void RequireUuid(Guid id)
    {
        if (id == Guid.Empty || id.ToString("D")[14] != '4') throw Refused();
    }

    private static InvalidOperationException Refused() => new("Owned oracle cleanup refused: process identity or file ownership could not be verified");
}
