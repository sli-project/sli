using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;

namespace Sli.Server.Jobs;

// Implemented by compiled, reviewed modules in pieces 13–16. Manifests select data, never code.
public interface ICoreJobPlugin
{
    void Register(CoreJobPluginCatalog catalog);
}
public sealed record CoreJobHandler(
    Func<NpgsqlConnection, JsonObject, CancellationToken, Task<JsonObject>> Stage,
    Func<NpgsqlConnection, JsonObject, JsonObject, CancellationToken, Task> Publish);
public delegate Task CoreJobSchedule(NpgsqlConnection connection, CoreJobQueue queue, CoreJobRegistry registry, string profile, CancellationToken ct);

public sealed class CoreJobPluginCatalog
{
    private readonly Dictionary<(string Plugin, string Handler), CoreJobHandler> handlers = [];
    private readonly Dictionary<string, CoreJobSchedule> schedules = [];
    public IEnumerable<string> Owners => handlers.Keys.Select(k => k.Plugin).Distinct();
    public void Add(string plugin, string handler, CoreJobHandler implementation, CoreJobSchedule? schedule = null)
    {
        // A module cannot extend the bundled allowlist by adding a manifest or an import path.
        var registry = new CoreJobRegistry();
        registry.Register(CoreJobRegistry.Bundled(plugin));
        if (plugin == "sli.workstations") registry.Register(CoreJobRegistry.Bundled("sli.workstations.projection"));
        if (!registry.Handlers.Any(h => h.Text("handler_id") == handler)) throw new CoreJobContractException("handler_not_allowlisted");
        handlers.Add((plugin, handler), implementation);
        if (schedule is not null) schedules[plugin] = schedule;
    }
    public CoreJobHandler Resolve(JsonObject job) => handlers.TryGetValue((job.Text("plugin_id"), job.Text("handler_id")), out var value) ? value : throw new CoreJobContractException("handler_version_unavailable");
    public bool Contains(JsonNode identity) => handlers.ContainsKey((identity.Text("plugin_id"), identity.Text("handler_id")));
    public Task ScheduleAsync(string plugin, NpgsqlConnection connection, CoreJobQueue queue, CoreJobRegistry registry, string profile, CancellationToken ct)
        => schedules.TryGetValue(plugin, out var schedule) ? schedule(connection, queue, registry, profile, ct) : Task.CompletedTask;
    public static CoreJobPluginCatalog Compiled()
    {
        var result = new CoreJobPluginCatalog();
        foreach (var type in typeof(CoreJobPluginCatalog).Assembly.GetTypes().Where(t => !t.IsAbstract && typeof(ICoreJobPlugin).IsAssignableFrom(t)))
            ((ICoreJobPlugin)Activator.CreateInstance(type)!).Register(result);
        return result;
    }
    public CoreJobRegistry Registry(string? runtimeRoot)
    {
        var registry = new CoreJobRegistry();
        foreach (string owner in Owners)
        {
            var active = new PluginGenerationReader(runtimeRoot).Read(owner).Generation;
            var seen = new HashSet<string>();
            var bundled = new List<JsonObject> { CoreJobRegistry.Bundled(owner) };
            if (owner == "sli.workstations") bundled.Add(CoreJobRegistry.Bundled("sli.workstations.projection"));
            foreach (var manifest in bundled)
                if (seen.Add(CoreJobJson.Digest(manifest))) registry.Register(manifest, active is null);
            if (runtimeRoot is null) continue;
            string directory = Path.Combine(runtimeRoot, owner, "versions");
            if (!Directory.Exists(directory))
            {
                if (active is not null) throw new CoreJobContractException("handler_version_unavailable");
                continue;
            }
            bool foundActive = active is null;
            foreach (var path in Directory.EnumerateDirectories(directory).Order(StringComparer.Ordinal))
            {
                string name = Path.GetFileName(path);
                if (!System.Text.RegularExpressions.Regex.IsMatch(name, "\\A[a-f0-9]{64}\\z") || new DirectoryInfo(path).LinkTarget is not null || !File.Exists(Path.Combine(path, "release.json"))) continue;
                JsonObject manifest;
                try { manifest = PluginPackageAdmission.Read(path, owner); }
                // A rejected candidate must not prevent rollback. Its pinned
                // jobs remain unavailable; never substitute another generation.
                catch (CoreJobContractException) when (name != active) { continue; }
                if (name == active) foundActive = true;
                if (seen.Add(CoreJobJson.Digest(manifest))) registry.Register(manifest, name == active);
                else if (name == active) registry.Activate(manifest);
            }
            if (!foundActive) throw new CoreJobContractException("handler_version_unavailable");
            if (active != new PluginGenerationReader(runtimeRoot).Read(owner).Generation) throw new CoreJobContractException("plugin_version_changed");
        }
        return registry;
    }
}

internal sealed class CoreJobAdmission : IDisposable
{
    private readonly FileStream? stream;
    private CoreJobAdmission(FileStream? stream) => this.stream = stream;
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)] private static extern int Flock(int fd, int operation);
    public static CoreJobAdmission Enter(string plugin, string? runtimeRoot, string? lockRoot)
    {
        // Validate ID and pointer before constructing paths.
        new PluginGenerationReader(runtimeRoot).Read(plugin);
        string? directory = runtimeRoot is null ? null : Path.Combine(runtimeRoot, plugin);
        void Check() { if (directory is not null && (File.Exists(Path.Combine(directory, "draining.json")) || Directory.Exists(Path.Combine(directory, "draining.json")))) throw new InvalidOperationException("plugin_update_draining"); }
        Check();
        string? path = lockRoot is not null ? Path.Combine(lockRoot, plugin + ".json") : directory is not null ? Path.Combine(directory, "admission.lock") : null;
        if (path is null) return new(null);
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("plugin_update_lock_unavailable");
        var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        try
        {
            if (Flock(checked((int)stream.SafeFileHandle.DangerousGetHandle()), 1) != 0) throw new IOException("plugin_update_lock_unavailable");
            Check(); return new(stream);
        }
        catch { stream.Dispose(); throw; }
    }
    public void Dispose() => stream?.Dispose();
}
