using System.CommandLine;
using System.Runtime.InteropServices;
using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.InstallationSetup;
using Sli.Server.Jobs;

namespace Sli.Server.Plugins;

// Host updater contract from plugins/update_runtime.py. Never imports package code.
public static class PluginRuntimeCommand
{
    public static Task<int> RunAsync(string[] args) => RunAsync(args,
        new ConfigurationBuilder().Build(), CoreJobPluginCatalog.Compiled(), Console.Out, Console.Error);

    internal static async Task<int> RunAsync(string[] args, IConfiguration configuration,
        CoreJobPluginCatalog catalog, TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var action = new Argument<string>("action");
        var plugin = new Argument<string>("plugin_id");
        var version = new Option<string?>("--version");
        var root = new RootCommand("Drain or check a reviewed native plugin registration.");
        foreach (var option in root.Options.Where(option => option.Name == "--version").ToArray()) root.Options.Remove(option);
        root.Arguments.Add(action); root.Arguments.Add(plugin); root.Options.Add(version);
        root.SetAction(async (parse, token) =>
        {
            using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
            using var signal = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM,
                context => { context.Cancel = true; stopping.Cancel(); }) : null;
            ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; stopping.Cancel(); };
            Console.CancelKeyPress += onCancel;
            try
            {
                string id = parse.GetValue(plugin)!;
                PluginGenerationReader.ValidateId(id);
                var packages = new InstallationPackages(configuration);
                switch (parse.GetValue(action))
                {
                    case "drain":
                        if (parse.GetValue(version) is not null) return 2;
                        await PluginDrain.WaitAsync(id, packages.RuntimeRoot, packages.LockRoot, output, stopping.Token);
                        break;
                    case "health":
                        if (parse.GetValue(version) is not { Length: > 0 } expected)
                            throw new InvalidOperationException("plugin_update_version_required");
                        PluginHealth.Check(id, expected, packages, catalog);
                        await output.WriteLineAsync(JsonSerializer.Serialize(new { status = "healthy", plugin_id = id, version = expected }));
                        break;
                    default: throw new InvalidOperationException("plugin_update_action_invalid");
                }
                return 0;
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            { await error.WriteLineAsync("plugin_update_cancelled"); return 130; }
            catch (Exception e)
            {
                // No paths, package bytes, database diagnostics or arbitrary exception text.
                string code = e.Message;
                string[] allowed = ["plugin_update_invalid_id", "plugin_update_invalid_generation", "plugin_update_fence_required",
                    "plugin_update_lock_unavailable", "plugin_update_generation_unsupported", "plugin_update_health_unavailable",
                    "plugin_update_health_failed", "plugin_update_version_required", "plugin_update_ui_version_mismatch",
                    "plugin_update_handler_mismatch", "plugin_update_action_invalid", "plugin_update_generation_changed",
                    "plugin_ui_invalid_descriptor", "plugin_ui_not_installed", "plugin_ui_integrity_failed", "plugin_ui_unsupported_api"];
                await error.WriteLineAsync(allowed.Contains(code, StringComparer.Ordinal) ? code : "plugin_update_runtime_failed");
                return 1;
            }
            finally { Console.CancelKeyPress -= onCancel; }
        });
        return await root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null })
            .InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }
}

internal static class PluginDrain
{
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)] private static extern int Flock(int fd, int operation);

    internal static async Task WaitAsync(string id, string? runtimeRoot, string? lockRoot, TextWriter output, CancellationToken ct)
    {
        PluginGenerationReader.ValidateId(id);
        runtimeRoot = Access.Administration.AssignmentValidation.Strip(runtimeRoot ?? "");
        lockRoot = Access.Administration.AssignmentValidation.Strip(lockRoot ?? "");
        string? directory = runtimeRoot.Length == 0 ? null : Path.Combine(runtimeRoot, id);
        bool Fenced() => directory is not null && (File.Exists(Path.Combine(directory, "draining.json"))
            || Directory.Exists(Path.Combine(directory, "draining.json")));
        void CheckFence() { if (!Fenced()) throw new InvalidOperationException("plugin_update_fence_required"); }
        CheckFence();
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("plugin_update_lock_unavailable");
        string path = lockRoot.Length != 0 ? Path.Combine(lockRoot, id + ".json") : Path.Combine(directory!, "admission.lock");
        // Use the existing inode, including a read-only manifest bind mount. Never create/replace it.
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        int fd = checked((int)stream.SafeFileHandle.DangerousGetHandle());
        DateTimeOffset nextHeartbeat = DateTimeOffset.MinValue;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            CheckFence();
            if (Flock(fd, 2 | 4) == 0)
            {
                CheckFence();
                await Emit("drained");
                return; // Closing releases LOCK_EX; the durable fence continues to deny admission.
            }
            int errno = Marshal.GetLastPInvokeError();
            if (errno is not (11 or 4)) throw new IOException("plugin_update_lock_unavailable");
            if (DateTimeOffset.UtcNow >= nextHeartbeat)
            {
                await Emit("waiting");
                nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(1);
            }
            await Task.Delay(50, ct); // Progress polling, not a drain deadline.
        }
        async Task Emit(string status)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new { status, plugin_id = id, pid = Environment.ProcessId,
                heartbeat_utc = DateTimeOffset.UtcNow }));
            await output.FlushAsync(ct);
        }
    }
}

internal static class PluginHealth
{
    internal static void Check(string id, string expected, InstallationPackages packages, CoreJobPluginCatalog catalog)
    {
        var reader = new PluginGenerationReader(packages.RuntimeRoot);
        var before = reader.Read(id);
        // Legacy release.json packages ship Python executables. Native hooks explicitly reject
        // these generations, so their manifests/UI cannot be used as evidence of health.
        if (before.Generation is not null) throw new InvalidOperationException("plugin_update_generation_unsupported");
        // GPO/workstations have no health hook in the frozen registry. Sigma has no native
        // contribution registration here. Do not turn their metadata into a positive check.
        if (id is not ("sli.ad" or "sli.remote-access" or "sli.file-audit"))
            throw new InvalidOperationException("plugin_update_health_unavailable");
        // Registration readiness, as in the source health hooks: no acquisition or writes.
        if (!new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules.Any(r => r.OwnerId == id))
            throw new InvalidOperationException("plugin_update_health_failed");
        if (id is "sli.ad" or "sli.remote-access")
        {
            var manifest = CoreJobRegistry.Bundled(id);
            var registry = new CoreJobRegistry(); registry.Register(manifest);
            if (registry.Handlers.Any(h => !catalog.Contains(h)))
                throw new InvalidOperationException("plugin_update_handler_mismatch");
            foreach (var handler in registry.Handlers) _ = catalog.Resolve(handler);
        }
        // Reuse the serving validator, including hashes, UTF-8 and symlink/path checks.
        // The host deliberately retains the fence until this succeeds and commit completes.
        var ui = packages.LoadUi(id, allowDraining: true);
        if (InstallationPackages.Text(ui.Descriptor["version"]) != expected)
            throw new InvalidOperationException("plugin_update_ui_version_mismatch");
        if (reader.Read(id) != before) throw new InvalidOperationException("plugin_update_generation_changed");
    }
}
