using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Workspace;

namespace Sli.Server.Jobs;

public sealed class CoreJobWorker(CoreJobPluginCatalog catalog) : IAsyncDisposable
{
    private NpgsqlConnection? childConnection;
    private string? childIdentity;
    public async ValueTask DisposeAsync()
    {
        if (childConnection is not null) await childConnection.DisposeAsync();
    }
    private static string? Env(string key) => Environment.GetEnvironmentVariable(key);
    private static string? DirectorySetting(string key) => string.IsNullOrWhiteSpace(Env(key)) ? null : Env(key)!.Trim();
    internal static bool Enabled(JsonNode identity, Func<string, string?> environment,
        IReadOnlySet<string>? enabledPlugins = null, Func<string, bool>? installed = null) => identity.Text("plugin_id") switch
    {
        "sli.remote-access" => environment("SLI_CORE_JOB_RADIUS_PILOT") == "1",
        "sli.ad" or "sli.gpo" => environment("SLI_CORE_JOB_AD_GPO_PILOT") == "1"
            && (installed?.Invoke(identity.Text("plugin_id")) ?? Installed(identity, PackageRoot()))
            && (enabledPlugins ?? EnabledPlugins()).Contains(identity.Text("plugin_id")),
        "sli.workstations" => identity.Text("handler_id") == "workstations.overview-project"
            ? environment("SLI_CORE_JOB_WORKSTATIONS_PROJECTION") == "1"
            : environment("SLI_CORE_JOB_WORKSTATIONS_RETENTION") == "1",
        _ => false
    };
    private static string? PackageRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, "config", "plugin_packages", "v3"))) return directory.FullName;
        return null;
    }
    internal static bool Installed(JsonNode identity, string? packageRoot, CoreJobPluginCatalog? available = null) => (available ?? CoreJobPluginCatalog.Compiled()).Contains(identity)
        && (packageRoot is null || File.Exists(Path.Combine(packageRoot, "config", "plugin_packages", "v3", identity.Text("plugin_id") + ".json")));
    private static IReadOnlySet<string> EnabledPlugins()
    {
        // Native packages retain navigation settings; standalone compiled deployments use the bundled declaration.
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string path = Path.Combine(directory.FullName, "config", "navigation_v3.json");
            if (File.Exists(path)) return JsonNode.Parse(File.ReadAllText(path))!["enabled_plugins"]!.AsArray().Select(p => p!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        }
        return WorkspaceJson.Declarations.GetProperty("navigation").GetProperty("enabled_plugins").EnumerateArray().Select(p => p.GetString()!).ToHashSet(StringComparer.Ordinal);
    }
    public async Task<int> RunAsync(string profile, bool once, CancellationToken stopping)
    {
        NpgsqlConnection? connection = null;
        await using var children = new CoreJobProcess.Persistent();
        return await RunAsync(profile, once, stopping, async ct =>
        {
            var settings = CoreJobIdentity.Settings(profile, "dispatcher", Env, CoreJobIdentity.ReadSecret);
            connection = new NpgsqlConnection(settings.ConnectionString);
            try { await connection.OpenAsync(ct); return new PostgresCoreJobSession(connection); }
            catch { await connection.DisposeAsync(); throw; }
        }, (owner, queue, registry, ct) => catalog.ScheduleAsync(owner, connection!, queue, registry, profile, ct),
            profile == "light" ? children.RunAsync : CoreJobProcess.RunAsync, Env, TimeProvider.System, (pause, ct) => Task.Delay(pause, ct),
            async (failed, code, permanent) =>
            {
                var settings = CoreJobIdentity.Settings(profile, "dispatcher", Env, CoreJobIdentity.ReadSecret);
                await using var recovery = new NpgsqlConnection(settings.ConnectionString);
                await recovery.OpenAsync(stopping);
                await new CoreJobQueue(new PostgresCoreJobSession(recovery)).FailAsync(failed, code, permanent, stopping);
            });
    }
    internal async Task<int> RunAsync(string profile, bool once, CancellationToken stopping,
        Func<CancellationToken, Task<ICoreJobSession>> open,
        Func<string, CoreJobQueue, CoreJobRegistry, CancellationToken, Task> schedule, CoreJobChild child,
        Func<string, string?> environment, TimeProvider clock, Func<TimeSpan, CancellationToken, Task> delay,
        Func<JsonObject, string, bool, Task>? recordFailure = null)
    {
        if (!CoreJobRegistry.Profiles.ContainsKey(profile)) throw new CoreJobContractException("executor_profile_invalid");
        ICoreJobSession? session = null;
        var scheduled = new Dictionary<string, long>();
        var scheduleInterval = TimeSpan.FromSeconds(profile == "light" ? 30 : 5);
        bool radiusLocked = false;
        try
        {
        do
        {
            if (stopping.IsCancellationRequested) return 0;
            var registry = catalog.Registry(DirectorySetting("SLI_PLUGIN_RUNTIME_DIR"));
            var identities = new JsonArray(registry.Identities(profile).Where(x => catalog.Contains(x!) && Enabled(x!, environment,
                installed: _ => Installed(x!, PackageRoot(), catalog))).Select(x => x!.DeepClone()).ToArray());
            WriteHeartbeat(profile, identities.Count != 0);
            bool dispatched = false;
            try
            {
                if (identities.Count != 0)
                {
                    session ??= await open(stopping);
                    var queue = new CoreJobQueue(session);
                    var admissions = new Dictionary<string, CoreJobAdmission>();
                    try
                    {
                        foreach (string owner in identities.Select(x => x!.Text("plugin_id")).Distinct())
                        {
                            try { admissions.Add(owner, CoreJobAdmission.Enter(owner, DirectorySetting("SLI_PLUGIN_RUNTIME_DIR"), DirectorySetting("SLI_PLUGIN_LOCK_DIR"))); }
                            catch (InvalidOperationException e) when (e.Message == "plugin_update_draining") { continue; }
                            if (owner == "sli.remote-access" && profile == "light" && !radiusLocked)
                            {
                                if (await session.CallAsync("radius_host_lock", [], stopping) is not true)
                                { admissions[owner].Dispose(); admissions.Remove(owner); continue; }
                                radiusLocked = true; // Session-level advisory locks are reentrant; acquire only once.
                            }
                            if (owner == "sli.remote-access" && string.IsNullOrEmpty(environment("SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID"))) throw new CoreJobContractException("radius_pilot_source_required");
                            if (!stopping.IsCancellationRequested && (!scheduled.TryGetValue(owner, out long last) || clock.GetElapsedTime(last) >= scheduleInterval))
                            {
                                // Throttle attempts as well as successful reads.
                                scheduled[owner] = clock.GetTimestamp();
                                await schedule(owner, queue, registry, stopping);
                            }
                        }
                        var admitted = new JsonArray(identities.Where(x => admissions.ContainsKey(x!.Text("plugin_id"))).Select(x => x!.DeepClone()).ToArray());
                        if (!stopping.IsCancellationRequested && admitted.Count != 0)
                        {
                            var job = await queue.ClaimAsync(profile, $"executor-{profile}-{Environment.ProcessId}", admitted, stopping);
                            if (job is not null)
                            {
                                dispatched = true;
                                // Preserve only the VPN host drain lock through the complete pilot execution.
                                foreach (var owner in admissions.Keys.ToArray())
                                    if (owner != "sli.remote-access" || job.Text("plugin_id") != owner) { admissions[owner].Dispose(); admissions.Remove(owner); }
                                var executor = new CoreJobExecutor(queue, registry, async (request, purpose, timeout, beat, ct) =>
                                    await child(request, purpose, timeout, beat is null ? null : async () => { await beat(); WriteHeartbeat(profile, true); }, ct),
                                    recordFailure: recordFailure);
                                await executor.ExecuteAsync(job, stopping);
                            }
                        }
                    }
                    finally { foreach (var admission in admissions.Values) admission.Dispose(); }
                }
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested) { return 0; }
            catch (Exception e) when (Recoverable(e) || DispatcherConnectionLost(e, session))
            {
                // An idle backend can close before Npgsql starts its next command.
                // In that case the driver reports a closed connection as InvalidOperationException.
                Exception failure = e is InvalidOperationException ? new NpgsqlException("Core job dispatcher connection closed", e) : e;
                Console.Error.WriteLine("core_executor_cycle_failed " + CanonicalJson.Serialize(CoreJobCommand.Diagnostic(failure)));
                WriteHeartbeat(profile, identities.Count != 0, CoreJobCommand.FailureCode(failure));
                if (session is not null) await session.DisposeAsync();
                session = null; radiusLocked = false;
            }
            if (once || stopping.IsCancellationRequested) return 0;
            if (dispatched) continue;
            try { await delay(TimeSpan.FromSeconds(5), stopping); } catch (OperationCanceledException) when (stopping.IsCancellationRequested) { return 0; }
        } while (true);
        }
        finally { if (session is not null) await session.DisposeAsync(); }
    }
    internal static bool Recoverable(Exception e) => e is NpgsqlException or IOException or TimeoutException;
    internal static bool DispatcherConnectionLost(Exception error, ICoreJobSession? session) =>
        error is InvalidOperationException && session is PostgresCoreJobSession { IsDisconnected: true }
        && error.TargetSite?.DeclaringType?.Assembly == typeof(NpgsqlConnection).Assembly;
    internal static void WriteHeartbeat(string profile, bool enabled, string? failure = null)
    {
        string path = Path.Combine(Env("SLI_EXECUTOR_STATUS_DIR") ?? Path.GetTempPath(), $"sli-executor-{profile}.json");
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, CanonicalJson.Serialize(new JsonObject { ["profile"] = profile, ["pid"] = Environment.ProcessId, ["enabled"] = enabled, ["error_code"] = failure, ["at_utc"] = DateTimeOffset.UtcNow.ToString("O") }));
        File.Move(temporary, path, true);
    }
    public async Task<JsonObject> ChildAsync(string profile, string purpose, JsonObject job, CancellationToken ct)
    {
        if (purpose is not ("handler" or "publisher")) throw new CoreJobContractException("executor_purpose_invalid");
        var registry = catalog.Registry(DirectorySetting("SLI_PLUGIN_RUNTIME_DIR"));
        registry.Resolve(job);
        if(job.Text("plugin_id")=="sli.workstations"&&!Enabled(job,Env))throw new CoreJobContractException("agent_plugin_disabled");
        if (job.Text("resource_profile") != profile) throw new CoreJobContractException("executor_profile_invalid");
        CoreJobProcess.Limits(job["budget"]!.AsObject());
        using var admission = CoreJobAdmission.Enter(job.Text("plugin_id"), DirectorySetting("SLI_PLUGIN_RUNTIME_DIR"), DirectorySetting("SLI_PLUGIN_LOCK_DIR"));
        var implementation = catalog.Resolve(job);
        var settings = CoreJobIdentity.Settings(profile, purpose == "handler" ? "executor" : "publisher", Env, CoreJobIdentity.ReadSecret, child: true);
        settings.Options = $"-c statement_timeout=0 -c idle_in_transaction_session_timeout=0 -c lock_timeout={job["budget"]!["lock_timeout_ms"]!.Integer()} -c search_path=pg_catalog,public";
        // A persistent child keeps exactly its own direct-purpose connection.
        // No pooled/runtime/admin identity can enter this process.
        if (childConnection is null)
        {
            childIdentity = settings.ConnectionString;
            childConnection = new NpgsqlConnection(childIdentity);
            await childConnection.OpenAsync(ct);
        }
        else if (childIdentity != settings.ConnectionString) throw new CoreJobContractException("executor_profile_invalid");
        var connection = childConnection;
        if(job.Text("plugin_id")=="sli.workstations"&&!await Workstations.WorkstationJobPlugin.EnabledAsync(connection,ct))throw new CoreJobContractException("agent_plugin_disabled");
        if (purpose == "handler") return await implementation.Stage(connection, job, ct);
        var result = job["staged_result"]!.AsObject();
        var queue = new CoreJobQueue(new PostgresCoreJobSession(connection));
        if (Workstations.WorkstationJobPlugin.Drains(job))
            return await Workstations.WorkstationJobPlugin.DrainAsync(connection, queue, job, result, ct);
        string status = await queue.PublishAsync(job, result, token => implementation.Publish(connection, job, result, token), ct);
        return new JsonObject { ["status"] = status };
    }
}
