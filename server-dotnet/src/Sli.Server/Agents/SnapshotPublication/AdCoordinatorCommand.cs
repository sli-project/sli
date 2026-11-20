using System.CommandLine;
using System.Text.Json.Nodes;
using System.Runtime.InteropServices;
using Npgsql;
using Sli.Server.Legacy;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.SnapshotPublication;

public sealed class AdCoordinatorLoop(Func<DateTimeOffset> now,
    Func<DateTimeOffset, CancellationToken, Task<int>> cycle,
    Func<string, DateTimeOffset?, CancellationToken, Task> heartbeat,
    Func<TimeSpan, CancellationToken, Task> delay)
{
    public const string Timezone = "Asia/Novosibirsk";
    public static string LocalAt(DateTimeOffset time) => TimeZoneInfo.ConvertTime(time, TimeZoneInfo.FindSystemTimeZoneById(Timezone)).ToString("yyyy-MM-dd'T'HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
    public static DateTimeOffset Slot(DateTimeOffset time) {
        var zone = TimeZoneInfo.FindSystemTimeZoneById(Timezone);
        var local = TimeZoneInfo.ConvertTime(time, zone);
        var boundary = local.Date.AddHours(local.Hour >= 18 ? 18 : local.Hour >= 6 ? 6 : -6);
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(boundary, DateTimeKind.Unspecified), zone), TimeSpan.Zero);
    }
    public async Task<int> RunAsync(bool once, bool noInitialDelay, CancellationToken ct)
    {
        if (!once && !noInitialDelay) {
            await heartbeat("initial_delay", null, ct);
            await delay(TimeSpan.FromSeconds(180), ct);
        }
        while (!ct.IsCancellationRequested) {
            int exit;
            try { exit = await cycle(Slot(now()), ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { Console.Error.WriteLine("ad_snapshot_coordinator_failed:" + WorkerFailure.Describe(error, "snapshot_publication")); exit = 1; }
            await heartbeat(exit == 0 ? "sleeping" : exit == 9 ? "lock_busy" : "failed", null, ct);
            if (once) return exit == 9 ? 0 : exit;
            var target = Slot(now()).AddHours(12);
            while (!ct.IsCancellationRequested && now() < target) {
                await heartbeat("waiting_for_calendar_slot", target, ct);
                await delay(TimeSpan.FromSeconds(Math.Clamp(Math.Ceiling((target - now()).TotalSeconds), 1, 300)), ct);
            }
        }
        return 0;
    }
}

public static class AdCoordinatorCommand
{
    internal const string LockName = "ad_log_reports_runtime_ad_snapshot_manifest_coordinator_worker";
    public static async Task<int> RunAsync(string[] args)
    {
        var once = new Option<bool>("--once"); var immediate = new Option<bool>("--no-initial-delay");
        var root = new RootCommand("Acquire, publish and verify exact AD snapshots at 06/18 Asia/Novosibirsk.");
        root.Options.Add(once); root.Options.Add(immediate);
        root.SetAction(async (parse, invocation) => {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(invocation);
            using var signal = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stop.Cancel(); }) : null;
            var ct = stop.Token;
            if ((Environment.GetEnvironmentVariable("SLI_LEGACY_COLLECTION_DISABLED") ?? "0").Trim() != "0")
                throw new WorkerFailure("admission", "legacy_collection_disabled");
            if (Environment.GetEnvironmentVariable("SLI_CORE_JOB_AD_GPO_PILOT") == "1") return 0;
            // Native Python records an idle heartbeat before reading any
            // context-import credentials when acquisition is disabled.
            if (Environment.GetEnvironmentVariable("ADLOG_ACQUISITION_DISABLED") == "1" || !OperatingSystem.IsWindows())
            {
                var installed = new ConfigurationManager(); installed.AddEnvironmentVariables(); installed.AddInstalledEnvironment();
                var idleHeartbeat = new LegacyHeartbeat(new Sli.Server.Infrastructure.PostgresConnectionFactory(installed));
                do {
                    await idleHeartbeat.WriteAsync("ad_snapshot_manifest_coordinator", $"ad-snapshot-manifest-coordinator-{Environment.ProcessId}",
                        "idle", "acquisition_disabled", 30, new JsonObject { ["acquisition_disabled"] = true }, ct);
                    if (parse.GetValue(once)) return 0;
                    await Task.Delay(TimeSpan.FromSeconds(30), ct);
                } while (!ct.IsCancellationRequested);
                return 0;
            }
            string dsn = GpoWorkerConfiguration.CreateNamed(Environment.GetEnvironmentVariable, GpoWorkerCommand.ReadBoundedFile,
                "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "ad_snapshot_manifest_coordinator", 0);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:PostgresConnectionString"] = dsn }).AddEnvironmentVariables().Build();
            var heartbeat = new LegacyHeartbeat(new Sli.Server.Infrastructure.PostgresConnectionFactory(config));
            string worker = $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():D}";
            JsonObject cursor = new();
            async Task Progress(string phase, JsonObject details, CancellationToken token) {
                cursor = (JsonObject)details.DeepClone(); cursor["phase"] = phase;
                await heartbeat.WriteAsync("ad_snapshot_manifest_coordinator", worker, "running", phase, 30, cursor, token);
            }
            string repository = Sli.Server.Storage.Lifecycle.LifecycleConfiguration.FindRoot();
            var acquisition = new AdCoordinatorAcquisition(repository, Environment.GetEnvironmentVariable, Progress,
                (server, token) => AdCoordinatorEndpoint.ValidateAsync(dsn, repository, server, Environment.GetEnvironmentVariable, token));
            var loop = new AdCoordinatorLoop(() => DateTimeOffset.UtcNow, async (slot, token) => {
                await using var db = new NpgsqlConnection(dsn); await db.OpenAsync(token);
                await using (var settings = new NpgsqlCommand("set statement_timeout=0; set lock_timeout=0", db)) await settings.ExecuteNonQueryAsync(token);
                await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext(@name))", db);
                acquire.Parameters.AddWithValue("name", LockName);
                if (await acquire.ExecuteScalarAsync(token) is not true) return 9;
                try {
                    using var admission = Sli.Server.Agents.Control.AgentAssignmentPluginAdmission.Enter("sli.ad", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
                    using var navigation = typeof(AdCoordinatorCommand).Assembly.GetManifestResourceStream("Sli.Server.Workspace.declarations.json")!;
                    bool gpo = JsonNode.Parse(navigation)!["navigation"]!["enabled_plugins"]!.AsArray().Any(p => p!.GetValue<string>() == "sli.gpo");
                    if (gpo) {
                        await using var enabled = new NpgsqlCommand("select not exists(select 1 from read_plugin_states_v1() where plugin_id='sli.gpo' and (not enabled or component_runtime<>'running'))", db);
                        gpo = await enabled.ExecuteScalarAsync(token) is true;
                    }
                    using var ticking = CancellationTokenSource.CreateLinkedTokenSource(token);
                    async Task Tick() {
                        while (!ticking.IsCancellationRequested) {
                            await Task.Delay(TimeSpan.FromSeconds(30), ticking.Token);
                            await heartbeat.WriteAsync("ad_snapshot_manifest_coordinator", worker, "running", cursor["phase"]?.ToString() ?? "cycle", 30, cursor, ticking.Token);
                        }
                    }
                    var tick = Tick();
                    try {
                        await Progress("cycle", new() { ["slot_start_utc"] = slot }, token);
                        var cycle = new AdCoordinatorCycle(db, Environment.GetEnvironmentVariable("ADLOG_AD_CONTEXT_DOMAIN") ?? "", gpo, acquisition.CollectAsync, Progress,
                            (id, cancellation) => AdCoordinatorRetention.RunAsync(db, id, Environment.GetEnvironmentVariable, cancellation));
                        cursor = await cycle.RunAsync(slot, token);
                        Console.WriteLine(cursor.ToJsonString());
                        return 0;
                    } catch (Exception error) when (error is not OperationCanceledException) {
                        cursor = new() { ["status"] = "failed", ["error_type"] = error.GetType().Name, ["error"] = WorkerFailure.Describe(error, "coordinator_cycle") };
                        Console.Error.WriteLine(cursor.ToJsonString()); return 1;
                    } finally {
                        await ticking.CancelAsync();
                        try { await tick; } catch (OperationCanceledException) when (ticking.IsCancellationRequested) { }
                    }
                }
                finally {
                    await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext(@name))", db);
                    release.Parameters.AddWithValue("name", LockName); await release.ExecuteScalarAsync(CancellationToken.None);
                }
            }, async (phase, target, token) => {
                var details = (JsonObject)cursor.DeepClone();
                if (target is {} next) { details["next_slot_start_utc"] = next; details["schedule_timezone"] = AdCoordinatorLoop.Timezone; details["scheduled_local_at"] = AdCoordinatorLoop.LocalAt(next); details["next_cycle_in_seconds"] = Math.Max(1, Math.Ceiling((next - DateTimeOffset.UtcNow).TotalSeconds)); }
                if (phase == "initial_delay") details["next_cycle_in_seconds"] = 180;
                if (phase == "lock_busy") { details = new() { ["status"] = "skipped", ["reason"] = "lock_busy" }; }
                try { await heartbeat.WriteAsync("ad_snapshot_manifest_coordinator", worker, phase == "failed" ? "failed" : phase == "sleeping" ? cursor["status"]?.ToString() ?? "idle" : "idle", phase, 43200, details, token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception error) { Console.Error.WriteLine("ad_snapshot_coordinator_heartbeat_unavailable:" + WorkerFailure.Describe(error, "heartbeat")); }
            }, Task.Delay);
            return await loop.RunAsync(parse.GetValue(once), parse.GetValue(immediate), ct);
        });
        try {
            var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
            int exit = await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
            return parsed.Errors.Count > 0 ? 2 : exit;
        }
        catch (OperationCanceledException) { return 0; }
        catch (Exception error) { Console.Error.WriteLine("ad_snapshot_coordinator_failed:" + WorkerFailure.Describe(error, "coordinator_startup")); return 1; }
    }
}
