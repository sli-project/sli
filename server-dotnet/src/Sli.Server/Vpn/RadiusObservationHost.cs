using System.CommandLine;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using Sli.Server.Infrastructure;
using Sli.Server.Agents.Radius;
using Sli.Server.Hosting;

namespace Sli.Server.Vpn;

public sealed class RadiusObservationLoop(Func<CancellationToken, Task<bool>> enabled,
    Func<CancellationToken, Task> cycle, Func<string, CancellationToken, Task> heartbeat,
    Func<TimeSpan, CancellationToken, Task> delay)
{
    public async Task<int> RunAsync(bool once, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && await enabled(ct)) {
            await heartbeat("cycle", ct);
            try { await cycle(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { Console.Error.WriteLine("radius_observation_host_failed:" + WorkerFailure.Describe(error, "consumer_cycle")); await heartbeat("cycle_failed", ct); return 1; }
            await heartbeat("sleep", ct);
            if (once) return 0;
            await delay(TimeSpan.FromSeconds(30), ct);
        }
        await heartbeat("disabled", ct); return 0;
    }
}

public static class RadiusObservationHost
{
    internal const string HostLock = "sli.remote-access:radius-session-observation:host:v1";
    internal static JsonObject Budget() => new() { ["memory_bytes"] = 256L * 1024 * 1024, ["max_result_bytes"] = 65536L };
    public static async Task<int> RunAsync(string[] args)
    {
        // Retain the reference --component entrypoint as well as the dedicated role command.
        if (args.Zip(args.Skip(1)).Any(pair => pair.First == "--component" && pair.Second == "radius-acquisition"))
            return await RadiusAcquisitionHost.RunAsync(args);
        var once = new Option<bool>("--once"); var child = new Option<bool>("--cycle-child");
        var component = new Option<string>("--component") { DefaultValueFactory = _ => "radius-session-observation" };
        var root = new RootCommand("Host isolated RADIUS observation cycles without execution deadlines. Acquisition is disabled.");
        root.Options.Add(once); root.Options.Add(child); root.Options.Add(component);
        root.SetAction(async (parse, invocation) => {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(invocation);
            using var signal = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stop.Cancel(); }) : null;
            var ct = stop.Token;
            if (parse.GetValue(component) != "radius-session-observation") { Console.Error.WriteLine("acquisition_disabled"); return 2; }
            if (parse.GetValue(child)) {
                CoreJobProcess.Isolate(); CoreJobProcess.Limits(Budget());
                var input=JsonNode.Parse(await Console.In.ReadToEndAsync(ct)) as JsonObject ?? throw new InvalidOperationException("consumer_subscription_invalid");
                return await Child(input,ct);
            }
            if (Environment.GetEnvironmentVariable("SLI_CORE_JOB_RADIUS_PILOT") == "1") { await Heartbeat("core_executor_pilot", ct); return 0; }
            if (Environment.GetEnvironmentVariable("ADLOG_ACQUISITION_DISABLED") == "1" || !OperatingSystem.IsWindows()) {
                do {
                    await Heartbeat("acquisition_disabled", ct);
                    if (parse.GetValue(once)) return 0;
                    await Task.Delay(TimeSpan.FromSeconds(30), ct);
                } while (!ct.IsCancellationRequested);
                return 0;
            }
            var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
            var settings = RadiusHostConfiguration.Settings(configuration, Environment.GetEnvironmentVariable, Sli.Server.Agents.SnapshotPublication.GpoWorkerCommand.ReadBoundedFile);
            var core = RadiusHostConfiguration.Factory(settings.Core); var broker = RadiusHostConfiguration.Factory(settings.Broker);
            await using var db = await core.OpenAsync(ct);
            if (await RadiusJobs.Scalar(db, "select pg_try_advisory_lock(hashtext($1))", ct, HostLock) is not true)
            { Console.Error.WriteLine("component_host_already_running"); return 9; }
            try {
                JsonObject? lastResult = null, loopFailure = null;
                var loop = new RadiusObservationLoop(async token => {
                    await RadiusJobs.Scalar(db, "select finish_remote_access_plugin_drain_v1()", token);
                    var guard = (await RadiusJobs.Rows(db, "select desired_activation,component_runtime,admission_mode from read_plugin_component_runtime_guard_v1('sli.remote-access','radius-session-observation')", token)).SingleOrDefault();
                    return RadiusPluginLaunchGuard.Allowed("radius-session-observation", guard);
                }, async token => {
                    try {
                    // Verify the host lock session before granting a child its short-lived credential.
                    await RadiusJobs.Scalar(db, "select 1", token);
                    await WithConsumerLogin(broker, async dsn => {
                        var start = StartInfo(Environment.ProcessPath ?? throw new InvalidOperationException(), dsn, Environment.GetEnvironmentVariable);
                        var files=new Sli.Server.Operations.OperationsFiles(configuration);
                        var consumer=RadiusSourceContracts.LoadConsumer(Path.Combine(files.Root,"config"),RadiusCollectionRoute.EnvironmentValues());
                        var input=new JsonObject { ["subscription_id"]=consumer["subscription_id"]!.DeepClone() };
                        var result = await RadiusObservationProcess.RunAsync(start, async progress => {
                            await RadiusJobs.Scalar(db, "select 1", token);
                            if (progress is not null) lastResult = new JsonObject { ["status"] = "running", ["worker_result"] = progress.DeepClone() };
                            await Heartbeat("cycle", token, lastResult);
                        }, token, input);
                        if (result.Text("status") != "completed") throw new InvalidOperationException("consumer_cycle_failed");
                        lastResult = new JsonObject { ["status"] = "passed", ["worker_result"] = new JsonObject { ["status"] = "completed", ["processed"] = result["processed"]?.DeepClone(), ["claimed"] = result["claimed"]?.DeepClone(), ["cursor_delivery_id"] = result["cursor_delivery_id"]?.DeepClone() }, ["peak_process_memory_bytes"] = result["resource_usage"]?["peak_memory_bytes"]?.DeepClone() };
                    }, token);
                    await RadiusJobs.Scalar(db, "select observe_remote_access_plugin_v1($1,false)", token, Configured(configuration));
                    } catch (Exception error) {
                        loopFailure = Failure(error, "component_runner");
                        loopFailure["worker_result"] = lastResult?["worker_result"]?.DeepClone(); throw;
                    }
                }, (phase, token) => Heartbeat(phase, token, phase == "cycle_failed" ? loopFailure : lastResult), Task.Delay);
                return await RadiusPluginLaunchGuard.RunAsync("radius-session-observation", () => loop.RunAsync(parse.GetValue(once), ct), DateTimeOffset.UtcNow, HeartbeatDirectory);
            }
            finally { await RadiusJobs.Scalar(db, "select pg_advisory_unlock(hashtext($1))", CancellationToken.None, HostLock); }
        });
        try {
            var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
            int exit = await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
            return parsed.Errors.Count > 0 ? 2 : exit;
        }
        catch (OperationCanceledException) {
            if (!args.Contains("--cycle-child", StringComparer.Ordinal)) await Heartbeat("shutdown", CancellationToken.None);
            return 0;
        }
        catch (Exception error) {
            Console.Error.WriteLine("radius_observation_host_failed:" + WorkerFailure.Describe(error, "radius_host_startup"));
            await Heartbeat("cycle_failed", CancellationToken.None, Failure(error, "host_control")); return 1;
        }
    }

    internal static ProcessStartInfo StartInfo(string executable, string dsn, Func<string, string?> environment)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(typeof(RadiusObservationHost).Assembly.Location);
        start.ArgumentList.Add("radius-session-observation"); start.ArgumentList.Add("--cycle-child");
        start.Environment.Clear();
        foreach (string key in new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "DOTNET_ROOT" })
            if (environment(key) is {} value) start.Environment[key] = value;
        if (OperatingSystem.IsWindows())
        {
            var windows = new Dictionary<string, string>();
            RadiusChildEnvironment.ConfigureWindows(windows, environment);
            foreach (var (key, value) in windows) start.Environment[key] = value;
        }
        start.Environment["SLI_PLUGIN_PG_DSN"] = dsn;
        start.Environment["DOTNET_GCHeapHardLimit"] = "8000000"; start.Environment["DOTNET_GCHeapCount"] = "1"; start.Environment["DOTNET_EnableDiagnostics"] = "0";
        return start;
    }

    internal static string ConsumerSubscription(JsonObject input)
    {
        if(input["subscription_id"] is not JsonValue value || !value.TryGetValue<string>(out var subscription) || subscription.Length is <1 or >512)
            throw new InvalidOperationException("consumer_subscription_invalid");
        return subscription;
    }

    private static async Task<int> Child(JsonObject input,CancellationToken ct)
    {
        string subscription=ConsumerSubscription(input);
        string stage = "child_environment";
        try {
            string dsn = ChildDsn(Environment.GetEnvironmentVariable);
            await using var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
            stage = "component_runner";
            var result = await RadiusObservationCycle.RunAsync(db, value => {
                Console.WriteLine(value.ToJsonString()); return Task.CompletedTask;
            }, ct, subscription);
            Console.WriteLine(result.ToJsonString()); return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) {
            var result = Failure(error, stage); result["contains_secret_material"] = false;
            Console.WriteLine(result.ToJsonString()); return 1;
        }
    }

    internal static async Task<JsonObject> RunConsumerCycleAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var transaction = await db.BeginTransactionAsync(ct);
        await RadiusJobs.Execute(db, "set local role adlog_radius_session_consumer", ct);
        // This registered subscription is the frozen accounting manual-control contract.
        const string subscription = "vpn-radius-session-observations-radius01-v1";
        var result = await RadiusJobs.ConsumeAsync(db, subscription, null, $"radius-session-observation:{Environment.ProcessId}", 500000, ct);
        await transaction.CommitAsync(ct);
        return result;
    }

    internal static JsonObject Failure(Exception error, string stage)
    {
        if (error is RadiusObservationFailure child) {
            var value = child.Failure;
            // Never trust arbitrary child strings, even if its result says it contains no secrets.
            string code = value.Text("error_code"), type = value.Text("error_type"), step = value.Text("failure_stage");
            return new JsonObject { ["status"] = "failed", ["failure_stage"] = step is "child_environment" or "component_runner" ? step : "result_validation",
                ["error_type"] = type is "VpnInputException" or "PostgresException" or "NpgsqlException" or "InvalidOperationException"
                    or "IOException" or "UnauthorizedAccessException" or "ArgumentException" or "JsonException" ? type : "UnknownError",
                ["error_code"] = SafeCode(code) };
        }
        string reason = error is PostgresException pg ? "postgres_" + pg.SqlState : error is NpgsqlException ? "postgres_unavailable"
            : error is VpnInputException or InvalidOperationException ? error.Message : "operation_failed";
        return new JsonObject { ["status"] = "failed", ["failure_stage"] = stage, ["error_type"] = error.GetType().Name, ["error_code"] = SafeCode(reason) };
    }

    private static string SafeCode(string code) => code is "consumer_worker_dsn_required" or "consumer_worker_identity_invalid"
        or "admin_database_environment_reached_plugin_child" or "component_lease_result_invalid" or "component_lease_release_invalid"
        or "exact_session_key_required" or "delivery_lease_lost" or "ephemeral_role_still_active" or "cycle_result_invalid"
        or "consumer_child_memory_exceeded" or "consumer_cycle_failed" or "postgres_unavailable" ? code
        : System.Text.RegularExpressions.Regex.IsMatch(code, @"\Apostgres_[0-9A-Z]{5}\z") ? code : "operation_failed";

    internal static string ChildDsn(Func<string, string?> get) {
        string[] prohibited = ["ADLOG_PG_DSN", "ADLOG_PG_DSN_FILE", "ADLOG_PG_PASSWORD", "ADLOG_PG_PASSWORD_FILE", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD", "ADLOG_PG_ADMIN_PASSWORD_FILE", "ConnectionStrings__Sli", "Sli__PostgresConnectionString"];
        if (prohibited.Any(key => !string.IsNullOrWhiteSpace(get(key)))) throw new InvalidOperationException("admin_database_environment_reached_plugin_child");
        string dsn = get("SLI_PLUGIN_PG_DSN") ?? throw new InvalidOperationException("consumer_worker_dsn_required");
        var settings = new NpgsqlConnectionStringBuilder(dsn);
        if (!System.Text.RegularExpressions.Regex.IsMatch(settings.Username ?? "", "\\Aadlog_radius_consumer_[a-f0-9]{16}\\z") || settings.Pooling || settings.Multiplexing) throw new InvalidOperationException("consumer_worker_identity_invalid");
        return new NpgsqlConnectionStringBuilder(dsn) { CommandTimeout = 0, Options = "-c statement_timeout=0 -c lock_timeout=0" }.ConnectionString;
    }

    internal static async Task WithConsumerLogin(IPostgresConnectionFactory factory, Func<string, Task> run, CancellationToken ct)
    {
        string role = "adlog_radius_consumer_" + Guid.NewGuid().ToString("N")[..16];
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await using var admin = await factory.OpenAsync(ct);
        using var quote = new NpgsqlCommandBuilder(); string id = quote.QuoteIdentifier(role), database = quote.QuoteIdentifier(admin.Database);
        async Task Acl(CancellationToken token) => await RadiusJobs.Scalar(admin, "select pg_advisory_xact_lock(hashtext($1))", token, "sli.radius.ephemeral_database_connect_acl.v1");
        await using (var tx = await admin.BeginTransactionAsync(ct)) {
            await Acl(ct);
            await RadiusJobs.Execute(admin, $"create role {id} noinherit login password '{password}' nosuperuser nocreatedb nocreaterole nobypassrls noreplication; grant adlog_radius_session_consumer to {id}; grant connect on database {database} to {id}", ct);
            // PostgreSQL can report an ineffective GRANT as a warning. Do not
            // publish a login unless its direct database grant was established.
            if (await RadiusJobs.Scalar(admin, """
                select exists(select 1 from pg_database d,aclexplode(d.datacl) a
                    where d.datname=current_database() and a.grantee=(select oid from pg_roles where rolname=$1)
                      and a.privilege_type='CONNECT')
                """, ct, role) is not true) throw new InvalidOperationException("consumer_database_connect_grant_failed");
            await tx.CommitAsync(ct);
        }
        try {
            var builder = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = role, Password = password, Pooling = false, Multiplexing = false, CommandTimeout = 0, Options = "-c statement_timeout=0 -c lock_timeout=0" };
            await run(builder.ConnectionString);
        }
        finally {
            await using var tx = await admin.BeginTransactionAsync(CancellationToken.None); await Acl(CancellationToken.None);
            // The unpooled client can finish closing before PostgreSQL removes its backend.
            var started = Stopwatch.GetTimestamp();
            while (true)
            {
                await RadiusJobs.Scalar(admin, "select pg_catalog.pg_stat_clear_snapshot()", CancellationToken.None);
                if (await RadiusJobs.Scalar(admin, """
                    select exists(select 1 from pg_catalog.pg_stat_activity
                        where usename=$1 and pid<>pg_backend_pid())
                    """, CancellationToken.None, role) is false)
                    break;
                if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(1))
                    throw new InvalidOperationException("ephemeral_role_still_active");
                await Task.Delay(TimeSpan.FromMilliseconds(25));
            }
            await RadiusJobs.Execute(admin, $"revoke adlog_radius_session_consumer from {id}; revoke connect on database {database} from {id}; drop role {id}", CancellationToken.None);
            await tx.CommitAsync(CancellationToken.None);
        }
    }

    private static bool Configured(IConfiguration configuration) {
        try {
            var files = new Sli.Server.Operations.OperationsFiles(configuration);
            string path = Environment.GetEnvironmentVariable("ADLOG_RADIUS_COLLECTION_ROUTES_PATH") ?? Path.Combine(files.Root, "config", "stage10_radius_collection_routes_v1.json");
            var file = new FileInfo(path); if (!file.Exists || file.Length > 1048576) return false;
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path));
            string[] keys = ["ADLOG_RADIUS_SOURCE_NAME", "ADLOG_RADIUS_SOURCE_INSTANCE_ID", "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC"];
            var env = keys.Where(k => Environment.GetEnvironmentVariable(k) is not null).ToDictionary(k => k, Environment.GetEnvironmentVariable);
            _ = RadiusCollectionRoute.Validate(document.RootElement, env);
            return !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC") ?? document.RootElement.GetProperty("accounting_route").GetProperty("share_unc").GetString());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException) { return false; }
    }

    private static string HeartbeatDirectory => Environment.GetEnvironmentVariable("SLI_PLUGIN_HEARTBEAT_DIR")
        ?? Path.Combine(new Sli.Server.Operations.OperationsFiles(new ConfigurationBuilder().AddEnvironmentVariables().Build()).DataRoot, "runtime");

    private static async Task Heartbeat(string phase, CancellationToken ct, JsonObject? lastResult = null)
    {
        string directory = HeartbeatDirectory;
        Directory.CreateDirectory(directory); string path = Path.Combine(directory, "plugin-radius-session-observation.json");
        string temporary = path + "." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var value = new JsonObject { ["schema_version"] = 1, ["plugin_id"] = "sli.remote-access", ["component_id"] = "radius-session-observation", ["worker_instance_id"] = $"radius-session-observation-{Environment.MachineName.ToLowerInvariant()}-{Environment.ProcessId}", ["process_pid"] = Environment.ProcessId, ["status"] = phase == "cycle_failed" ? "blocked" : phase is "disabled" or "shutdown" ? "stopped" : phase == "cycle" ? "running" : "idle", ["phase"] = phase, ["expected_interval_seconds"] = 30, ["heartbeat_at_utc"] = DateTimeOffset.UtcNow, ["last_result"] = lastResult?.DeepClone(), ["contains_secret_material"] = false };
        await File.WriteAllTextAsync(temporary, value.ToJsonString(), ct); File.Move(temporary, path, true);
    }
}
