using System.CommandLine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Vpn;

internal sealed class RadiusAcquisitionLoop(Func<CancellationToken, Task<bool>> enabled, Func<CancellationToken, Task> cycle,
    Func<string, Exception?, CancellationToken, Task> heartbeat, Func<TimeSpan, CancellationToken, Task> delay)
{
    internal async Task<int> RunAsync(bool once, CancellationToken ct)
    {
        try {
            while (!ct.IsCancellationRequested && await enabled(ct)) {
                await heartbeat("cycle", null, ct);
                try { await cycle(ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error) { await heartbeat("cycle_failed", error, CancellationToken.None); return 1; }
                await heartbeat("sleep", null, ct);
                if (once) return 0;
                await delay(TimeSpan.FromSeconds(300), ct);
            }
            await heartbeat("disabled", null, CancellationToken.None); return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) {
            await heartbeat("stopped", null, CancellationToken.None); return 0;
        }
    }
}

public static class RadiusAcquisitionHost
{
    internal const string Component = "radius-acquisition";
    internal const string HostLock = "sli.remote-access:radius-acquisition:host:v1";
    public static async Task<int> RunAsync(string[] args)
    {
        var once = new Option<bool>("--once"); var child = new Option<bool>("--cycle-child");
        var component = new Option<string>("--component") { DefaultValueFactory = _ => Component };
        var root = new RootCommand("Collect RADIUS accounting with durable cursors and isolated per-cycle credentials.");
        root.Options.Add(once); root.Options.Add(child); root.Options.Add(component);
        root.SetAction(async (parse, invocation) => {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(invocation);
            using var signal = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stop.Cancel(); }) : null;
            var ct = stop.Token;
            if (parse.GetValue(component) != Component) return 2;
            var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
            if (parse.GetValue(child)) {
                if (await Console.In.ReadLineAsync(ct) != "start") throw new InvalidOperationException("plugin_child_ownership_required");
                return await Child(configuration, ct);
            }
            if (Environment.GetEnvironmentVariable("SLI_CORE_JOB_RADIUS_PILOT") == "1") { await Heartbeat("core_executor_pilot", configuration, null, null, ct); return 0; }
            if (Environment.GetEnvironmentVariable("ADLOG_ACQUISITION_DISABLED") == "1" || !OperatingSystem.IsWindows()) {
                do {
                    await Heartbeat("acquisition_disabled", configuration, null, null, ct);
                    if (parse.GetValue(once)) return 0;
                    await Task.Delay(TimeSpan.FromSeconds(300), ct);
                } while (!ct.IsCancellationRequested);
                return 0;
            }
            RadiusSourceIdentity.Verify();
            var source = RadiusAcquisitionSource.Load(configuration);
            var settings = RadiusHostConfiguration.Settings(configuration, Environment.GetEnvironmentVariable, Sli.Server.Agents.SnapshotPublication.GpoWorkerCommand.ReadBoundedFile);
            settings.Core.CommandTimeout = 0; settings.Core.Timeout = 0; settings.Core.Options = "-c statement_timeout=0 -c lock_timeout=0";
            settings.Broker.CommandTimeout = 0; settings.Broker.Timeout = 0; settings.Broker.Options = settings.Core.Options;
            var core = RadiusHostConfiguration.Factory(settings.Core); var broker = RadiusHostConfiguration.Factory(settings.Broker);
            await using var db = await core.OpenAsync(ct);
            if (await RadiusJobs.Scalar(db, "select pg_try_advisory_lock(hashtext($1))", ct, HostLock) is not true)
                throw new InvalidOperationException("component_host_already_running");
            try {
                JsonObject? last = null;
                var loop = new RadiusAcquisitionLoop(async token => {
                    var guard = (await RadiusJobs.Rows(db, "select desired_activation,component_runtime,admission_mode from read_plugin_component_runtime_guard_v1('sli.remote-access','radius-acquisition')", token)).SingleOrDefault();
                    return Enabled(guard);
                }, async token => {
                    await RadiusJobs.Scalar(db, "select 1", token);
                    JsonObject? cycleResult = null;
                    await WithAcquisitionLogin(broker, source, async dsn => {
                        last = null;
                        var result = await RunChildAsync(ChildStartInfo(dsn), async progress => {
                            last = progress; await Heartbeat("cycle", configuration, last, null, token);
                        }, token);
                        ValidateResult(result);
                        cycleResult = result;
                        last = new JsonObject { ["status"] = "passed", ["worker_result"] = result.DeepClone() };
                    }, token);
                    await RadiusJobs.Scalar(db, "select observe_remote_access_plugin_v1($1,$2)", token, true, cycleResult!.Number("outbox_rows") > 0);
                }, (phase, error, token) => Heartbeat(phase, configuration, last, error, token), Task.Delay);
                return await loop.RunAsync(parse.GetValue(once), ct);
            }
            finally { await RadiusJobs.Scalar(db, "select pg_advisory_unlock(hashtext($1))", CancellationToken.None, HostLock); }
        });
        try {
            var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
            int exit = await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
            return parsed.Errors.Count > 0 ? 2 : exit;
        }
        catch (OperationCanceledException) { return 0; }
        catch (Exception error) {
            // The child must never write paths, SQL, account names or credentials.
            Console.Error.WriteLine("radius_acquisition_failed:" + WorkerFailure.Describe(error, "radius_acquisition"));
            if (args.Contains("--cycle-child")) await Write(new JsonObject { ["status"] = "failed", ["error_code"] = FailureCode(error) }, CancellationToken.None);
            else await Heartbeat("cycle_failed", new ConfigurationBuilder().Build(), null, error, CancellationToken.None);
            return 1;
        }
    }

    internal static bool Enabled(JsonObject? guard) => guard is not null &&
        (guard.Text("desired_activation"), guard.Text("component_runtime"), guard.Text("admission_mode")) == ("enabled_manual", "running", "open");

    private static async Task<int> Child(IConfiguration configuration, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("vpn_source_windows_required");
        string dsn = ChildDsn(Environment.GetEnvironmentVariable);
        RadiusSourceIdentity.Verify();
        var source = RadiusAcquisitionSource.Load(configuration);
        await using var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
        var reader = new Sli.Agent.Core.RadiusTailSource(new RadiusFileSystem());
        var result = await RadiusAcquisitionCycle.RunAsync(db, source, (cursor, recover) => {
            if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("vpn_source_windows_required");
            return RadiusSourceIdentity.Read(source, () => reader.Read(source.Directory, cursor, 1000, recover));
        }, progress => Write(progress, ct), ct);
        await Write(result, ct); return 0;
    }

    private static Task Write(JsonObject value, CancellationToken ct) => Console.Out.WriteLineAsync(value.ToJsonString().AsMemory(), ct);

    internal static string ChildDsn(Func<string, string?> get)
    {
        string[] prohibited = ["ADLOG_PG_DSN", "ADLOG_PG_DSN_FILE", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD", "ADLOG_PG_ADMIN_PASSWORD_FILE", "ConnectionStrings__Sli", "Sli__PostgresConnectionString"];
        if (prohibited.Any(key => !string.IsNullOrWhiteSpace(get(key)))) throw new InvalidOperationException("admin_database_environment_reached_plugin_child");
        var settings = new NpgsqlConnectionStringBuilder(get("SLI_PLUGIN_PG_DSN") ?? throw new InvalidOperationException("worker_dsn_required"));
        if (!System.Text.RegularExpressions.Regex.IsMatch(settings.Username ?? "", "\\Aadlog_radius_manual_[a-f0-9]{16}\\z") || settings.Pooling || settings.Multiplexing || settings.CommandTimeout != 0)
            throw new InvalidOperationException("acquisition_worker_identity_invalid");
        return settings.ConnectionString;
    }

    internal static ProcessStartInfo ChildStartInfo(string dsn)
    {
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("plugin_child_executable_missing");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(typeof(RadiusAcquisitionHost).Assembly.Location);
        start.ArgumentList.Add(Component); start.ArgumentList.Add("--cycle-child");
        start.Environment.Clear();
        foreach (string key in new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "DOTNET_ROOT", "ADLOG_COLLECTION_PRINCIPAL", "ADLOG_COLLECTION_PRINCIPAL_SID",
            "ADLOG_VPN_SOURCE_CREDENTIAL_MODE", "ADLOG_RADIUS_COLLECTION_ROUTES_PATH", "ADLOG_RADIUS_SOURCE_NAME", "ADLOG_RADIUS_SOURCE_INSTANCE_ID", "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", "ADLOG_DATA_DIR", "SLI_DATA_DIR" })
            if (Environment.GetEnvironmentVariable(key) is {} value) start.Environment[key] = value;
        start.Environment["SLI_PLUGIN_PG_DSN"] = dsn;
        return start;
    }

    // No elapsed-time or CPU watchdog: report the live child and cursor until
    // exit or an explicit shutdown. Never forward its stderr to operations.
    internal static async Task<JsonObject> RunChildAsync(ProcessStartInfo start, Func<JsonObject, Task> heartbeat, CancellationToken ct)
    {
        using var process = new Process { StartInfo = start };
        process.Start();
        using var ownership = RadiusChildOwnership.Attach(process);
        using var io = new CancellationTokenSource();
        JsonObject? last = null;
        var errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, io.Token);
        async Task Read() {
            var buffer = new char[1024]; var line = new System.Text.StringBuilder(); int count;
            while ((count = await process.StandardOutput.ReadAsync(buffer.AsMemory(), io.Token)) > 0)
                for (int i = 0; i < count; i++) {
                    if (buffer[i] == '\n') {
                        var value = JsonNode.Parse(line.ToString()) as JsonObject ?? throw new InvalidOperationException("cycle_result_invalid");
                        last = SafeResult(value); line.Clear();
                    } else { if (line.Length >= 65536) throw new InvalidOperationException("cycle_result_invalid"); line.Append(buffer[i]); }
                }
            if (line.Length != 0) throw new InvalidOperationException("cycle_result_invalid");
        }
        var output = Read(); var exited = process.WaitForExitAsync(ct);
        try {
            await process.StandardInput.WriteLineAsync("start".AsMemory(), ct); process.StandardInput.Close();
            while (!exited.IsCompleted) {
                var tick = Task.Delay(TimeSpan.FromSeconds(10), ct);
                await Task.WhenAny(exited, output, tick);
                if (output.IsFaulted) await output;
                // Pipe EOF is not proof of process exit. Keep publishing liveness.
                if (output.IsCompleted && !exited.IsCompleted) await Task.WhenAny(exited, tick);
                ct.ThrowIfCancellationRequested();
                await heartbeat(new JsonObject { ["status"] = "running", ["child_pid"] = process.Id, ["worker_result"] = last?.DeepClone() });
            }
            await exited;
            ownership?.Dispose();
            await output; await errors;
            if (last?.Text("status") == "failed") throw new WorkerFailure("component_runner", last.Text("error_code"));
            if (process.ExitCode != 0) throw new InvalidOperationException("plugin_component_cycle_failed");
            return last ?? throw new InvalidOperationException("cycle_result_invalid");
        }
        finally {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            ownership?.Dispose(); io.Cancel();
            await process.WaitForExitAsync(CancellationToken.None);
            try { await output; await errors; } catch (Exception) { /* Child data is never logged. */ }
        }
    }

    internal static JsonObject SafeResult(JsonObject value)
    {
        var result = new JsonObject();
        string status = value.Text("status");
        if (status == "failed") {
            string code = value.Text("error_code");
            result["status"] = "failed"; result["error_code"] = SafeFailureCode(code); return result;
        }
        if (status is not ("running" or "committed" or "no_new_complete_records")) throw new InvalidOperationException("component_cycle_result_invalid");
        result["status"] = status;
        foreach (string key in new[] { "records", "evidence_rows", "observation_rows", "outbox_rows", "cursor_revision_before", "cursor_revision_after" })
            if (value[key] is {} number) {
                if (number is not JsonValue scalar || !scalar.TryGetValue<long>(out long n) || n < 0) throw new InvalidOperationException("cycle_result_invalid");
                result[key] = n;
            }
        return result;
    }

    internal static void ValidateResult(JsonObject result)
    {
        _ = SafeResult(result);
        if (result.Text("status") is not ("committed" or "no_new_complete_records") ||
            new[] { "records", "evidence_rows", "observation_rows", "outbox_rows", "cursor_revision_before", "cursor_revision_after" }.Any(k => result[k] is null))
            throw new InvalidOperationException("component_cycle_result_invalid");
    }

    internal static async Task WithAcquisitionLogin(IPostgresConnectionFactory factory, RadiusAcquisitionSource source, Func<string, Task> run, CancellationToken ct)
    {
        await using var admin = await factory.OpenAsync(ct);
        var state = (await RadiusJobs.Rows(admin, """
            select s.desired_activation source_activation,sub.desired_activation subscription_activation,
              exists(select 1 from schema_migrations where version=58 and name='radius_accounting_transaction_foundation') foundation,
              exists(select 1 from schema_migrations where version=59 and name='radius_identity_spine_resolver') resolver
            from acquisition_source_instances s join acquisition_consumer_subscriptions sub on sub.source_instance_id=s.source_instance_id
            where s.source_instance_id=$1 and sub.subscription_id=$2
            """, ct, source.SourceId, source.Subscription)).SingleOrDefault() ?? throw new InvalidOperationException("manual_registration_not_found");
        if (state["foundation"]?.GetValue<bool>() != true || state["resolver"]?.GetValue<bool>() != true) throw new InvalidOperationException("manual_required_migration_missing");
        if (state.Text("source_activation") != "disabled" || state.Text("subscription_activation") != "disabled") throw new InvalidOperationException("manual_activation_not_disabled");
        string role = "adlog_radius_manual_" + Guid.NewGuid().ToString("N")[..16];
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var quote = new NpgsqlCommandBuilder(); string id = quote.QuoteIdentifier(role), database = quote.QuoteIdentifier(admin.Database);
        bool created = false, activated = false;
        try {
            await using (var tx = await admin.BeginTransactionAsync(ct)) {
                await RadiusJobs.Scalar(admin, "select pg_advisory_xact_lock(hashtext('sli.radius.ephemeral_database_connect_acl.v1'))", ct);
                await RadiusJobs.Execute(admin, $"create role {id} noinherit login password '{password}' nosuperuser nocreatedb nocreaterole nobypassrls noreplication; grant adlog_radius_accounting_worker to {id}; grant connect on database {database} to {id}", ct);
                await tx.CommitAsync(ct); created = true;
            }
            await Activation(admin, source, "manual_enabled", ct); activated = true;
            var builder = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = role, Password = password, Pooling = false, Multiplexing = false, CommandTimeout = 0, Timeout = 0,
                Options = "-c statement_timeout=0 -c lock_timeout=0" };
            await run(builder.ConnectionString);
        }
        finally {
            try { if (activated) await Activation(admin, source, "disabled", CancellationToken.None); }
            finally {
                if (created) {
                    await using var tx = await admin.BeginTransactionAsync(CancellationToken.None);
                    await RadiusJobs.Scalar(admin, "select pg_advisory_xact_lock(hashtext('sli.radius.ephemeral_database_connect_acl.v1'))", CancellationToken.None);
                    if (Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from pg_stat_activity where usename=$1 and pid<>pg_backend_pid()", CancellationToken.None, role)) != 0)
                        throw new InvalidOperationException("ephemeral_role_still_active");
                    await RadiusJobs.Execute(admin, $"revoke adlog_radius_accounting_worker from {id}; revoke connect on database {database} from {id}; drop role {id}", CancellationToken.None);
                    await tx.CommitAsync(CancellationToken.None);
                }
            }
        }
    }

    private static async Task Activation(NpgsqlConnection db, RadiusAcquisitionSource source, string target, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        await RadiusJobs.Execute(db, "set local role adlog_storage_owner", ct);
        var state = (await RadiusJobs.Rows(db, "select s.desired_activation source_activation,sub.desired_activation subscription_activation from acquisition_source_instances s join acquisition_consumer_subscriptions sub on sub.source_instance_id=s.source_instance_id where s.source_instance_id=$1 and sub.subscription_id=$2 for update of s,sub", ct, source.SourceId, source.Subscription)).SingleOrDefault();
        if (state is null) throw new InvalidOperationException("manual_registration_not_found");
        if (target == "manual_enabled" && (state.Text("source_activation") != "disabled" || state.Text("subscription_activation") != "disabled")) throw new InvalidOperationException("manual_activation_not_disabled");
        if (await RadiusJobs.Execute(db, "update acquisition_source_instances set desired_activation=$1,updated_at=now() where source_instance_id=$2", ct, target, source.SourceId) != 1 ||
            await RadiusJobs.Execute(db, "update acquisition_consumer_subscriptions set desired_activation=$1 where subscription_id=$2 and source_instance_id=$3", ct, target, source.Subscription, source.SourceId) != 1)
            throw new InvalidOperationException("manual_activation_failed");
        await tx.CommitAsync(ct);
    }

    internal static JsonObject HeartbeatValue(string phase, JsonObject? last, Exception? error)
    {
        string code = error is null ? "" : FailureCode(error);
        return new JsonObject { ["schema_version"] = 1, ["plugin_id"] = "sli.remote-access", ["component_id"] = Component,
            ["worker_instance_id"] = $"{Component}-{Environment.MachineName.ToLowerInvariant()}-{Environment.ProcessId}", ["process_pid"] = Environment.ProcessId,
            ["status"] = phase == "cycle_failed" ? "blocked" : phase is "disabled" or "stopped" ? "stopped" : phase == "cycle" ? "running" : "idle",
            ["phase"] = phase, ["expected_interval_seconds"] = 300, ["heartbeat_at_utc"] = DateTimeOffset.UtcNow,
            ["last_result"] = error is null ? last?.DeepClone() : new JsonObject { ["status"] = "failed", ["failure_stage"] = "component_runner", ["error_type"] = "Exception", ["error_code"] = code,
                ["worker_result"] = last?.DeepClone(), ["message"] = FailureMessage(code) }, ["contains_secret_material"] = false };
    }

    // Codes are compiled identifiers, never arbitrary exception text from a source.
    private static readonly HashSet<string> FailureCodes = new(StringComparer.Ordinal) {
        "component_host_already_running", "manual_registration_not_found", "manual_required_migration_missing", "manual_activation_not_disabled", "manual_activation_failed", "ephemeral_role_still_active",
        "component_lease_result_invalid", "component_lease_release_invalid", "subscription_not_found", "subscription_not_manually_enabled", "radius_source_binding_changed", "collection_packet_local_tail_mismatch",
        "radius_dedicated_read_only_share_not_configured", "manual_control_contract_invalid", "worker_dsn_required", "acquisition_worker_identity_invalid", "admin_database_environment_reached_plugin_child",
        "vpn_source_credential_mode_invalid", "vpn_source_thread_impersonation_forbidden", "vpn_source_credential_path_invalid", "vpn_source_credential_size_invalid", "vpn_source_dpapi_failed", "vpn_source_credential_payload_invalid", "vpn_source_credential_acl_invalid", "vpn_source_access_failed",
        "tail_reparse_point_forbidden", "tail_candidate_limit_exceeded", "tail_inventory_failed", "tail_accounting_file_not_observed", "tail_cursor_generation_not_found", "tail_cursor_past_eof",
        "tail_record_too_large", "tail_record_encoding_invalid", "tail_file_replaced_during_recovery", "tail_file_replaced_during_open", "tail_file_truncated_during_open", "tail_file_read_failed",
        "tail_recovery_last_hash_required", "tail_recovery_boundary_not_found", "tail_recovery_boundary_ambiguous", "tail_recovery_exhausted_byte_budget", "tail_recovery_read_failed",
        "database_compatible_shape_required", "accounting_status_unsupported_or_missing", "record_local_timestamp_invalid", "account_session_id_required", "nas_identity_required", "access_accept_class_required", "access_accept_distinguished_name_required", "radius_route_invalid", "radius_policy_invalid",
        "agent_radius_cursor_conflict", "cursor_compare_and_swap_failed", "permission_denied", "io_unavailable", "postgres_unavailable", "operation_failed", "plugin_component_cycle_failed"
    };
    internal static string SafeFailureCode(string code) => FailureCodes.Contains(code) || System.Text.RegularExpressions.Regex.IsMatch(code, "\\Apostgres_[A-Z0-9]{5}\\z") ? code : "operation_failed";
    internal static string FailureCode(Exception error) => error switch {
        WorkerFailure failure => SafeFailureCode(failure.Diagnostic.Split(':')[^1]),
        PostgresException postgres => "postgres_" + postgres.SqlState,
        NpgsqlException => "postgres_unavailable",
        UnauthorizedAccessException => "permission_denied",
        IOException => "io_unavailable",
        Sli.Agent.Core.AgentException source => SafeFailureCode(source.Code),
        Sli.Server.Agents.Radius.RadiusImportPending pending => SafeFailureCode(pending.Code),
        InvalidOperationException => SafeFailureCode(error.Message),
        ArgumentException => SafeFailureCode(error.Message),
        _ => "operation_failed"
    };
    private static string FailureMessage(string code) => code switch {
        "manual_required_migration_missing" => "Схема базы данных для сбора RADIUS ещё не готова.",
        "component_host_already_running" => "Сбор RADIUS уже выполняется другим процессом.",
        "permission_denied" or "vpn_source_access_failed" => "Процессу сбора RADIUS не разрешён доступ к источнику.",
        "radius_dedicated_read_only_share_not_configured" => "Для RADIUS не настроена общая папка с доступом только для чтения.",
        "agent_radius_cursor_conflict" or "cursor_compare_and_swap_failed" => "Позиция чтения RADIUS изменилась во время сбора. Данные не перезаписаны.",
        "tail_cursor_generation_not_found" or "tail_recovery_boundary_not_found" => "Не найден файл RADIUS с сохранённой позицией чтения.",
        "database_compatible_shape_required" or "accounting_status_unsupported_or_missing" => "Формат записи RADIUS не соответствует формату журнала NPS.",
        _ => "Сбор RADIUS остановлен из-за ошибки источника или базы данных."
    };

    private static async Task Heartbeat(string phase, IConfiguration configuration, JsonObject? last, Exception? error, CancellationToken ct)
    {
        var files = new Sli.Server.Operations.OperationsFiles(configuration);
        string directory = Environment.GetEnvironmentVariable("SLI_PLUGIN_HEARTBEAT_DIR") ?? Path.Combine(files.DataRoot, "runtime");
        Directory.CreateDirectory(directory); string path = Path.Combine(directory, "plugin-radius-acquisition.json");
        string temporary = path + "." + Environment.ProcessId + ".tmp";
        await File.WriteAllTextAsync(temporary, HeartbeatValue(phase, last, error).ToJsonString(), ct); File.Move(temporary, path, true);
    }
}
