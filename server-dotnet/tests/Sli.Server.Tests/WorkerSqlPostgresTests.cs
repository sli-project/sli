using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;
using Sli.Server.Hosting;
using Microsoft.Extensions.Configuration;

namespace Sli.Server.Tests;

public sealed partial class WorkerSqlPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Installed_units_run_with_only_their_rendered_environment()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(nativeJobAddress: true);
        await fixture.StartAsync(ct);
        // Observe real discovery calls in this disposable cluster; no SQL substitutes.
        await using (var owner = new NpgsqlConnection(fixture.Pg.ConnectionString)) {
            await owner.OpenAsync(ct);
            await AuthorizeStorageAsync(owner, fixture.Pg.Root, ct);
            await PostCollectionPostgres.Sql(owner, "alter system set track_functions='all'", ct);
            await PostCollectionPostgres.Sql(owner, "select pg_reload_conf()", ct);
            foreach (string purpose in new[] { "dispatcher", "executor", "publisher" })
                await PostCollectionPostgres.Sql(owner, $"alter role sli_job_{purpose}_light login", ct);
        }
        string root = SqlPostgresFixture.Repository();
        var render = ProcessInfo(Environment.GetEnvironmentVariable("SLI_TEST_PYTHON") ?? (OperatingSystem.IsWindows()
            ? "python" : "python3"), root);
        render.ArgumentList.Add("-B"); render.ArgumentList.Add("-c");
        render.ArgumentList.Add("from deploy.linux import native_runtime as n; import json; n.clickhouse.configured_mode=lambda: 'native'; print(json.dumps(n.dotnet_units('synthetic',dict(profiles=['light'],radius_pilot=False,bind='192.0.2.1',health_url='https://192.0.2.1:8443/api/health/ready'))))");
        var rendered = await RunProcess(render, ct);
        Assert.Equal(0, rendered.Exit);
        var units = JsonNode.Parse(rendered.Out)!.AsObject();
        string credentials = Path.Combine(fixture.Pg.Root, "credentials"); Directory.CreateDirectory(credentials);
        var failures = new List<string>();
        foreach (string service in new[] { "post-collection", "entity-state", "ad-snapshot-manifest-coordinator", "semantic", "executor-light", "notification-setup" })
        {
            string unit = units[$"sli-dotnet-{service}.service"]!.GetValue<string>();
            var info = ProcessInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", root);
            info.ArgumentList.Add(typeof(Program).Assembly.Location);
            string[] arguments = Regex.Match(unit, @"(?m)^ExecStart=\S+ (.+)$").Groups[1].Value.Trim().Split(' ');
            string command = arguments[0];
            foreach (string argument in arguments) info.ArgumentList.Add(argument);
            if (service != "notification-setup") info.ArgumentList.Add("--once");
            var loaded = Regex.Matches(unit, @"(?m)^LoadCredential=([^:]+):").Select(m => m.Groups[1].Value).ToHashSet();
            foreach (string name in loaded) await File.WriteAllTextAsync(Path.Combine(credentials, name), "synthetic-test-password\n", ct);
            foreach (Match setting in Regex.Matches(unit, "(?m)^Environment=\"([^=]+)=(.*)\"$"))
            {
                string key = setting.Groups[1].Value, value = setting.Groups[2].Value;
                if (value.StartsWith("%d/", StringComparison.Ordinal)) { Assert.Contains(value[3..], loaded); value = Path.Combine(credentials, value[3..]); }
                else if (key.EndsWith("_DSN", StringComparison.Ordinal)) {
                    string role = Regex.Match(value, @"user=([^ ]+)").Groups[1].Value;
                    var db = new NpgsqlConnectionStringBuilder(fixture.Dsn(role));
                    value = $"host={db.Host} port={db.Port} dbname={db.Database} user={role}";
                }
                else if (key is "ADLOG_DATA_DIR" or "ADLOG_LOG_DIR" or "SLI_PLUGIN_RUNTIME_DIR" or "SLI_PLUGIN_LOCK_DIR" or "SLI_PLUGIN_HEARTBEAT_DIR" or "SLI_TELEGRAM_SECRET_DIR" or "SLI_EXECUTOR_STATUS_DIR") {
                    value = Path.Combine(fixture.Pg.Root, key); Directory.CreateDirectory(value);
                    if (key == "SLI_PLUGIN_LOCK_DIR") {
                        // Native admission locks the pre-existing bundled manifest inode.
                        // An empty directory fails on Linux after Windows has already
                        // refused flock; reproduce the installed files on both platforms.
                        foreach (string manifest in Directory.GetFiles(Path.Combine(root, "config/plugin_packages/v3"), "*.json"))
                            File.Copy(manifest, Path.Combine(value, Path.GetFileName(manifest)), overwrite: true);
                    }
                }
                else if (key == "SLI_TELEGRAM_SETUP_SOCKET") value = Path.Combine(fixture.Pg.Root, "control.sock");
                else if (key == "SLI_NOTIFICATION_STATUS_FILE") value = Path.Combine(fixture.Pg.Root, "notification-heartbeat.json");
                else if (key == "SLI_JOB_PG_HOST") value = "127.0.0.2";
                info.Environment[key] = value;
            }
            Assert.DoesNotContain("ConnectionStrings__Sli", info.Environment.Keys);
            Assert.DoesNotContain("ADLOG_PG_ADMIN_USER", info.Environment.Keys);
            if (service == "executor-light") {
                // The unit still runs when the bundled workstation job is disabled.
                Assert.Equal("0", info.Environment["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"]);
                using var admissionInode = File.OpenRead(Path.Combine(info.Environment["SLI_PLUGIN_LOCK_DIR"]!, "sli.workstations.json"));
                if (OperatingSystem.IsWindows()) {
                    var denied = Assert.Throws<PlatformNotSupportedException>(() => Sli.Server.Jobs.CoreJobAdmission.Enter("sli.workstations", info.Environment["SLI_PLUGIN_RUNTIME_DIR"], info.Environment["SLI_PLUGIN_LOCK_DIR"]));
                    Assert.Equal("plugin_update_lock_unavailable", denied.Message);
                }
            }
            // Root ownership, statx/ACLs and the socket are exercised on Debian.
            if (service == "notification-setup" && !OperatingSystem.IsWindows()) continue;
            var result = await RunProcess(info, ct);
            if (service == "semantic") {
                // An empty installation has no operator policy admission. Both
                // runtimes must refuse it; never turn that guard off to start.
                Assert.Equal(1, result.Exit);
                Assert.Contains("production_admission:enabled_policy_set_differs", result.Error);
                await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
                await PostCollectionPostgres.Sql(owner, """
                    insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                    values('synthetic-native',1,'control_health','disabled','{}',sha256('{}'::bytea));
                    insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
                    values('synthetic-native',1,false,'synthetic-test');
                    """, ct);
                result = await RunProcess(info, ct);
                await PostCollectionPostgres.Sql(owner, "select pg_stat_clear_snapshot()", ct);
                await using var calls = new NpgsqlCommand("select calls from pg_stat_user_functions where funcid='public.default_detection_sources()'::regprocedure", owner);
                Assert.Equal(1L, await calls.ExecuteScalarAsync(ct));
            }
            output.WriteLine($"{command}: exit={result.Exit} {result.Out}{result.Error}");
            if (service == "notification-setup") {
                Assert.Equal(1, result.Exit); Assert.Contains("notification_setup_root_required", result.Error);
            }
            else if (result.Exit != 0 || result.Error.Contains("_failed", StringComparison.Ordinal)) failures.Add(command + ": " + result.Out + result.Error);
            if (service != "notification-setup") {
                string name = service switch { "what-where-when" => "what_where_when_projection", "remote-access" => "plugin_radius_session_observation",
                    "executor-light" => "core_job_executor_light", _ => service.Replace('-', '_') };
                var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"), ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = info.Environment["ADLOG_DATA_DIR"]
                }).Build();
                var operations = new Sli.Server.Operations.OperationsService(new Sli.Server.Operations.OperationsQueries(new Sli.Server.Infrastructure.PostgresConnectionFactory(config)),
                    new Sli.Server.Operations.OperationsFiles(config), new(), new(), TimeProvider.System);
                var item = Assert.Single((await operations.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == name)!;
                Assert.Equal("disabled", (string?)item["state"]); Assert.Equal("stopped", (string?)item["status"]);
                Assert.Equal("native_process_heartbeat", (string?)item["observation_source"]); Assert.NotNull(item["heartbeat_at"]);
            }
            if (service == "remote-access") {
                var heartbeat = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(info.Environment["SLI_PLUGIN_HEARTBEAT_DIR"]!, "plugin-radius-session-observation.json"), ct))!;
                Assert.Equal("acquisition_disabled", heartbeat["phase"]!.GetValue<string>());
                Assert.Equal("idle", heartbeat["status"]!.GetValue<string>());
            }
            if (service == "ad-snapshot-manifest-coordinator") {
                await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
                await using var heartbeat = new NpgsqlCommand("select status='idle' and phase='acquisition_disabled' from runtime_worker_heartbeats where worker_name='ad_snapshot_manifest_coordinator'", owner);
                Assert.Equal(true, await heartbeat.ExecuteScalarAsync(ct));
            }
            if (service is "post-collection" or "ad-snapshot-manifest-coordinator" or "semantic") {
                string setting = service == "semantic" ? "ADLOG_SEMANTIC_WORKER_PASSWORD_FILE" : "ADLOG_PG_PASSWORD_FILE";
                string saved = info.Environment[setting]!;
                info.Environment[setting] = Path.Combine(fixture.Pg.Root, "synthetic-private-unavailable");
                var invalid = await RunProcess(info, ct);
                Assert.Equal(1, invalid.Exit);
                Assert.Contains("server_configuration_invalid:" + setting + ":unavailable", invalid.Error);
                Assert.DoesNotContain("synthetic-private", invalid.Error);
                info.Environment[setting] = saved;
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public void Worker_errors_disclose_only_fixed_codes_and_steps()
    {
        var postgres = new PostgresException("synthetic-private-sql", "ERROR", "ERROR", "42501", detail: "synthetic-private-detail");
        Assert.Equal("publication:postgres_42501", WorkerFailure.Describe(postgres, "publication"));
        Assert.Equal("socket:io_unavailable", WorkerFailure.Describe(new IOException("synthetic-private-path"), "socket"));
        Assert.Equal("socket:notification_setup_acl_invalid", WorkerFailure.Describe(new IOException("notification_setup_acl_invalid"), "socket"));
        Assert.Equal("startup:operation_failed", WorkerFailure.Describe(new InvalidOperationException("synthetic-private-value"), "startup"));
    }

    private static async Task AuthorizeStorageAsync(NpgsqlConnection db, string archive, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var record = new Sli.Server.Storage.Direct.DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64), archive,
            new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 }, "synthetic", now, now.AddHours(1), null, "");
        await using var command = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values('v2',@authority,@preflight,@digest,@archive,@evidence::jsonb,'synthetic',@at,@expires)
            """, db);
        command.Parameters.AddWithValue("authority", record.Authority); command.Parameters.AddWithValue("preflight", record.PreflightDigest);
        command.Parameters.AddWithValue("digest", Sli.Server.Storage.Direct.DirectRuntimeAuthorization.Digest(record));
        command.Parameters.AddWithValue("archive", archive); command.Parameters.AddWithValue("evidence", record.Evidence.ToJsonString());
        command.Parameters.AddWithValue("at", record.AuthorizedAt); command.Parameters.AddWithValue("expires", record.ExpiresAt);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static ProcessStartInfo ProcessInfo(string executable, string root)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = root };
        var inherited = new[] { "PATH", "LD_LIBRARY_PATH", "SystemRoot", "WINDIR", "DOTNET_ROOT", "DOTNET_HOST_PATH", "DOTNET_CLI_HOME", "TEMP", "TMP" }
            .Select(k => (k, value: Environment.GetEnvironmentVariable(k))).ToArray();
        info.Environment.Clear(); foreach (var (key, value) in inherited) if (value is not null) info.Environment[key] = value;
        return info;
    }

    private static async Task<(int Exit, string Out, string Error)> RunProcess(ProcessStartInfo info, CancellationToken ct)
    {
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        return (process.ExitCode, await stdout, await stderr);
    }

    [Fact]
    public async Task Every_worker_runs_once_with_native_database_roles_on_empty_and_synthetic_data()
    {
        var ct = TestContext.Current.CancellationToken;
        // CoreJobIdentity, like the Python executor, uses database sli, port 5432.
        // A separate loopback address keeps this cluster away from installed services.
        await using var fixture = new SqlPostgresFixture(nativeJobAddress: true);
        await fixture.StartAsync(ct);
        string root = SqlPostgresFixture.Repository();
        // Keep role checks for retained CLI entry points, including services hidden in beta.
        var commands = new[] { "core-job-executor", "storage-lifecycle-worker", "collection-worker", "legacy-post-collection-worker", "semantic-worker",
            "account-watch-worker", "account-decoy-worker", "file-decoy-worker", "file-ransom-worker", "nps-threshold-worker", "semantic-production-worker",
            "smtp-delivery-worker", "report-producer", "notification-delivery-worker", "telegram-delivery-worker", "password-producer", "password-risk-consumer",
            "entity-state-worker", "what-where-when-projection-worker", "post-collection-worker", "agent-import-worker", "radius-accounting-worker",
            "gpo-snapshot-worker", "ad-snapshot-manifest-coordinator-worker", "radius-session-observation", "ad-snapshot-worker" };
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await AuthorizeStorageAsync(admin, fixture.Pg.Root, ct);
        await PostCollectionPostgres.Sql(admin, "create role sql_report_login login noinherit; grant adlog_report_producer to sql_report_login", ct);
        await PostCollectionPostgres.Sql(admin, "create role sql_nps_login login noinherit; grant adlog_nps_agent_import_worker to sql_nps_login", ct);
        string radiusRoute = Path.Combine(fixture.Pg.Root, "synthetic-radius-route.json");
        await File.WriteAllTextAsync(radiusRoute, RadiusCollectionRouteTests.Route, ct);
        await PostCollectionPostgres.Sql(admin, """
            insert into report_producer_principals select oid,rolname from pg_roles where rolname='sql_report_login';
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select oid,rolname,'00000000-0000-4000-8000-000000000001','sli.windows.ad-dc','sql-fixture','1','','core_event',1,'00000000-0000-4000-8000-000000000001' from pg_roles where rolname='sli_semantic_login';
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,agent_id)
            select oid,rolname,'00000000-0000-4000-8000-000000000001','sli.file-audit','sql-fixture','1','sql-fixture','file_audit_observation','00000000-0000-4000-8000-000000000001' from pg_roles where rolname='sli_semantic_login';
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('synthetic-sql',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) select policy_id,policy_version,lifecycle_status='enabled','synthetic-test' from semantic_risk_policies;
            insert into sli_plugin_file_audit.policy_revisions(agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            values('00000000-0000-4000-8000-000000000001','sql-fixture',1,now(),'session',1,'{}',repeat('a',64));
            """, ct);
        foreach (string p in new[] { "light", "heavy", "long" }) foreach (string purpose in new[] { "dispatcher", "executor", "publisher" })
            await PostCollectionPostgres.Sql(admin, $"alter role sli_job_{purpose}_{p} login", ct);
        Directory.CreateDirectory(Path.Combine(fixture.Pg.Root, "executor"));
        string secret = Path.Combine(fixture.Pg.Root, "synthetic-password.txt"); await File.WriteAllTextAsync(secret, "synthetic-test-password", ct);
        var failures = new List<string>(); int count = 0;
        foreach (bool populated in new[] { false, true })
        {
            long eventId = 0;
            if (populated) {
                var accepted = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4722]);
                eventId = Assert.Single(accepted).EventId;
                await ShortEventAdmissionPostgresTests.WriteAsync(fixture, accepted, ct);
                await using var state = new NpgsqlCommand("""
                    insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do nothing;
                    insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                    select 101,t.id,'synthetic-worker-user','Synthetic worker user',d.id,sha256('worker-user'::bytea) from storage_v2_entity_type t cross join domains d where t.value='ad_user' and d.fqdn='example.test';
                    insert into entity_state_projection_jobs(job_id,source_event_db_id,candidate_states)
                    values('00000000-0000-4000-8000-000000000001',@event,jsonb_build_array(jsonb_build_object(
                        'entity_id',101,'state_type','account.access','severity','medium','status','enabled','summary','Synthetic account enabled',
                        'rule_id','account-enabled-4722','rule_version','1','source_event_db_id',@event,'observed_at_utc',to_char(now() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'details_json','{}'::jsonb)));
                    """, admin);
                state.Parameters.AddWithValue("event", eventId);
                await state.ExecuteNonQueryAsync(ct);
            }
            foreach (string command in commands)
            foreach (string? profile in command == "core-job-executor" ? new string?[] { "light", "heavy", "long" } : [null])
            {
                // Detector commands register policies in this same disposable DB.
                // Admit the synthetic enabled set as an owner before production,
                // just as an installation must do before switching worker modes.
                if (command == "semantic-production-worker") await PostCollectionPostgres.Sql(admin, "insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) select policy_id,policy_version,lifecycle_status='enabled','synthetic-test' from semantic_risk_policies on conflict(policy_id,policy_version) do nothing", ct);
                Guid? notificationJob = null;
                if (populated && command is "smtp-delivery-worker" or "telegram-delivery-worker" or "notification-delivery-worker") {
                    notificationJob = Guid.NewGuid();
                    await using var notification = new NpgsqlCommand("""
                        insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) values(@id,1,1,@channel,false);
                        insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,channel)
                        values(@id,@id,1,'test_problem',@id,1,@channel);
                        """, admin);
                    notification.Parameters.AddWithValue("id", notificationJob.Value);
                    notification.Parameters.AddWithValue("channel", command == "telegram-delivery-worker" ? "telegram" : "smtp");
                    await notification.ExecuteNonQueryAsync(ct);
                }
                var args = new List<string> { command, "--once" };
                if (profile is not null) { args.Add("--profile"); args.Add(profile); }
                if (command is "account-watch-worker" or "account-decoy-worker" or "file-decoy-worker" or "file-ransom-worker" or "nps-threshold-worker")
                {
                    string kind = command[..^7]; bool file = kind.StartsWith("file-");
                    var rule = new JsonObject { ["scope"] = new JsonObject { ["installation_id"] = "00000000-0000-4000-8000-000000000001", ["plugin_id"] = file ? "sli.file-audit" : "sli.windows.ad-dc", ["source_instance_id"] = "sql-fixture", ["source_generation"] = "1", ["collection_scope_id"] = file ? "sql-fixture" : "" }, ["evaluation_mode"] = "enabled" };
                    if (file) rule["agent_id"] = "00000000-0000-4000-8000-000000000001";
                    if (kind == "file-ransom") rule["source_policy_revision"] = "1";
                    string path = Path.Combine(fixture.Pg.Root, kind + ".json"); await File.WriteAllTextAsync(path, rule.ToJsonString(), ct);
                    args.Add("--rule-file"); args.Add(path);
                }
                var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") {
                    UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = root
                };
                // Do not inherit installed credentials, *_FILE settings or arbitrary PG defaults.
                var inherited = new[] { "PATH", "LD_LIBRARY_PATH", "SystemRoot", "WINDIR", "DOTNET_ROOT", "DOTNET_HOST_PATH", "DOTNET_CLI_HOME", "TEMP", "TMP" }
                    .Select(k => (k, value: Environment.GetEnvironmentVariable(k))).ToArray();
                info.Environment.Clear(); foreach (var (key, value) in inherited) if (value is not null) info.Environment[key] = value;
                info.ArgumentList.Add(typeof(Program).Assembly.Location); foreach (string arg in args) info.ArgumentList.Add(arg);
                string role = command == "storage-lifecycle-worker" ? "sli_storage_lifecycle_login" : command is "smtp-delivery-worker" or "telegram-delivery-worker" or "notification-delivery-worker" ? "sli_notification_login" : "adlog_user";
                var settings = new Dictionary<string, string> {
                    ["ADLOG_PG_DSN"] = fixture.Dsn(role), ["ConnectionStrings__Sli"] = fixture.Dsn(role),
                    ["ADLOG_STORAGE_V2_WORKER_DSN"] = fixture.Dsn("sli_storage_login"), ["ADLOG_AD_CONTEXT_WORKER_DSN"] = fixture.Dsn("sli_context_login"),
                    ["ADLOG_SEMANTIC_WORKER_DSN"] = fixture.Dsn("sli_semantic_login"),
                    ["SLI_NPS_AGENT_IMPORT_ENABLED"] = "1", ["SLI_NPS_AGENT_WORKER_DSN"] = fixture.Dsn("sql_nps_login"), ["ADLOG_RADIUS_COLLECTION_ROUTES_PATH"] = radiusRoute,
                    ["ADLOG_DATA_DIR"] = Path.Combine(fixture.Pg.Root, "data-files"), ["ADLOG_LOG_DIR"] = Path.Combine(fixture.Pg.Root, "logs"),
                    ["ADLOG_PG_ADMIN_USER"] = "adlog_user", ["ADLOG_PG_ADMIN_PASSWORD_FILE"] = secret,
                    ["SLI_REPORT_PRODUCER_PG_DSN"] = fixture.Dsn("sql_report_login"), ["SLI_REPORT_PRODUCER_PG_PASSWORD_FILE"] = secret,
                    ["SLI_REPORT_PRODUCER_STATUS_FILE"] = Path.Combine(fixture.Pg.Root, "report-status.json"),
                    ["SLI_NOTIFICATION_STATUS_FILE"] = Path.Combine(fixture.Pg.Root, "notification-status.json"),
                    ["SLI_EXECUTOR_STATUS_DIR"] = Path.Combine(fixture.Pg.Root, "executor"),
                    ["SLI_JOB_PG_HOST"] = "127.0.0.2", ["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"] = "0", ["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] = "0",
                    ["SLI_CORE_JOB_AD_GPO_PILOT"] = "1",
                    ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"] = "1", ["ADLOG_SEMANTIC_DEVELOPMENT_SCOPE"] = "1",
                    ["ADLOG_SEMANTIC_RUNTIME_MODE"] = command == "semantic-worker" ? "development" : "findings-v1",
                    ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = command == "semantic-worker" ? "0" : "1"
                };
                if (command == "storage-lifecycle-worker")
                    settings["ADLOG_STORAGE_LIFECYCLE_DELETE_DSN"] = fixture.Dsn("sli_storage_lifecycle_delete_login");
                foreach (string stage in new[] { "ASSEMBLY", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION" }) settings["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = command == "semantic-worker" ? "0" : "1";
                foreach (string p in new[] { "LIGHT", "HEAVY", "LONG" }) foreach (string purpose in new[] { "DISPATCHER", "EXECUTOR", "PUBLISHER" }) settings[$"SLI_JOB_{purpose}_{p}_PASSWORD_FILE"] = secret;
                foreach (var (key, value) in settings) info.Environment[key] = value;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15));
                using var process = Process.Start(info)!;
                var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
                try { await process.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) {
                    failures.Add(command + ": one-pass deadline exceeded");
                    await using var activity = new NpgsqlCommand("select coalesce(string_agg(usename||':'||state||':'||coalesce(wait_event,'')||':'||query,E'\\n'),'') from pg_stat_activity where datname=current_database() and pid<>pg_backend_pid()", admin);
                    output.WriteLine("Timed out " + command + ": " + await activity.ExecuteScalarAsync(ct));
                    if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(ct);
                }
                string result = await stdout + await stderr;
                string label = $"{command} {profile} populated={populated}";
                output.WriteLine($"{label}: exit={process.ExitCode} {result}");
                if (command == "collection-worker") {
                    Assert.Equal(0, process.ExitCode);
                    var blocked = JsonNode.Parse(result)!.AsObject();
                    Assert.Equal("disabled", blocked["status"]?.ToString());
                    Assert.Equal("module_disabled", blocked["reason"]?.ToString());
                }
                else if (process.ExitCode != 0) failures.Add(label + ": " + result);
                if (notificationJob is {} job && process.ExitCode == 0) {
                    await using var state = new NpgsqlCommand("select state from notification_outbox where id=@id", admin); state.Parameters.AddWithValue("id", job);
                    if (await state.ExecuteScalarAsync(ct) as string != "cancelled") failures.Add(label + ": claimed synthetic job did not reach cancelled state");
                }
                if (populated && command == "entity-state-worker" && process.ExitCode == 0) {
                    await using var projected = new NpgsqlCommand("select status='completed' and exists(select 1 from entity_state_current where entity_id=101 and status='enabled') from entity_state_projection_jobs where source_event_db_id=@event", admin);
                    projected.Parameters.AddWithValue("event", eventId);
                    if (await projected.ExecuteScalarAsync(ct) is not true) failures.Add(label + ": synthetic projection was not committed");
                }
                if (command == "semantic-production-worker" && process.ExitCode != 0) {
                    await using var inspect = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await inspect.OpenAsync(ct);
                    await PostCollectionPostgres.Sql(inspect, "set role adlog_semantic_worker", ct);
                    await using var transaction = await inspect.BeginTransactionAsync(ct);
                    var session = new Sli.Server.Semantic.SemanticSession(inspect, transaction);
                    output.WriteLine((await session.QueryAsync(Sli.Server.Semantic.SemanticProductionSql.Guard0, ct)).ToJsonString());
                    try { await Sli.Server.Semantic.SemanticProduction.GuardAsync(session, "findings-v1", ct); }
                    catch (InvalidOperationException error) { output.WriteLine("Production admission: " + error.Message); }
                }
                count++;
            }
        }
        output.WriteLine($"Checked {commands.Length} commands, {count} one-pass processes");
        string log = await fixture.Pg.DiagnosticsAsync(ct);
        if (Regex.IsMatch(log, @"(?m)^.*(?:ERROR:|FATAL:|ОШИБКА:).*$")) failures.Add(log);
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    internal static Task SeedAsync(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        insert into servers(id,domain_id,hostname,fqdn,role) select 1,id,'fixture','fixture.example.test','domain_controller' from domains where fqdn='example.test';
        insert into log_sources(name) values('sql-fixture');
        insert into storage_v2_channel(value) values('Security') on conflict(value) do nothing;
        insert into storage_v2_provider(value) values('Microsoft-Windows-Security-Auditing') on conflict(value) do nothing;
        insert into events_v2_core(id,server_id,domain_id,log_source_id,event_id,channel_id,provider_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
        select 1,1,d.id,(select id from log_sources where name='sql-fixture'),4625,c.id,p.id,now()-interval '1 minute',now(),sha256('synthetic-event'::bytea),sha256('synthetic-source'::bytea),(select version from event_catalog_revisions order by id desc limit 1)
        from domains d cross join storage_v2_channel c cross join storage_v2_provider p where d.fqdn='example.test' and c.value='Security' and p.value='Microsoft-Windows-Security-Auditing';
        """, ct);
}
