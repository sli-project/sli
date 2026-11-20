using Microsoft.Extensions.Configuration;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Vpn;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusObservationHostTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Host_and_broker_do_not_expire_live_database_commands()
    {
        var values = new Dictionary<string, string?> {
            ["ADLOG_PG_DSN"] = "Host=postgres.example.test;Database=sli;Username=fixture_core;Password=fixture_core",
            ["ADLOG_PG_ADMIN_USER"] = "fixture_broker", ["ADLOG_PG_ADMIN_PASSWORD"] = "fixture_generated"
        };
        var settings = RadiusHostConfiguration.Settings(new ConfigurationBuilder().Build(), values.GetValueOrDefault, _ => throw new Exception("no files"));
        Assert.Equal(0, settings.Core.CommandTimeout);
        Assert.Equal(0, settings.Broker.CommandTimeout);
        Assert.False(settings.Core.Pooling);
        Assert.False(settings.Broker.Multiplexing);
    }

    [Fact]
    public async Task Once_runs_one_cycle_without_sleep_and_disabled_runs_none()
    {
        int cycles = 0; var phases = new List<string>();
        var loop = new RadiusObservationLoop(_ => Task.FromResult(true), _ => { cycles++; return Task.CompletedTask; },
            (phase, _) => { phases.Add(phase); return Task.CompletedTask; }, (_, _) => throw new Exception("no sleep"));
        Assert.Equal(0, await loop.RunAsync(true, Ct));
        Assert.Equal(1, cycles); Assert.Equal(new[] { "cycle", "sleep" }, phases);
        phases.Clear();
        loop = new(_ => Task.FromResult(false), _ => throw new Exception("disabled"),
            (phase, _) => { phases.Add(phase); return Task.CompletedTask; }, (_, _) => throw new Exception("no sleep"));
        Assert.Equal(0, await loop.RunAsync(false, Ct)); Assert.Equal(new[] { "disabled" }, phases);
    }

    [Fact]
    public async Task Cancellation_during_cycle_is_not_reported_as_failure()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var phases = new List<string>();
        var loop = new RadiusObservationLoop(_ => Task.FromResult(true), token => { stop.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; },
            (phase, _) => { phases.Add(phase); return Task.CompletedTask; }, (_, _) => throw new Exception("no sleep"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(false, stop.Token));
        Assert.DoesNotContain("cycle_failed", phases);
    }

    [Fact]
    public void Child_has_memory_isolation_without_a_cumulative_CPU_deadline()
    {
        Assert.False(RadiusObservationHost.Budget().ContainsKey("cpu_seconds"));
        Assert.Equal(256L * 1024 * 1024, RadiusObservationHost.Budget()["memory_bytes"]!.GetValue<long>());
        var failure = RadiusObservationHost.Failure(new InvalidOperationException("synthetic-private-password"), "component_runner");
        Assert.Equal("operation_failed", failure["error_code"]!.ToString());
        Assert.DoesNotContain("synthetic-private-password", failure.ToJsonString());
        failure = RadiusObservationHost.Failure(new VpnInputException("delivery_lease_lost"), "component_runner");
        Assert.Equal("delivery_lease_lost", failure["error_code"]!.ToString());
    }

    [Fact]
    public async Task Protocol_reports_cursor_and_rejects_missing_final_result_or_unbounded_messages()
    {
        string Progress(long id) => new JsonObject { ["status"] = "running", ["claimed"] = id, ["processed"] = id, ["cursor_delivery_id"] = id,
            ["contains_secret_material"] = false, ["private_value"] = "synthetic-private" }.ToJsonString() + "\n";
        string final = "{\"status\":\"completed\",\"claimed\":2,\"processed\":2,\"cursor_delivery_id\":2,\"contains_secret_material\":false}";
        var cursors = new List<long>();
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Progress(1) + Progress(2) + final));
        var result = await RadiusObservationProcess.ReadAsync(input, p => {
            cursors.Add(p["cursor_delivery_id"]!.GetValue<long>()); Assert.False(p.ContainsKey("private_value"));
        }, Ct);
        Assert.Equal(new long[] { 1, 2 }, cursors); Assert.Equal("completed", result["status"]!.ToString());
        foreach (string invalid in new[] { Progress(1), new string('x', 65537), "[]\n", final + "\n" + final,
            "{\"status\":\"completed\",\"contains_secret_material\":true}",
            "{\"status\":\"completed\",\"contains_secret_material\":\"false\"}" }) {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(invalid));
            Assert.Equal("cycle_result_invalid", (await Assert.ThrowsAsync<InvalidOperationException>(() => RadiusObservationProcess.ReadAsync(stream, _ => { }, Ct))).Message);
        }
    }

    private static ProcessStartInfo SyntheticChild(string windows, string unix)
    {
        string executable = OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh";
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in OperatingSystem.IsWindows() ? new[] { "-NoProfile", "-NonInteractive", "-Command", windows } : new[] { "-c", unix }) start.ArgumentList.Add(arg);
        return start;
    }

    [Fact]
    public async Task Child_progress_reaches_host_and_cancelled_child_exits_before_cleanup()
    {
        const string running = "{\"status\":\"running\",\"claimed\":1,\"processed\":0,\"cursor_delivery_id\":0,\"contains_secret_material\":false}";
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        int childPid = 0;
        var start = SyntheticChild("[Console]::Error.WriteLine($PID); [Console]::Out.WriteLine('" + running + "'); while ($true) { Start-Sleep -Milliseconds 100 }",
            "printf '%s\\n' '" + running + "'; while :; do sleep 1; done");
        // Capture only this test's PID in its progress callback, using the isolated fixture marker.
        string marker = Path.Combine(Path.GetTempPath(), "radius-child-" + Guid.NewGuid().ToString("N"));
        if (OperatingSystem.IsWindows()) start.ArgumentList[^1] = "[IO.File]::WriteAllText('" + marker + "', [string]$PID); " + start.ArgumentList[^1];
        else start.ArgumentList[^1] = "echo $$ > '" + marker + "'; " + start.ArgumentList[^1];
        try {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RadiusObservationProcess.RunAsync(start, async progress => {
                if (progress is not null) { childPid = int.Parse(await File.ReadAllTextAsync(marker, Ct)); stop.Cancel(); }
            }, stop.Token));
            Assert.True(childPid > 0);
            try { using var child = Process.GetProcessById(childPid); Assert.True(child.HasExited); }
            catch (ArgumentException) { /* Already reaped. */ }
        }
        finally { File.Delete(marker); }
    }

    [Fact]
    public async Task Peak_memory_sampling_tolerates_exit_between_liveness_check_and_sampling()
    {
        var start = SyntheticChild("[Console]::ReadLine() | Out-Null; exit 1", "read -r line; exit 1");
        using var child = Process.Start(start)!;
        long? livePeak;
        try { livePeak = RadiusObservationProcess.SamplePeakMemory(child); }
        finally
        {
            child.StandardInput.Close();
            await child.WaitForExitAsync(Ct);
        }
        Assert.True(livePeak is >= 0);

        long? exitedPeak = RadiusObservationProcess.SamplePeakMemory(child);
        if (OperatingSystem.IsLinux()) Assert.Null(exitedPeak);
        else Assert.True(exitedPeak is null or >= 0);
        Assert.Equal(1, child.ExitCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Child_exit_keeps_final_progress_and_safe_failure_metadata(bool failed)
    {
        const string running = "{\"status\":\"running\",\"claimed\":2,\"processed\":1,\"cursor_delivery_id\":1,\"contains_secret_material\":false}";
        string final = failed
            ? "{\"status\":\"failed\",\"failure_stage\":\"component_runner\",\"error_type\":\"VpnInputException\",\"error_code\":\"delivery_lease_lost\",\"contains_secret_material\":false}"
            : "{\"status\":\"completed\",\"claimed\":2,\"processed\":2,\"cursor_delivery_id\":2,\"contains_secret_material\":false}";
        var start = SyntheticChild("[Console]::Out.WriteLine('" + running + "'); [Console]::Out.WriteLine('" + final + "'); exit " + (failed ? "1" : "0"),
            "printf '%s\\n' '" + running + "' '" + final + "'; exit " + (failed ? "1" : "0"));
        long cursor = 0;
        Task<JsonObject> Run() => RadiusObservationProcess.RunAsync(start, p => { if (p is not null) cursor = p["cursor_delivery_id"]!.GetValue<long>(); return Task.CompletedTask; }, Ct);
        if (failed) {
            var error = await Assert.ThrowsAsync<RadiusObservationFailure>(Run);
            var failure = RadiusObservationHost.Failure(error, "host_control");
            Assert.Equal("component_runner", failure["failure_stage"]!.ToString()); Assert.Equal("delivery_lease_lost", failure["error_code"]!.ToString());
        }
        else { var result = await Run(); Assert.Equal(2L, result["processed"]!.GetValue<long>()); }
        Assert.Equal(1, cursor);
    }

    [Fact]
    public async Task Native_command_idle_gate_writes_reference_heartbeat_without_database_credentials()
    {
        string directory = Path.Combine(Path.GetTempPath(), "radius-idle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (string arg in new[] { typeof(RadiusObservationHost).Assembly.Location, "radius-session-observation", "--component", "radius-session-observation", "--once" }) start.ArgumentList.Add(arg);
            start.Environment.Clear();
            foreach (string key in new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "DOTNET_ROOT" })
                if (Environment.GetEnvironmentVariable(key) is {} value) start.Environment[key] = value;
            start.Environment["ADLOG_ACQUISITION_DISABLED"] = "1";
            start.Environment["ADLOG_DATA_DIR"] = directory; start.Environment["SLI_PLUGIN_HEARTBEAT_DIR"] = directory;
            using var process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync(Ct); var stderr = process.StandardError.ReadToEndAsync(Ct);
            await process.WaitForExitAsync(Ct); Assert.Equal(0, process.ExitCode);
            Assert.Equal("", await stdout); Assert.Equal("", await stderr);
            var heartbeat = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(directory, "plugin-radius-session-observation.json"), Ct))!;
            Assert.Equal("sli.remote-access", heartbeat["plugin_id"]!.ToString()); Assert.Equal("acquisition_disabled", heartbeat["phase"]!.ToString());
            Assert.Equal("idle", heartbeat["status"]!.ToString()); Assert.Equal(30, heartbeat["expected_interval_seconds"]!.GetValue<int>());
            Assert.Equal(process.Id, heartbeat["process_pid"]!.GetValue<int>()); Assert.False(heartbeat["contains_secret_material"]!.GetValue<bool>());
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    private static async Task Schema(NpgsqlConnection db)
    {
        string Migration(string name) => File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations", name));
        string Admission(string name) => Regex.Match(Migration("075_plugin_component_admission.sql"), @"create (?:table|function) " + name + @"\b[\s\S]*?" + (name.EndsWith("v1", StringComparison.Ordinal) && name.StartsWith("plugin_", StringComparison.Ordinal) ? @"\r?\n\);" : @"\r?\n\$\$;")).Value;
        await PostCollectionPostgres.Sql(db, """
            create role adlog_radius_session_consumer noinherit nologin;
            create table plugin_installations_v1(plugin_id text primary key, package_lifecycle text, desired_activation text, component_runtime text);
            insert into plugin_installations_v1 values('sli.remote-access','registered','enabled_manual','running');
            create table core_evidence_manifests(evidence_uid uuid primary key,canonical_record_sha256 text);
            create table radius_accounting_session_observations(observation_id uuid primary key,identity_state text,timestamp_state text,session_identity_key text,
              evidence_uid uuid references core_evidence_manifests,exact_principal_key text,lifecycle_event text,observed_at_utc timestamptz);
            create table acquisition_delivery_outbox(delivery_id bigint primary key,observation_id uuid references radius_accounting_session_observations,
              subscription_id text,attempt_count integer not null default 0,available_at timestamptz not null default now(),created_at timestamptz not null default now(),
              delivery_state text not null default 'queued',lease_token uuid,lease_until timestamptz,heartbeat_at timestamptz,last_error_code text,updated_at timestamptz,delivered_at timestamptz);
            """, Ct);
        foreach (string name in new[] { "plugin_component_admission_v1", "plugin_component_leases_v1", "acquire_plugin_component_lease_v1", "release_plugin_component_lease_v1" }) {
            string sql = Admission(name); Assert.NotEmpty(sql); await PostCollectionPostgres.Sql(db, sql, Ct);
        }
        string receipts = Regex.Match(Migration("061_radius_session_consumer_projection.sql"), @"create table radius_session_projection_receipts[\s\S]*?\r?\n\);").Value;
        await PostCollectionPostgres.Sql(db, receipts, Ct);
        string projection = Regex.Match(Migration("061_radius_session_consumer_projection.sql"), @"create table radius_vpn_session_projection[\s\S]*?\r?\n\);").Value;
        await PostCollectionPostgres.Sql(db, projection, Ct);
        await PostCollectionPostgres.Sql(db, """
            insert into plugin_component_admission_v1(plugin_id,component_id,admission_mode) values('sli.remote-access','radius-session-observation','open');
            grant usage on schema public to adlog_radius_session_consumer;
            grant select,insert,update on acquisition_delivery_outbox,radius_session_projection_receipts to adlog_radius_session_consumer;
            grant select on radius_accounting_session_observations to adlog_radius_session_consumer;
            grant select on core_evidence_manifests to adlog_radius_session_consumer;
            grant select,insert,delete on radius_vpn_session_projection to adlog_radius_session_consumer;
            """, Ct);
    }

    [Fact]
    public async Task Recurring_cycle_commits_more_than_fifty_receipts_and_replays_without_duplicates()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var admin = await pg.OpenAsync(Ct); await Schema(admin);
        await PostCollectionPostgres.Sql(admin, """
            insert into radius_accounting_session_observations(observation_id,identity_state,timestamp_state,session_identity_key) select md5(i::text)::uuid,'unresolved','ready',null from generate_series(1,61) i;
            insert into acquisition_delivery_outbox(delivery_id,observation_id,subscription_id) select i,md5(i::text)::uuid,'vpn-radius-session-observations-radius01-v1' from generate_series(1,61) i;
            """, Ct);
        var cursors = new List<long>();
        await RadiusObservationHost.WithConsumerLogin(new Connections(pg.ConnectionString), async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            var result = await RadiusObservationCycle.RunAsync(child, p => { cursors.Add(p["cursor_delivery_id"]!.GetValue<long>()); return Task.CompletedTask; }, Ct);
            Assert.Equal(61, result["processed"]!.GetValue<long>());
            result = await RadiusObservationCycle.RunAsync(child, _ => Task.CompletedTask, Ct); Assert.Equal(0, result["claimed"]!.GetValue<long>());
            Assert.Equal(61, result["cursor_delivery_id"]!.GetValue<long>());
        }, Ct);
        Assert.Contains(61L, cursors);
        Assert.Equal(61L, await RadiusJobs.Scalar(admin, "select count(*) from radius_session_projection_receipts", Ct));
        Assert.Equal(61L, await RadiusJobs.Scalar(admin, "select count(*) from acquisition_delivery_outbox where delivery_state='delivered' and attempt_count=1", Ct));
        Assert.Equal(2L, await RadiusJobs.Scalar(admin, "select count(*) from plugin_component_leases_v1 where release_outcome='completed'", Ct));
    }

    [Fact]
    public async Task Failed_delivery_keeps_prior_cursor_retry_state_and_releases_component_login()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var admin = await pg.OpenAsync(Ct); await Schema(admin);
        await PostCollectionPostgres.Sql(admin, """
            insert into radius_accounting_session_observations(observation_id,identity_state,timestamp_state,session_identity_key) values(md5('1')::uuid,'unresolved','ready',null),(md5('2')::uuid,'exact','ready','');
            insert into acquisition_delivery_outbox(delivery_id,observation_id,subscription_id) select i,md5(i::text)::uuid,'vpn-radius-session-observations-radius01-v1' from generate_series(1,2) i;
            """, Ct);
        var cursors = new List<long>();
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusObservationHost.WithConsumerLogin(new Connections(pg.ConnectionString), async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            await RadiusObservationCycle.RunAsync(child, p => { cursors.Add(p["cursor_delivery_id"]!.GetValue<long>()); return Task.CompletedTask; }, Ct);
        }, Ct));
        Assert.Equal("exact_session_key_required", error.Message); Assert.Equal(1L, cursors[^1]);
        Assert.Equal(1L, await RadiusJobs.Scalar(admin, "select count(*) from radius_session_projection_receipts", Ct));
        Assert.Equal(1L, await RadiusJobs.Scalar(admin, "select count(*) from acquisition_delivery_outbox where delivery_id=2 and delivery_state='failed' and attempt_count=1 and available_at>now() and last_error_code='consumer_processing_failed' and lease_token is null", Ct));
        Assert.Equal(1L, await RadiusJobs.Scalar(admin, "select count(*) from plugin_component_leases_v1 where release_outcome='failed'", Ct));
        Assert.Equal(0L, await RadiusJobs.Scalar(admin, "select count(*) from pg_roles where rolname like 'adlog_radius_consumer_%'", Ct));
    }

    [Fact]
    public async Task Accounting_start_and_stop_rebuild_one_session_using_real_projection_constraints()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var admin = await pg.OpenAsync(Ct); await Schema(admin);
        await PostCollectionPostgres.Sql(admin, """
            insert into core_evidence_manifests select md5(i::text)::uuid,repeat('a',64) from generate_series(1,2) i;
            insert into radius_accounting_session_observations(observation_id,identity_state,timestamp_state,session_identity_key,evidence_uid,exact_principal_key,lifecycle_event,observed_at_utc)
            select md5(i::text)::uuid,'exact','ready','radius-session:'||repeat('a',64),md5(i::text)::uuid,
              'S-1-5-21-100000001-200000002-300000003-1001',case when i=1 then 'start' else 'stop' end,
              '2026-11-08T00:00:00Z'::timestamptz+i*interval '1 minute' from generate_series(1,2) i;
            insert into acquisition_delivery_outbox(delivery_id,observation_id,subscription_id) select i,md5(i::text)::uuid,'vpn-radius-session-observations-radius01-v1' from generate_series(1,2) i;
            """, Ct);
        await RadiusObservationHost.WithConsumerLogin(new Connections(pg.ConnectionString), async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            var result = await RadiusObservationCycle.RunAsync(child, _ => Task.CompletedTask, Ct); Assert.Equal(2, result["processed"]!.GetValue<long>());
        }, Ct);
        Assert.Equal(1L, await RadiusJobs.Scalar(admin, "select count(*) from radius_vpn_session_projection where lifecycle_state='closed' and completeness='complete' and duration_seconds=60 and observation_count=2", Ct));
        Assert.Equal(2L, await RadiusJobs.Scalar(admin, "select count(*) from radius_session_projection_receipts where outcome='projected'", Ct));
    }
}
