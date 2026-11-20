using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusAcquisitionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static RadiusAcquisitionSource Source(string root) => new("radius.example.test", "radius.example.test", "fixture-subscription", @"\\radius.example.test\accounting", "N. Central Asia Standard Time", 420, root, root);
    private sealed class Database(string dsn) : IPostgresConnectionFactory {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }
    private static string Line(string packet = "4", string status = "1") {
        var fields = Enumerable.Repeat("", 66).ToArray(); fields[0] = "fixture-nps"; fields[1] = "IAS";
        fields[2] = "11/08/2026"; fields[3] = "10:00:00"; fields[4] = packet; fields[6] = "cn=fixture,dc=example,dc=test";
        fields[11] = "fixture-nas"; fields[26] = "fixture-class"; fields[31] = status; fields[35] = "fixture-session";
        return string.Join(',', fields.Select(f => "\"" + f + "\""));
    }

    [Fact] public async Task HostUsesReferenceIntervalGuardOnceFailureAndCancellation() {
        var phases = new List<string>(); int cycles = 0;
        var loop = new RadiusAcquisitionLoop(_ => Task.FromResult(cycles < 3), _ => { cycles++; return Task.CompletedTask; },
            (phase, _, _) => { phases.Add(phase); return Task.CompletedTask; }, (interval, _) => { Assert.Equal(TimeSpan.FromSeconds(300), interval); return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(false, Ct)); Assert.Equal(3, cycles); Assert.Equal("disabled", phases[^1]);
        phases.Clear(); cycles = 0; Assert.Equal(0, await loop.RunAsync(true, Ct)); Assert.Equal(1, cycles); Assert.Equal(new[] { "cycle", "sleep" }, phases);
        loop = new(_ => Task.FromResult(true), _ => throw new IOException("fixture private data"), (p, e, _) => { phases.Add(p); if (e is not null) Assert.IsType<IOException>(e); return Task.CompletedTask; }, (_, _) => throw new Exception("failure must not sleep"));
        Assert.Equal(1, await loop.RunAsync(false, Ct)); Assert.Equal("cycle_failed", phases[^1]);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        loop = new(_ => Task.FromResult(true), token => { stop.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; }, (p, _, _) => { phases.Add(p); return Task.CompletedTask; }, Task.Delay);
        Assert.Equal(0, await loop.RunAsync(false, stop.Token)); Assert.Equal("stopped", phases[^1]);
        Assert.True(RadiusAcquisitionHost.Enabled(JsonNode.Parse("{\"desired_activation\":\"enabled_manual\",\"component_runtime\":\"running\",\"admission_mode\":\"open\"}")!.AsObject()));
        Assert.False(RadiusAcquisitionHost.Enabled(JsonNode.Parse("{\"desired_activation\":\"disabled\",\"component_runtime\":\"draining\",\"admission_mode\":\"drain_only\"}")!.AsObject()));
        Assert.False(RadiusAcquisitionHost.Enabled(null));
        Assert.Equal(2, await RadiusAcquisitionHost.RunAsync(["--unknown-option"])); Assert.Equal(0, await RadiusAcquisitionHost.RunAsync(["--help"]));
    }

    [Fact] public void ChildRejectsAdminEnvironmentAndHeartbeatNeverCopiesPrivateErrors() {
        var env = new Dictionary<string, string?> { ["SLI_PLUGIN_PG_DSN"] = "Host=postgres.example.test;Database=sli;Username=adlog_radius_manual_0123456789abcdef;Password=fixture-generated;Pooling=false;Command Timeout=0" };
        Assert.Equal("adlog_radius_manual_0123456789abcdef", new NpgsqlConnectionStringBuilder(RadiusAcquisitionHost.ChildDsn(env.GetValueOrDefault)).Username);
        foreach (string key in new[] { "ADLOG_PG_DSN", "ADLOG_PG_ADMIN_PASSWORD", "ConnectionStrings__Sli" }) {
            env[key] = "fixture private value";
            Assert.Equal("admin_database_environment_reached_plugin_child", Assert.Throws<InvalidOperationException>(() => RadiusAcquisitionHost.ChildDsn(env.GetValueOrDefault)).Message); env.Remove(key);
        }
        env["SLI_PLUGIN_PG_DSN"] = "Host=postgres.example.test;Username=fixture_admin;Pooling=false;Command Timeout=0";
        Assert.Throws<InvalidOperationException>(() => RadiusAcquisitionHost.ChildDsn(env.GetValueOrDefault));
        var value = RadiusAcquisitionHost.HeartbeatValue("cycle_failed", null, new InvalidOperationException("fixture-private-password"));
        Assert.Equal("blocked", value.Text("status")); Assert.DoesNotContain("fixture-private", value.ToJsonString());
        Assert.Equal(300, value["expected_interval_seconds"]!.GetValue<int>());
        var safe = RadiusAcquisitionHost.SafeResult(new JsonObject { ["status"] = "running", ["cursor_revision_before"] = 5L, ["password"] = "fixture-private" });
        Assert.DoesNotContain("fixture-private", safe.ToJsonString());
        Assert.Throws<InvalidOperationException>(() => RadiusAcquisitionHost.ValidateResult(safe));
        Assert.Throws<InvalidOperationException>(() => RadiusAcquisitionHost.SafeResult(new JsonObject { ["status"] = "committed", ["records"] = "private" }));
        var start = RadiusAcquisitionHost.ChildStartInfo("fixture-child-dsn");
        Assert.False(start.Environment.ContainsKey("ADLOG_PG_DSN")); Assert.False(start.Environment.ContainsKey("ADLOG_PG_ADMIN_PASSWORD")); Assert.Equal("fixture-child-dsn", start.Environment["SLI_PLUGIN_PG_DSN"]);
    }

    [Fact] public void WindowsIdentityAndCredentialAclFailClosed() {
        if (!OperatingSystem.IsWindows()) return;
        const string sid = "S-1-5-21-100000001-200000002-300000003-1101";
        Assert.True(RadiusSourceIdentity.Matches(@"EXAMPLE\fixture", sid, 1, @"example\FIXTURE", sid));
        Assert.False(RadiusSourceIdentity.Matches(@"EXAMPLE\fixture", sid, 0, @"EXAMPLE\fixture", sid));
        Assert.False(RadiusSourceIdentity.Matches(@"EXAMPLE\fixture", sid, 1, null, sid));
        var owner = new SecurityIdentifier(sid);
        var descriptor = new RawSecurityDescriptor($"O:{sid}G:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)");
        RadiusSourceIdentity.ValidateAcl(descriptor, owner, true);
        Assert.Throws<InvalidOperationException>(() => { if (OperatingSystem.IsWindows()) RadiusSourceIdentity.ValidateAcl(descriptor, owner, false); });
        descriptor = new RawSecurityDescriptor($"O:{sid}G:{sid}D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)");
        Assert.Throws<InvalidOperationException>(() => { if (OperatingSystem.IsWindows()) RadiusSourceIdentity.ValidateAcl(descriptor, owner, true); });
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(new { version = 1, purpose = "sli.vpn-source-credentials", owner_sid = sid, username = @"EXAMPLE\fixture", password = "fixture-generated" }));
        Assert.Equal(@"EXAMPLE\fixture", RadiusSourceIdentity.ValidatePayload(json.RootElement, sid).Username);
        Assert.Throws<InvalidOperationException>(() => { if (OperatingSystem.IsWindows()) RadiusSourceIdentity.ValidatePayload(json.RootElement, "S-1-5-21-100000001-200000002-300000003-1102"); });
    }

    [Fact] public async Task DisabledAndPilotCommandsWriteHeartbeatsWithoutDatabaseOrSourceContact() {
        string directory = Path.Combine(Path.GetTempPath(), "sli-radius-command-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try {
            foreach (bool pilot in new[] { false, true }) {
                var start = new System.Diagnostics.ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                foreach (string arg in new[] { typeof(RadiusAcquisitionHost).Assembly.Location, "radius-acquisition", "--once" }) start.ArgumentList.Add(arg);
                start.Environment.Clear();
                foreach (string key in new[] { "SystemRoot", "PATH", "DOTNET_ROOT", "TEMP", "TMP" }) if (Environment.GetEnvironmentVariable(key) is {} value) start.Environment[key] = value;
                start.Environment["ADLOG_ACQUISITION_DISABLED"] = "1"; start.Environment["SLI_CORE_JOB_RADIUS_PILOT"] = pilot ? "1" : "0";
                start.Environment["SLI_PLUGIN_HEARTBEAT_DIR"] = directory; start.Environment["ADLOG_DATA_DIR"] = directory; start.Environment["ADLOG_PG_DSN"] = "fixture-invalid-dsn-must-not-be-read";
                using var process = System.Diagnostics.Process.Start(start)!;
                var stdout = process.StandardOutput.ReadToEndAsync(Ct); var stderr = process.StandardError.ReadToEndAsync(Ct);
                await process.WaitForExitAsync(Ct); Assert.Equal(0, process.ExitCode); _ = await stdout; _ = await stderr;
                var heartbeat = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(directory, "plugin-radius-acquisition.json"), Ct))!.AsObject();
                Assert.Equal(pilot ? "core_executor_pilot" : "acquisition_disabled", heartbeat.Text("phase")); Assert.Equal("idle", heartbeat.Text("status"));
            }
        }
        finally { Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase); Directory.Delete(directory, true); }
    }

    [Fact] public async Task ChildProcessReportsProgressAndStopsOnlyOnExplicitCancellation() {
        var start = new System.Diagnostics.ProcessStartInfo { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        string json = "{\"status\":\"running\",\"cursor_revision_before\":7}";
        if (OperatingSystem.IsWindows()) {
            start.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            string script = "[Console]::Out.WriteLine('" + json + "'); [Console]::Out.Flush(); [Console]::In.ReadLine() | Out-Null; Start-Sleep -Seconds 600";
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)) }) start.ArgumentList.Add(arg);
        } else {
            start.FileName = "/bin/sh"; start.ArgumentList.Add("-c"); start.ArgumentList.Add("printf '%s\\n' '" + json + "'; read line; sleep 600");
        }
        start.Environment.Clear();
        foreach (string key in new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP" }) if (Environment.GetEnvironmentVariable(key) is {} value) start.Environment[key] = value;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct); int pid = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RadiusAcquisitionHost.RunChildAsync(start, value => {
            Assert.Equal(7, value["worker_result"]!.Number("cursor_revision_before")); pid = (int)value.Number("child_pid"); stop.Cancel(); return Task.CompletedTask;
        }, stop.Token));
        Assert.True(pid > 0);
        Assert.Throws<ArgumentException>(() => System.Diagnostics.Process.GetProcessById(pid));
    }

    [Fact] public async Task AcquisitionReadsRealFilesCommitsEvidenceOutboxCursorAndEmptyRotation() {
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(pg.ConnectionString); await admin.OpenAsync(Ct); await Schema(admin);
        var source = Source(pg.Root); var phases = new List<JsonObject>();
        string[] lines = [Line("2", ""), Line(), Line()];
        JsonObject? result = null;
        async Task Run(Func<RadiusCursor, bool, RadiusTailBatch> read) => await RadiusAcquisitionHost.WithAcquisitionLogin(new Database(pg.ConnectionString), source, async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            result = await RadiusAcquisitionCycle.RunAsync(child, source, read, p => { phases.Add(p); return Task.CompletedTask; }, Ct);
        }, Ct);
        await Run((cursor, recovery) => { Assert.Equal(0, cursor.ByteOffset); Assert.False(recovery); return new("fixture-generation", 0, 300, false, lines, 1, 300, 0, PhysicalLines: 3); });
        Assert.Equal("committed", result!.Text("status")); Assert.Equal(3, result.Number("evidence_rows")); Assert.Equal(2, result.Number("outbox_rows"));
        Assert.Equal(1, result.Number("cursor_revision_after"));
        Assert.Equal(3, await Count(admin, "core_evidence_manifests")); Assert.Equal(2, await Count(admin, "radius_accounting_session_observations")); Assert.Equal(2, await Count(admin, "acquisition_delivery_outbox"));
        Assert.Equal(3, Directory.GetFiles(Path.Combine(pg.Root, "published"), "*.record", SearchOption.AllDirectories).Length);
        Assert.Equal(2L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from radius_accounting_session_observations where identity_state='exact' and session_identity_key is not null", Ct)));
        await Run((cursor, recovery) => { Assert.Equal(300, cursor.ByteOffset); Assert.True(recovery); return new(cursor.FileGeneration, 300, 302, false, [], 1, 2, 0, PhysicalLines: 1); });
        Assert.Equal(2, result!.Number("cursor_revision_after")); Assert.Equal(0, result.Number("records"));
        await Run((cursor, _) => new("rotated-generation", 0, 0, true, [], 2, 0, 0));
        Assert.Equal(3, result!.Number("cursor_revision_after"));
        await Run((cursor, _) => new(cursor.FileGeneration, 0, 0, false, [], 1, 5, 5));
        Assert.Equal("no_new_complete_records", result!.Text("status")); Assert.Equal(3, result.Number("cursor_revision_after"));
        Assert.Equal(4L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from fixture_leases where outcome='completed'", Ct)));
        Assert.Equal(0L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from pg_roles where rolname like 'adlog_radius_manual_%'", Ct)));
        Assert.Equal("disabled", await RadiusJobs.Scalar(admin, "select desired_activation from acquisition_source_instances", Ct));
        Assert.Equal(4, phases.Count);
        // The production file reader is the same handle-based implementation as the agent.
        if (OperatingSystem.IsWindows()) {
            string directory = Path.Combine(pg.Root, "accounting"); Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "in-fixture.log"); await File.WriteAllTextAsync(path, Line() + "\r\n\r\npartial", Ct);
            var fileSystem = new RadiusFileSystem(); var file = Assert.Single(fileSystem.Inventory(directory));
            var cursor = new RadiusCursor(source.SourceId, "radius-accounting", "fixture-binding", RadiusTailSource.DeriveGeneration(source.SourceId, file.Name, file.CreationTimeNs), 0, null);
            var tail = new RadiusTailSource(fileSystem).Read(directory, cursor, 1000, false);
            RadiusAcquisitionCycle.ValidateTail(cursor, tail); Assert.Single(tail.Records); Assert.Equal(2, tail.PhysicalLines); Assert.Equal(7, tail.PartialTrailingBytes);
        }
    }

    [Fact] public async Task AcquisitionRollsBackFailureReleasesLoginAndRejectsStaleCursor() {
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(pg.ConnectionString); await admin.OpenAsync(Ct); await Schema(admin);
        var source = Source(pg.Root);
        async Task Run(Func<RadiusCursor, bool, RadiusTailBatch> read) => await RadiusAcquisitionHost.WithAcquisitionLogin(new Database(pg.ConnectionString), source, async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            await RadiusAcquisitionCycle.RunAsync(child, source, read, _ => Task.CompletedTask, Ct);
        }, Ct);
        await PostCollectionPostgres.Sql(admin, "alter table acquisition_delivery_outbox add constraint fixture_reject check (false)", Ct);
        await Assert.ThrowsAsync<PostgresException>(() => Run((cursor, _) => new(cursor.FileGeneration, 0, 100, false, [Line()], 1, 100, 0, PhysicalLines: 1)));
        Assert.Equal(0, await Count(admin, "core_evidence_manifests")); Assert.Equal(0, await Count(admin, "radius_accounting_session_observations"));
        Assert.Equal(0L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select revision from acquisition_stream_cursors", Ct)));
        Assert.Equal("disabled", await RadiusJobs.Scalar(admin, "select desired_activation from acquisition_source_instances", Ct));
        Assert.Equal(0L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from pg_roles where rolname like 'adlog_radius_manual_%'", Ct)));
        await PostCollectionPostgres.Sql(admin, "alter table acquisition_delivery_outbox drop constraint fixture_reject", Ct);
        await Assert.ThrowsAsync<Sli.Server.Agents.Radius.RadiusImportPending>(() => Run((cursor, _) => {
            using var update = new NpgsqlCommand("update acquisition_stream_cursors set revision=revision+1", admin); update.ExecuteNonQuery();
            return new(cursor.FileGeneration, 0, 2, false, [], 1, 2, 0, PhysicalLines: 1);
        }));
        Assert.Equal(0L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select byte_offset from acquisition_stream_cursors", Ct)));
        await Assert.ThrowsAsync<IOException>(() => Run((_, _) => throw new IOException("fixture share unavailable")));
        Assert.Equal(3L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from fixture_leases where outcome='failed'", Ct)));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RadiusAcquisitionHost.WithAcquisitionLogin(new Database(pg.ConnectionString), source, async dsn => {
            await using var child = new NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            await RadiusAcquisitionCycle.RunAsync(child, source, (cursor, _) => { stop.Cancel(); return new(cursor.FileGeneration, 0, 2, false, [], 1, 2, 0, PhysicalLines: 1); }, _ => Task.CompletedTask, stop.Token);
        }, Ct));
        Assert.Equal(1L, Convert.ToInt64(await RadiusJobs.Scalar(admin, "select count(*) from fixture_leases where outcome='cancelled'", Ct)));
        Assert.Equal("disabled", await RadiusJobs.Scalar(admin, "select desired_activation from acquisition_consumer_subscriptions", Ct));
        await PostCollectionPostgres.Sql(admin, "delete from schema_migrations where version=59", Ct);
        bool contacted = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => RadiusAcquisitionHost.WithAcquisitionLogin(new Database(pg.ConnectionString), source, _ => { contacted = true; return Task.CompletedTask; }, Ct));
        Assert.False(contacted);
    }

    private static async Task<long> Count(NpgsqlConnection db, string table) {
        Assert.Contains(table, new[] { "core_evidence_manifests", "radius_accounting_session_observations", "acquisition_delivery_outbox" });
        return Convert.ToInt64(await RadiusJobs.Scalar(db, $"select count(*) from {table}", Ct));
    }

    private static Task Schema(NpgsqlConnection db) => PostCollectionPostgres.Sql(db, """
        create role adlog_storage_owner;
        create role adlog_radius_accounting_worker noinherit;
        create table schema_migrations(version integer,name text);
        insert into schema_migrations values(58,'radius_accounting_transaction_foundation'),(59,'radius_identity_spine_resolver');
        create table acquisition_source_instances(source_instance_id text primary key,desired_activation text,updated_at timestamptz default now());
        create table acquisition_consumer_subscriptions(subscription_id text primary key,source_instance_id text,stream_id text,transport_binding text,desired_activation text);
        create table acquisition_stream_cursors(source_instance_id text,stream_id text,transport_binding text,cursor_epoch uuid,file_generation text,byte_offset bigint,last_record_sha256 text,revision bigint,previous_file_generation text,previous_generation_last_record_sha256 text,updated_at timestamptz default now());
        insert into acquisition_source_instances values('radius.example.test','disabled');
        insert into acquisition_consumer_subscriptions values('fixture-subscription','radius.example.test','radius-accounting','fixture-binding','disabled');
        insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset,revision) values('radius.example.test','radius-accounting','fixture-binding','00000000-0000-4000-8000-000000000001','fixture-generation',0,0);
        create table radius_accounting_class_cache(source_instance_id text,class_scope_sha256 text,exact_principal_key text,expires_at_utc timestamptz,updated_at timestamptz default now(),primary key(source_instance_id,class_scope_sha256));
        create table core_evidence_manifests(evidence_uid uuid primary key,source_instance_id text,stream_id text,transport_binding text,cursor_epoch uuid,file_generation text,cursor_start_byte_offset bigint,batch_record_ordinal integer,canonical_record_sha256 text,object_reference text,object_sha256 text,object_size_bytes integer,verified_at_utc timestamptz);
        create table radius_accounting_session_observations(observation_id uuid primary key,evidence_uid uuid references core_evidence_manifests,lifecycle_event text,session_identity_key text,exact_principal_key text,identity_state text,observed_at_utc timestamptz,timestamp_basis text,timestamp_state text,session_confirmed_by_accounting bool,producer_contract_id text,resource_groups text[],row_sensitivity text,field_categories text[],evidence_access_requirement text,label_policy_version text,provenance_json jsonb);
        create table acquisition_delivery_outbox(subscription_id text,evidence_uid uuid references core_evidence_manifests,observation_id uuid references radius_accounting_session_observations,idempotency_key text unique);
        create table fixture_leases(id uuid primary key,outcome text);
        create function acquire_plugin_component_lease_v1(uuid,text,text,text,text) returns table(lease_uid uuid,component_id text,admission_mode text,expires_at_utc timestamptz) language plpgsql as $$
          begin insert into fixture_leases values($1,null); return query select $1,$3,'open'::text,now()+interval '120 seconds'; end $$;
        create function release_plugin_component_lease_v1(uuid,text,text) returns boolean language plpgsql as $$
          begin update fixture_leases set outcome=$3 where id=$1; return found; end $$;
        create function sli_radius_resolve_principal_key(text,text) returns text language sql as $$select 'sid:S-1-5-21-100000001-200000002-300000003-1101'::text$$;
        grant usage on schema public to adlog_storage_owner,adlog_radius_accounting_worker;
        grant select,update on acquisition_source_instances,acquisition_consumer_subscriptions to adlog_storage_owner;
        grant select,update on acquisition_source_instances,acquisition_consumer_subscriptions,acquisition_stream_cursors to adlog_radius_accounting_worker;
        grant select,insert,update,delete on radius_accounting_class_cache,fixture_leases to adlog_radius_accounting_worker;
        grant select,insert on core_evidence_manifests,radius_accounting_session_observations,acquisition_delivery_outbox to adlog_radius_accounting_worker;
        """, Ct);
}
