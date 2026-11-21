using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Agents.Radius;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class PostCollectionDatabaseTests
{
    private sealed class PluginEnvironment : IDisposable
    {
        private readonly string? runtime = Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), locks = Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
        public PluginEnvironment() { Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", ""); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR", ""); }
        public void Dispose() { Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", runtime); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR", locks); }
    }
    private static JsonObject Fixture(string name, [CallerFilePath] string path = "") => JsonNode.Parse(File.ReadAllText(Path.Combine(Path.GetDirectoryName(path)!, name)))!.AsObject();
    private sealed class Factory(PostCollectionPostgres pg) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => pg.OpenAsync(ct, "adlog_user"); }

    private static Task CreateBindingTablesAsync(NpgsqlConnection db, CancellationToken ct) => PostCollectionPostgres.Sql(db, """
        create table sli_agent_module_bindings(agent_id uuid references sli_agents(id),module_id text,
            source_instance_id text not null,source_name text not null,channel text not null,module_version text not null,
            primary key(agent_id,module_id));
        create table servers(id bigint primary key,domain_id bigint not null,hostname text not null,
            fqdn text,role text not null,is_active boolean not null);
        grant select on sli_agent_module_bindings,servers to adlog_user;
        """, ct);

    [Fact]
    public async Task WorkerConnectionsHaveNoExecutionDeadlineAndMonitorCanWriteWhileInboxSessionIsBusy()
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new PluginEnvironment();
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        var dsn = new NpgsqlConnectionStringBuilder(pg.ConnectionString) { CommandTimeout = 1,
            Options = "-c statement_timeout=1 -c lock_timeout=1" };
        Assert.True(AgentImportCommand.TryCreateFactory(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = dsn.ConnectionString }).Build(), out var factory));
        await using var process = await factory!.OpenAsync(ct);
        Assert.Equal(0, process.CommandTimeout);
        await using (var check = new NpgsqlCommand("select current_setting('statement_timeout'),current_setting('lock_timeout')", process)) {
            await using var reader = await check.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal("0", reader.GetString(0)); Assert.Equal("0", reader.GetString(1));
        }
        await PostCollectionPostgres.Sql(process, "select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", ct);
        await using var blocking = await pg.OpenAsync(ct);
        await CreateBindingTablesAsync(blocking, ct);
        await using var transaction = await blocking.BeginTransactionAsync(ct);
        await using (var hold = new NpgsqlCommand("lock sli_agent_packet_inbox in access exclusive mode", blocking, transaction)) await hold.ExecuteNonQueryAsync(ct);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var runtime = new PostCollectionRuntime(process, factory, new AgentWorkstationInboxConsumer(factory));
        var run = runtime.RunAsync(new(true, 1), stop.Token);
        try {
            await using var observer = await pg.OpenAsync(ct);
            DateTime? first = null;
            // Wait for a second heartbeat while the inbox query is still waiting
            // on our own transaction. No source data or external service is used.
            while (true) {
                await using var read = new NpgsqlCommand("select heartbeat_at from runtime_worker_heartbeats where worker_name='post_collection' and phase='event_inbox'", observer);
                if (await read.ExecuteScalarAsync(ct) is DateTime at) {
                    if (first is { } previous && at > previous) break;
                    first = at;
                }
                Assert.False(run.IsCompleted, "The inbox must remain blocked until the test releases its lock.");
                await Task.Delay(20, ct);
            }
            await transaction.CommitAsync(ct);
            if (await run != 0) Assert.Fail(await pg.DiagnosticsAsync(ct));
        }
        finally {
            stop.Cancel();
            await transaction.DisposeAsync();
            try { await run; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task SnapshotCursorSurvivesDeletionOfPreviouslyScannedCycleAndWrapsForRetry()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        Guid agent = Guid.NewGuid();
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agents(id,status,assigned_modules) values(@agent,'disabled','[]');
            insert into sli_agent_snapshot_bindings values(@agent,'sli.ad-snapshot');
            insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy)
              select gen_random_uuid(),@agent,'sli.ad-snapshot','2026-10-01T00:00:00Z'::timestamptz + i*interval '1 hour',
                'S-1-5-21-100000001-200000002-300000003','{}'::jsonb from generate_series(0,4) i
            """, db)) { seed.Parameters.AddWithValue("agent", agent); await seed.ExecuteNonQueryAsync(ct); }
        var scanner = new SnapshotCycleConsumer();
        var first = await scanner.RunOnceAsync(pg.ConnectionString, ct);
        Assert.Equal(4, first.Scanned); Assert.Equal(0, first.Imported);
        await using (var delete = new NpgsqlCommand("delete from sli_agent_snapshot_cycles where cycle_id=@id", db)) {
            delete.Parameters.AddWithValue("id", Guid.Parse((string)first.Cursor!["cycle_id"]!)); await delete.ExecuteNonQueryAsync(ct);
        }
        Assert.Equal(1, (await scanner.RunOnceAsync(pg.ConnectionString, ct)).Scanned);
        Assert.Equal(0, (await scanner.RunOnceAsync(pg.ConnectionString, ct)).Scanned);
        Assert.Null(scanner.Cursor);
        Assert.Equal(4, (await scanner.RunOnceAsync(pg.ConnectionString, ct)).Scanned);
    }

    [Theory]
    [InlineData(SnapshotPolicy.Ad, "ad-publication-source-vector.json")]
    [InlineData(SnapshotPolicy.Gpo, "gpo-publication-source-vector.json")]
    public async Task WorkerPublishesPastFiveStalledCyclesAndLeavesFutureSlotsPending(string module, string fixture)
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new PluginEnvironment();
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        var vector = Fixture(fixture); var config = vector["config"]!.AsObject();
        Guid agent = Guid.NewGuid(), healthy = Guid.NewGuid();
        string slot = vector["cycle"]?["slot_start_utc"]?.GetValue<string>() ?? "2026-10-08T11:00:00+00:00";
        var due = DateTimeOffset.Parse(slot);
        await using (var domain = new NpgsqlCommand("update domains set domain_sid=@sid,fqdn=@dns where id=7", db)) {
            domain.Parameters.AddWithValue("sid", config["domain_sid"]!.GetValue<string>());
            domain.Parameters.AddWithValue("dns", config["domain_dns"]!.GetValue<string>()); await domain.ExecuteNonQueryAsync(ct);
        }
        await SeedAsync(db, agent, healthy, module, config, vector["families"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject()), slot, ct);
        // Missing chunks keep five older cycles pending; the final slot is not due yet.
        foreach (int hours in new[] { -5, -4, -3, -2, -1, 1 }) {
            await using var seed = new NpgsqlCommand("insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy) values(@cycle,@agent,@module,@slot,@sid,@policy)", db);
            seed.Parameters.AddWithValue("cycle", Guid.NewGuid()); seed.Parameters.AddWithValue("agent", agent);
            seed.Parameters.AddWithValue("module", module); seed.Parameters.AddWithValue("slot", due.AddHours(hours).ToString("O"));
            seed.Parameters.AddWithValue("sid", config["domain_sid"]!.GetValue<string>());
            seed.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, config.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        var result = await GpoWorkerCommand.RunOnceAsync(pg.ConnectionString, null, module, ct, due);
        Assert.Equal(0, result.ExitCode); Assert.Equal(6, result.Scanned); Assert.Equal(healthy, result.NextAfter);
        await using (var published = new NpgsqlCommand("select publication_state from sli_agent_snapshot_cycles where cycle_id=@cycle", db)) {
            published.Parameters.AddWithValue("cycle", healthy); Assert.Equal("published", await published.ExecuteScalarAsync(ct));
        }
        await using var pending = new NpgsqlCommand("select count(*) from sli_agent_snapshot_cycles where publication_state='pending'", db);
        Assert.Equal(6L, await pending.ExecuteScalarAsync(ct));
        // A later invocation starts at the beginning and retries deferred evidence.
        Assert.Equal(5, (await GpoWorkerCommand.RunOnceAsync(pg.ConnectionString, null, module, ct, due)).Scanned);
    }

    [Fact]
    public async Task IsolatedPostgresChecksLockRolesAdGpoRetryRollbackAndReplay()
    {
        var ct = TestContext.Current.CancellationToken;
        using var pluginEnvironment = new PluginEnvironment();
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var admin = await pg.OpenAsync(ct);
        await CreateBindingTablesAsync(admin, ct);
        await PostCollectionPostgres.Sql(admin, """
            insert into sli_agents(id,assigned_modules) values('00000000-0000-4000-8000-000000000001','[]');
            insert into sli_agent_packet_inbox values(gen_random_uuid(),now(),null,
                '{"agent_id":"00000000-0000-4000-8000-000000000001","module_id":"sli.windows.ad-dc"}',
                '{}','[]');
            """, ct);
        async Task<int> HostOnce()
        {
            var builder = Host.CreateApplicationBuilder([]);
            builder.Services.AddSingleton<IPostgresConnectionFactory>(new Factory(pg));
            builder.Services.AddSingleton<AgentWorkstationInboxConsumer>(); builder.Services.AddSingleton(new AgentImportOptions(true, 10));
            builder.Services.AddSingleton<AgentImportWorker>(); builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentImportWorker>());
            using var host = builder.Build(); var worker = host.Services.GetRequiredService<AgentImportWorker>(); await host.RunAsync(ct); return worker.ExitCode;
        }
        string? enabled = Environment.GetEnvironmentVariable("SLI_NPS_AGENT_IMPORT_ENABLED");
        try {
            Environment.SetEnvironmentVariable("SLI_NPS_AGENT_IMPORT_ENABLED", "0");
            await PostCollectionPostgres.Sql(admin, "select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", ct);
            Assert.Equal(9, await HostOnce());
            await PostCollectionPostgres.Sql(admin, "select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", ct);
            if (await HostOnce() != 0) Assert.Fail(await pg.DiagnosticsAsync(ct));
        } finally { Environment.SetEnvironmentVariable("SLI_NPS_AGENT_IMPORT_ENABLED", enabled); }
        await using (var check = new NpgsqlCommand("""
            select status,phase,details_json->'snapshots'->>'scanned',
              pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process')),
              details_json->'agent_packets'->>'scanned',details_json->'agent_packets'->'pending_reasons'->>'agent_storage_unavailable'
            from runtime_worker_heartbeats where worker_name='post_collection'
            """, admin)) {
            await using var r = await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal("idle", r.GetString(0)); Assert.Equal("sleep", r.GetString(1)); Assert.Equal("0", r.GetString(2)); Assert.True(r.GetBoolean(3)); Assert.Equal("1", r.GetString(4)); Assert.Equal("1",r.GetString(5));
        }
        await PostCollectionPostgres.Sql(admin, "select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", ct);

        var vector = Fixture("ad-publication-source-vector.json"); var policy = vector["config"]!.AsObject();
        var families = vector["families"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject());
        Guid agent = Guid.NewGuid(), cycle = Guid.NewGuid(); string slot = vector["cycle"]!["slot_start_utc"]!.GetValue<string>();
        await SeedAsync(admin, agent, cycle, SnapshotPolicy.Ad, policy, families, slot, ct);
        await using (var unprivileged = await pg.OpenAsync(ct, "adlog_user")) {
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => AdSnapshotPublisher.ProcessAsync(unprivileged, cycle, ct));
            Assert.Equal("agent_snapshot_worker_role_required", failure.Message);
        }
        await using var worker = await pg.OpenAsync(ct, "adlog_context_worker");
        await DrainingAsync("sli.ad", () => AdSnapshotPublisher.ProcessAsync(worker, cycle, ct), ct);
        await using (var check = new NpgsqlCommand("select count(*) from ad_context_runs", admin)) Assert.Equal(0L, await check.ExecuteScalarAsync(ct));
        var result = await AdSnapshotPublisher.ProcessAsync(worker, cycle, ct);
        Assert.True(result.PublicationState == "published", result.PublicationState == "published" ? null : result.PendingReason + await pg.DiagnosticsAsync(ct));
        await using (var check = new NpgsqlCommand("select (select count(*) from ad_context_runs),(select count(*) from users_report_v2_snapshots),(select count(*) from computers_v6_source_snapshots),(select count(*) from ad_snapshot_projection_receipts where status='completed'),(select count(*) from ad_snapshot_projection_outputs)", admin)) {
            await using var r = await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal(5L, r.GetInt64(0)); Assert.Equal(1L, r.GetInt64(1)); Assert.Equal(1L, r.GetInt64(2)); Assert.Equal(3L, r.GetInt64(3)); Assert.Equal(3L, r.GetInt64(4));
        }
        Assert.Null((await AdSnapshotPublisher.ProcessAsync(worker, cycle, ct)).PendingReason);
        // Force the retained publication to be re-read; replay cannot duplicate sources or outputs.
        await PostCollectionPostgres.Sql(admin, $"update sli_agent_snapshot_cycles set publication_state='pending',manifest_id=null,published_at=null where cycle_id='{cycle:D}'", ct);
        Assert.Equal("published", (await AdSnapshotPublisher.ProcessAsync(worker, cycle, ct)).PublicationState);
        await PostCollectionPostgres.Sql(admin, $"update sli_agents set status='disabled' where id='{agent:D}'", ct);
        Assert.Equal("agent_disabled", (await Assert.ThrowsAsync<ProtocolException>(() => AdSnapshotPublisher.ProcessAsync(worker, cycle, ct))).Code);
        await PostCollectionPostgres.Sql(admin, $"update sli_agents set status='active',assigned_modules='[]'::jsonb where id='{agent:D}'", ct);
        Assert.Equal("agent_module_not_assigned", (await Assert.ThrowsAsync<ProtocolException>(() => AdSnapshotPublisher.ProcessAsync(worker, cycle, ct))).Code);

        Guid damagedAgent = Guid.NewGuid(), damaged = Guid.NewGuid();
        await SeedAsync(admin, damagedAgent, damaged, SnapshotPolicy.Ad, policy, families, "2026-10-05T11:00:00+00:00", ct);
        await PostCollectionPostgres.Sql(admin, $"update sli_agent_snapshot_chunks set payload=jsonb_set(payload,'{{family_sha256}}',to_jsonb(repeat('a',64))) where cycle_id='{damaged:D}' and family='computers_v6'", ct);
        Assert.Equal("agent_snapshot_cycle_invalid", (await Assert.ThrowsAsync<ProtocolException>(() => AdSnapshotPublisher.ProcessAsync(worker, damaged, ct))).Code);
        // Cursor walks past denied/corrupt evidence and wraps instead of starving the queue.
        var scanner = new SnapshotCycleConsumer();
        var firstScan = await scanner.RunOnceAsync(pg.ConnectionString, ct);
        Assert.Equal(1, firstScan.Scanned); Assert.True(firstScan.PendingReasons.ContainsKey("agent_snapshot_cycle_invalid"));
        Assert.Equal(0, (await scanner.RunOnceAsync(pg.ConnectionString, ct)).Scanned);
        Assert.Equal(1, (await scanner.RunOnceAsync(pg.ConnectionString, ct)).Scanned);

        Guid failedAgent = Guid.NewGuid(), failed = Guid.NewGuid();
        var changedFamilies = families.ToDictionary(p => p.Key, p => (JsonObject)p.Value.DeepClone());
        foreach (var family in changedFamilies.Where(p => p.Key != "computers_v6")) { family.Value["run_id"] = Guid.NewGuid().ToString(); family.Value.Remove("bundle_sha256"); }
        await SeedAsync(admin, failedAgent, failed, SnapshotPolicy.Ad, policy, changedFamilies, "2026-10-06T11:00:00+00:00", ct);
        await PostCollectionPostgres.Sql(admin, "create function p04_refuse_users() returns trigger language plpgsql as $$begin raise exception 'synthetic-private-failure'; end$$; create trigger p04_fail before insert on users_report_v2_snapshots for each row execute function p04_refuse_users()", ct);
        var pending = await AdSnapshotPublisher.ProcessAsync(worker, failed, ct);
        Assert.Equal("agent_ad_publication_failed", pending.PendingReason);
        await using (var check = new NpgsqlCommand($"select transport_state,publication_state,(select count(*) from ad_context_runs) from sli_agent_snapshot_cycles where cycle_id='{failed:D}'", admin)) {
            await using var r = await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal("complete", r.GetString(0)); Assert.Equal("pending", r.GetString(1)); Assert.Equal(5L, r.GetInt64(2));
        }
        await PostCollectionPostgres.Sql(admin, "drop trigger p04_fail on users_report_v2_snapshots", ct);
        var retry = await scanner.RunOnceAsync(pg.ConnectionString, ct);
        Assert.Equal(1, retry.Scanned); Assert.Empty(retry.PendingReasons);
        await using (var check = new NpgsqlCommand($"select publication_state from sli_agent_snapshot_cycles where cycle_id='{failed:D}'", admin)) Assert.Equal("published", await check.ExecuteScalarAsync(ct));

        var gpo = Fixture("gpo-publication-source-vector.json"); Guid gpoCycle = Guid.NewGuid();
        await using (var rebind = new NpgsqlCommand("update domains set domain_sid=@sid,fqdn=@dns where id=7", admin)) {
            rebind.Parameters.AddWithValue("sid", gpo["config"]!["domain_sid"]!.GetValue<string>()); rebind.Parameters.AddWithValue("dns", gpo["config"]!["domain_dns"]!.GetValue<string>()); await rebind.ExecuteNonQueryAsync(ct);
        }
        await SeedAsync(admin, Guid.NewGuid(), gpoCycle, SnapshotPolicy.Gpo, gpo["config"]!.AsObject(), gpo["families"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject()), "2026-10-08T11:00:00+00:00", ct);
        await DrainingAsync("sli.gpo", () => GpoSnapshotPublisher.ProcessAsync(worker, gpoCycle, ct), ct);
        var gpoResult = await GpoSnapshotPublisher.ProcessAsync(worker, gpoCycle, ct);
        Assert.True(gpoResult.PublicationState == "published", gpoResult.PublicationState == "published" ? null : gpoResult.PendingReason + await pg.DiagnosticsAsync(ct));
        await AccountingCursorAsync(pg, admin, ct);
    }

    private static async Task DrainingAsync(string plugin, Func<Task<GpoPublicationResult>> publish, CancellationToken ct)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-p04-drain-" + Guid.NewGuid().ToString("N")), directory = Path.Combine(root, plugin);
        Directory.CreateDirectory(directory); string marker = Path.Combine(directory, "draining.json"); await File.WriteAllTextAsync(marker, "{}", ct);
        try {
            Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", root);
            var result = await publish(); Assert.True(result.TransportComplete); Assert.Equal("pending", result.PublicationState);
            Assert.Equal(plugin == "sli.ad" ? "agent_ad_publication_failed" : "agent_gpo_publication_failed", result.PendingReason);
        } finally { Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", ""); File.Delete(marker); Directory.Delete(directory); Directory.Delete(root); }
    }

    private static async Task AccountingCursorAsync(PostCollectionPostgres pg, NpgsqlConnection admin, CancellationToken ct)
    {
        for (int i = 0; i < 2; i++) {
            Guid agent = Guid.NewGuid(), packet = Guid.NewGuid(); string source = Guid.NewGuid().ToString();
            var envelope = new Envelope(packet.ToString(), agent.ToString(), source, "sli.radius-accounting", "1.0.0", new string('a', 64), "radius", source, 1, Cursor.Start("file_offset"), Cursor.Start("file_offset"), "sli.collection-packet.v1", Packets.Digest(new JsonObject()), 0, 2, "2026-10-08T12:00:00+00:00", "complete", 0, 0).ToJson();
            await using var seed = new NpgsqlCommand("insert into sli_agents(id,status,assigned_modules) values(@agent,@status,'[]'::jsonb); insert into sli_agent_packet_inbox values(@packet,@received,null,@envelope,'{}'::jsonb,'[]'::jsonb)", admin);
            seed.Parameters.AddWithValue("agent", agent); seed.Parameters.AddWithValue("status", i == 0 ? "disabled" : "active"); seed.Parameters.AddWithValue("packet", packet); seed.Parameters.AddWithValue("received", DateTime.UtcNow.AddSeconds(i)); seed.Parameters.AddWithValue("envelope", NpgsqlDbType.Jsonb, envelope.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        string? runtime = Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), locks = Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR");
        try {
            Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", ""); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR", "");
            var consumer = new RadiusInboxConsumer(); var binding = new RadiusImportBinding(Path.GetTempPath(), "synthetic.radius");
            var first = await consumer.RunUnderProcessLockAsync(pg.ConnectionString, binding, 1, ct); Assert.Equal(1, first.Scanned); Assert.True(first.PendingReasons.ContainsKey("agent_disabled"));
            var second = await consumer.RunUnderProcessLockAsync(pg.ConnectionString, binding, 1, ct); Assert.Equal(1, second.Scanned); Assert.True(second.PendingReasons.ContainsKey("agent_module_not_assigned"));
            Assert.Equal(0, (await consumer.RunUnderProcessLockAsync(pg.ConnectionString, binding, 1, ct)).Scanned);
            Assert.True((await consumer.RunUnderProcessLockAsync(pg.ConnectionString, binding, 1, ct)).PendingReasons.ContainsKey("agent_disabled"));
        } finally { Environment.SetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR", runtime); Environment.SetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR", locks); }
    }

    internal static async Task SeedAsync(NpgsqlConnection db, Guid agent, Guid cycle, string module, JsonObject config, IReadOnlyDictionary<string, JsonObject> families, string slot, CancellationToken ct)
    {
        var policy = new SnapshotPolicy(module, config); var assignments = new JsonArray(new JsonObject { ["module_id"] = module, ["enabled"] = true, ["config"] = config.DeepClone() });
        await using (var c = new NpgsqlCommand("insert into sli_agents(id,assigned_modules) values(@agent,@assignments); insert into sli_agent_snapshot_bindings values(@agent,@module); insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy) values(@cycle,@agent,@module,@slot,@sid,@policy)", db)) {
            c.Parameters.AddWithValue("agent", agent); c.Parameters.AddWithValue("module", module); c.Parameters.AddWithValue("cycle", cycle); c.Parameters.AddWithValue("slot", slot); c.Parameters.AddWithValue("sid", config["domain_sid"]!.GetValue<string>());
            c.Parameters.AddWithValue("assignments", NpgsqlDbType.Jsonb, assignments.ToJsonString()); c.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, config.ToJsonString()); await c.ExecuteNonQueryAsync(ct);
        }
        Cursor before = Cursor.Start("snapshot"); int sequence = 0;
        foreach (var family in policy.Families) {
            byte[] bytes = CanonicalJson.ToBytes(families[family]); int chunks = (bytes.Length + SnapshotStream.FragmentBytes - 1) / SnapshotStream.FragmentBytes;
            for (int i = 0; i < chunks; i++) {
                var payload = new JsonObject { ["contract"] = module + ".chunk.v1", ["cycle_id"] = cycle.ToString("D"), ["family"] = family, ["slot_start_utc"] = slot, ["chunk_index"] = i, ["chunk_count"] = chunks, ["cycle_families"] = config["families"]!.DeepClone(), ["total_objects"] = families[family][family == "computers_v6" ? "objects" : family == "gpo_v2" ? "gpos" : "records"]!.AsArray().Count, ["total_bytes"] = bytes.Length, ["family_sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)), ["records"] = new JsonArray(new JsonObject { ["data_b64"] = Convert.ToBase64String(bytes.AsSpan(i * SnapshotStream.FragmentBytes, Math.Min(SnapshotStream.FragmentBytes, bytes.Length - i * SnapshotStream.FragmentBytes))) }), ["domain_sid"] = config["domain_sid"]!.DeepClone(), ["domain_dns"] = config["domain_dns"]!.DeepClone(), ["scope"] = config["scope"]!.DeepClone() };
                var after = SnapshotStream.MakeCursor(payload); Guid packet = Guid.NewGuid();
                var envelope = new Envelope(packet.ToString("D"), agent.ToString("D"), policy.SourceId, module, "1.0.0", policy.Revision, "snapshot", policy.SourceId, ++sequence, before, after, module + ".chunk.v1", Packets.Digest(payload), 1, CanonicalJson.Length(payload), "2026-10-08T12:00:00+00:00", "complete", 0, 0).ToJson();
                await using var c = new NpgsqlCommand("insert into sli_agent_receipts values(@packet,@agent,@module,@sequence,@envelope,@hash); insert into sli_agent_snapshot_chunks values(@packet,@cycle,@family,@index,@payload)", db);
                c.Parameters.AddWithValue("packet", packet); c.Parameters.AddWithValue("agent", agent); c.Parameters.AddWithValue("module", module); c.Parameters.AddWithValue("sequence", (long)sequence); c.Parameters.AddWithValue("envelope", NpgsqlDbType.Jsonb, envelope.ToJsonString()); c.Parameters.AddWithValue("hash", Packets.Digest(envelope)); c.Parameters.AddWithValue("cycle", cycle); c.Parameters.AddWithValue("family", family); c.Parameters.AddWithValue("index", i); c.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString()); await c.ExecuteNonQueryAsync(ct); before = after;
            }
        }
    }
}
