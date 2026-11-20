using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Agents.Radius;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/core/test_nps_pipeline_runtime.py; all database traffic is
// confined to the fixture's generated loopback cluster, never an inherited DSN.
public sealed class NpsPipelineRuntimeTests
{
    private const string Stamp = "2026-09-10T14:00:00+00:00";
    private const string Server = "radius01.example.test";
    private sealed class Connections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public int Opens { get; private set; }
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { Opens++; return pg.OpenAsync(ct); }
    }
    private static JsonObject RegisteredRoute() => new() {
        ["source_name"] = Server, ["source_instance_id"] = Server, ["owner_confirmed_ip"] = "192.0.2.10",
        ["event_log_ready"] = true, ["event_log_adapter"] = "windows-eventlog-pywin32"
    };
    private static JsonObject Channel(long? candidate, bool exhausted = false) => new() {
        ["channel"] = "Security", ["status"] = "completed", ["count"] = candidate.HasValue ? 1 : 0,
        ["batch_max_record_id"] = candidate, ["start_time_utc"] = Stamp, ["channel_generation_identity"] = "generation-a",
        ["continuity"] = new JsonObject { ["query_exhausted"] = exhausted, ["generation_stable_during_read"] = true, ["truncated"] = !exhausted }
    };
    private static JsonObject Summary(JsonObject channel) => new() { ["finished_at"] = Stamp, ["channels"] = new JsonArray(channel) };
    private static JsonObject Stats(long? candidate) => new() {
        ["Security"] = new JsonObject { ["inserted"] = candidate.HasValue ? 1 : 0, ["skipped"] = 0 }
    };

    [Theory]
    [InlineData("completed", true, true, false, true)]
    [InlineData("completed", false, true, true, false)]
    [InlineData("completed", true, false, false, false)]
    [InlineData("completed", null, null, null, false)]
    [InlineData("partial_timeout", true, true, false, false)]
    public void FilteredBackfillRequiresExhaustedStableQuery(string status, bool? exhausted, bool? stable, bool? truncated, bool expected)
    {
        var item = new JsonObject { ["status"] = status, ["continuity"] = new JsonObject() };
        if (exhausted.HasValue) item["continuity"]!["query_exhausted"] = exhausted;
        if (stable.HasValue) item["continuity"]!["generation_stable_during_read"] = stable;
        if (truncated.HasValue) item["continuity"]!["truncated"] = truncated;
        Assert.Equal(expected, CollectionRuntimePipeline.ChannelBackfillCompleted(item, requireQueryExhaustion: true));
    }

    [Fact]
    public void DcBackfillDefaultIsUnchangedAndNpsRequiresBooleanProof()
    {
        Assert.True(CollectionRuntimePipeline.ChannelBackfillCompleted(new JsonObject { ["status"] = "completed" }));
        Assert.False(CollectionRuntimePipeline.ChannelBackfillCompleted(new JsonObject { ["status"] = "completed" }, true));
        var item = Channel(10, exhausted: true);
        item["continuity"]!["query_exhausted"] = 1;
        Assert.False(CollectionRuntimePipeline.ChannelBackfillCompleted(item, true));
    }

    [Fact]
    public void NpsAdmissionUsesItsRegisteredEndpointWithoutADOrDatabaseLookup()
    {
        // A minimal NPS registration has no DC inventory, AD domain or credential lookup.
        Assert.Equal(Server, NpsPipelineRuntime.ResolveEndpoint(RegisteredRoute(), Server, Server));
        Assert.Equal(Server, NpsPipelineRuntime.ResolveEndpoint(RegisteredRoute(), Server.ToUpperInvariant()));
        foreach (string target in new[] { "dc.example.test", "192.0.2.10", "radius01" }) {
            Assert.Equal("nps_eventlog_endpoint_invalid", Assert.Throws<InvalidOperationException>(() =>
                NpsPipelineRuntime.ResolveEndpoint(RegisteredRoute(), target)).Message);
        }
        Assert.Equal("nps_eventlog_endpoint_invalid", Assert.Throws<InvalidOperationException>(() =>
            NpsPipelineRuntime.ResolveEndpoint(RegisteredRoute(), Server, "dc.example.test")).Message);
        var route = RegisteredRoute(); route["event_log_ready"] = false;
        Assert.Equal("nps_eventlog_registered_route_required", Assert.Throws<InvalidOperationException>(() =>
            NpsPipelineRuntime.ResolveEndpoint(route, Server)).Message);
    }

    [Theory]
    [InlineData(5603344L, null)]
    [InlineData(null, "generation-a")]
    [InlineData(null, null)]
    public void UnpairedArchiveCursorKeepsCanonicalTimeWithoutManufacturingGeneration(long? record, string? generation)
    {
        var channels = new JsonObject { ["Security"] = new JsonObject {
            ["start_time_utc"] = "2026-08-01T00:00:00Z", ["after_record_id"] = record, ["channel_generation_identity"] = generation
        } };
        string before = channels.ToJsonString();
        var request = NpsPipelineRuntime.BuildArchivePlan(Server, channels);
        Assert.Empty(request.ChannelAfterRecordIds); Assert.Empty(request.ChannelCursorGenerations);
        Assert.Equal("2026-08-01T00:00:00Z", request.ChannelStartTimes["Security"]);
        Assert.Equal("2026-08-01T00:00:00Z", request.StartTimeUtc);
        Assert.Equal(before, channels.ToJsonString());
        channels["Security"]!["after_record_id"] = 5603344L;
        channels["Security"]!["channel_generation_identity"] = "generation-a";
        var paired = NpsPipelineRuntime.BuildArchivePlan(Server, channels);
        Assert.Equal(5603344L, paired.ChannelAfterRecordIds["Security"]);
        Assert.Equal("generation-a", paired.ChannelCursorGenerations["Security"]);
    }

    private static async Task Setup(PostCollectionPostgres pg, CancellationToken ct)
    {
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        string root = PostCollectionPostgres.Repository();
        // Use the same canonical tables as Python's disposable_pg vector.
        foreach (var (path, tables) in new[] {
            ("config/postgres_schema_v8.sql", new[] { "forests", "domains", "sites", "servers", "archive_settings", "collection_runs", "collection_channel_state", "collector_cursor_audit" }),
            ("config/postgres_migrations/009_storage_v2_foundation.sql", new[] { "storage_v2_provider", "storage_v2_channel", "storage_v2_computer", "storage_v2_keywords", "storage_v2_domain_name", "events_v2_core" })
        }) {
            string schema = await File.ReadAllTextAsync(Path.Combine(root, path), ct);
            foreach (string table in tables) {
                var statement = Regex.Match(schema, @"create table if not exists " + Regex.Escape(table) + @" \([\s\S]*?\r?\n\);");
                Assert.True(statement.Success, table);
                await PostCollectionPostgres.Sql(db, statement.Value, ct);
            }
        }
        await PostCollectionPostgres.Sql(db, """
            alter table collection_channel_state add column channel_generation_identity text;
            insert into forests(id,name) values(1,'example.test');
            insert into domains(id,forest_id,fqdn) values(1,1,'example.test');
            insert into servers(id,domain_id,hostname) values(1,1,'radius01.example.test');
            insert into storage_v2_channel(id,value) values(1,'Security');
            insert into archive_settings(key,value) values('archive_start_utc','2026-09-10T14:00:00+00:00');
            """, ct);
    }

    private static async Task Seed(NpgsqlConnection db, long? old, long? candidate, CancellationToken ct, bool backfill = false)
    {
        await PostCollectionPostgres.Sql(db, "delete from collector_cursor_audit; delete from collection_channel_state; delete from events_v2_core", ct);
        await using var command = new NpgsqlCommand("""
            insert into collection_channel_state(server_hostname,channel,archive_start_utc,last_event_record_id,channel_generation_identity,backfill_completed)
            select @server,'Security',@stamp,@old,'generation-a',@backfill where @old is not null;
            insert into events_v2_core(id,server_id,domain_id,log_source_id,event_record_id,event_id,channel_id,time_created_utc,normalized_at,normalized_hash,source_core_sha256)
            select 1,1,1,1,@candidate,6272,1,@stamp::timestamptz,now(),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex') where @candidate is not null
            """, db);
        command.Parameters.AddWithValue("server", Server); command.Parameters.AddWithValue("stamp", Stamp);
        command.Parameters.AddWithValue("backfill", backfill);
        command.Parameters.AddWithValue("old", NpgsqlTypes.NpgsqlDbType.Bigint, (object?)old ?? DBNull.Value);
        command.Parameters.AddWithValue("candidate", NpgsqlTypes.NpgsqlDbType.Bigint, (object?)candidate ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<string> RetainedCursorState(NpgsqlConnection db, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select jsonb_build_array((select to_jsonb(s) from collection_channel_state s),
                                     (select jsonb_agg(to_jsonb(a)) from collector_cursor_audit a))::text
            """, db);
        return Assert.IsType<string>(await command.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task DisabledNpsDoesNotChangeRetainedCursorOrAudit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await Setup(pg, ct);
        var runtime = new NpsPipelineRuntime(new CollectionRuntimePipeline(new Connections(pg)));
        await using var db = await pg.OpenAsync(ct);
        foreach (var (name, old, candidate) in new (string, long?, long?)[] {
            ("new", null, 10), ("empty", null, null),
            ("reset", 20, 8), ("rollback", 20, 8), ("complete_to_truncated", 10, 20)
        }) {
            await Seed(db, old, candidate, ct, backfill: name == "complete_to_truncated");
            var channel = Channel(candidate);
            if (name == "reset") {
                channel["channel_generation_identity"] = "generation-b";
                channel["cursor_strategy"] = "time_window_fallback"; channel["cursor_fallback_reason"] = "channel_generation_changed";
                channel["channel_latest_record_id_before_read"] = 8;
            }
            string before = await RetainedCursorState(db, ct);
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                runtime.CommitAsync(Server, Stamp, Summary(channel), Stats(candidate), ct, traceId: "isolated-" + name));
            Assert.Equal("module_disabled", error.Message);
            Assert.Equal(before, await RetainedCursorState(db, ct));
        }
    }

    [Fact]
    public async Task RegisteredLegacyPipelineDoesNotReadOrAdvanceRetainedCursors()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await Setup(pg, ct);
        var services = new ServiceCollection().AddLogging();
        var connections = new Connections(pg);
        services.AddSingleton<IPostgresConnectionFactory>(connections); services.AddLegacyJobs(hosted: false);
        using var provider = services.BuildServiceProvider(); using var scope = provider.CreateScope();
        var pipeline = scope.ServiceProvider.GetRequiredService<CollectionRuntimePipeline>();
        var runtime = scope.ServiceProvider.GetRequiredService<NpsPipelineRuntime>();
        await using var db = await pg.OpenAsync(ct);
        await Seed(db, 5603344, null, ct);
        await PostCollectionPostgres.Sql(db, "update collection_channel_state set channel_generation_identity=null", ct);
        string before = await RetainedCursorState(db, ct);
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.PrepareAsync(RegisteredRoute(), Server, Server, ct));
        Assert.Equal("module_disabled", refused.Message);
        Assert.Equal(before, await RetainedCursorState(db, ct));
        await Seed(db, 10, 20, ct, backfill: true);
        before = await RetainedCursorState(db, ct);
        Assert.Equal("module_disabled", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            pipeline.UpdateCollectionStateAsync(Server, Stamp, Summary(Channel(20)), Stats(20), ct))).Message);
        foreach (bool exhausted in new[] { false, true })
            Assert.Equal("module_disabled", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
                runtime.CommitAsync(Server, Stamp, Summary(Channel(20, exhausted)), Stats(20), ct))).Message);
        Assert.Equal(before, await RetainedCursorState(db, ct));
        Assert.Equal(0, connections.Opens);
    }

    [Fact]
    public async Task DisabledNpsNeverWritesAuditForConfirmedOrUnconfirmedInput()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await Setup(pg, ct);
        var runtime = new NpsPipelineRuntime(new CollectionRuntimePipeline(new Connections(pg)));
        await using var db = await pg.OpenAsync(ct);
        await Seed(db, 10, 20, ct);
        await PostCollectionPostgres.Sql(db, """
            create function reject_test_audit() returns trigger language plpgsql as $$begin raise exception 'test_audit_rejected'; end$$;
            create trigger reject_test_audit before insert on collector_cursor_audit for each row execute function reject_test_audit();
            """, ct);
        string before = await RetainedCursorState(db, ct);
        foreach (long? imported in new long?[] { null, 20 })
            Assert.Equal("module_disabled", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
                runtime.CommitAsync(Server, Stamp, Summary(Channel(20)), Stats(imported), ct))).Message);
        Assert.Equal(before, await RetainedCursorState(db, ct));
    }
}
