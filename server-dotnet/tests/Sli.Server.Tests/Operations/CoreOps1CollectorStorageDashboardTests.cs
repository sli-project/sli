using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Vectors from tests/core/test_core_ops1_collector_storage_dashboard.py.
public sealed class CoreOps1CollectorStorageDashboardTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    [Theory]
    [InlineData(30, "running", true)]
    [InlineData(15, "running", true)]
    [InlineData(14, "running", false)]
    [InlineData(30, "completed", false)]
    public async Task PostCollectionMarksOnlyRunningRowsWithStaleHeartbeat(int age, string status, bool stale)
    {
        using var app = await OperationsEndpointTests.Start(settings: new() { ["Sli:Operations:ADLOG_POST_COLLECTION_STALE_MINUTES"] = "15" });
        string marker = OperationsEndpointTests.Now.AddMinutes(-age).ToString("O");
        app.Queries.PostSummary = new(new JsonObject { ["status"] = status, ["count"] = 1 });
        app.Queries.PostItems = new(new JsonObject { ["id"] = 1, ["source_job_id"] = 7, ["status"] = status, ["heartbeat_at"] = marker, ["updated_at"] = marker });
        var data = await app.Service.CollectorAsync(Ct);
        Assert.Equal(stale ? 1 : 0, (int)data["post_collection"]!["summary"]!["stale_running"]!);
        Assert.Equal(stale, (bool)data["post_collection"]!["items"]![0]!["stale_running"]!);
        Assert.Equal(age, (long)data["post_collection"]!["items"]![0]!["heartbeat_age_minutes"]!);
        Assert.Equal(stale ? 1 : 0, (long)data["summary"]!["stale_post_collection"]!);
    }

    [Fact]
    public async Task CollectorSurvivesPostCollectionDependencyFailureWithEmptyUnavailableContract()
    {
        using var app = await OperationsEndpointTests.Start(); app.Queries.FailContaining = "post_collection_jobs";
        var data = await app.Service.CollectorAsync(Ct); var post = data["post_collection"]!;
        Assert.Equal("postgres", (string?)post["backend"]); Assert.Equal("unavailable", (string?)post["status"]);
        Assert.Empty(post["summary"]!.AsObject()); Assert.Empty(post["items"]!.AsArray());
        Assert.Equal("InvalidOperationException", (string?)post["error_type"]);
        Assert.Single(data["items"]!.AsArray()); Assert.DoesNotContain("private-db-password", data.ToJsonString());
    }

    [Fact]
    public async Task RetiredCollectorLeavesCursorAndAuditUnchangedForAllLegacyVectors()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        string schema = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_schema.sql"), Ct);
        foreach (string table in new[] { "archive_settings", "collection_channel_state", "collector_cursor_audit" }) {
            string definition = schema.Split("create table if not exists " + table + " (", 2)[1].Split(");", 2)[0];
            await PostCollectionPostgres.Sql(db, "create table " + table + " (" + definition + ");", Ct);
        }
        await PostCollectionPostgres.Sql(db, """
            alter table collection_channel_state add column channel_generation_identity text;
            create table servers(id integer primary key,hostname text);
            create table storage_v2_channel(id integer primary key,value text);
            create table events_v2_core(event_record_id bigint,time_created_utc text,server_id integer,channel_id integer);
            insert into servers values(1,'DC1'); insert into storage_v2_channel values(1,'Security');
            insert into archive_settings(key,value) values('archive_start_utc','2026-07-01T00:00:00+00:00');
            """, Ct);
        // Failed collection, forward progress + generation, rollback, proven reset, partial reset withheld.
        (long Old, long Published, string Status, long Count, long Inserted, string? Proof)[] vectors = [
            (100,120,"failed",0,0,null),
            (100,120,"completed",1000,1000,"generation"),
            (200,150,"completed",1000,1000,null),
            (500000,42,"completed",12,12,"reset"),
            (500000,42,"partial_timeout",12,12,"reset")
        ];
        foreach (var v in vectors) {
            await PostCollectionPostgres.Sql(db, "truncate collection_channel_state,collector_cursor_audit,events_v2_core", Ct);
            await using var tx = await db.BeginTransactionAsync(Ct); await using var session = new SemanticSession(db, tx);
            string? oldTime = v.Status == "partial_timeout" ? null : v.Status == "failed" ? "2026-07-10T00:00:00+00:00"
                : v.Proof == "generation" ? "2026-07-10T00:01:00+00:00" : "2026-07-10T00:02:00+00:00";
            await session.QueryAsync("""
                insert into collection_channel_state(server_hostname,channel,archive_start_utc,last_event_record_id,last_event_time_utc)
                values('DC1','Security','2026-07-01T00:00:00+00:00',$1,$2)
                """, Ct, v.Old, oldTime);
            string start = v.Proof == "reset" ? "2026-07-25T00:00:00+00:00" : "2026-07-10T00:00:00+00:00";
            string? eventTime = v.Status == "partial_timeout" ? null : v.Proof == "reset" ? "2026-07-25T00:01:00+00:00" : "2026-07-10T00:01:00+00:00";
            await session.QueryAsync("insert into events_v2_core values($1,$2,1,1)", Ct, v.Published, eventTime);
            var channel = new JsonObject { ["channel"] = "Security", ["status"] = v.Status, ["count"] = v.Count };
            if (v.Proof == "generation") channel["channel_generation_identity"] = "generation-stable";
            if (v.Proof == "reset") {
                channel["batch_max_record_id"] = 42; channel["channel_latest_record_id_before_read"] = 42;
                channel["cursor_strategy"] = "time_window_fallback"; channel["cursor_fallback_reason"] = "latest_record_id_before_saved_cursor";
            }
            var summary = new JsonObject { ["finished_at"] = start.Replace("00:00:00", "00:02:00"), ["channels"] = new JsonArray(channel) };
            var stats = new JsonObject { ["Security"] = new JsonObject { ["inserted"] = v.Inserted, ["skipped"] = 0 } };
            long? job = v.Status == "failed" ? 10 : v.Proof == "generation" ? 11 : null;
            string? trace = job is null ? null : "trace-" + job;
            var before = await session.QueryAsync("select * from collection_channel_state", Ct);
            var rejected = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                LegacyCollectionState.UpdateAsync(session, new("DC1", start, summary, stats), job, trace, Ct));
            Assert.Equal("module_disabled", rejected.Message);
            Assert.True(JsonNode.DeepEquals(before, await session.QueryAsync("select * from collection_channel_state", Ct)));
            Assert.Empty(await session.QueryAsync("select * from collector_cursor_audit", Ct));
            await session.CommitAsync(Ct);
        }
        string log = await pg.DiagnosticsAsync(Ct);
        Assert.DoesNotContain("ERROR:", log); Assert.DoesNotContain("FATAL:", log);
    }
}
