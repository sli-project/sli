using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticOutboxThroughputPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Upgrade_adds_ordered_claim_and_queue_drains_with_continuing_arrivals()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 455);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await Seed(owner, 1, 400_000, ct);
        await PostCollectionPostgres.Sql(owner, "analyze semantic_processing_outbox", ct);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
        await ExplainClaim(worker, ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/456_semantic_outbox_claim.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(owner, "analyze semantic_processing_outbox", ct);
        Assert.Contains("Index Scan using semantic_outbox_claim456", await ExplainClaim(worker, ct));

        // Virtual minutes and a conservative budget of 512 completions/min.
        // The native consumer benchmark exercises actual job processing.
        const int arrivals = 250, claimSize = 128, leasesPerMinute = 4;
        int lastId = 400_000, remaining = lastId, minutes = 0;
        const int maxMinutes = (400_000 + 261) / 262;
        while (remaining > 0 && minutes < maxMinutes)
        {
            await Seed(owner, lastId + 1, arrivals, ct); lastId += arrivals;
            remaining += arrivals; minutes++;
            for (int i = 0; i < leasesPerMinute; i++)
            {
                await using var session = new SemanticSession(worker, await worker.BeginTransactionAsync(ct));
                var jobs = await SemanticProduction.Claim(session, ct, count: claimSize);
                Assert.Equal(Math.Min(claimSize, remaining), jobs.Count);
                if (jobs.Count == 0) break;
                Assert.Equal((long)lastId - remaining + 1, jobs[0].Number("source_event_id"));
                Assert.Equal((long)lastId - remaining + jobs.Count, jobs[^1].Number("source_event_id"));
                await SemanticProduction.CompleteBatch(session, jobs.Select(job => job!).ToArray(), ct);
                await session.CommitAsync(ct);
                remaining -= jobs.Count;
            }
        }
        Assert.Equal(0, remaining);
        await using (var count = new NpgsqlCommand("select count(*) from semantic_processing_outbox where status='completed'", owner))
            Assert.Equal((long)lastId, await count.ExecuteScalarAsync(ct));
        output.WriteLine($"Drained {lastId:N0} jobs in {minutes} virtual minutes at {arrivals} arrivals/minute.");
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using var index = new NpgsqlCommand("select to_regclass('public.semantic_outbox_claim456') is null", owner);
        Assert.Equal(true, await index.ExecuteScalarAsync(ct));
    }

    private async Task<string> ExplainClaim(NpgsqlConnection worker, CancellationToken ct)
    {
        await using var session = new ExplainSession(new SemanticSession(worker, await worker.BeginTransactionAsync(ct)), output);
        var rows = await SemanticProduction.Claim(session, ct, count: 128);
        Assert.Equal(128, rows.Count);
        Assert.Equal(1L, rows[0].Number("source_event_id"));
        return session.Plan;
    }

    [Fact]
    public async Task Scheduled_claims_preserve_lane_order_and_reserve_a_backfill_turn()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await Seed(owner, 1, 128, ct);
        await Seed(owner, 1001, 512, ct, live: true);
        var production = new SemanticProduction(null!, new(true, true, false, true, false, false), SemanticRuntimeSettings.FindingsMode, 128);

        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
        await using var web = new NpgsqlConnection(fixture.Dsn("adlog_user")); await web.OpenAsync(ct);
        await using var lag = new NpgsqlCommand(OperationsService.SemanticOutboxLagSql, web);
        lag.Parameters.AddWithValue("version", SemanticEvent.Version);
        lag.Parameters.AddWithValue("replay", SemanticEvent.Version + "+r7-%");
        await CheckLag(hasLive: true, hasHistory: true);
        foreach (int first in new[] { 1001, 1129, 1257, 1, 1385 })
        {
            await using var session = new SemanticSession(worker, await worker.BeginTransactionAsync(ct));
            var jobs = await production.ClaimScheduled(session, 128, ct);
            Assert.Equal(Enumerable.Range(first, 128).Select(id => (long)id), jobs.Select(job => job.Number("source_event_id")));
            await SemanticProduction.CompleteBatch(session, jobs.Select(job => job!).ToArray(), ct);
            await session.CommitAsync(ct);
            if (first == 1) await CheckLag(hasLive: true, hasHistory: false);
        }
        await CheckLag(hasLive: false, hasHistory: false);

        async Task CheckLag(bool hasLive, bool hasHistory)
        {
            await using var ages = await lag.ExecuteReaderAsync(ct);
            Assert.True(await ages.ReadAsync(ct));
            if (hasLive) Assert.InRange(ages.GetInt64(0), 360, 480);
            else Assert.True(ages.IsDBNull(0));
            if (hasHistory) Assert.InRange(ages.GetInt64(1), 7200, 7320);
            else Assert.True(ages.IsDBNull(1));
        }
    }

    internal static async Task Seed(NpgsqlConnection db, int first, int count, CancellationToken ct, bool live = false)
    {
        await using var command = new NpgsqlCommand("""
        insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,
            processor_id,processor_version,idempotency_key,source_id,domain_id,partition_key,occurred_at_utc,
            source_identity_json,available_at,created_at,payload_json)
        select gen_random_uuid(),n,'normalize_event',1,'semantic-shadow',@version,sha256(n::text::bytea),
            1,1,'1:1',now(),jsonb_build_object('id',n,'server_id',1,'domain_id',1,'log_source_id',1,
                'event_id',1102,'time_created_utc',now(),'normalized_hash',repeat('a',64),'migrated_at',now(),'channel','Security'),
            timestamp with time zone '2000-01-01 00:00:00+00'+n*interval '1 millisecond',
            now()-case when @live then interval '6 minutes' else interval '2 hours' end,
            case when @live then '{"queue_lane":"live"}'::jsonb else '{}'::jsonb end
        from generate_series(@first,@last) n
        """, db) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("version", SemanticEvent.Version);
        command.Parameters.AddWithValue("first", first);
        command.Parameters.AddWithValue("last", first + count - 1);
        command.Parameters.AddWithValue("live", live);
        await command.ExecuteNonQueryAsync(ct);
    }

    private sealed class ExplainSession(SemanticSession session, ITestOutputHelper output) : ISemanticSession
    {
        internal string Plan { get; private set; } = "";
        public async Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            await session.ExecuteAsync("savepoint explain_claim", ct);
            var plan = await session.QueryAsync("explain (analyze, buffers) " + sql, ct, values);
            await session.ExecuteAsync("rollback to savepoint explain_claim", ct);
            Plan = string.Join('\n', plan.Select(row => row.Text("QUERY PLAN")));
            output.WriteLine(Plan);
            return await session.QueryAsync(sql, ct, values);
        }
        public Task CommitAsync(CancellationToken ct) => session.CommitAsync(ct);
        public ValueTask DisposeAsync() => session.DisposeAsync();
    }
}
