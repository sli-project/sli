using System.Diagnostics;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class SemanticOutboxRetentionMemoryPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Fragmented_coverage_checks_a_thousand_jobs_without_per_job_memory_growth()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 377);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        // 2.7 million jobs and 270,000 disjoint decision ranges. Each ten-event
        // producer batch decided nine ids; the tenth is a genuine gap, not one
        // that compaction is allowed to fill. range_agg and + are the producer's
        // operations. The compaction test below also checks chunk boundaries.
        await using (var seed = new NpgsqlCommand("""
            insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
            select 'facts-v1','synthetic-v1',range_agg(int8range(id+1,id+10,'[)'))
            from generate_series(0::bigint,2699990,10) s(id);
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,
              processor_id,processor_version,idempotency_key,status,completed_at,updated_at,created_at,
              source_id,domain_id,partition_key,occurred_at_utc,source_identity_json,payload_json)
            select ('00000000-0000-4000-8000-'||lpad(id::text,12,'0'))::uuid,id,'normalize_event',1,
              'synthetic','synthetic-v1',sha256(convert_to(id::text,'UTF8')),'completed',
              '2026-10-01Z','2026-10-01Z','2026-10-01Z',
              1,1,'synthetic','2026-10-01Z',jsonb_build_object('id',id,'server_id',900001,'domain_id',1,'log_source_id',1,
                'event_id',4625,'time_created_utc','2026-10-01Z','normalized_hash',encode(sha256(id::text::bytea),'hex'),
                'migrated_at','2026-10-01Z','channel','Security'),'{}'
            from generate_series(1,2700000) s(id);
            analyze semantic_processing_outbox;
            """, db) { CommandTimeout = 0 }) await seed.ExecuteNonQueryAsync(ct);
        await using (var size = new NpgsqlCommand("""
            select octet_length(multirange_send(decided_ids)),
              (select count(*) from unnest(decided_ids))
            from semantic_producer_coverage where runtime_mode='facts-v1'
            """, db)) {
            await using var reader = await size.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            output.WriteLine($"coverage: binary bytes={reader.GetInt32(0)}, ranges={reader.GetInt64(1)}");
            Assert.Equal(270000L, reader.GetInt64(1));
        }
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options = "-c role=adlog_storage_lifecycle_delete", CommandTimeout = 0, Pooling = true, MaxPoolSize = 1 }.ConnectionString);
        int pid;
        await using (var probe = await deletion.OpenConnectionAsync(ct)) pid = probe.ProcessID;
        using var backend = Process.GetProcessById(pid);
        var retention = new SemanticOutboxRetention(deletion, state.Files, "facts-v1");
        Guid after = Guid.Empty;
        var growth = new List<long>();
        foreach (int count in new[] { 10, 100, 1000 }) {
            backend.Refresh(); long before = backend.WorkingSet64, peak = before;
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var watch = Stopwatch.StartNew();
            var run = retention.RunAsync(new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), after, count, bounded.Token);
            while (!run.IsCompleted) {
                backend.Refresh(); peak = Math.Max(peak, backend.PeakWorkingSet64);
                // Stop only this test's backend on a regression, before it can
                // exhaust the host. This is a memory assertion, no time limit.
                if (peak - before > 256L * 1024 * 1024) { bounded.Cancel(); break; }
                await Task.Delay(5, ct);
            }
            try {
                var result = await run;
                Assert.Equal(count, LifecycleJson.Number(result, "deleted_count"));
                after = Guid.Parse(result["last_scanned_job_id"]!.ToString());
            } catch (OperationCanceledException) when (!ct.IsCancellationRequested) {
                Assert.Fail($"coverage check exceeded 256 MiB: batch={count}, before={before}, peak={peak}");
            }
            backend.Refresh(); peak = Math.Max(peak, backend.PeakWorkingSet64);
            output.WriteLine($"batch={count}: RSS before={before}, peak={peak}, growth={peak-before}, elapsed={watch.Elapsed.TotalMilliseconds:F1} ms");
            growth.Add(peak - before);
            Assert.True(peak - before <= 256L * 1024 * 1024);
        }
        Assert.True(growth[2] <= Math.Max(growth[0], growth[1]) + 32L * 1024 * 1024,
            $"coverage memory scales with job count: {string.Join(',', growth)}");
        Assert.Equal(2698890L, await Scalar(db, "select count(*) from semantic_processing_outbox", ct));
        Assert.Equal(true, await Scalar(db, "select decided_ids @> 1110::bigint and not decided_ids @> 1120::bigint from semantic_producer_coverage where runtime_mode='facts-v1'", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Producer_merges_adjacent_and_overlapping_batches_without_filling_gaps()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 331);
        await using var db = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(db, "set local role adlog_semantic_worker", ct);
        var session = new SemanticSession(db, tx);
        await SemanticProducer.RecordDecisions(session, [1, 3, 5, 7, 9], "facts-v1", ct);
        Assert.Equal(5L, await Scalar(db, "select count(*) from semantic_producer_coverage cross join lateral unnest(decided_ids)", ct));
        await SemanticProducer.RecordDecisions(session, [2, 4, 6, 8, 10], "facts-v1", ct);
        await SemanticProducer.RecordDecisions(session, [9, 10, 11, 11, 12, 14], "facts-v1", ct);
        Assert.Equal(2L, await Scalar(db, "select count(*) from semantic_producer_coverage cross join lateral unnest(decided_ids)", ct));
        Assert.Equal(true, await Scalar(db, "select decided_ids = '{[1,13),[14,15)}'::int8multirange from semantic_producer_coverage", ct));
        await tx.CommitAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 }; return await command.ExecuteScalarAsync(ct);
    }
}
