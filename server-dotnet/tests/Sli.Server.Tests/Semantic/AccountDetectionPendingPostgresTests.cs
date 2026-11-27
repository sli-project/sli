using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class AccountDetectionPendingPostgresTests
{
    [Fact]
    public async Task Upgrade_discards_old_queue_and_committed_cycles_drain_one_hundred_thousand_events()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 451);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var at = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        var initial = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4624], occurredAt: at);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, initial, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(_ => null),
            SemanticRuntimeSettings.FindingsMode, 32);
        var (before, sources) = await production.ProcessDefaultDetections(worker, ct);
        Assert.Equal(0, before.Number("failed"));
        var source = Assert.Single(sources)!["source"]!;

        // Copy an attested row inside the isolated fixture for scale. New
        // arrivals below exercise the normal storage writer.
        string partition = $"event_hot_d{at:yyyyMMdd}";
        await using (var seed = new NpgsqlCommand($"""
            alter table {partition} disable trigger attest_short_event337;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
            select 2000000+g,h.time_created_utc+g*interval '1 millisecond',h.event_kind,
                h.domain_id,h.computer,h.method,h.outcome,h.fields,sha256(int8send(g))
            from event_hot h cross join generate_series(1::bigint,99999) g where h.event_id=900001;
            alter table {partition} enable trigger attest_short_event337;
            analyze event_hot;
            """, owner) { CommandTimeout = 0 })
            await seed.ExecuteNonQueryAsync(ct);
        Assert.Equal(199998L, await Pending());
        const string migration = "config/postgres_migrations/455_account_detection_pending.sql";
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), migration), null, ct);
        Assert.Equal(0L, await Pending());

        // A rollback must undo the seed cursor and acknowledgments together.
        await using (var attempt = await worker.BeginTransactionAsync(ct))
        {
            await SemanticProduction.RunDefaultSource(new SemanticSession(worker, attempt), source, ct);
            await attempt.RollbackAsync(ct);
        }
        Assert.Equal(1L, await Count("semantic_account_decoy_checks"));
        Assert.Equal(1L, await Count("semantic_account_watch_checks"));
        var (drained, _) = await production.ProcessDefaultDetections(worker, ct);
        Assert.Equal(0, drained.Number("failed"));
        Assert.Equal(100000L, await Count("semantic_account_decoy_checks"));
        Assert.Equal(100000L, await Count("semantic_account_watch_checks"));
        Assert.Equal(0L, await Pending());

        // A one-shot account read leaves no subscription behind.
        var scope = source["scope"]!.AsObject();
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(worker, tx);
            var replay = await session.QueryAsync("""
                select * from public.read_account_decoy_events($1,$2,$3,$4,$5,null::uuid)
                """, ct, Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"),
                scope.Text("source_instance_id"), scope.Text("source_generation"), new string('c', 64));
            Assert.Equal(128, replay.Count);
            await tx.CommitAsync(ct);
        }
        var agent = ShortEventAdmissionPostgresTests.Agent;
        var late = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4624, 1102],
            occurredAt: at.AddHours(-1), registered: (agent, agent, 900001, 1),
            packetId: Guid.Parse("00000000-0000-4000-8000-000000000455"), sequence: 2, firstRecordId: 2);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, late, ct);
        Assert.Equal(2L, await Pending());
        var (caughtUp, _) = await production.ProcessDefaultDetections(worker, ct);
        Assert.Equal(0, caughtUp.Number("failed"));
        Assert.Equal(100001L, await Count("semantic_account_decoy_checks"));
        Assert.Equal(100001L, await Count("semantic_account_watch_checks"));
        Assert.Equal(0L, await Pending());
        await fixture.AssertNoSqlErrorsAsync(ct);

        Task<long> Pending() => Count("account_detection_pending451");
        async Task<long> Count(string table)
        {
            await using var query = new NpgsqlCommand($"select count(*) from public.{table}", owner);
            return (long)(await query.ExecuteScalarAsync(ct))!;
        }
    }

    [Fact]
    public async Task Lifecycle_reclaims_pending_rows_and_both_indexes_when_hot_partition_expires()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var at = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(12));
        var initial = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4624], occurredAt: at);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, initial, ct);
        await using var semantic = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using (var worker = await semantic.OpenAsync(ct))
        await using (var tx = await worker.BeginTransactionAsync(ct))
        {
            var session = new SemanticSession(worker, tx);
            JsonNode scope = (await session.QueryAsync("select source from public.default_detection_sources()", ct)).Single()!["source"]!["scope"]!;
            await session.QueryAsync("select public.subscribe_account_checkpoint455($1,$2,$3::jsonb)",
                ct, "decoy", new string('d', 64), scope);
            await tx.CommitAsync(ct);
        }
        await using var indexes = new NpgsqlCommand("""
            select array_agg(ix.inhrelid order by ix.inhrelid)
            from pg_inherits ix join pg_index i on i.indexrelid=ix.inhrelid
            where ix.inhparent in ('public.event_hot_detection_scope451'::regclass,'public.event_hot_detection_witness451'::regclass)
              and i.indrelid=to_regclass(@partition)
            """, owner);
        indexes.Parameters.AddWithValue("partition", $"public.event_hot_d{at:yyyyMMdd}");
        var oldIndexes = (uint[])(await indexes.ExecuteScalarAsync(ct))!;
        Assert.Equal(2, oldIndexes.Length);
        await using var config = new LifecycleRuntime(name => name switch {
            "ADLOG_PG_DSN" => fixture.Dsn("sli_storage_lifecycle_login"),
            "ADLOG_STORAGE_LIFECYCLE_DELETE_DSN" => fixture.Dsn("sli_storage_lifecycle_delete_login"),
            "Sli:Storage:HotRetentionDays" => "1",
            _ => null
        }, new LifecycleFiles(fixture.Pg.Root));
        Assert.True(await config.TryLockAsync(StorageLifecycleWorker.LockName, ct));
        var result = await config.ExpirePartitionsAsync(DateTime.UtcNow.Date.AddDays(1), 1, ct);
        Assert.Equal(1L, LifecycleJson.Number(result, "account_detection_pending_deleted"));
        await using var cleanup = new NpgsqlCommand("""
            select not exists(select 1 from public.account_detection_pending451)
               and not exists(select 1 from pg_class where oid=any(@indexes))
            """, owner);
        cleanup.Parameters.AddWithValue("indexes", NpgsqlDbType.Array | NpgsqlDbType.Oid, oldIndexes);
        Assert.True((bool)(await cleanup.ExecuteScalarAsync(ct))!);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
