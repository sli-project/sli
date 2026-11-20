using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticEventIdIndexPostgresTests(ITestOutputHelper output)
{
    private static string Migration => Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/357_short_event_id_indexes.sql");

    [Fact]
    public async Task Five_thousand_absent_ids_do_not_rescan_hot_and_cold_storage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 356);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using (var version = new NpgsqlCommand("select current_setting('server_version_num')::int / 10000", owner))
            Assert.Equal(18, await version.ExecuteScalarAsync(ct));
        var native = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, [native[0]], ct);
        // Synthetic post-import rows on the real schema. Admission itself is
        // covered by ShortEventAdmissionPostgresTests; no trigger is disabled.
        await using (var seed = new NpgsqlCommand("""
            create temp table synthetic_event as select * from event_hot limit 1;
            delete from event_hot; delete from event_cold_facts;
            insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                select n,900001,c.id,n+1000000,date_trunc('day',t.time_created_utc)+n*interval '0.5 second',t.source_sha256
                from generate_series(1,101000) n cross join synthetic_event t
                join storage_v2_channel c on c.value='Security'
                where n>100000 or n%20<>0;
            insert into event_cold_facts(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256,event_record_id)
                select n,date_trunc('day',t.time_created_utc)+n*interval '0.5 second',t.event_kind,t.domain_id,t.computer,t.method,t.outcome,t.fields,t.source_sha256,n+1000000
                from generate_series(1,101000) n cross join synthetic_event t
                where (n<=100000 and n%20<>0) or n>100500;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
                select n,date_trunc('day',t.time_created_utc)+n*interval '0.5 second',t.event_kind,t.domain_id,t.computer,t.method,t.outcome,t.fields
                from generate_series(1,100500) n cross join synthetic_event t where n>100000 or n%20<>0;
            update event_hot h set method=t.method,source_sha256=t.source_sha256,event_record_id=h.event_id+1000000 from synthetic_event t;
            insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
                select @mode,@version,range_agg(int8range(n,n+1,'[)')) from generate_series(1::bigint,100000) n where n%20<>0;
            analyze event_hot; analyze event_cold_facts; analyze storage_v2_event_identity_allocations;
            """, owner) { CommandTimeout = 0 }) {
            seed.Parameters.AddWithValue("mode", SemanticRuntimeSettings.FindingsMode); seed.Parameters.AddWithValue("version", SemanticEvent.Version);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await using var worker = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_semantic_login")) { CommandTimeout = 0 }.ConnectionString);
        await worker.OpenAsync(ct); await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
        var before = await Measure(worker, ct);
        output.WriteLine($"Before 357: {before.Milliseconds:F3} ms, {before.Buffers} buffers, {before.RowsRead} table tuples read");
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        var after = await Measure(worker, ct);
        output.WriteLine($"After 357: {after.Milliseconds:F3} ms, {after.Buffers} buffers, {after.RowsRead} table tuples read");
        Assert.Equal(Enumerable.Range(100001, 1000).Select(n => (long)n), after.Ids);
        Assert.Equal(before.Ids, after.Ids);
        // Resource bounds, independent of machine speed and planner node names.
        Assert.InRange(after.Buffers, 1, 100000);
        Assert.InRange(after.RowsRead, 1, 50000);

        await using (var decisions = new NpgsqlCommand("""
            update semantic_producer_coverage set decided_ids=decided_ids+int8multirange(int8range(100001,101001,'[)'))
                where runtime_mode=@mode and processor_version=@version;
            insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
                select 20,900001,c.id,1000020,date_trunc('day',t.time_created_utc)+interval '10 seconds',t.source_sha256 from synthetic_event t join storage_v2_channel c on c.value='Security';
            insert into event_cold_facts(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256,event_record_id)
                select 20,date_trunc('day',time_created_utc)+interval '10 seconds',event_kind,domain_id,computer,method,outcome,fields,source_sha256,1000020 from synthetic_event;
            """, owner)) {
            decisions.Parameters.AddWithValue("mode", SemanticRuntimeSettings.FindingsMode); decisions.Parameters.AddWithValue("version", SemanticEvent.Version);
            await decisions.ExecuteNonQueryAsync(ct);
        }
        var late = await Measure(worker, ct);
        Assert.Equal(new long[] { 20 }, late.Ids);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task<(long[] Ids, long Buffers, long RowsRead, double Milliseconds)> Measure(NpgsqlConnection worker, CancellationToken ct)
    {
        await using var tx = await worker.BeginTransactionAsync(ct);
        await using var query = new NpgsqlCommand(SemanticProducerBackfill.SelectionSql, worker, tx) { CommandTimeout = 0 };
        query.Parameters.AddWithValue(SemanticRuntimeSettings.FindingsMode); query.Parameters.AddWithValue(SemanticEvent.Version); query.Parameters.AddWithValue(1000);
        var ids = new List<long>();
        await using (var reader = await query.ExecuteReaderAsync(ct)) while (await reader.ReadAsync(ct)) ids.Add(reader.GetInt64(0));
        query.CommandText = "explain (analyze,buffers,format json) " + SemanticProducerBackfill.SelectionSql;
        var explained = JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)![0]!;
        var plan = explained["Plan"]!;
        long buffers = plan["Shared Hit Blocks"]!.GetValue<long>() + plan["Shared Read Blocks"]!.GetValue<long>();
        // Transaction-local counters are synchronous: no sleeps, statistics
        // flush races, or assertions on EXPLAIN's loop/row implementation.
        await using var stats = new NpgsqlCommand("""
            select coalesce(sum(seq_tup_read+idx_tup_fetch),0)::bigint from pg_stat_xact_user_tables
            where relid in (select relid from pg_partition_tree('event_hot') union select relid from pg_partition_tree('event_cold_facts'))
            """, worker, tx);
        long rows = (long)(await stats.ExecuteScalarAsync(ct))!;
        await tx.CommitAsync(ct);
        return (ids.ToArray(), buffers, rows, explained["Execution Time"]!.GetValue<double>());
    }

    [Fact]
    public async Task Database_at_356_accepts_357_resumes_partial_build_and_indexes_new_storage_partitions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 356);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using (var version = new NpgsqlCommand("select max(version) from schema_migrations", owner))
            Assert.Equal(356, await version.ExecuteScalarAsync(ct));
        // A stopped online build has the parent plus some unattached leaves.
        await PostCollectionPostgres.Sql(owner, """
            set role adlog_storage_owner;
            create index event_hot_event_id357 on only event_hot(event_id);
            do $$ declare child record; begin
                select c.oid::regclass as tbl,c.relname into strict child
                    from pg_inherits t join pg_class c on c.oid=t.inhrelid
                    where t.inhparent='event_hot'::regclass order by c.oid limit 1;
                execute format('create index %I on %s(event_id)',child.relname||'_event_id357',child.tbl);
            end $$;
            reset role;
            """, ct);
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await AssertIndexed(owner, ct);
        await PostCollectionPostgres.Sql(owner, """
            set role adlog_storage_lifecycle_worker;
            select create_event_storage_partitions(current_date+400,current_date+401);
            reset role;
            set role adlog_storage_worker;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
                values(42,(current_date+400)::timestamp at time zone 'UTC',4720,1,'dc.example.test','{}','{}','{}');
            insert into event_cold_facts select * from event_hot where event_id=42;
            reset role;
            """, ct);
        await AssertIndexed(owner, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration, ".rollback.sql"), null, ct);
        await using (var preserved = new NpgsqlCommand("""
            select (select max(version) from schema_migrations)=356
                and to_regclass('public.event_hot_event_id357') is null
                and to_regclass('public.event_cold_facts_event_id357') is null
                and exists(select 1 from event_hot where event_id=42)
                and exists(select 1 from event_cold_facts where event_id=42)
            """, owner)) Assert.Equal(true, await preserved.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Migration, null, ct);
        await AssertIndexed(owner, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task AssertIndexed(NpgsqlConnection db, CancellationToken ct)
    {
        await using var check = new NpgsqlCommand("""
            select bool_and(i.indisvalid and i.indisready and c.relowner='adlog_storage_owner'::regrole)
                and not exists (
                    select 1 from pg_inherits t
                    where t.inhparent in ('event_hot'::regclass,'event_cold_facts'::regclass)
                      and not exists (
                        select 1 from pg_inherits a join pg_index leaf on leaf.indexrelid=a.inhrelid
                        where a.inhparent=case t.inhparent when 'event_hot'::regclass then 'event_hot_event_id357'::regclass
                            else 'event_cold_facts_event_id357'::regclass end
                          and leaf.indrelid=t.inhrelid and leaf.indisvalid and leaf.indisready))
            from pg_index i join pg_class c on c.oid=i.indexrelid
            where i.indexrelid in ('event_hot_event_id357'::regclass,'event_cold_facts_event_id357'::regclass)
            """, db);
        Assert.Equal(true, await check.ExecuteScalarAsync(ct));
    }
}
