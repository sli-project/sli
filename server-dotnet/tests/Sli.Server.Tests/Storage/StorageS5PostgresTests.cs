using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageS5PostgresTests
{
    [Fact]
    public async Task Predecessor_accepts_retention_and_only_complete_expired_partitions_are_removed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion:340);
        string migration = Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/342_short_storage_retention.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            set timezone='Asia/Bangkok';
            select create_event_storage_partitions('2025-01-31','2025-02-01');
            select create_ad_snapshot_change_partition('2025-01-31 23:59:59+00');
            select create_ad_snapshot_change_partition('2025-02-01 00:00:00+00');
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
            values(1,'2025-01-31 23:59:59+00',4720,1,'dc01.example.test','{}','{}','{}'),
                  (2,'2025-02-01 00:00:00+00',4720,1,'dc01.example.test','{}','{}','{}');
            insert into event_cold_facts select * from event_hot where event_id in (1,2);
            set role adlog_storage_lifecycle_delete;
            select * from expire_short_storage_partitions342('2025-02-01 00:00:00+00','2025-02-01 00:00:00+00','2025-02-01 00:00:00+00');
            reset role;
            """,ct);
        await using (var count = new NpgsqlCommand("select count(*),min(event_id) from event_hot where event_id in (1,2)",db)) {
            await using var r = await count.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(1L,r.GetInt64(0)); Assert.Equal(2L,r.GetInt64(1));
        }
        await using (var query = new NpgsqlCommand("""
            select (select count(*) from event_cold_facts where event_id in (1,2))=1,
                   to_regclass('ad_snapshot_change_history_m202501') is null,
                   to_regclass('ad_snapshot_change_history_m202502') is not null,
                   to_regclass('events_v2_core') is not null,
                   not has_function_privilege('adlog_user','expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)','EXECUTE'),
                   not has_function_privilege('adlog_storage_lifecycle_worker','expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)','EXECUTE'),
                   not has_table_privilege('adlog_user','ad_snapshot_change_history','INSERT,UPDATE,DELETE')
            """,db)) {
            await using var r = await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            for (int i=0;i<r.FieldCount;i++) Assert.True(r.GetBoolean(i));
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using (var query = new NpgsqlCommand("select to_regprocedure('expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)') is null",db))
            Assert.Equal(true,await query.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
