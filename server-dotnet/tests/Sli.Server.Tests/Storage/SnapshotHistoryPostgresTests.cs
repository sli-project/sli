using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class SnapshotHistoryPostgresTests
{
    [Fact]
    public async Task Predecessor_accepts_history_migration_monthly_partitions_role_reads_and_rollback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 337);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/338_ad_snapshot_change_storage.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(db, """
            set timezone='Asia/Bangkok';
            set role adlog_storage_lifecycle_worker;
            select create_ad_snapshot_change_partition('2026-12-31 23:59:59+00');
            select create_ad_snapshot_change_partition('2027-01-01 00:00:00+00');
            select create_ad_snapshot_change_partition('2027-01-01 00:00:00+00');
            insert into ad_snapshot_change_history(observed_at,record_id,batch_id,manifest_id,domain_id,family,payload_json)
            values('2026-12-31 23:59:59+00',repeat('a',64),repeat('b',64),gen_random_uuid(),1,'users_v2','{}'),
                  ('2027-01-01 00:00:00+00',repeat('c',64),repeat('d',64),gen_random_uuid(),1,'gpo_v2','{}');
            reset role;
            set role adlog_user;
            """, ct);
        await using (var query = new NpgsqlCommand("select tableoid::regclass::text from ad_snapshot_change_history order by observed_at", db)) {
            await using var reader = await query.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("ad_snapshot_change_history_m202612", reader.GetString(0));
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("ad_snapshot_change_history_m202701", reader.GetString(0));
        }
        await using (var query = new NpgsqlCommand("""
            select has_table_privilege('adlog_user','ad_snapshot_change_history','SELECT'),
                   has_table_privilege('adlog_user','ad_snapshot_change_history','INSERT,UPDATE,DELETE'),
                   has_function_privilege('adlog_storage_lifecycle_worker','expire_ad_snapshot_change_partitions(timestamptz)','EXECUTE'),
                   has_function_privilege('adlog_user','create_ad_snapshot_change_partition(timestamptz)','EXECUTE')
            """, db)) {
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetBoolean(0)); Assert.False(reader.GetBoolean(1)); Assert.False(reader.GetBoolean(2)); Assert.False(reader.GetBoolean(3));
        }
        await PostCollectionPostgres.Sql(db, """
            reset role; set role adlog_storage_lifecycle_delete;
            select expire_ad_snapshot_change_partitions('2027-01-01 00:00:00+00');
            reset role; set role adlog_user;
            """, ct);
        await using (var query = new NpgsqlCommand("select count(*),min(tableoid::regclass::text) from ad_snapshot_change_history", db)) {
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(1L, reader.GetInt64(0)); Assert.Equal("ad_snapshot_change_history_m202701", reader.GetString(1));
        }
        await PostCollectionPostgres.Sql(db, "reset role;", ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using (var query = new NpgsqlCommand("""
            select to_regclass('public.ad_snapshot_change_history') is null,
                   to_regprocedure('public.create_ad_snapshot_change_partition(timestamptz)') is null,
                   to_regprocedure('public.expire_ad_snapshot_change_partitions(timestamptz)') is null,
                   not exists(select 1 from schema_migrations where version=338),
                   exists(select 1 from schema_migrations where version=336)
            """, db)) {
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            for (int i = 0; i < reader.FieldCount; i++) Assert.True(reader.GetBoolean(i));
        }
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
