using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageS2PostgresTests
{
    [Fact]
    public async Task Database_at_334_accepts_335_and_rollback_preserves_old_events()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 334);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await WorkerSqlPostgresTests.SeedAsync(db, ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/335_event_storage_s2.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(db, """
            set timezone='Asia/Bangkok';
            set role adlog_storage_lifecycle_worker;
            select create_event_storage_partitions('2026-12-31','2027-01-02');
            select create_event_storage_partitions('2026-12-31','2027-01-02');
            reset role;
            set role adlog_storage_worker;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
            values(1,'2026-12-31 23:59:59+00',4720,1,'dc01.example.test','{}','{}','{}'),
                  (2,'2027-01-01 00:00:00+00',4720,1,'dc01.example.test','{}','{}','{}');
            insert into event_cold_facts select * from event_hot;
            reset role;
            """, ct);
        await using (var query = new NpgsqlCommand("""
            select tableoid::regclass::text from event_hot order by event_id;
            select tableoid::regclass::text from event_cold_facts order by event_id;
            select has_table_privilege('adlog_storage_worker','event_hot','INSERT'),
                   has_table_privilege('adlog_user','event_hot','INSERT'),
                   has_function_privilege('adlog_storage_lifecycle_worker','create_event_storage_partitions(date,date)','EXECUTE'),
                   has_function_privilege('adlog_user','create_event_storage_partitions(date,date)','EXECUTE');
            """, db)) {
            await using var reader = await query.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("event_hot_d20261231", reader.GetString(0));
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("event_hot_d20270101", reader.GetString(0));
            Assert.True(await reader.NextResultAsync(ct));
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("event_cold_facts_m202612", reader.GetString(0));
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("event_cold_facts_m202701", reader.GetString(0));
            Assert.True(await reader.NextResultAsync(ct)); Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetBoolean(0)); Assert.False(reader.GetBoolean(1));
            Assert.True(reader.GetBoolean(2)); Assert.False(reader.GetBoolean(3));
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using (var query = new NpgsqlCommand("""
            select not exists(select 1 from schema_migrations where version=335),
                   to_regclass('public.event_hot') is null, to_regclass('public.event_cold_facts') is null,
                   to_regclass('public.event_cold_daily') is null,
                   to_regprocedure('public.create_event_storage_partitions(date,date)') is null,
                   exists(select 1 from events_v2_core where id=1);
            """, db)) {
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            for (int i = 0; i < reader.FieldCount; i++) Assert.True(reader.GetBoolean(i));
        }
        // A retry after rollback follows the same clean upgrade path.
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Database_at_335_accepts_336_application_role_reads_but_cannot_write_and_rollback_revokes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 335);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/336_event_storage_read_grants.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(db, """
            set role adlog_storage_worker;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
            values(1,now(),4720,1,'dc01.example.test','{}','{}','{}');
            insert into event_cold_facts select * from event_hot;
            reset role;
            set role adlog_storage_lifecycle_worker;
            select create_event_storage_partitions(current_date+60,current_date+61);
            reset role;
            """, ct);
        // A partition created after 336 is readable through its parent without a grant of its own.
        await PostCollectionPostgres.Sql(db, """
            set role adlog_storage_worker;
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
            values(2,now()+interval '60 days',4720,1,'dc01.example.test','{}','{}','{}');
            reset role;
            """, ct);
        await PostCollectionPostgres.Sql(db, "set role adlog_user;", ct);
        await using (var read = new NpgsqlCommand("""
            select (select count(*) from event_hot), (select count(*) from event_cold_facts), (select count(*) from event_cold_daily);
            """, db)) {
            await using var reader = await read.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(2L, reader.GetInt64(0)); Assert.Equal(1L, reader.GetInt64(1)); Assert.Equal(0L, reader.GetInt64(2));
        }
        foreach (var table in new[] { "event_hot", "event_cold_facts", "event_cold_daily" }) {
            await PostCollectionPostgres.Sql(db, "reset role; set role adlog_user;", ct);
            await using var check = new NpgsqlCommand($"""
                select has_table_privilege('adlog_user','{table}','SELECT'), has_table_privilege('adlog_user','{table}','INSERT'),
                       has_table_privilege('adlog_user','{table}','UPDATE'), has_table_privilege('adlog_user','{table}','DELETE')
                """, db);
            await using var r = await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.True(r.GetBoolean(0)); Assert.False(r.GetBoolean(1)); Assert.False(r.GetBoolean(2)); Assert.False(r.GetBoolean(3));
        }
        var denied = await Assert.ThrowsAsync<PostgresException>(async () => {
            await using var insert = new NpgsqlCommand("insert into event_hot select * from event_hot", db);
            await insert.ExecuteNonQueryAsync(ct);
        });
        Assert.Equal("42501", denied.SqlState);
        await PostCollectionPostgres.Sql(db, "reset role;", ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using (var query = new NpgsqlCommand("""
            select not exists(select 1 from schema_migrations where version=336),
                   not has_table_privilege('adlog_user','event_hot','SELECT'),
                   not has_table_privilege('adlog_user','event_cold_facts','SELECT'),
                   not has_table_privilege('adlog_user','event_cold_daily','SELECT'),
                   exists(select 1 from schema_migrations where version=335);
            """, db)) {
            await using var reader = await query.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            for (int i = 0; i < reader.FieldCount; i++) Assert.True(reader.GetBoolean(i));
        }
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        // The denied insert above is expected to be logged as an SQL error, so the log is not asserted clean.
    }
}
