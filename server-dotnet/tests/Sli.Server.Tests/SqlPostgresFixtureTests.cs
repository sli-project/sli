using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed class SqlPostgresFixtureTests
{
    [Fact]
    public async Task Current_schema_copies_isolate_data_and_roles_and_keep_worker_access()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var first = new SqlPostgresFixture();
        await using var second = new SqlPostgresFixture(maxConnections: 17);
        await Task.WhenAll(first.StartAsync(ct), second.StartAsync(ct));

        await using var firstDb = await first.Pg.OpenAsync(ct);
        await using var secondDb = await second.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(firstDb, """
            delete from auth_users where username='platform-owner';
            create role sli_fixture_only;
            """, ct);
        await using var check = new NpgsqlCommand("""
            select exists(select from auth_users where username='platform-owner'),
                   exists(select from pg_roles where rolname='sli_fixture_only'),
                   current_setting('max_connections')::int
            """, secondDb);
        await using var rows = await check.ExecuteReaderAsync(ct);
        Assert.True(await rows.ReadAsync(ct));
        Assert.True(rows.GetBoolean(0));
        Assert.False(rows.GetBoolean(1));
        Assert.Equal(17, rows.GetInt32(2));

        await using var worker = new NpgsqlConnection(second.Dsn("sli_storage_login"));
        await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_storage_worker", ct);
    }
}
