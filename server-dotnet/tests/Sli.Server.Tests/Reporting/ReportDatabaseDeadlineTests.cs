using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportDatabaseDeadlineTests
{
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db, "set statement_timeout='1s'; set lock_timeout='1s'", ct);
            return db;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reports_clear_inherited_deadlines_and_preserve_transaction_mode(bool write)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(ct);
        var reports = new ReportDatabase(new Connections(pg.ConnectionString));
        await using var session = await reports.OpenAsync(write, ct);
        var row = Assert.Single(await session.QueryAsync("""
            select current_setting('statement_timeout') as statement_limit,
                current_setting('lock_timeout') as lock_limit,current_setting('transaction_read_only') as read_only
            """, [], ct));
        Assert.Equal("0", row["statement_limit"]!.ToString());
        Assert.Equal("0", row["lock_limit"]!.ToString());
        Assert.Equal(write ? "off" : "on", row["read_only"]!.ToString());
        await session.CommitAsync(ct);
    }
}
