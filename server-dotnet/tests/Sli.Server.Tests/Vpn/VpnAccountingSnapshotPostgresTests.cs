using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

[Collection("Semantic producer environment")]
public sealed class VpnAccountingSnapshotPostgresTests
{
    [Fact]
    public async Task Accepted_read_uses_one_snapshot_and_new_read_stops_after_plugin_is_disabled()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.InstallAsync(ct, throughVersion: 406);
        using var env = await VpnAccountingPostgresFixture.RegisterAsync(fixture, ct);
        var store = new PostgresVpnStore(new Connections(fixture.Dsn("adlog_user")));

        Assert.True(store.AccountingConfigured);
        Assert.Null(await store.OpenAccountingAsync(ct));
        await VpnAccountingPostgresFixture.SetEnabledAsync(fixture, true, ct);
        await using var accepted = await store.OpenAccountingAsync(ct);
        Assert.NotNull(accepted);
        await VpnAccountingPostgresFixture.SetEnabledAsync(fixture, false, ct);
        Assert.Null(await store.OpenAccountingAsync(ct));
        var snapshot = Assert.Single(await accepted.ReadAsync("""
            select enabled,current_setting('transaction_read_only') as read_only,
                current_setting('transaction_isolation') as isolation
            from read_plugin_states_v1() where plugin_id='sli.remote-access'
            """, [], ct));
        Assert.True(snapshot["enabled"]!.GetValue<bool>());
        Assert.Equal("on", snapshot["read_only"]!.GetValue<string>());
        Assert.Equal("repeatable read", snapshot["isolation"]!.GetValue<string>());
        Assert.NotEmpty(await accepted.ReadAsync(VpnSql.SessionDomains, [0L, 256], ct));
    }

    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn);
            await db.OpenAsync(ct);
            return db;
        }
    }
}
