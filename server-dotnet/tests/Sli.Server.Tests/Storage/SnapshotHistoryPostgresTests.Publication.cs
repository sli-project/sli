using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class SnapshotHistoryPostgresTests
{
    [Theory]
    [InlineData("true")]
    [InlineData("false")]
    public async Task Snapshot_publication_commits_when_ClickHouse_is_absent(string shortReads)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await LifecycleRolePostgresTests.SeedSnapshots(admin, ct);
        await using var worker = new NpgsqlConnection(fixture.Dsn("adlog_user")); await worker.OpenAsync(ct);
        var settings = new Dictionary<string,string?> { ["ADLOG_SNAPSHOT_HISTORY_DSN"] = fixture.Dsn("sli_storage_lifecycle_login") };
        var manifests = await AdJson.ReadAsync(admin, "select manifest_id::text from ad_snapshot_manifests order by slot_start_utc,manifest_id", ct);
        foreach (var manifest in manifests) {
            var result = await Sli.Server.Agents.SnapshotPublication.AdCoordinatorRetention.RunAsync(worker,
                Guid.Parse(manifest["manifest_id"]!.ToString()), settings.GetValueOrDefault, ct);
            Assert.Equal("executed", result["status"]!.ToString());
        }
        await using var query = new NpgsqlCommand("select count(*) from ad_snapshot_change_history where record_kind='history'", admin);
        Assert.True((long)(await query.ExecuteScalarAsync(ct))! > 0);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"), ["Sli:Storage:ShortEventReads"] = shortReads,
            ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:Storage:HistoryClickHousePort"] = "invalid"
        }).Build();
        var connections = new PostgresConnectionFactory(configuration);
        var store = new AdV2Store(connections, configuration);
        foreach (string key in new[] { "ad.users.v2", "ad.computers.v6" }) {
            var request = new AdV2Request(key,"view",null,[1],new(),"changes",null,false,50,null,"UTC");
            var result = await store.ReadAsync(request, _ => true, ct);
            Assert.NotEqual("error", result["state"]!.ToString());
            if (key == "ad.users.v2") Assert.NotEmpty(result["items"]!.AsArray());
        }
        foreach(string family in new[]{"users_v2","computers_v6"}) {
            var historyRequest=new AdV2Request(family=="users_v2"?"ad.users.v2":"ad.computers.v6","view",null,[1],
                AdJson.Obj(new {period=new {from_utc=DateTimeOffset.UtcNow.AddDays(-200).ToString("O"),to_utc=DateTimeOffset.UtcNow.AddDays(1).ToString("O")}}),"history",null,false,50,null,"UTC");
            var history=await AdSnapshotHistory.ReadAsync(worker,historyRequest,configuration,ct);
            Assert.NotEqual("error",history["state"]!.ToString());
            Assert.NotEmpty(history["collections"]!["changes"]!.AsArray());
        }
        var from = DateTimeOffset.UtcNow.AddDays(-200); var to = DateTimeOffset.UtcNow.AddDays(1);
        var gpo = await new GpoReadStore(connections, configuration).HistoryAsync([1],from,to,"",ct);
        Assert.NotEqual("unavailable",gpo["state"]!.ToString()); Assert.NotEmpty(gpo["items"]!.AsArray());
        await PostCollectionPostgres.Sql(admin,"update ad_snapshot_change_history set payload_json='{}' where record_kind='history' and family='gpo_v2'",ct);
        Assert.Equal("unavailable",(await new GpoReadStore(connections,configuration).HistoryAsync([1],from,to,"",ct))["state"]!.ToString());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

}
