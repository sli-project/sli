using System.Diagnostics;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class SetupSourcesPostgresTests(ITestOutputHelper output)
{
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db;
        }
    }

    [Fact]
    public async Task Sources_load_latest_current_revision_without_scanning_retained_packet_payloads()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using (var seed = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules,
                policy_revision,applied_policy_revision,applied_collection_state,last_seen,collection_policy)
            values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011',repeat('a',64),
                'dc01.example.test','[{"module_id":"sli.windows.ad-dc","enabled":true,"config":{"policy_revision":2}}]',
                2,2,'active',now(),'{"state":"active","interval_seconds":60}');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            select '00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',n,md5('setup-source:'||n)::uuid,
                repeat('a',64),jsonb_build_object('policy_revision',case when n=30001 then '2' else '1' end),
                '{"status":"committed"}',now()-interval '1 hour'+n*interval '0.1 second'
            from generate_series(1,30001) n;
            """, db)) await seed.ExecuteNonQueryAsync(ct);
        // Batch writes keep stream-health trigger updates bounded in the disposable database.
        for (int first = 1; first <= 30001; first += 1000)
        {
            await using var inbox = new NpgsqlCommand("""
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
                select packet_id,envelope,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}',
                    '[]',received_at,received_at+interval '1 second'
                from sli_agent_receipts where sequence between @first and @last;
                """, db);
            inbox.Parameters.AddWithValue("first", first); inbox.Parameters.AddWithValue("last", first + 999);
            await inbox.ExecuteNonQueryAsync(ct);
        }
        await PostCollectionPostgres.Sql(db, "analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze sli_agent_stream_receipts", ct);
        var watch = Stopwatch.StartNew();
        var health = await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))), ct);
        output.WriteLine("Sources: {0:F1} ms", watch.Elapsed.TotalMilliseconds);
        Assert.Null(health["diagnostics"]); Assert.NotEqual("unavailable", (string?)health["state"]);
        var source = Assert.Single(health["items"]!.AsArray())!;
        Assert.Equal("dc01.example.test", (string?)source["name"]);
        var channels = source["modules"]![0]!["channels"]!.AsArray();
        var security = Assert.Single(channels, c => (string?)c?["channel"] == "Security")!;
        Assert.NotNull(security["last_packet_at"]); Assert.NotNull(security["last_import_at"]);
        Assert.All(channels.Where(c => (string?)c?["channel"] != "Security"), c => Assert.Null(c!["last_packet_at"]));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}

