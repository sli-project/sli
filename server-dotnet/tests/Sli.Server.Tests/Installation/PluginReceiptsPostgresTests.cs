using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

// Vectors from tests/reporting/test_plugin_receipts_postgres.py. Each test owns
// a native PostgreSQL cluster; the production reader binds and executes its SQL.
public sealed class PluginReceiptsPostgresTests
{
    sealed class Connections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public int Opens;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Opens++;
            return pg.OpenAsync(ct);
        }
    }

    sealed class Fixture : IAsyncDisposable
    {
        readonly PostCollectionPostgres pg = new(canonicalSchema: true);
        public readonly Connections Connections;
        public readonly InstallationService Service;
        public Fixture()
        {
            Connections = new(pg);
            Service = new(new InstallationDatabase(Connections), new InstallationPackages(new ConfigurationBuilder().Build()));
        }
        public async Task StartAsync(CancellationToken ct)
        {
            await pg.StartAsync(ct);
            await SqlAsync("""
                create table sli_agent_receipts(
                    packet_id text primary key,module_id text not null,received_at timestamptz not null);
                create table sli_agent_packet_inbox(packet_id text primary key,imported_at timestamptz);
                create table sli_agent_snapshot_cycles(module_id text not null,
                    transport_state text,completed_at timestamptz,publication_state text,published_at timestamptz);
                """, ct);
        }
        public async Task SqlAsync(string sql, CancellationToken ct)
        {
            await using var db = await pg.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db, sql, ct);
        }
        public ValueTask DisposeAsync() => pg.DisposeAsync();
    }

    static void FactEquals(JsonObject actual, string state, string? received = null, string? imported = null, string? completed = null)
    {
        var expected = new JsonObject {
            ["state"] = state, ["last_received_at"] = received,
            ["last_imported_at"] = imported, ["last_snapshot_completed_at"] = completed };
        Assert.True(JsonNode.DeepEquals(expected, actual), actual.ToJsonString());
    }

    [Fact]
    public async Task TransportImportAndSnapshotPublicationRemainSeparate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(); await f.StartAsync(ct);
        await f.SqlAsync("""
            insert into sli_agent_receipts values
                ('ad-old','sli.windows.ad-dc','2026-01-01'),
                ('ad-pending','sli.windows.ad-dc','2026-01-03'),
                ('ad-history','sli.windows.ad-dc-history','2026-01-04'),
                ('snapshot-chunk','sli.ad-snapshot','2026-01-05'),
                ('gpo-chunk','sli.gpo-snapshot','2026-01-06'),
                ('nps','sli.vpn-nps','2026-01-07'),
                ('other','unknown','2026-12-01');
            insert into sli_agent_packet_inbox values
                ('ad-old','2026-01-02'),('ad-pending',null),('ad-history',null),
                ('snapshot-chunk','2026-01-30');
            insert into sli_agent_snapshot_cycles values
                ('sli.ad-snapshot','complete','2026-01-05','pending',null),
                ('sli.gpo-snapshot','complete','2026-01-06','published','2026-01-08'),
                ('sli.gpo-snapshot','pending',null,'pending',null);
            """, ct);

        var facts = await f.Service.ReceiptsAsync(["sli.ad", "sli.gpo", "sli.remote-access", "sli.sigma", "sli.file-audit"], ct);

        Assert.Equal(5, facts.Count);
        FactEquals(facts["sli.ad"], "observed", "2026-01-05T00:00:00+00:00", "2026-01-02T00:00:00+00:00", "2026-01-05T00:00:00+00:00");
        FactEquals(facts["sli.gpo"], "observed", "2026-01-06T00:00:00+00:00", "2026-01-08T00:00:00+00:00", "2026-01-06T00:00:00+00:00");
        FactEquals(facts["sli.remote-access"], "observed", "2026-01-07T00:00:00+00:00");
        FactEquals(facts["sli.sigma"], "not_supported");
        FactEquals(facts["sli.file-audit"], "no_receipts");
        Assert.Equal(1, f.Connections.Opens);
    }

    [Fact]
    public async Task EmptyRuntimeReceiptsAreNotUnavailable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(); await f.StartAsync(ct);

        var facts = await f.Service.ReceiptsAsync(["sli.ad"], ct);

        FactEquals(facts["sli.ad"], "no_receipts");
        Assert.Equal(1, f.Connections.Opens);
    }

    [Fact]
    public async Task PluginStateUsesTheRealDatabaseReaderAndArrayBindings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(); await f.StartAsync(ct);
        await f.SqlAsync("""
            insert into sli_agent_receipts values ('runtime','sli.windows.ad-dc','2026-10-25');
            create function read_plugin_states_v1() returns table(plugin_id text)
                language sql as $$select 'sli.ad'::text$$;
            """, ct);

        var response = await f.Service.DispatchAsync("GET", "/api/v1/plugins", new JsonObject(),
            new Principal("session", 1, "admin", "synthetic"), null, false, ct);

        var item = Assert.Single(response["items"]!.AsArray())!;
        Assert.Equal("sli.ad", (string?)item["plugin_id"]);
        FactEquals(item["data_receipts"]!.AsObject(), "observed", "2026-10-25T00:00:00+00:00");
        Assert.Equal(2, f.Connections.Opens);
    }
}
