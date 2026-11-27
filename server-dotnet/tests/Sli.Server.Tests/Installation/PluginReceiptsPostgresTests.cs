using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Semantic;
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
        public Fixture(bool preview = false)
        {
            Connections = new(pg);
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
                { ["modules:preview"] = preview.ToString() }).Build();
            Service = new(new InstallationDatabase(Connections), new InstallationPackages(configuration), configuration);
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
                create table sli_agents(id integer, status text, assigned_modules jsonb, collection_policy jsonb,
                    file_audit jsonb, registration_host_name text);
                create table sli_agent_module_bindings(agent_id integer, module_id text);
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
    public async Task File_audit_state_combines_the_active_assignment_and_durable_receipt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(preview: true);
        await f.StartAsync(ct);
        await f.SqlAsync("""
            insert into sli_agents values
                (1, 'active', '[{"module_id":"sli.file-audit","enabled":true,"config":{"roots":[{}]}}]',
                 '{"interval_seconds":60}', '{}', 'file.example.test');
            create function read_plugin_states_v1() returns table(plugin_id text,enabled boolean)
                language sql as $$select 'sli.file-audit'::text,true$$;
            """, ct);
        async Task<JsonNode> ReadStatus()
        {
            var response = await f.Service.DispatchAsync("GET", "/api/v1/plugins", new(),
                new Principal("session", 1, "admin", "fixture"), null, true, ct);
            return Assert.Single(response["items"]!.AsArray())!["status"]!;
        }

        Assert.Equal("waiting", (await ReadStatus())["state"]!.ToString());
        await f.SqlAsync("""
            insert into sli_agent_receipts values ('fixture-packet','sli.file-audit',now()-interval '1 minute');
            insert into sli_agent_packet_inbox values ('fixture-packet',now()-interval '30 seconds');
            """, ct);
        var working = await ReadStatus();
        Assert.Equal("working", working["state"]!.ToString());
        Assert.NotNull(working["last_data_at"]);

        await f.SqlAsync("""
            update sli_agents set file_audit=jsonb_build_object('state','failed','reported_at',now());
            """, ct);
        var failure = await ReadStatus();
        Assert.Equal("error", failure["state"]!.ToString());
        Assert.Equal("file.example.test", failure["error_object"]!.ToString());
        Assert.NotNull(failure["error_at"]);
    }

    [Fact]
    public async Task Sigma_status_preserves_consumed_data_across_idle_heartbeats()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(preview: true);
        await f.StartAsync(ct);
        await f.SqlAsync("""
            create table semantic_risk_policies(policy_id text,policy_version integer,source_kind text,lifecycle_status text,definition_json jsonb);
            create table semantic_policy_admission(policy_id text,policy_version integer,enabled boolean);
            create function semantic_policy_mode_v160(text,integer,text) returns text language sql as $$select 'enabled'::text$$;
            create table runtime_worker_heartbeats(worker_name text primary key,worker_id text,process_pid integer,status text,phase text,
                expected_interval_seconds integer,started_at timestamptz,heartbeat_at timestamptz,updated_at timestamptz,details_json jsonb);
            create function read_plugin_states_v1() returns table(plugin_id text,enabled boolean)
                language sql as $$select 'sli.sigma'::text,true$$;
            """, ct);
        async Task<JsonNode> ReadStatus()
        {
            var response = await f.Service.DispatchAsync("GET", "/api/v1/plugins", new(),
                new Principal("session", 1, "admin", "fixture"), null, true, ct);
            return Assert.Single(response["items"]!.AsArray())!["status"]!;
        }
        Assert.Equal("no_sources", (await ReadStatus())["state"]!.ToString());
        await f.SqlAsync("""
            insert into semantic_risk_policies values ('fixture',1,'detection_match','active','{"source_selector":{"execution":{"scope":{}}}}');
            insert into semantic_policy_admission values ('fixture',1,true);
            """, ct);
        Assert.Equal("waiting", (await ReadStatus())["state"]!.ToString());

        await using var connection = await f.Connections.OpenAsync(ct);
        var worker = Guid.NewGuid();
        Task Pulse(string status, JsonNode? observation = null) => SemanticProduction.Heartbeat(connection, worker,
            SemanticRuntimeSettings.FindingsMode, status, 30, ct, observation is null ? null : new JsonObject { ["sigma"] = observation });
        string stamp = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        await Pulse("running", new JsonObject { ["last_data_at"] = stamp });
        await Pulse("running");
        var first = await ReadStatus();
        Assert.Equal("working", first["state"]!.ToString());
        Assert.Equal(stamp, first["last_data_at"]!.ToString());

        await Pulse("error", new JsonObject { ["failure_at"] = stamp });
        Assert.Equal("error", (await ReadStatus())["state"]!.ToString());
        await Pulse("idle", new JsonObject());
        var idle = await ReadStatus();
        Assert.Equal("working", idle["state"]!.ToString());
        Assert.Equal(stamp, idle["last_data_at"]!.ToString());
    }

    [Fact]
    public async Task PluginStateReturnsReceiptsAndAssignedSourcesFromPostgres()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var f = new Fixture(); await f.StartAsync(ct);
        await f.SqlAsync("""
            insert into sli_agent_receipts values ('runtime','sli.windows.ad-dc','2026-10-25');
            insert into sli_agents values
                (1, 'active', '[{"module_id":"sli.workstations","enabled":true}]',
                 '{"interval_seconds":60}', '{}', 'station.example.test');
            create function read_plugin_states_v1() returns table(plugin_id text,enabled boolean)
                language sql as $$values ('sli.ad'::text,true), ('sli.workstations'::text,true)$$;
            """, ct);

        var response = await f.Service.DispatchAsync("GET", "/api/v1/plugins", new JsonObject(),
            new Principal("session", 1, "admin", "synthetic"), null, false, ct);

        var items = response["items"]!.AsArray().OfType<JsonObject>().ToDictionary(item => (string)item["plugin_id"]!);
        var ad = items["sli.ad"];
        FactEquals(ad["data_receipts"]!.AsObject(), "observed", "2026-10-25T00:00:00+00:00");
        Assert.Equal("no_sources", (string?)ad["status"]!["state"]);

        var workstation = items["sli.workstations"];
        Assert.Equal("waiting", (string?)workstation["status"]!["state"]);
        Assert.Equal(1, (int?)workstation["source_count"]);
        Assert.Equal("station.example.test", (string?)Assert.Single(workstation["source_names"]!.AsArray()));
    }
}
