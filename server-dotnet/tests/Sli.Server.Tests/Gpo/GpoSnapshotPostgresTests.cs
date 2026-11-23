using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Gpo;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

public sealed class GpoSnapshotPostgresTests
{
    [Fact]
    public async Task Reader_returns_only_complete_policy_snapshots_from_the_authorized_domain()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into domains(id, forest_id, fqdn)
            select id + 20, forest_id, 'another.example.test' from domains where fqdn='example.test';
            """, ct);
        await using var domainQuery = new NpgsqlCommand("select id from domains where fqdn='example.test'", db);
        long domain = (long)(await domainQuery.ExecuteScalarAsync(ct))!;
        Guid first = await PublishAsync(domain, 1, "900");
        Guid second = await PublishAsync(domain, 2, "900");
        Guid third = await PublishAsync(domain, 3, "600");
        Guid fourth = await PublishAsync(domain, 4, "600", collection: "partial");
        Guid foreign = await PublishAsync(domain + 20, 5, "1200");
        Guid failed = await PublishAsync(domain, 6, "500", collection: "failed");
        Guid unavailable = await PublishAsync(domain, 7, "400", report: "partial");
        Guid otherPolicy = await PublishAsync(domain, 8, "300", policy: "another-policy");

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
        }).Build();
        var store = new GpoReadStore(new PostgresConnectionFactory(config), config);
        var choices = await store.PolicySnapshotsAsync(domain, "synthetic-policy", null, ct);
        Assert.Equal(new[] { fourth, third, second, first }, choices.Select(snapshot => snapshot.Id));
        Assert.All(choices, snapshot => Assert.Null(snapshot.Payload));

        var request = new GpoRequest("all", "", "gpos", null, "asc", 500, null, "UTC", DateTimeOffset.UtcNow.AddDays(-7), DateTimeOffset.UtcNow)
        {
            DomainId = domain, PolicyId = "synthetic-policy", ComparePolicySnapshots = (first, third),
        };
        var result = await GpoSnapshotComparison.QueryAsync(store, request, ct);
        var change = Assert.Single(result["collections"].Rows("snapshot_comparison"));
        Assert.Equal(("changed", "900", "600"), (change.Text("kind"), change.Text("before_value"), change.Text("after_value")));
        var equal = await GpoSnapshotComparison.QueryAsync(store, request with { ComparePolicySnapshots = (second, first) }, ct);
        Assert.Empty(Assert.IsType<JsonArray>(equal["collections"]!["snapshot_comparison"]));
        foreach (Guid excluded in new[] { foreign, failed, unavailable, otherPolicy })
        {
            var denied = await GpoSnapshotComparison.QueryAsync(store, request with { ComparePolicySnapshots = (first, excluded) }, ct);
            Assert.Equal("unavailable", denied["coverage"].Text("snapshot_comparison_state"));
            Assert.Null(denied["collections"]!["snapshot_comparison"]);
        }

        Task<Guid> PublishAsync(long target, int day, string value, string collection = "complete", string report = "observed",
            string policy = "synthetic-policy") => PublishVersionAsync(db, target, day, value, ct, collection, report, policy);
    }

    [Fact]
    public async Task Exact_detail_from_real_inventory_keeps_the_first_version_and_its_scope_after_new_publication()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using var domainQuery = new NpgsqlCommand("select id from domains where fqdn='example.test'", db);
        long domain = (long)(await domainQuery.ExecuteScalarAsync(ct))!;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
        }).Build();
        var store = new GpoReadStore(new PostgresConnectionFactory(config), config);
        using var host = await GpoEndpointTests.Host(store, scope: JsonSerializer.Serialize(new { kind = "domain", ids = new[] { domain } }));
        using var client = host.GetTestClient();
        string inventory = $"/api/v2/reports/ad.gpo.v2/data?tab=gpos&view=all&domain={domain}";
        Guid first = await PublishVersionAsync(db, domain, 1, "600", ct, version: 7, scopeName: "First scope", size: 1);
        var list = JsonNode.Parse(await client.GetStringAsync(inventory, ct))!;
        Assert.Equal(first.ToString("D"), list["coverage"].Text("snapshot_id"));

        Guid second = await PublishVersionAsync(db, domain, 2, "900", ct, version: 12, scopeName: "Second scope", size: 1);
        var refreshed = JsonNode.Parse(await client.GetStringAsync(inventory, ct))!;
        Assert.Equal(second.ToString("D"), refreshed["coverage"].Text("snapshot_id"));

        string detail = inventory + "&policy_id=synthetic-policy&snapshot=";
        var pinned = JsonNode.Parse(await client.GetStringAsync(detail + first, ct))!;
        Assert.Equal(first.ToString("D"), pinned["coverage"].Text("snapshot_id"));
        Assert.Equal(list["coverage"].Text("observed_at_utc"), pinned["coverage"].Text("observed_at_utc"));
        Assert.Equal("600", Assert.Single(pinned["collections"].Rows("settings")).Text("value_display"));
        Assert.Equal("First scope", Assert.Single(pinned["collections"].Rows("links")).Text("scope_name"));
        Assert.Equal(7, Assert.Single(pinned["collections"].Rows("versions")).Number("computer_directory_version"));
        using var denied = await client.GetAsync(detail.Replace($"domain={domain}", $"domain={domain + 20}") + first, ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        await using var expire = new NpgsqlCommand("""
            delete from public.gpo_report_v2_source_snapshots where domain_id=@domain and source_run_id=@snapshot
            """, db);
        expire.Parameters.AddWithValue("domain", domain);
        expire.Parameters.AddWithValue("snapshot", first);
        Assert.Equal(1, await expire.ExecuteNonQueryAsync(ct));
        using var expired = await client.GetAsync(detail + first, ct);
        Assert.Equal(HttpStatusCode.NotFound, expired.StatusCode);
        Assert.DoesNotContain("Second scope", await expired.Content.ReadAsStringAsync(ct));
    }

    private static async Task<Guid> PublishVersionAsync(NpgsqlConnection db, long target, int day, string value, CancellationToken ct,
        string collection = "complete", string report = "observed", string policy = "synthetic-policy",
        int version = 1, string? scopeName = null, int size = 230)
    {
            string stamp = $"2026-10-{day:D2}T12:00:00Z";
            var snapshot = JsonNode.Parse("""
                {"schema_version":"sli.ad-gpo.snapshot/1.0","collector_version":"synthetic-gpo","demo":false,
                 "domain":{},"scope":{},"source_states":{
                   "gpo_list":{"status":"observed"},"gpo_reports":{"status":"observed"},"gpc_directory":{"status":"observed"},
                   "sysvol_gpt":{"status":"observed"},"links":{"status":"observed"},"permissions":{"status":"observed"},"wmi_filters":{"status":"observed"}},
                 "gpos":[{"id":"synthetic-policy","guid":"10000000-0000-0000-0000-000000000001","display_name":"Synthetic policy",
                          "source_states":{"report":{"status":"observed"}}}],
                 "settings":[{"id":"setting","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"System/Timeout","setting_name":"Timeout"}],
                 "scopes":[],"links":[],"permissions":[],"wmi_filters":[],"unresolved_links":[],"collection_errors":[]}
                """)!.AsObject();
            snapshot["started_at"] = stamp;
            snapshot["completed_at"] = stamp;
            snapshot["observed_at"] = stamp;
            snapshot["collection_status"] = collection;
            snapshot["gpos"]![0]!["id"] = policy;
            snapshot["gpos"]![0]!["source_states"]!["report"]!["status"] = report;
            snapshot["settings"]![0]!["gpo_id"] = policy;
            snapshot["settings"]![0]!["id"] = "setting-" + value;
            snapshot["settings"]![0]!["value_display"] = value;
            snapshot["gpos"]![0]!["computer"] = new JsonObject { ["directory_version"] = version, ["sysvol_version"] = version };
            if (scopeName is not null)
            {
                snapshot["scopes"]!.AsArray().Add(new JsonObject { ["id"] = "scope", ["name"] = scopeName });
                snapshot["links"]!.AsArray().Add(new JsonObject
                {
                    ["id"] = "link", ["scope_id"] = "scope", ["scope_name"] = scopeName, ["gpo_id"] = policy,
                    ["raw_options"] = 0, ["enabled"] = true, ["enforced"] = false,
                });
                snapshot["gpos"]![0]!["link_ids"] = new JsonArray("link");
            }
            for (int i = 1; i < size; i++)
            {
                snapshot["settings"]!.AsArray().Add(new JsonObject
                {
                    ["id"] = $"synthetic-setting-{i}", ["gpo_id"] = policy, ["side"] = "computer",
                    ["extension"] = "security", ["path"] = $"System/Setting-{i}", ["setting_name"] = $"Setting {i}",
                    ["value_display"] = "Enabled",
                });
            }
            Guid id = Guid.NewGuid();
            await using var tx = await db.BeginTransactionAsync(ct);
            await GpoSnapshotStore.StoreAndVerifyAsync(db, tx, target, id, snapshot, insert: true, ct);
            await tx.CommitAsync(ct);
            return id;
    }
}
