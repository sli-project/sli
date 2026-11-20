using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Xunit;
using static Sli.Server.Ad.AdJson;
using static Sli.Server.Tests.Ad.NewLogonPairsNativeFixture;

namespace Sli.Server.Tests.Ad;

public sealed class NewLogonPairsNativeFixtureTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Observed = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Empty_migrated_installation_reuses_domain_and_seeds_complete_context()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        var before = await ReadAsync(db, "select id,forest_id,fqdn from domains order by id", Ct);
        Assert.Equal("example.test", Assert.Single(before).Text("fqdn"));
        var seed = await SeedAsync(fixture.Pg, Observed, 2, Ct);
        Assert.Equal(before[0].Int("id"), seed.DomainId);
        Assert.True(JsonNode.DeepEquals(Array(before), Array(await ReadAsync(db, "select id,forest_id,fqdn from domains order by id", Ct))));
        Assert.Equal(2, seed.ServerIds.Length); Assert.Equal(2, seed.ServerIds.Distinct().Count());
        Assert.Equal(2, seed.ComputerGuids.Count); Assert.Equal(2, seed.ComputerGuids.Values.Distinct().Count());
        foreach (var (table, expected) in ContextTables.Zip(new[] { 2, 1, 2, 1, 1 }))
            Assert.Equal(expected, (await ReadAsync(db, $"select count(*) as count from {table} where domain_id=$1", Ct, seed.DomainId))[0].Int("count"));

        // Prove these are usable, hash-verified report inputs, rather than row counts alone.
        var computers = Assert.Single(await AdLogonPairs.ContextSnapshots(db, "computers_v6", [seed.DomainId], Ct));
        Assert.Equal(2, computers["snapshot"]!["objects"]!.AsArray().Count);
        Assert.Equal(2, AdLogonReports.Population([computers]).Count);
        var users = Assert.Single(await AdLogonPairs.ContextSnapshots(db, "users_v2", [seed.DomainId], Ct));
        Assert.Equal(new[] { "synthetic-user-0", "synthetic-user-1" }, users["snapshot"]!["users"]!.AsArray().Select(u => u.Text("samAccountName")));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Theory]
    [InlineData("servers")]
    [InlineData("ad_context_runs")]
    [InlineData("entities_v2")]
    [InlineData("users_report_v2_snapshots")]
    [InlineData("computers_v6_source_snapshots")]
    public async Task Populated_context_is_refused_before_any_rows_change(string table)
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        long domain = (await ReadAsync(db, "select id from domains where fqdn='example.test'", Ct))[0].Int("id");
        switch (table)
        {
            case "servers":
                await ExecuteAsync(db, "insert into servers(domain_id,hostname,fqdn,role) values($1,'EXISTING','existing.example.test','domain_controller')", Ct, domain);
                break;
            case "ad_context_runs":
                await StoreRunAsync(db, domain, Observed, Ct);
                break;
            case "entities_v2":
                await ExecuteAsync(db, "insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing", Ct);
                await ExecuteAsync(db, """
                    insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,first_seen_utc,last_seen_utc,source_core_sha256)
                    select id,'existing-synthetic','Existing synthetic',$1,$2,$2,decode($3,'hex') from storage_v2_entity_type where value='ad_computer'
                    """, Ct, domain, Observed, AdJobPlugin.Digest(new JsonObject()));
                break;
            case "users_report_v2_snapshots":
                await StoreUsersAsync(db, domain, Observed, Obj(new { users = System.Array.Empty<object>() }), 0, Ct);
                break;
            case "computers_v6_source_snapshots":
                await StoreComputersAsync(db, domain, Observed, SyntheticSnapshot(Observed, 2), Ct);
                break;
        }
        var before = await RowsAsync(db);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SeedAsync(fixture.Pg, Observed, 2, Ct));
        Assert.Equal($"native fixture requires empty example.test {table}", error.Message);
        Assert.True(JsonNode.DeepEquals(before, await RowsAsync(db)), "Refusal must preserve existing payloads, every other context source and installation identities");
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    static async Task<JsonObject> RowsAsync(NpgsqlConnection db)
    {
        var result = new JsonObject();
        foreach (string table in ContextTables.Concat(new[] { "domains", "forests", "ad_context_sections", "ad_context_entity_versions", "ad_context_entity_aliases", "storage_v2_entity_type" }))
        {
            await using var command = new NpgsqlCommand($"select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb)::text from {table} t", db);
            result[table] = JsonNode.Parse((string)(await command.ExecuteScalarAsync(Ct))!);
        }
        return result;
    }
}
