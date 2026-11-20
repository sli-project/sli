using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

public sealed class NewLogonPairsContextNativeTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    const int Population = 5000;

    // Parity: tests/reporting/test_new_logon_pairs_context_native.py.
    // Only this test's owned PostgreSQL cluster is used; no inherited DSN or history service.
    [Fact]
    public async Task Full_context_retains_all_5000_workstations_and_accounts_on_first_and_repeat_reads()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(1,'example.test'),(2,'other.example.test');
            create table servers(id bigint primary key,domain_id bigint,role text);
            insert into servers values(20,1,'domain_controller'),(30,2,'domain_controller'),
                (15,1,'member_server'),(10,1,'domain_controller');
            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,
                source_completed_at_utc timestamptz,collection_status text,base_inventory_status text,
                object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,
                source_state text,payload_json jsonb,payload_sha256 bytea);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
            """, Ct);

        var observed = DateTimeOffset.UtcNow;
        var snapshot = SyntheticSnapshot(observed);
        var users = Obj(new { users = Enumerable.Range(0, Population).Select(i => new { samAccountName = $"synthetic-user-{i}" }) });
        string[] guids = snapshot["objects"]!.AsArray().Select(o => o!.Text("objectGuid")!).ToArray();
        await using (var seed = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,1,@uuid,@observed,'complete','observed',@population,@payload,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,1,@observed,'complete',@users,decode(@userHash,'hex'));
            insert into ad_context_entity_aliases
                select 1,'object_guid',guid,ordinality from unnest(@guids::text[]) with ordinality as g(guid,ordinality);
            """, db))
        {
            seed.Parameters.AddWithValue("uuid", Guid.Parse(snapshot["metadata"]!.Text("snapshot_id")!));
            seed.Parameters.AddWithValue("observed", observed);
            seed.Parameters.AddWithValue("population", Population);
            seed.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, snapshot.ToJsonString());
            seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(snapshot));
            seed.Parameters.AddWithValue("users", NpgsqlDbType.Jsonb, users.ToJsonString());
            seed.Parameters.AddWithValue("userHash", AdJobPlugin.Digest(users));
            seed.Parameters.AddWithValue("guids", guids);
            await seed.ExecuteNonQueryAsync(Ct);
        }

        for (int observation = 0; observation < 2; observation++)
        {
            // These are the report's production context readers and classifiers.
            var sources = await AdLogonPairs.ContextSnapshots(db, "computers_v6", [1], Ct);
            var userSources = await AdLogonPairs.ContextSnapshots(db, "users_v2", [1], Ct);
            var servers = await AdLogonPairs.DomainControllers(db, [1], Ct);
            var computers = AdLogonReports.Population(sources);
            var accounts = AdLogonPairs.Accounts(userSources.SelectMany(s => s["snapshot"]!["users"]!.AsArray().OfType<JsonObject>()).ToArray());

            Assert.Equal(new long[] { 10, 20 }, servers.Select(s => s.Int("id")));
            Assert.Equal(Population, computers.Count);
            Assert.Equal(guids.Order(StringComparer.Ordinal), computers.Select(c => c.Text("object_guid")!).Order(StringComparer.Ordinal));
            Assert.All(computers, c => Assert.True(c.Int("entity_id") > 0));
            Assert.Equal(Population, accounts.Count);
            Assert.Equal(Enumerable.Range(0, Population).Select(i => $"synthetic-user-{i}").Order(StringComparer.Ordinal), accounts.Keys.Order(StringComparer.Ordinal));
            Assert.All(accounts.Values, service => Assert.False(service));
            // .NET passes source completeness into novelty calculation rather than exposing context.partial.
            Assert.Equal("complete", Assert.Single(sources).Text("source_state"));
            Assert.Equal("complete", Assert.Single(userSources).Text("source_state"));
        }
    }

    static JsonObject SyntheticSnapshot(DateTimeOffset observed)
    {
        using var stream = typeof(NewLogonPairsContextNativeTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var snapshot = JsonNode.Parse(stream)!.AsObject();
        var template = snapshot["objects"]![0]!.AsObject();
        string stamp = observed.ToString("O", CultureInfo.InvariantCulture);
        var metadata = snapshot["metadata"]!.AsObject();
        metadata["snapshot_id"] = Guid.NewGuid().ToString();
        metadata["label"] = "Synthetic native context";
        metadata["started_at"] = stamp;
        metadata["completed_at"] = stamp;
        metadata["object_count"] = Population;
        foreach (var stage in metadata["sources"]!.AsArray())
            stage!["counts"] = new JsonObject { [stage.Text("status")!] = Population };
        var objects = new JsonArray();
        for (int i = 0; i < Population; i++)
        {
            var item = (JsonObject)template.DeepClone();
            string guid = new Guid($"00000000-0000-0000-0000-{i + 1:000000000000}").ToString();
            string name = $"PC-{i}", dns = $"pc-{i}.example.test";
            string address = $"192.0.2.{i % 250 + 1}";
            item["id"] = guid; item["objectGuid"] = guid;
            item["name"] = name; item["dnsHostName"] = dns;
            item["deviceType"] = "workstation";
            item["osName"] = "Windows 11 Pro"; item["osVersion"] = "10.0 (26100)";
            item["osBuild"] = "26100"; item["osFamily"] = "Windows 11";
            item["classification"] = Obj(new { status = "observed", value = "workstation", rule_id = "device-classification/os-workstation-v1", evidence = new[] { "OperatingSystem is Windows client" } });
            item["ipv4s"] = new JsonArray(address);
            item["ou"] = "Workstations";
            item["distinguishedName"] = $"CN={name},OU=Workstations,DC=example,DC=test";
            item["canonicalName"] = $"example.test/Workstations/{name}";
            item["sid"] = $"S-1-5-21-100000001-200000002-300000003-{20000 + i}";
            item["spns"] = new JsonArray($"HOST/{dns}");
            item["roleHint"] = "Workstation"; item["roleEvidence"] = "Synthetic Windows client OS";
            item["description"] = "Synthetic native CI workstation";
            item["location"] = "Synthetic";
            item["collectedAt"] = stamp; item["lastLogonTimestamp"] = stamp; item["exactLastLogon"] = stamp;
            foreach (var (_, state) in item["sources"]!.AsObject())
                if (state!["observed_at"] is not null) state["observed_at"] = stamp;
            item["sources"]!["dns"]!["value"] = Obj(new { ipv4 = new[] { address }, ipv6 = System.Array.Empty<string>() });
            item["sources"]!["os"]!["value"] = Obj(new { name = "Windows 11 Pro", version = "10.0 (26100)", service_pack = "" });
            foreach (string key in new[] { "last_logon_timestamp", "exact_last_logon" }) item["sources"]![key]!["value"] = stamp;
            objects.Add(item);
        }
        snapshot["objects"] = objects;
        return snapshot;
    }
}
