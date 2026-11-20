using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Disposable PostgreSQL: native context, short-layer observations and HTTP dispatch.
[Collection("AD source native environment")]
public sealed class NewLogonPairsNativeTests(ITestOutputHelper output)
{
    const int Population = 5000;
    static readonly DateTimeOffset Start = new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero).AddDays(-1);
    static readonly DateTimeOffset End = Start.AddDays(1), Baseline = Start.AddDays(-30);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static string GuidFor(int index) => $"00000000-0000-0000-0000-{index + 1:000000000000}";
    static string SidFor(int index) => $"S-1-5-21-100000001-200000002-300000003-{10000 + index}";
    static string Stamp(DateTimeOffset value) => value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    [Fact]
    public async Task Native_context_and_short_history_preserve_empty_known_new_and_volume_results()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(Ct);
        await SeedContext(pg);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = pg.ConnectionString,
            ["Sli:Storage:HotRetentionDays"] = "365",
            ["Sli:Storage:ShortEventReads"] = "false",
            ["Sli:Storage:HistoryReadMode"] = "invalid"
        }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        using var host = await AdV2Tests.Host(store);
        using var client = host.GetTestClient(); client.Timeout = Timeout.InfiniteTimeSpan;
        await using var db = await pg.OpenAsync(Ct);
        await AssertNativeContext(db);

        JsonObject? volume = null;
        foreach (var (label, count, known, corrupt) in new[] {
            ("empty", 0, false, false), ("new_pairs", 10, false, false),
            ("known_pairs", 10, true, false), 
            ("volume_first", 50000, false, false), ("volume_repeat", -1, false, false),
        }) {
            output.WriteLine("History vector: " + label);
            if (count >= 0) await SeedEvents(db,count,known);
            using var response = await client.GetAsync($"/api/v2/reports/ad.new-logon-pairs/data?period=custom&from={Start:yyyy-MM-ddTHH:mm:ssZ}&to={End:yyyy-MM-ddTHH:mm:ssZ}&baseline_days=30", Ct);
            string body = await response.Content.ReadAsStringAsync(Ct);
            Assert.True(response.StatusCode == HttpStatusCode.OK, label + ": " + body);
            var result = JsonNode.Parse(body)!.AsObject();
            var items = result["items"]!.AsArray();
            if (result["state"]?.ToString() == "error") {
                var limitation = (result["limitations"] as JsonArray)?.FirstOrDefault()?["code"];
                output.WriteLine($"History vector {label} failed: {result["coverage"]?["reason"]}; {limitation}");
            }
            if (count == 0 || known) {
                Assert.Equal(count==0?"empty":"partial", result["state"]!.ToString());
                Assert.Empty(items);
                if (count == 0) Assert.Contains(result["limitations"]!.AsArray(), l => l!["code"]!.ToString() == "history_empty");
                continue;
            }
            int eventsPerWindow = count < 0 ? 50000 : count;
            int expectedPairs = label == "new_pairs" ? 10 : Population;
            int expectedCount = label == "new_pairs" ? 1 : 10;
            Assert.True(result["state"]!.ToString() == "partial", label + ": " + body);
            Assert.Equal(label == "new_pairs" ? 10 : 50, items.Count);
            foreach (string flag in new[] { "baseline_covered", "period_covered", "baseline_history_covered", "period_history_covered" })
                Assert.False(result["coverage"]![flag]!.GetValue<bool>(), label + ": " + flag);
            Assert.False(result["coverage"]!["truncated"]!.GetValue<bool>());
            foreach (var item in items.OfType<JsonObject>()) AssertPair(item,expectedPairs,eventsPerWindow,expectedCount);
            Assert.Equal(expectedPairs > 50, result["has_more"]!.GetValue<bool>());
            if (expectedPairs > 50) Assert.False(string.IsNullOrEmpty(result["next_cursor"]!.ToString()));
            else Assert.Null(result["next_cursor"]);
            if (label == "volume_first") volume = result;
            if (label == "volume_repeat") Assert.True(JsonNode.DeepEquals(volume, result), "Repeated volume request changed the report");
        }
        Assert.DoesNotContain("ERROR:", await pg.DiagnosticsAsync(Ct), StringComparison.Ordinal);
    }

    static async Task AssertNativeContext(NpgsqlConnection db)
    {
        // Keep the preflight snapshot scoped to this check before the report reads its own context.
        var sources = await AdLogonPairs.ContextSnapshots(db, "computers_v6", [1], Ct);
        var computers = AdLogonReports.Population(sources);
        var users = (await AdLogonPairs.ContextSnapshots(db, "users_v2", [1], Ct))
            .Single()["snapshot"]!["users"]!.AsArray().OfType<JsonObject>().ToArray();
        Assert.Equal(Population, computers.Count);
        Assert.Equal(Population, users.Length);
        Assert.Equal("complete", sources.Single()["source_state"]!.ToString());
    }

    static void AssertPair(JsonObject item, int expectedPairs, int eventsPerWindow, int count)
    {
        int user = int.Parse(item["user_sid"]!.ToString().Split('-')[^1], CultureInfo.InvariantCulture) - 10000;
        Assert.InRange(user, 0, expectedPairs - 1);
        int computer = (user + 1) % Population;
        Assert.Equal("PC-" + computer, item["computer"]!.ToString());
        Assert.Equal(GuidFor(computer), item["computer_guid"]!.ToString());
        Assert.Equal(computer + 1L, item["computer_entity_id"]!.GetValue<long>());
        Assert.Equal(eventsPerWindow + 1L + user, item["source_event_id"]!.GetValue<long>());
        Assert.Equal(count, item["count"]!.GetValue<int>());
        Assert.Equal("no_baseline", item["novelty"]!.ToString());
        Assert.Equal("yes", item["prior_user_logon"]!.ToString());
        Assert.Equal(Start.AddTicks(user * 10L), DateTimeOffset.Parse(item["first_seen"]!.ToString(), CultureInfo.InvariantCulture));
    }

    static async Task SeedContext(PostCollectionPostgres pg)
    {
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text,is_archived boolean default false);
            insert into domains(id,fqdn) values(1,'example.test');
            create table platform_settings(key text,value text);
            insert into platform_settings values('reports.domain_fqdn','example.test');
            create table ad_context_runs(domain_id bigint,status text,observed_at_utc timestamptz);
            create table servers(id bigint,domain_id bigint,role text);
            insert into servers values(1,1,'domain_controller'),(2,1,'domain_controller');
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
            create table storage_v2_entity_type(id bigint,value text);
            create table entities_v2(id bigint,domain_id bigint,entity_type_id bigint);

            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,source_completed_at_utc timestamptz,
                collection_status text,base_inventory_status text,object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
            """, Ct);
        using var stream = typeof(NewLogonPairsNativeTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: Ct))!.AsObject();
        var template = payload["objects"]![0]!.AsObject();
        var objects = new JsonArray(); var users = new JsonArray();
        for (int i = 0; i < Population; i++) {
            var item = (JsonObject)template.DeepClone(); string guid = GuidFor(i);
            item["id"] = guid; item["objectGuid"] = guid; item["name"] = "PC-" + i;
            item["dnsHostName"] = $"pc-{i}.example.test";
            item["sid"] = $"S-1-5-21-100000001-200000002-300000003-{20000 + i}";
            item["osName"] = "Windows 11 Pro"; item["classification"]!["result"] = "workstation";
            item["ipv4s"] = new JsonArray(); item["ipv6s"] = new JsonArray();
            objects.Add(item);
            users.Add(new JsonObject { ["samAccountName"] = "synthetic-user-" + i, ["sid"] = SidFor(i) });
        }
        payload["objects"] = objects; payload["metadata"]!["object_count"] = Population;
        var userPayload = new JsonObject { ["users"] = users };
        await using var seed = new NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,1,@uuid,@observed,'complete','observed',5000,@payload,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,1,@observed,'complete',@users,decode(@userHash,'hex'));
            insert into ad_context_entity_aliases select 1,'object_guid',value->>'objectGuid',ordinality
                from jsonb_array_elements(cast(@payload as jsonb)->'objects') with ordinality;
            """, db);
        seed.Parameters.AddWithValue("uuid", Guid.Parse(payload["metadata"]!["snapshot_id"]!.ToString()));
        seed.Parameters.AddWithValue("observed", End.UtcDateTime);
        seed.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
        seed.Parameters.AddWithValue("users", NpgsqlDbType.Jsonb, userPayload.ToJsonString());
        seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
        seed.Parameters.AddWithValue("userHash", AdJobPlugin.Digest(userPayload));
        await seed.ExecuteNonQueryAsync(Ct);
    }

    static async Task SeedEvents(NpgsqlConnection db,int count,bool known)
    {
        await PostCollectionPostgres.Sql(db,"truncate event_hot",Ct);
        await using var seed=new NpgsqlCommand("""
            insert into event_hot
            select (w*@count+n)::bigint,
                case when w=0 then @baseline::timestamptz+n*interval '1 second' else @start::timestamptz+(n-1)*interval '1 microsecond' end,
                4624,1,'S-1-5-21-100000001-200000002-300000003-'||(10000+(n-1)%5000)::text,null,
                'PC-'||(case when w=0 or @known then (n-1)%5000 else n%5000 end)::text,'DC-'||((n-1)%2)::text,
                jsonb_build_object('$server_id',(n-1)%2+1,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing','LogonType','3'),
                '{}'::jsonb,'{}'::jsonb
            from generate_series(1,@count) n cross join generate_series(0,1) w
            """,db);
        seed.Parameters.AddWithValue("count",count);seed.Parameters.AddWithValue("known",known);
        seed.Parameters.AddWithValue("baseline",Baseline);seed.Parameters.AddWithValue("start",Start);await seed.ExecuteNonQueryAsync(Ct);
    }

}
