using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Domains;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Domains;
using Xunit;

namespace Sli.Server.Tests;

public sealed class StandSlowEndpointsPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Synthetic_retained_window_serves_home_operations_and_domain_changes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        output.WriteLine("Seeding disposable PostgreSQL: 200000 events, 20000 AD runs, 60000 sections");
        await using (var seed = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,fqdn,role)
                select 1,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test';
            select public.create_event_storage_partitions((now() at time zone 'UTC')::date-5,(now() at time zone 'UTC')::date);
            -- This reader benchmark uses the same compact shape and layers as
            -- the short store: individual changes also have durable fact rows.
            with hot as (
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields)
                select n,now()-n*interval '2 seconds',case when n%100=0 then 4728 else 4625 end,
                    d.id,'dc01.example.test',
                    '{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
                    '{}','{}'
                from generate_series(1,200000) n cross join domains d where d.fqdn='example.test'
                returning *
            )
            insert into event_cold_facts select * from hot where event_kind=4728;
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
            select md5(n::text)::uuid,'synthetic','1',d.id,'full',now()-n*interval '1 minute',sha256(n::text::bytea),'completed'
                from generate_series(1,20000) n cross join domains d where d.fqdn='example.test';
            insert into ad_context_sections(run_id,section_name,status,record_count)
                select run_id,section,'complete',0 from ad_context_runs
                cross join unnest(array['directory_accounts','domain_posture','domain_health']) section;
            analyze;
            """, db) { CommandTimeout = 0 }) await seed.ExecuteNonQueryAsync(ct);
        string token = await fixture.SeedOwnerAsync(ct);
        using var host = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost)
            .WithWebHostBuilder(b => b.ConfigureLogging(l => l.ClearProviders())
                .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                    ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                    ["Sli:ProjectRoot"] = SqlPostgresFixture.Repository(),
                    ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"),
                    ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs"),
                    ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:OwnerSetup"] = "0"
                })));
        using var client = host.CreateClient(); client.Timeout = Timeout.InfiniteTimeSpan;
        client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
        foreach (string path in new[] { "/api/v1/home/summary?contract=v2", "/api/v1/operations/overview",
            "/api/v2/reports/security.events.chains/data?period=7d&limit=50",
            "/api/v1/operations/overview?view=workers", "/api/v1/operations/overview?view=storage" })
        {
            var timer = Stopwatch.StartNew();
            using var response = await client.GetAsync(path, ct);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!;
            output.WriteLine("{0}: {1:F1} ms; HTTP {2}; state={3}", path, timer.Elapsed.TotalMilliseconds, (int)response.StatusCode, body["state"]?.ToString() ?? "-");
            Assert.True(response.IsSuccessStatusCode, body.ToJsonString());
            if (path.Contains("security.events.chains")) Assert.Equal(50, body["items"]!.AsArray().Count);
            if (path.Contains("home/summary")) Assert.DoesNotContain(body["readers"]!.AsArray(), r => r?["state"]?.ToString() == "error");
        }
        await Plan(db, "home sections", HomeSummarySql.Sections, ct, ("ids", new long[] { 1 }), ("sections", "domain_posture,domain_health"));
        await Plan(db, "operations queues", OperationsSql.Queues, ct);
        var period = new AdPeriod(DateTimeOffset.UtcNow.AddDays(-7), DateTimeOffset.UtcNow);
        var query = AdSecurityQuery.Create(new("security", false, false, 1, period, 50, new(), null));
        await Plan(db, "domain changes page", query.SelectSql, ct, query.Args.Select((v, i) => ((i + 1).ToString(), v!)).ToArray());
        await Plan(db, "domain changes categories", query.CategorySql, ct, query.CategoryArgs.Select((v, i) => ((i + 1).ToString(), v!)).ToArray());
    }

    async Task Plan(NpgsqlConnection db, string name, string sql, CancellationToken ct, params (string Name, object Value)[] args)
    {
        await using var command = new NpgsqlCommand("explain(analyze,buffers,format json) " + sql, db) { CommandTimeout = 60 };
        foreach (var (key, value) in args)
            if (int.TryParse(key, out _)) command.Parameters.Add(new() { Value = value });
            else command.Parameters.AddWithValue(key, value);
        var plan = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)![0]!;
        output.WriteLine("{0}: {1} ms, hit={2}, read={3}, temp={4}", name, plan["Execution Time"]!,
            plan["Plan"]!["Shared Hit Blocks"]!, plan["Plan"]!["Shared Read Blocks"]!, plan["Plan"]!["Temp Written Blocks"]!);
        void Nodes(JsonNode node)
        {
            if (node["Relation Name"] is not null || node["Node Type"]?.ToString() == "Sort")
                output.WriteLine("  {0} {1}: rows={2}, loops={3}, removed={4}", node["Node Type"]!,
                    node["Relation Name"]?.ToString() ?? "", node["Actual Rows"]!, node["Actual Loops"]!, node["Rows Removed by Filter"]?.ToString() ?? "0");
            foreach (var child in node["Plans"] as JsonArray ?? []) Nodes(child!);
        }
        Nodes(plan["Plan"]!);
    }
}
