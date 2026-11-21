using System.Diagnostics;
using System.Net;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class SecurityProblemsV2Tests
{
    [Fact]
    public async Task PasswordQueuePageStaysWithinItsResponseBudget()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("""
            delete from findings_active;
            insert into findings_active(id,rule_code,first_seen_utc,last_seen_utc,evidence_count,severity)
            select n,case when n%2=0 then 'semantic.qw.password-spray' else 'semantic.qw.password-brute-force' end,
                '2026-11-21T10:00:00Z','2026-11-21T10:05:00Z',120,'high'
            from generate_series(100,159) n;
            insert into finding_event_details337(finding_id,event_db_id,event_id,time_created_utc,domain_id,
                target_user_name,target_domain_name,ip_address,workstation_name,event_record_id,hostname,channel,evidence_role)
            select f.id,f.id*1000+n,(array[4625,4771,4776])[1+n%3],f.first_seen_utc::timestamptz+n*interval '2 seconds',7,
                'user-'||case when f.id%2=0 then n%30 else f.id end,'example.test',
                case when n%3<>2 then '192.0.2.'||f.id end,
                case when n%3=2 then 'client-'||f.id||'.example.test' end,
                f.id*1000+n,'dc.example.test','Security','semantic_scenario'
            from findings_active f cross join generate_series(1,120) n;
            create index on finding_event_details337(finding_id,event_id);
            analyze findings_active;
            analyze finding_event_details337;
            """);
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition,
            nativeReader: new SecurityProblemsReader(pg.Repository, pg.Evidence));
        const string path = "/api/v2/reports/security.problems/data?population=open&tz=Asia%2FNovosibirsk&limit=50";
        using (var warmup = await host.Client.GetAsync(path, Ct)) Assert.Equal(HttpStatusCode.OK, warmup.StatusCode);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("ru");
        for (int i = 0; i < 3; i++) {
            var timer = Stopwatch.StartNew();
            using var response = await host.Client.GetAsync(path, Ct);
            var bytes = await response.Content.ReadAsByteArrayAsync(Ct);
            timer.Stop();
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = O(System.Text.Encoding.UTF8.GetString(bytes));
            TestContext.Current.TestOutputHelper!.WriteLine($"Queue request {i + 1}: {timer.Elapsed.TotalMilliseconds:F1} ms, {bytes.Length} bytes");
            Assert.True(timer.Elapsed < TimeSpan.FromSeconds(1), $"Queue took {timer.Elapsed.TotalMilliseconds:F1} ms");
            Assert.True(bytes.Length < 50_000, $"Queue returned {bytes.Length} bytes");
            var items = result["items"]!.AsArray();
            Assert.Equal(50, items.Count);
            foreach (var row in items) {
                long id = row!["id"]!.GetValue<long>();
                string address = $"192.0.2.{id}";
                Assert.Equal(address, row["actor_text"]!.ToString());
                Assert.Equal(id % 2 == 0 ? $"{address} (учётных записей: 30)" : $"example.test\\user-{id}", row["entity_text"]!.ToString());
                Assert.Null(row["evidence"]);
                Assert.Null(row["status_history"]);
                Assert.Null(row["what_happened"]);
            }
        }
        await pg.Sql("""
            update finding_event_details337 set ip_address=null,workstation_name='client-159.example.test' where finding_id=159;
            insert into finding_status_history values(1,159,'new','active',now(),'fixture-operator','fixture comment');
            """);
        using var description = await host.Client.GetAsync(path + "&id=159", Ct);
        Assert.Equal(HttpStatusCode.OK, description.StatusCode);
        var problem = Assert.Single((await ReportFixture.Body(description))["items"]!.AsArray())!;
        Assert.Equal("client-159.example.test", problem["actor_text"]!.ToString());
        Assert.Contains("example.test\\user-159", problem["what_happened"]!.ToString());
        Assert.Equal("fixture comment", Assert.Single(problem["status_history"]!.AsArray())!["note"]!.ToString());
        using var evidence = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/159/detail?population=open&limit=20", Ct);
        Assert.Equal(HttpStatusCode.OK, evidence.StatusCode);
        var detail = await ReportFixture.Body(evidence);
        Assert.Equal(120, detail["filtered_count"]!.GetValue<long>());
        Assert.Equal(20, detail["items"]!.AsArray().Count);
    }
}
