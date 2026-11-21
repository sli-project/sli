using System.Diagnostics;
using System.Net;
using Npgsql;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class SecurityProblemsV2Tests
{
    [Fact]
    public async Task LoadedPasswordQueueServesStoredFactsWithinItsBudget()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await ProblemQueuePagingTests.SeedPopulation(db, Ct);
        await PostCollectionPostgres.Sql(db, """
            update findings set status='closed' where id>50;
            update findings set rule_code='semantic.qw.password-spray',actor=null,target=null,source=null,
                first_seen_utc='2026-11-21T10:00:00Z',last_seen_utc='2026-11-21T10:05:00Z',evidence_count=2000 where id<=50;
            delete from finding_event_copies337 where finding_id<=50;
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,evidence_role)
            select f.id,f.id*10000+n,'2026-11-21T10:00:00Z'::timestamptz+n*interval '100 milliseconds',
                (array[4625,4771,4776])[1+n%3],d.id,'dc01.example.test',
                jsonb_build_object('$server_id',1,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                    '$principals',jsonb_build_object('TargetUserName','user-'||n,'TargetDomainName','example.test',
                    'IpAddress','192.0.2.'||f.id)), '{}','{}',sha256((f.id*10000+n)::text::bytea),'semantic_scenario'
            from findings f cross join domains d cross join generate_series(1,2000) n
            where f.id<=50 and d.fqdn='example.test';
            analyze findings;
            analyze finding_event_copies337;
            """, Ct);
        var connections = new Database(fixture.Dsn("adlog_user"));
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition,
            nativeReader: new SecurityProblemsReader(new ProblemRepository(connections, TimeProvider.System),
                new SecurityProblemEvidence(new SemanticDatabase(connections))));
        const string path = "/api/v2/reports/security.problems/data?population=open&tz=Asia%2FNovosibirsk&limit=50";
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        // An in-flight finding update must leave the committed queue readable.
        await using var writer = await db.BeginTransactionAsync(Ct);
        await using (var hold = new NpgsqlCommand("""
            select id from findings where id=50 for update;
            select event_id from finding_event_copies337 where finding_id=50 and event_id=500001 for update;
            """, db, writer)) await hold.ExecuteNonQueryAsync(Ct);
        var slowest = TimeSpan.Zero;
        for (int i = 0; i < 3; i++) {
            var timer = Stopwatch.StartNew();
            using var response = await host.Client.GetAsync(path, Ct);
            var bytes = await response.Content.ReadAsByteArrayAsync(Ct);
            timer.Stop();
            if (timer.Elapsed > slowest) slowest = timer.Elapsed;
            TestContext.Current.TestOutputHelper!.WriteLine($"Loaded queue request {i + 1}: {timer.Elapsed.TotalMilliseconds:F1} ms");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = O(System.Text.Encoding.UTF8.GetString(bytes));
            Assert.Equal(50, result["filtered_count"]!.GetValue<long>());
            var rows = result["items"]!.AsArray();
            Assert.Equal(50, rows.Count);
            foreach (var row in rows) {
                string ip = $"192.0.2.{row!["id"]}";
                Assert.Equal(ip, row["actor_text"]!.ToString());
                Assert.Equal($"{ip} (2000 accounts)", row["entity_text"]!.ToString());
            }
        }
        await writer.RollbackAsync(Ct);

        if (Environment.GetEnvironmentVariable("SLI_TEST_QUEUE_EXPLAIN") == "1") {
            await PostCollectionPostgres.Sql(db, """
                alter database postgres set session_preload_libraries='auto_explain';
                alter database postgres set auto_explain.log_min_duration=0;
                alter database postgres set auto_explain.log_analyze=on;
                alter database postgres set auto_explain.log_buffers=on;
                alter database postgres set auto_explain.log_nested_statements=on;
                """, Ct);
            using var response = await host.Client.GetAsync(path, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            await File.WriteAllTextAsync(Path.Combine(Path.GetTempPath(), "problems-queue-explain.log"),
                await fixture.Pg.DiagnosticsAsync(Ct), Ct);
        }
        Assert.True(slowest < TimeSpan.FromSeconds(3), $"Loaded queue took {slowest.TotalMilliseconds:F1} ms");
    }

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
