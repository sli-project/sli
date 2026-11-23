using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
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
    [Theory]
    [InlineData(50)]
    [InlineData(73)]
    public Task LoadedPasswordQueueServesStoredFactsWithinItsBudget(int findings) => ReadLoadedPasswordQueue(findings);

    [Fact]
    public Task LoadedPasswordQueueReadsAnExplicitSevenDayWindow() => ReadLoadedPasswordQueue(80);

    [Fact]
    public async Task PasswordQueueFallbackAliasesUseTheAuthorizedPageSnapshot()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var owner = await fixture.Pg.OpenAsync(Ct);
        await ProblemQueuePagingTests.SeedPopulation(owner, Ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into domains(id,forest_id,fqdn) select 2,forest_id,'other.example.test' from domains where id=1;
            update findings set rule_code='semantic.qw.password-spray',title='synthetic-alias-snapshot' where id=1;
            update finding_event_copies337 set method=jsonb_set(method,'{$principals}',
                '{"TargetUserName":"local-visible","IpAddress":"192.0.2.1"}') where finding_id=1;
            alter function public.password_queue_presentation399(bigint,text) rename to original_password_queue_presentation;
            create function public.password_queue_presentation399(bigint,text) returns table(facts jsonb,aliases jsonb)
            language plpgsql stable as $$begin
              perform pg_advisory_xact_lock(399041);
              return query select p.facts,p.aliases from public.original_password_queue_presentation($1,$2) p;
            end$$;
            select pg_advisory_lock(399041);
            """, Ct);
        var connections = new Database(fixture.Dsn("adlog_user"));
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition,
            nativeReader: new SecurityProblemsReader(new ProblemRepository(connections, TimeProvider.System),
                new SecurityProblemEvidence(new SemanticDatabase(connections))));
        const string path = "/api/v2/reports/security.problems/data?queue_view=all&domain=1&q=synthetic-alias-snapshot&limit=50";
        var pending = host.Client.GetAsync(path, Ct);
        try
        {
            await using var blocked = new NpgsqlCommand("""
                select exists(select 1 from pg_stat_activity where datname=current_database()
                    and pg_backend_pid()=any(pg_blocking_pids(pid)))
                """, owner);
            var wait = Stopwatch.StartNew();
            while (!(bool)(await blocked.ExecuteScalarAsync(Ct))!)
            {
                Assert.False(pending.IsCompleted, "The request must pause in the authorized page query.");
                Assert.True(wait.Elapsed < TimeSpan.FromSeconds(10), "The page query did not reach the advisory lock.");
                await Task.Delay(20, Ct);
            }
            await PostCollectionPostgres.Sql(owner, """
                update finding_event_copies337 set domain_id=2,method=jsonb_set(method,'{$principals,TargetUserName}','"foreign-hidden"')
                where finding_id=1;
                """, Ct);
        }
        finally
        {
            await PostCollectionPostgres.Sql(owner, "select pg_advisory_unlock(399041)", Ct);
        }

        using var inFlight = await pending;
        Assert.Equal(HttpStatusCode.OK, inFlight.StatusCode);
        var row = Assert.Single((await ReportFixture.Body(inFlight))["items"]!.AsArray())!;
        Assert.Equal("local-visible", Assert.Single(row["queue_attack"]!["accounts"]!.AsArray())!.ToString());
        using var next = await host.Client.GetAsync(path, Ct);
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);
        Assert.Empty((await ReportFixture.Body(next))["items"]!.AsArray());
    }

    private async Task ReadLoadedPasswordQueue(int findings)
    {
        bool week = findings == 80;
        var today = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero);
        string eventDay = today.AddDays(-2).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        string outsideWeek = today.AddDays(-30).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct, throughVersion: week ? 398 : null);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await ProblemQueuePagingTests.SeedPopulation(db, Ct, pendingFinding: week ? 81 : null);
        var load = Stopwatch.StartNew();
        await PostCollectionPostgres.Sql(db, $$"""
            update findings set status='closed' where id>{{findings}};
            update findings set rule_code='semantic.qw.password-spray',actor=null,target=null,source=null,
                first_seen_utc='{{eventDay}}T10:00:00Z',last_seen_utc='{{eventDay}}T10:05:00Z',
                evidence_count={{(week ? "case when id=80 then 9500 when id<=75 then 1900 else 2000 end" : "2000")}}
                where id<={{findings}};
            delete from finding_event_copies337 where finding_id<={{findings}};
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,evidence_role)
            select f.id,f.id*10000+n,'{{eventDay}}T10:00:00Z'::timestamptz+n*interval '100 milliseconds',
                (array[4625,4771,4776])[1+n%3],d.id,'dc01.example.test',
                jsonb_build_object('$server_id',1,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                    '$principals',jsonb_build_object('TargetUserName','user-'||n,'TargetDomainName','example.test',
                    'IpAddress','192.0.2.'||f.id)), '{}','{}',sha256((f.id*10000+n)::text::bytea),'semantic_scenario'
            from findings f cross join domains d cross join lateral generate_series(1,f.evidence_count) n
            where f.id<={{findings}} and d.fqdn='example.test';
            analyze findings;
            analyze finding_event_copies337;
            """, Ct);
        TestContext.Current.TestOutputHelper!.WriteLine($"Seeded {findings * 2000} retained copies: {load.Elapsed.TotalMilliseconds:F1} ms");
        if (week)
        {
            await PostCollectionPostgres.Sql(db, $"""
                update findings set first_seen_utc='{outsideWeek}T10:00:00Z',last_seen_utc='{outsideWeek}T10:05:00Z' where id>80;
                """, Ct);
            await using var population = new NpgsqlCommand("""
                select count(*),max(copies),sum(copies)::bigint from (
                    select count(*) as copies from finding_event_copies337 where finding_id<=80 group by finding_id
                ) population
                """, db);
            await using (var counts = await population.ExecuteReaderAsync(Ct))
            {
                Assert.True(await counts.ReadAsync(Ct));
                Assert.Equal(80L, counts.GetInt64(0));
                Assert.Equal(9500L, counts.GetInt64(1));
                Assert.Equal(160000L, counts.GetInt64(2));
            }
            string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/399_password_queue_projection.sql");
            var upgrade = Stopwatch.StartNew();
            await fixture.Pg.ApplyFileAsync(migration, null, Ct);
            TestContext.Current.TestOutputHelper!.WriteLine($"Full migration 399 with 80 published findings, 160000 copies, largest finding 9500: {upgrade.Elapsed.TotalMilliseconds:F1} ms");
            await using var hydrated = new NpgsqlCommand("select count(*) from public.password_queue_projection399 where valid", db);
            Assert.Equal(80L, await hydrated.ExecuteScalarAsync(Ct));
        }
        else
        {
            var refresh = Stopwatch.StartNew();
            await PostCollectionPostgres.Sql(db, $"select public.refresh_password_queue_presentation399(id) from findings where id<={findings} order by id", Ct);
            TestContext.Current.TestOutputHelper!.WriteLine($"Projection for {findings} existing findings with 2000 copies each: {refresh.Elapsed.TotalMilliseconds:F1} ms");
        }
        var connections = new Database(fixture.Dsn("adlog_user"));
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Definition,
            nativeReader: new SecurityProblemsReader(new ProblemRepository(connections, TimeProvider.System),
                new SecurityProblemEvidence(new SemanticDatabase(connections))));
        string view = findings switch {
            50 => "population=open",
            73 => "queue_view=open&direction=desc&sort=last_seen_utc",
            _ => "queue_view=all&direction=desc&domain=1&sort=last_seen_utc&" + WeekWindow(today.AddDays(-4)),
        };
        string path = $"/api/v2/reports/security.problems/data?{view}&tz=Asia%2FNovosibirsk&limit=50";
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        // An in-flight finding update must leave the committed queue readable.
        await using var writer = await db.BeginTransactionAsync(Ct);
        await using (var hold = new NpgsqlCommand("""
            select id from findings where id=50 for update;
            select event_id from finding_event_copies337 where finding_id=50 and event_id=500001 for update;
            """, db, writer)) await hold.ExecuteNonQueryAsync(Ct);
        var slowest = TimeSpan.Zero;
        string? firstPageCursor = null;
        for (int i = 0; i < 3; i++) {
            var timer = Stopwatch.StartNew();
            using var response = await host.Client.GetAsync(path, Ct);
            var bytes = await response.Content.ReadAsByteArrayAsync(Ct);
            timer.Stop();
            if (timer.Elapsed > slowest) slowest = timer.Elapsed;
            TestContext.Current.TestOutputHelper!.WriteLine($"Loaded {findings}-finding queue request {i + 1}: {timer.Elapsed.TotalMilliseconds:F1} ms");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = O(System.Text.Encoding.UTF8.GetString(bytes));
            Assert.Equal(findings, result["filtered_count"]!.GetValue<long>());
            Assert.Equal(findings > 50, result["has_more"]!.GetValue<bool>());
            var rows = result["items"]!.AsArray();
            Assert.Equal(50, rows.Count);
            if (findings == 80)
            {
                Assert.Equal(Enumerable.Range(31, 50).Reverse().Select(id => (long)id), Ids(result));
                firstPageCursor = result["next_cursor"]!.GetValue<string>();
            }
            foreach (var row in rows) {
                var id = row!["id"]!.GetValue<long>();
                string ip = $"192.0.2.{id}";
                Assert.Equal(ip, row["actor_text"]!.ToString());
                int accounts = week ? id == 80 ? 9500 : id <= 75 ? 1900 : 2000 : 2000;
                Assert.Equal($"{ip} ({accounts} accounts)", row["entity_text"]!.ToString());
                if (findings >= 73) {
                    var attack = row["queue_attack"]!.AsObject();
                    Assert.Equal(ip, Assert.Single(attack["addresses"]!.AsArray())!.ToString());
                    Assert.Equal(new[] { "user-1", "user-10", "user-100", "user-1000", "user-1001", "user-1002", "user-1003", "user-1004" },
                        attack["accounts"]!.AsArray().Select(name => name!.ToString()));
                }
            }
        }
        await writer.RollbackAsync(Ct);

        if (findings == 80)
        {
            var fresh = Stopwatch.StartNew();
            string freshPath = path.Replace(WeekWindow(today.AddDays(-4)), WeekWindow(today.AddDays(-3)), StringComparison.Ordinal);
            using var response = await host.Client.GetAsync(freshPath, Ct);
            var bytes = await response.Content.ReadAsByteArrayAsync(Ct);
            TestContext.Current.TestOutputHelper!.WriteLine($"First HTTP request for a different seven-day period on the same host: {fresh.Elapsed.TotalMilliseconds:F1} ms");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(Enumerable.Range(31, 50).Reverse().Select(id => (long)id), Ids(O(System.Text.Encoding.UTF8.GetString(bytes))));
        }

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
            await File.WriteAllTextAsync(Path.Combine(Path.GetTempPath(), $"problems-queue-{findings}-explain.log"),
                await fixture.Pg.DiagnosticsAsync(Ct), Ct);
        }
        // Keep the original CI budget on the original workload. The installed
        // queue shape tracks the additional list path and reports its timings.
        if (findings == 50)
            Assert.True(slowest < TimeSpan.FromSeconds(3), $"Loaded queue took {slowest.TotalMilliseconds:F1} ms");
        if (firstPageCursor is not null)
            await VerifyWeekQueueAfterChanges(db, host.Client, path, firstPageCursor, eventDay);
    }

    private static string WeekWindow(DateTimeOffset from) => $"time_from={Uri.EscapeDataString(ProblemJson.Iso(from))}" +
        $"&time_to={Uri.EscapeDataString(ProblemJson.Iso(from.AddDays(7)))}";

    private static async Task VerifyWeekQueueAfterChanges(NpgsqlConnection db, HttpClient client, string path, string cursor, string eventDay)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select computer.id,type.id,computer.name,computer.name,d.id,sha256(computer.name::bytea)
            from domains d cross join storage_v2_entity_type type
                cross join (values(500,'synthetic-computer'),(501,'other-computer'),(502,'empty-computer')) computer(id,name)
            where d.fqdn='example.test' and type.value='ad_computer';
            insert into finding_entities(finding_id,entity_id,entity_type,display_name,entity_role)
            select id,case when id=77 then 501 else 500 end,'ad_computer','Synthetic computer','target'
            from findings where id between 76 and 80;
            update findings set status='closed' where id=78;
            insert into finding_queue_deferrals(finding_id,until_at) values(79,now()+interval '1 day');
            """, Ct);
        var scoped = await Read(path + "&entity_id=500&population=open");
        Assert.Equal(new long[] { 80, 76 }, Ids(scoped));
        Assert.Equal(2L, scoped["filtered_count"]!.GetValue<long>());
        var empty = await Read(path + "&entity_id=502&population=open");
        Assert.Empty(Ids(empty));
        Assert.Equal(0L, empty["filtered_count"]!.GetValue<long>());

        // Publish one previously out-of-window fixture through the same tables used by the report gate.
        await PostCollectionPostgres.Sql(db, $"""
            begin;
            update findings set status='new',first_seen_utc='{eventDay}T11:00:00Z',last_seen_utc='{eventDay}T11:05:00Z' where id=81;
            update finding_event_copies337 set time_created_utc='{eventDay}T11:00:00Z' where finding_id=81;
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
                select md5('scenario-81')::uuid,id,md5('job-81')::uuid,fingerprint,1 from findings where id=81;
            commit;
            """, Ct);
        var updated = await Read(path);
        Assert.Equal(81L, Ids(updated)[0]);
        Assert.Equal(81L, updated["filtered_count"]!.GetValue<long>());
        var next = await Read(path + "&cursor=" + Uri.EscapeDataString(cursor));
        Assert.Equal(Enumerable.Range(1, 30).Reverse().Select(id => (long)id), Ids(next));
        Assert.False(next["has_more"]!.GetValue<bool>());

        async Task<JsonObject> Read(string url)
        {
            using var response = await client.GetAsync(url, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return O(await response.Content.ReadAsStringAsync(Ct));
        }
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
                Assert.Equal(id % 2 == 0 ? $"{address} (учётных записей: 30)" : $"user-{id}", row["entity_text"]!.ToString());
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
        Assert.Contains("user-159", problem["what_happened"]!.ToString());
        Assert.Equal("fixture comment", Assert.Single(problem["status_history"]!.AsArray())!["note"]!.ToString());
        using var evidence = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/159/detail?population=open&limit=20", Ct);
        Assert.Equal(HttpStatusCode.OK, evidence.StatusCode);
        var detail = await ReportFixture.Body(evidence);
        Assert.Equal(120, detail["filtered_count"]!.GetValue<long>());
        Assert.Equal(20, detail["items"]!.AsArray().Count);
    }
}
