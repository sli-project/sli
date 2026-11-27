using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ProblemQueueLoadPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task InstalledQueueReaderMeetsFirstPageBudgetAndPreservesResults()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 437);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, "alter system set max_wal_size='4GB'", ct);
        await PostCollectionPostgres.Sql(owner, "select pg_reload_conf()", ct);
        await PostCollectionPostgres.Sql(owner, "set work_mem='128MB'", ct);
        await ProblemQueuePagingTests.SeedPopulation(owner, ct);
        await using (var seed = new NpgsqlCommand(Seed, owner) { CommandTimeout = 0 })
            await seed.ExecuteNonQueryAsync(ct);
        await PostCollectionPostgres.Sql(owner, "vacuum analyze", ct);
        await using var reader = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await reader.OpenAsync(ct);
        await PostCollectionPostgres.Sql(reader, "set jit=off", ct);

        var query = new FindingQuery(null, null, null, null, null, null, null, [1], 50, false) {
            QueueView = "all", QueueList = true, PageQueue = true, GroupQueue = true, QueueAssigneesVisible = true
        };
        var before = ProblemRepository.FindingsQueries(query, usePasswordProjection: true);
        await Measure(reader, "Before page", before.Page, before.Arguments, ct);
        await Measure(reader, "Before counts", before.Summary, before.Arguments, ct);

        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/438_problem_queue_read.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(owner, "vacuum analyze", ct);
        await PostCollectionPostgres.Sql(reader, "set " + ProblemRepository.QueueWorkMem, ct);
        var after = ProblemRepository.FindingsQueries(query, usePasswordProjection: true, useQueueRead: true);
        var page = await Measure(reader, "After page", after.Page, after.Arguments, ct);
        var counts = await Measure(reader, "After counts", after.Summary, after.Arguments, ct);
        await VerifyEndpoint(fixture, before, reader, ct);

        foreach (var variant in new[] {
            query, query with { GroupQueue = false }, query with { QueueView = "active", GroupQueue = false },
            query with { QueueView = "deferred" }, query with { QueueView = "resolved", OldestFirst = true },
            query with { QueueView = "open", Domains = [1, 2], Suppressed = true, Risk = "all" },
            query with { Domains = [] }, query with { Search = "Synthetic", QueueAssignee = "synthetic-user" }
        })
        {
            await AssertParity(reader, variant, ct);
        }
        var first = await Read(reader, after.Page, after.Arguments, ct);
        Assert.Equal(51, first.Count);
        var last = first[49]!;
        await AssertParity(reader, query with {
            BeforeId = last["queue_cursor_id"]!.GetValue<long>(),
            BeforeSeen = DateTimeOffset.Parse(last["queue_sort_at"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture)
        }, ct);

        await PostCollectionPostgres.Sql(owner, """
            update findings set status='active',target='changed-object',last_seen_utc=(now()+interval '1 day')::text where id=217;
            update finding_event_copies337 set domain_id=2 where finding_id=217;
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,evidence_role)
            select finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,'synthetic-duplicate' from finding_event_copies337
            where finding_id=217 and event_kind in (104,1102) limit 1;
            update semantic_security_scenarios set strict_keys_json='{"entity":"synthetic-moved"}'
                where scenario_id=md5('load-221')::uuid;
            delete from finding_event_copies337 where finding_id=216;
            delete from findings where id=20000 and not exists (
                select 1 from semantic_finding_publications where finding_id=20000);
            """, ct);
        await AssertParity(reader, query, ct);
        await AssertParity(reader, query with { Domains = [2] }, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await AssertParity(reader, query, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
        Assert.InRange(page.Milliseconds, 0, 300);
        Assert.InRange(page.Blocks, 0, 3000);
        Assert.InRange(counts.Milliseconds, 0, 200);
    }

    private async Task VerifyEndpoint(SqlPostgresFixture fixture,
        (string Page, string Summary, Dictionary<string, object?> Arguments) before,
        NpgsqlConnection db, CancellationToken ct)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build();
        var connections = new PostgresConnectionFactory(config);
        var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), definition,
            nativeReader: new SecurityProblemsReader(new ProblemRepository(connections, TimeProvider.System),
                new SecurityProblemEvidence(new SemanticDatabase(connections))));

        var watch = Stopwatch.StartNew();
        byte[] response = await host.Client.GetByteArrayAsync(
            "/api/v2/reports/security.problems/data?queue_view=all&domain=1&limit=50&direction=desc&sort=last_seen_utc", ct);
        watch.Stop();
        output.WriteLine($"First report request: {watch.Elapsed.TotalMilliseconds:F3} ms");
        var body = JsonNode.Parse(response)!;
        var expected = await Read(db, before.Page, before.Arguments, ct);
        Assert.Equal(expected.Take(50).Select(r => r!["id"]!.ToString()),
            body["items"]!.AsArray().Select(r => r!["id"]!.ToString()));
        var counters = (await Read(db, before.Summary, before.Arguments, ct)).OfType<JsonObject>().ToArray();
        long Count(params string[] statuses) => counters
            .Where(r => statuses.Length == 0 || statuses.Contains(r["status"]!.ToString()))
            .Sum(r => r["count"]!.GetValue<long>());
        var tabs = body["series"]!["queue_counts"]!;
        Assert.Equal(Count(), tabs["all"]!.GetValue<long>());
        Assert.Equal(Count("new", "confirmed", "repeated"), tabs["open"]!.GetValue<long>());
        Assert.Equal(Count("active", "review"), tabs["active"]!.GetValue<long>());
        Assert.Equal(Count("deferred"), tabs["deferred"]!.GetValue<long>());
        Assert.Equal(Count("closed", "false_positive"), tabs["resolved"]!.GetValue<long>());
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"First report request took {watch.Elapsed.TotalMilliseconds:F3} ms");
    }

    private static async Task AssertParity(NpgsqlConnection db, FindingQuery query, CancellationToken ct)
    {
        var before = ProblemRepository.FindingsQueries(query, usePasswordProjection: true);
        var after = ProblemRepository.FindingsQueries(query, usePasswordProjection: true, useQueueRead: true);
        var expected = await Read(db, before.Page, before.Arguments, ct);
        var actual = await Read(db, after.Page, after.Arguments, ct);
        Assert.Equal(expected.Select(r => r!["id"]!.ToString()), actual.Select(r => r!["id"]!.ToString()));
        Assert.True(JsonNode.DeepEquals(expected, actual), "Queue rows changed.");
        var expectedCounts = await Read(db, before.Summary, before.Arguments, ct);
        var actualCounts = await Read(db, after.Summary, after.Arguments, ct);
        Assert.Equal(expectedCounts.Select(r => r!.ToJsonString()).Order(), actualCounts.Select(r => r!.ToJsonString()).Order());
    }

    private async Task<(double Milliseconds, int Blocks)> Measure(NpgsqlConnection db, string label, string sql,
        Dictionary<string, object?> args, CancellationToken ct)
    {
        await using var command = Command(db, "explain (analyze,buffers,timing off,format json) select to_jsonb(r) from (" + sql + ") r", args);
        var explain = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)![0]!;
        var plan = explain["Plan"]!;
        double ms = explain["Execution Time"]!.GetValue<double>();
        int blocks = Blocks(plan);
        output.WriteLine($"{label}: {ms:F3} ms, {blocks} execution buffers, {explain["Planning Time"]} ms planning");
        if (label.StartsWith("After", StringComparison.Ordinal) && (blocks > 3000 || ms > 200))
            WritePlan(plan);
        return (ms, blocks);
    }

    private static int Blocks(JsonNode plan) => new[] { "Shared Hit Blocks", "Shared Read Blocks", "Temp Read Blocks", "Temp Written Blocks" }
        .Sum(name => plan[name]?.GetValue<int>() ?? 0);

    private void WritePlan(JsonNode plan)
    {
        var children = plan["Plans"] as JsonArray ?? [];
        int own = Blocks(plan) - children.OfType<JsonObject>().Sum(Blocks);
        if (Blocks(plan) > 200)
            output.WriteLine($"  {plan["Node Type"]} {plan["Relation Name"] ?? plan["Index Name"]} {plan["Subplan Name"]}: own={own}, total={Blocks(plan)}, rows={plan["Actual Rows"]}, loops={plan["Actual Loops"]}");
        foreach (var child in children.OfType<JsonObject>()) WritePlan(child);
    }

    private static async Task<JsonArray> Read(NpgsqlConnection db, string sql, Dictionary<string, object?> args, CancellationToken ct)
    {
        await using var command = Command(db, "select to_jsonb(r) from (" + sql + ") r", args);
        var result = new JsonArray();
        await using var rows = await command.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct)) result.Add(JsonNode.Parse(rows.GetString(0)));
        return result;
    }

    private static NpgsqlCommand Command(NpgsqlConnection db, string sql, Dictionary<string, object?> args)
    {
        var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        foreach (var (name, value) in args) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    private const string Seed = """
        insert into domains(id,forest_id,fqdn) select 2,forest_id,'other.example.test' from domains where id=1;
        insert into findings(id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc,assigned_to,repeat_count)
        select n,'semantic:'||encode(sha256(('load-'||n)::bytea),'hex'),
            case n%31 when 0 then 'semantic.qw.security-log-cleared' when 1 then 'semantic.qw.privileged-group-addition'
                when 2 then 'semantic.qw.audit-disabled' else 'semantic.synthetic-load' end,'Synthetic load finding',
            (array['new','confirmed','repeated','active','review','closed','false_positive'])[1+n%7],
            (array['high','medium','low','critical'])[1+n%4],'synthetic-source','synthetic-actor',
            'object-'||(n%5249),100,(date_trunc('day', now())+n*interval '1 second')::text,
            (date_trunc('day', now())+n*interval '1 second')::text,
            case when n%11=0 then 'synthetic-user' end,n%3
        from generate_series(215,20000) n;
        insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
        select md5('load-'||n)::uuid,'synthetic-load','control_gap',sha256(('load-identity-'||n)::bytea),sha256(('load-'||n)::bytea),
            'synthetic',case when n%17=0 then jsonb_build_object('entity','synthetic-entity-'||(n%17)) else '{}'::jsonb end,
            300,'Synthetic load scenario','Synthetic queue load',now(),now(),'low' from generate_series(215,20000) n;
        insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
        select md5('load-observation-'||n)::uuid,sha256(('load-observation-'||n)::bytea),'synthetic','synthetic','unknown',
            'Synthetic queue load',now(),'synthetic-load-'||n from generate_series(215,20000) n;
        insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
        select md5('load-job-'||n)::uuid,'synthetic-paging',1,'control_health',md5('load-observation-'||n)::uuid,
            md5('load-observation-'||n)::uuid::text,'enabled',sha256(('load-job-'||n)::bytea),'completed',now()
        from generate_series(215,20000) n;
        insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
        select md5('load-job-'||n)::uuid,md5('load-'||n)::uuid,'enabled','low',1,1,false,'low',1,'unknown',1
        from generate_series(215,20000) n;
        insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
        select md5('load-'||id)::uuid,id,md5('load-job-'||id)::uuid,fingerprint,100 from findings where id>=215 and id%97<>0 and id<>20000;
        insert into finding_queue_deferrals(finding_id,until_at)
        select id,now()+(case when id%2=0 then interval '1 day' else interval '-1 day' end) from findings where id%59=0;
        insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
        select n,1000000+k,date_trunc('day',now())+k%500000*interval '100 milliseconds',
            case when k%10=0 then (array[1102,4728,4719,104,4732,4756])[1+k%6] else 4625 end,
            case when n%20=0 or n%43=0 and k%2=0 then 2 else 1 end,'synthetic-actor','dc01.example.test',
            '{"$channel":"Security"}','{}','{}',sha256(k::text::bytea),'semantic_scenario'
        from generate_series(1, 2000000-(select count(*) from finding_event_copies337)) k
        cross join lateral (select 215+k%19786 as n) f order by n,k;
        select public.create_event_storage_partitions((now() at time zone 'UTC')::date,(now() at time zone 'UTC')::date);
        insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256)
        select n,date_trunc('day',now())+n*interval '100 milliseconds',4625,1,'synthetic-actor','synthetic-target',
            '192.0.2.1','dc01.example.test','{}','{}','{}',sha256(n::text::bytea)
        from generate_series(1,500000) n;
        """;
}
