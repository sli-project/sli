using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class ProblemQueuePagingTests
{
    const string MembershipFixture = """
        with findings_active as (
          select null::text as fingerprint,null::text as source,0 as repeat_count,n::bigint as id,'synthetic-rule'::text as rule_code,'new'::text as status,
            'high'::text as severity,1::bigint as evidence_count,
            'S-1-5-21-100000001-200000002-300000003-' || case when n<=149 then '1101' else n::text end as target,
            __ACTOR__::text as actor,'2026-10-25T12:00:00Z'::text as first_seen_utc,'2026-10-25T12:00:00Z'::text as last_seen_utc
          from generate_series(1,209) n
        ), finding_entities as (select null::bigint as finding_id,null::text as display_name,'container_entity'::text as entity_role where false),
        finding_event_details337 as (
          select id as finding_id,id as event_db_id,4728 as event_id,7 as domain_id,11 as server_id,
            '2026-10-25T12:00:00Z'::timestamptz as time_created_utc,
            'S-1-5-21-100000001-200000002-300000003-512'::text as target_user_sid,
            'S-1-5-21-100000001-200000002-300000003-' || case when id<=149 then '1101' else id::text end as membership_member_sid,
            'Security'::text as channel,'Microsoft-Windows-Security-Auditing'::text as identity_provider from findings_active
        ),
        domains(id,fqdn) as (values(7,'example.test')),
        semantic_security_scenarios as (select null::bytea as scenario_key,null::text as scenario_kind,null::text as partition_key,null::jsonb as strict_keys_json where false),
        """;

    const string NoEvidenceFixture = """
        with findings_active as (
          select null::text as fingerprint,null::text as source,0 as repeat_count,n::bigint as id,'synthetic-rule'::text as rule_code,'new'::text as status,'high'::text as severity,1::bigint as evidence_count,
            case when n=162 then 'other-actor' when n=164 then null else 'EXAMPLE\operator' end as actor,
            case when n=163 then 'other-object' else 'synthetic-object' end as target,
            case when n=165 then '2026-10-10T09:14:00Z' else '2026-10-09T09:14:00Z' end as first_seen_utc,
            case when n=165 then '2026-10-10T09:14:00Z' else '2026-10-09T09:14:00Z' end as last_seen_utc
          from generate_series(1,166) n
        ), finding_entities as (select 166::bigint as finding_id,'other-group'::text as display_name,'container_entity'::text as entity_role),
        finding_event_details337 as (select null::bigint as finding_id,null::bigint as event_db_id,null::integer as event_id where false),
        domains as (select null::bigint as id,null::text as fqdn where false),
        semantic_security_scenarios as (select null::bytea as scenario_key,null::text as scenario_kind,null::text as partition_key,null::jsonb as strict_keys_json where false),
        """;

    static string Grouped(string fixture, string where = "") => fixture + ProblemCohorts.Queue("from findings_active findings", where, "findings.status", "false")[5..];
    static async Task<JsonObject[]> Rows(NpgsqlConnection db, string sql, params (string Key, object Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, db);
        command.Parameters.AddWithValue("cohort_zone", "UTC");
        foreach (var (key, value) in parameters) command.Parameters.AddWithValue(key, value);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var rows = new List<JsonObject>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken)) {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(reader.GetValue(i)));
            rows.Add(row);
        }
        return rows.ToArray();
    }

    [Fact]
    public async Task RepeatsOfOneObjectAcrossDaysAndActorsHaveOneRowAndLatestTime()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(TestContext.Current.CancellationToken);
        await using var db = await pg.OpenAsync(TestContext.Current.CancellationToken);
        string fixture = NoEvidenceFixture.Replace("generate_series(1,166)", "generate_series(162,166)")
            .Replace("when n=163 then 'other-object'", "when n=163 then 'synthetic-object'");
        var row = Assert.Single(await Rows(db, Grouped(fixture) + " select * from queue_groups"));
        Assert.Equal(5, row["occurrence_count"]!.GetValue<long>());
        Assert.Equal(DateTimeOffset.Parse("2026-10-10T09:14:00Z"), DateTimeOffset.Parse(row["last_seen_utc"]!.ToString()));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetainedWitnessesGroup209FindingsAndPageAll61RowsEvenWithoutActor(bool missingActor)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(TestContext.Current.CancellationToken);
        await using var db = await pg.OpenAsync(TestContext.Current.CancellationToken);
        string cte = Grouped(MembershipFixture.Replace("__ACTOR__", missingActor ? "null" : "'synthetic-actor'"));
        var counts = Assert.Single(await Rows(db, cte + " select count(*) as groups,sum(occurrence_count) as occurrences from queue_groups"));
        Assert.Equal("61", counts["groups"]!.ToString()); Assert.Equal("209", counts["occurrences"]!.ToString());
        var loaded = new List<JsonObject>(); long? after = null;
        for (int page = 0; page < 2; page++) {
            var rows = await Rows(db, cte + " select * from queue_groups" + (after is null ? "" : " where queue_cursor_id<@after") + " order by queue_cursor_id desc limit 51",
                after is null ? [] : [("after", after.Value)]);
            loaded.AddRange(rows.Take(50)); after = rows.Length > 50 ? rows[49]["queue_cursor_id"]!.GetValue<long>() : null;
        }
        Assert.Equal(61, loaded.Count); Assert.Equal(61, loaded.Select(r => r["id"]!.GetValue<long>()).Distinct().Count());
        Assert.Equal(209, loaded.Sum(r => r["occurrence_count"]!.GetValue<long>())); Assert.Null(after);
        var main = Assert.Single(loaded, r => r["occurrence_count"]!.GetValue<long>() == 149);
        Assert.Equal("rule-object", JsonNode.Parse(main["problem_cohort"]!.ToString())![0]!.ToString());
        // Filtering the population before grouping must also reduce the occurrence count.
        string filtered = Grouped(MembershipFixture.Replace("__ACTOR__", "null"), " where findings.id>100");
        var summary = Assert.Single(await Rows(db, filtered + " select count(*) as groups,sum(occurrence_count) as occurrences from queue_groups"));
        Assert.Equal("61", summary["groups"]!.ToString()); Assert.Equal("109", summary["occurrences"]!.ToString());
    }

    [Fact]
    public async Task SameFindingsGroupWithoutLegacyEvidenceAndDrillDownExactly()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(TestContext.Current.CancellationToken);
        await using var db = await pg.OpenAsync(TestContext.Current.CancellationToken);
        var rows = await Rows(db, Grouped(NoEvidenceFixture) + " select * from queue_groups order by occurrence_count desc");
        Assert.Equal(new long[] { 165, 1 }, rows.Select(r => r["occurrence_count"]!.GetValue<long>()));
        string cohort = rows[0]["problem_cohort"]!.ToString();
        _ = ProblemCohorts.Parse(cohort);
        var members = await Rows(db, NoEvidenceFixture.TrimEnd().TrimEnd(',') + " select findings.id from findings_active findings" + ProblemCohorts.Sql("queue-cohort") + " where cohort.key=@cohort::jsonb order by findings.id", ("cohort", cohort));
        Assert.Equal(Enumerable.Range(1, 166).Where(n => n != 163).Select(n => (long)n), members.Select(r => r["id"]!.GetValue<long>()));
    }

    [Fact]
    public async Task GroupingAndRuntimeReaderCompileWithMigratedReaderRole()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct, "adlog_user");
        await PostCollectionPostgres.Sql(db, "set search_path=pg_catalog,public", ct);
        Assert.Empty(await Rows(db, ProblemCohorts.Queue("from findings_active findings", " where false", "findings.status", "false") + " select * from queue_groups"));
        var repository = new ProblemRepository(new ReaderConnections(fixture), TimeProvider.System);
        foreach (bool grouped in new[] { true, false }) {
            var query = SecurityProblemsReader.Input(Context()) with { GroupQueue = grouped, BeforeId = 99, Compact = true };
            var result = await repository.FindingsAsync(query, new(Context().Access), ct);
            Assert.Empty(result["items"]!.AsArray()); Assert.Empty(result["summary"]!.AsArray()); Assert.False(result["has_more"]!.GetValue<bool>());
        }
        await using var admin = await fixture.Pg.OpenAsync(ct);
        await SeedPopulation(admin, ct);
        await using var domain = new NpgsqlCommand("select id from domains where fqdn='example.test'", admin);
        long domainId = Convert.ToInt64(await domain.ExecuteScalarAsync(ct));
        // A published open problem without a domain witness belongs to an all-domain grant,
        // but not to a selected domain. Both screens must make the same choice.
        await PostCollectionPostgres.Sql(admin, "update findings set target='unscoped-object' where id=211", ct);
        foreach (bool allDomains in new[] { false, true }) {
            long[]? scope = allDomains ? null : [domainId];
            var query = SecurityProblemsReader.Input(Context() with { DomainIds = scope }) with { Compact = true };
            var queue = await repository.FindingsAsync(query, new(Context().Access), ct);
            var report = new Sli.Server.Domains.HomeReport(
                new("security.problems", "security.queue", "domain", new HashSet<string> { "security" }, new HashSet<string>(), null, false),
                Context(identity: false).Access.Reports.Single(), default, default);
            var now = DateTimeOffset.UtcNow;
            var stamp = now.ToString("O");
            var domains = new[] { new Sli.Server.Domains.DomainItem(domainId, "example.test", false,
                new(stamp, stamp, "complete", stamp, stamp, stamp, stamp)) };
            var parameters = new Microsoft.AspNetCore.Http.QueryCollection(allDomains ? [] :
                new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["domain_id"] = domainId.ToString() });
            var home = await new Sli.Server.Domains.HomeDecisionSummary(new Sli.Server.Domains.HomeSummaryReaders(
                new Sli.Server.Domains.HomeSummaryRepository(new ReaderConnections(fixture)))).Build(report, domains,
                new("api_key", 1, "admin"), Sli.Server.Domains.HomeSummaryQuery.Parse(parameters, now), ct);
            Assert.Equal(queue["summary"]!.AsArray().Sum(r => r!["count"]!.GetValue<long>()), home["total"]!.GetValue<long>());
            Assert.Equal(allDomains ? 62 : 61, home["total"]!.GetValue<long>());
        }
        foreach (bool grouped in new[] { true, false }) {
            long? after = null; var loaded = new List<JsonObject>();
            do {
                long? previous = after;
                var query = SecurityProblemsReader.Input(Context() with { DomainIds = [domainId] }) with { GroupQueue = grouped, BeforeId = after, Compact = true };
                var result = await repository.FindingsAsync(query, new(Context().Access), ct);
                var items = result["items"]!.AsArray().OfType<JsonObject>().ToArray(); loaded.AddRange(items);
                Assert.Equal(grouped ? 61 : 209, result["summary"]!.AsArray().Sum(r => r!["count"]!.GetValue<long>()));
                if (grouped) Assert.Equal(209, result["summary"]!.AsArray().Sum(r => long.Parse(r!["occurrences"]!.ToString())));
                after = result["has_more"]!.GetValue<bool>() ? items[^1][grouped ? "queue_cursor_id" : "id"]!.GetValue<long>() : null;
                Assert.True(after is null || previous is null || after < previous, "The queue cursor must advance");
            } while (after is not null);
            Assert.Equal(grouped ? 61 : 209, loaded.Count);
            Assert.Equal(loaded.Count, loaded.Select(r => r["id"]!.GetValue<long>()).Distinct().Count());
            Assert.All(loaded, r => Assert.InRange(r["id"]!.GetValue<long>(), 1, 209));
            Assert.Contains(loaded, r => r["status"]!.ToString() == "active"); Assert.Contains(loaded, r => r["status"]!.ToString() == "review");
            if (grouped) Assert.Equal(149, Assert.Single(loaded, r => r["target"]!.ToString() == "synthetic-object")["occurrence_count"]!.GetValue<long>());
            else Assert.Equal(Enumerable.Range(1, 209).Reverse().Select(n => (long)n), loaded.Select(r => r["id"]!.GetValue<long>()));
        }
        foreach (var (parameters, id, expected) in new (JsonObject, long, bool)[] {
            (new() { ["id"] = "212" }, 212, true), (new() { ["population"] = "open" }, 212, false),
            (new() { ["population"] = "attention" }, 212, false), (new() { ["status"] = "closed" }, 212, true),
            (new() { ["risk"] = "accepted" }, 214, true)
        }) {
            var query = SecurityProblemsReader.Input(Context(parameters) with { DomainIds = [domainId] }, id.ToString()) with { Limit = 1, Compact = true };
            var result = await repository.FindingsAsync(query, new(Context().Access), ct);
            Assert.Equal(expected ? 1 : 0, result["items"]!.AsArray().Count);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    internal static async Task SeedPopulation(NpgsqlConnection db, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname,fqdn,role)
                select 1,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test';
            insert into findings(id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc)
            select n,'semantic:'||encode(sha256(('finding-'||n)::bytea),'hex'),'synthetic-rule','Synthetic finding',
                case n when 208 then 'active' when 209 then 'review' when 212 then 'closed' else 'new' end,'high','semantic-production',
                'synthetic-actor',case when n<=149 or n>=210 then 'synthetic-object' else 'object-'||n end,1,now()::text,now()::text
            from generate_series(1,214) n;
            -- 210 is unpublished; 211 has no witness proving access to this domain;
            -- 212 is closed; 213 is suppressed; 214 has an active risk acceptance.
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
            select n,case when n=213 then 2 else 1 end,now(),4625,d.id,
                case when n=213 then 'S-1-5-21-100000001-200000002-300000003-9999' else 'S-1-5-21-100000001-200000002-300000003-1101' end,'dc01',
                jsonb_build_object('$server_id',1,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                    '$principals',jsonb_build_object('SubjectUserSid',case when n=213 then 'S-1-5-21-100000001-200000002-300000003-9999'
                        else 'S-1-5-21-100000001-200000002-300000003-1101' end)),
                '{}','{}',sha256(n::text::bytea),'semantic_scenario'
            from generate_series(1,214) n cross join domains d where n<>211 and d.fqdn='example.test';
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            select md5('scenario-'||n)::uuid,'synthetic','control_gap',sha256(('identity-'||n)::bytea),sha256(('scenario-'||n)::bytea),'synthetic','{}',300,'Synthetic scenario','Synthetic paging',now(),now(),'low' from generate_series(1,214) n;
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values('synthetic-paging',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            select md5('observation-'||n)::uuid,sha256(('observation-'||n)::bytea),'synthetic','synthetic','unknown','Synthetic paging',now(),'synthetic-'||n from generate_series(1,214) n;
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            select md5('job-'||n)::uuid,'synthetic-paging',1,'control_health',md5('observation-'||n)::uuid,(md5('observation-'||n)::uuid)::text,'enabled',sha256(('job-'||n)::bytea),'completed',now() from generate_series(1,214) n;
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            select md5('job-'||n)::uuid,md5('scenario-'||n)::uuid,'enabled','low',1,1,false,'low',1,'unknown',1 from generate_series(1,214) n;
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            select md5('scenario-'||n)::uuid,n,md5('job-'||n)::uuid,'semantic:'||encode(sha256(('finding-'||n)::bytea),'hex'),1 from generate_series(1,214) n where n<>210;
            insert into semantic_suppressions(semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by)
            select 'synthetic-rule',id,'subject_sid','S-1-5-21-100000001-200000002-300000003-9999','Synthetic suppression',now()+interval '1 day','synthetic-user' from domains where fqdn='example.test';
            insert into semantic_suppressions(semantic_type,scope_kind,scope_value,kind,finding_id,reason,responsible_user_id,expires_at,created_by)
            select 'synthetic-rule','finding','214','risk_acceptance',214,'Synthetic accepted risk',id,now()+interval '1 day','synthetic-user' from auth_users where username='platform-owner';
            """, ct);
    }

    sealed class ReaderConnections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }
}
