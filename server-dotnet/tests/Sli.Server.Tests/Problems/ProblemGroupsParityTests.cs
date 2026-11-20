using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests.Problems;

// Behavioral vectors from tests/reporting/test_problem_groups.py.
public sealed class ProblemGroupsParityTests
{
    const string Member = "S-1-5-21-100000001-200000002-300000003-1101";
    const string Group = "S-1-5-21-100000001-200000002-300000003-512";
    static string Cohort => JsonSerializer.Serialize(new object[] { "membership", "synthetic-rule", 7, 11, Member, Group, "2026-10-01" });
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static long N(JsonNode? node) => long.Parse(node!.ToString(), System.Globalization.CultureInfo.InvariantCulture);
    static FindingQuery Query(string cohort, int limit = 200) => new(null, null, null, null, null, null, null, [7], limit, false)
        { Cohort = cohort, Compact = true, PageQueue = true, Population = "attention" };

    [Fact]
    public void ExactTypedCohortsRoundTripAndRejectInvalidIdentitiesAndDays()
    {
        const string queue = """["queue","synthetic-rule","synthetic-actor","synthetic-object",["synthetic-group"],"2026-10-09"]""";
        foreach (string raw in new[] { Cohort, queue, "[\"finding\",7]", """["object","r",7,11,"x","2026-10-01"]""" })
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(raw), ProblemCohorts.Parse(raw)));
        var invalid = new[] { "{}", "[]", "[\"finding\",0]", "[\"finding\",true]",
            """["membership","r",7,11,"SID","SID","bad"]""",
            Cohort.Replace("2026-10-01", "2026-02-30"), """["object","r",true,11,"x","2026-10-01"]""",
            queue.Replace("\"synthetic-actor\"", "null"), queue.Replace("\"synthetic-group\"", "null"),
            queue.Replace("2026-10-09", "invalid") };
        foreach (string raw in invalid)
            Assert.Equal("problem_cohort_invalid", Assert.Throws<ProblemException>(() => ProblemCohorts.Parse(raw)).Code);
    }

    [Fact]
    public async Task GeneratedLongCohortLinksSurviveTheRealParserAndRequireIdentityAccess()
    {
        var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        var parameter = definition.Params.Single(p => p["key"]!.ToString() == "cohort");
        Assert.True(parameter["hidden"]!.GetValue<bool>());
        Assert.Equal(new[] { "identity_basic" }, parameter["field_categories"]!.AsArray().Select(v => v!.ToString()));
        foreach (string target in new[] { new string('x', 300), string.Concat(Enumerable.Repeat("Учётка", 300)) })
        {
            string cohort = new JsonArray("object", "synthetic", 7, 11, target, "2026-10-01").ToJsonString(new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            string link = HomeSummaryQuery.Href("security.problems", new Dictionary<string, object?> { ["domain"] = 7, ["cohort"] = cohort, ["tz"] = "UTC" });
            var (parsed, _) = ReportParameters.Parse(definition, new QueryCollection(QueryHelpers.ParseQuery(link[link.IndexOf('?')..])));
            Assert.Equal(cohort, parsed["cohort"]!.ToString());
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(cohort), ProblemCohorts.Parse(parsed["cohort"]!.ToString())));
        }
        var repo = new ProblemEndpointTests.Repository();
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), definition, nativeReader: new SecurityProblemsReader(repo, new SecurityProblemEvidence(new Sli.Server.Semantic.SemanticDatabase(new NoDatabase()))));
        using (var allowed = await host.Client.GetAsync("/api/v2/reports/security.problems/data?cohort=" + Uri.EscapeDataString(Cohort), Ct))
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var facts = ProblemEndpointTests.Facts();
        // Remove identity from both capability and atomic report grants.
        host.Facts.Value = StripIdentity(facts);
        int before = repo.Calls;
        using var denied = await host.Client.GetAsync("/api/v2/reports/security.problems/data?cohort=" + Uri.EscapeDataString(Cohort), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Equal(before, repo.Calls);
    }

    static AccessFacts StripIdentity(AccessFacts facts)
    {
        // AccessFacts is intentionally composed by the same public composer as production.
        return JsonSerializer.Deserialize<AccessFacts>(JsonSerializer.Serialize(facts).Replace("identity_basic", "technical"))!;
    }
    sealed class NoDatabase : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("No evidence read expected");
    }
    sealed class Database(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    sealed class HomeRows(string state, string[] objects) : IHomeSummaryRepository
    {
        public List<string> Calls { get; } = [];
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            if (sql == HomeAgentLinkWarning.Sql) return Task.FromResult<IReadOnlyList<JsonObject>>([]);
            if (sql.Contains("to_regprocedure('public.detections_use_short337()')"))
                return Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["installed"] = true }]);
            if (sql.Contains("public.detections_use_short337() as enabled"))
                return Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["enabled"] = true }]);
            if (sql.Contains("population as materialized"))
            {
                Calls.Add("aggregate");
                return Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["cohort"] = JsonNode.Parse(Cohort), ["rule_code"] = "synthetic-rule", ["total"] = 188,
                    ["total_problems"] = 208, ["total_groups"] = 9, ["object_names"] = JsonSerializer.SerializeToNode(objects),
                    ["domain_name"] = "example.test", ["representative"] = new JsonObject { ["id"] = 7, ["evidence_count"] = 1 } }]);
            }
            if (sql.Contains("runtime_worker_heartbeats")) { Calls.Add("heartbeat"); return Task.FromResult<IReadOnlyList<JsonObject>>([]); }
            Calls.Add("names");
            if (state == "unavailable") throw new InvalidOperationException("private-source-error");
            if (state == "timeout") throw new OperationCanceledException("private-source-error");
            return Task.FromResult<IReadOnlyList<JsonObject>>(objects.SelectMany((sid, i) =>
                Enumerable.Range(0, state == "ambiguous" ? 2 : 1).Select(n => new JsonObject { ["request_index"] = i,
                    ["witness_verified"] = true, ["entity_id"] = state == "no_match" ? null : JsonValue.Create(i * 2 + n + 1),
                    ["label"] = state == "no_match" ? null : sid, ["source_run_id"] = "synthetic-run",
                    ["observed_at_utc"] = "2026-08-01T00:00:00Z", ["event_db_id"] = 91 })).ToArray());
        }
    }
    static HomeReport HomeReport()
    {
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { 7 } }),
            new HashSet<string> { "security", "identity_basic", "raw_evidence" }, new HashSet<string> { "view" }, 1, 1);
        return new(new("security.problems", "security.queue", "domain", new HashSet<string> { "security" }, new HashSet<string>(), null, false),
            new("security.queue", true, [grant]), JsonSerializer.SerializeToElement(new { }), JsonSerializer.SerializeToElement(new { }));
    }
    static Task<JsonObject> Home(IHomeSummaryRepository rows) => new HomeDecisionSummary(new(rows)).Build(HomeReport(),
        [new DomainItem(7, "example.test", false, new(null, null, null, null, null, null, null))], new Principal("api_key", 1, "viewer"),
        HomeSummaryQuery.Parse(new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["contract"] = "v3" }), DateTimeOffset.UtcNow), Ct);

    [Theory]
    [InlineData("no_match")]
    [InlineData("ambiguous")]
    [InlineData("unavailable")]
    [InlineData("timeout")]
    [InlineData("named")]
    public async Task OptionalNamesKeepProvenCountsExactLinksIdentifiersAndProvenance(string state)
    {
        var rows = new HomeRows(state, [Member, Group]);
        var body = await Home(rows); var group = body["groups"]![0]!;
        Assert.Equal(188, N(group["total"])); Assert.Equal(208, N(body["total"]));
        string link = group["href"]!.ToString();
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(Cohort), JsonNode.Parse(QueryHelpers.ParseQuery(link[link.IndexOf('?')..])["cohort"].ToString())));
        var objects = group["objects"]!.AsArray();
        Assert.Equal(new[] { Member, Group }, objects.Select(o => o!["identifier"]!.ToString()));
        Assert.All(objects, obj => {
            Assert.Equal(state == "named" ? obj!["identifier"]!.ToString() : "", obj!["name"]!.ToString());
            Assert.Equal(state == "timeout" ? "unavailable" : state, obj["name_state"]!.ToString());
            if (state == "named") { Assert.Equal("synthetic-run", obj["source"]!["source_run_id"]!.ToString()); Assert.Equal(91, N(obj["source"]!["event_db_id"])); }
        });
        Assert.Equal(new[] { "aggregate", "heartbeat", "names" }, rows.Calls);
        Assert.DoesNotContain("private-source-error", body.ToJsonString()); Assert.Null(group["representative"]);
    }

    [Theory]
    [InlineData("ordinary-name")]
    [InlineData("00000000-0000-4000-8000-000000000001")]
    [InlineData("sid:not-a-principal")]
    public async Task UntypedIdentifiersRemainLiteral(string value)
    {
        var rows = new HomeRows("unavailable", [value]); var body = await Home(rows);
        var obj = body["groups"]![0]!["objects"]![0]!;
        Assert.Equal(value, obj["identifier"]!.ToString()); Assert.Equal(value, obj["name"]!.ToString()); Assert.Equal("literal", obj["name_state"]!.ToString());
        Assert.Equal(new[] { "aggregate", "heartbeat" }, rows.Calls);
    }

    [Fact]
    public async Task NativeCohortsPreserveFullPopulationExactDaysIncompleteSourcesAndKeysets()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, FixtureSql, Ct);
        var repository = new ProblemRepository(new Database(pg.ConnectionString), TimeProvider.System);
        var access = ProblemLifecycleTests.Access("security.queue");
        async Task<IReadOnlyList<JsonObject>> Groups(string zone = "UTC", string extra = "") => await new HomeSummaryRepository(new Database(pg.ConnectionString))
            .ReadAsync(HomeDecisionSql.Groups(true).Replace("is_semantic_finding_published_v1(findings.id)", "is_semantic_finding_published_v1(findings.id)" + extra),
                new Dictionary<string, object?> { ["ids"] = new long[] { 7 }, ["from"] = null, ["to"] = null, ["since"] = null, ["zone"] = zone }, Ct);
        var groups = await Groups();
        Assert.Equal(8, groups.Count); Assert.All(groups, row => Assert.Equal(22, N(row["total_problems"])));
        var main = groups.Single(row => N(row["occurrence_count"]) == 189);
        Assert.Equal("rule-object", main["cohort"]![0]!.ToString()); Assert.True(N(main["total_groups"]) > 8);
        var data = await repository.FindingsAsync(Query(Cohort), access, Ct);
        Assert.Equal(Enumerable.Range(1, 188).Select(i => (long)i).Reverse(), data["items"]!.AsArray().Select(r => N(r!["id"])));
        Assert.False(data["has_more"]!.GetValue<bool>());
        Assert.Contains(await Groups("Europe/Berlin"), r => N(r["occurrence_count"]) == 189 && r["day"] is null);
        foreach (int id in Enumerable.Range(193, 5).Append(198).Append(210))
        {
            var row = Assert.Single(await Groups(extra: $" and findings.id={id}"));
            Assert.Equal(1, N(row["occurrence_count"]));
            if (id is 193 or 198) Assert.Null(row["domain_name"]);
        }
        // Singleton drilldown never regroups an otherwise complete membership witness.
        var singleton = await repository.FindingsAsync(Query("[\"finding\",7]"), access, Ct);
        Assert.Equal(7, N(Assert.Single(singleton["items"]!.AsArray())!["id"]));
        await PostCollectionPostgres.Sql(db, """
            insert into findings_active(id,rule_code,title,severity,created_at,first_seen_utc,last_seen_utc,assigned_to,actor,target,evidence_count,status,repeat_count,updated_at) select 210+n,rule_code,title,severity,created_at,first_seen_utc,last_seen_utc,assigned_to,actor,target,evidence_count,status,repeat_count,updated_at from findings_active cross join generate_series(1,17) n where id=1;
            insert into finding_evidence(finding_id,event_id) select 210+n,210+n from generate_series(1,17) n;
            insert into events_v2_core(id,event_id,domain_id,server_id,time_created_utc,target_user_sid,channel_id,provider_id) select 210+n,event_id,domain_id,server_id,time_created_utc,target_user_sid,channel_id,provider_id from events_v2_core cross join generate_series(1,17) n where id=1;
            insert into event_facts_v2 select 210+n,membership_member_sid from event_facts_v2 cross join generate_series(1,17) n where event_id=1;
            """, Ct);
        Assert.Contains(await Groups(), r => N(r["occurrence_count"]) == 206 && N(r["total_problems"]) == 22);
        var first = await repository.FindingsAsync(Query(Cohort), access, Ct);
        Assert.True(first["has_more"]!.GetValue<bool>()); Assert.Equal(200, first["items"]!.AsArray().Count);
        long after = N(first["items"]!.AsArray()[^1]!["id"]);
        var second = await repository.FindingsAsync(Query(Cohort) with { BeforeId = after }, access, Ct);
        Assert.False(second["has_more"]!.GetValue<bool>()); Assert.Equal(5, second["items"]!.AsArray().Count);
        var ids = first["items"]!.AsArray().Concat(second["items"]!.AsArray()).Select(r => N(r!["id"])).ToArray();
        Assert.Equal(Enumerable.Range(1, 188).Concat(Enumerable.Range(211, 17)).Select(i => (long)i).OrderDescending(), ids); Assert.Equal(205, ids.Distinct().Count());
        Assert.Equal(205, second["summary"]!.AsArray().Sum(r => N(r!["count"])));
        // Published queue identities may group without retained events; exact domain/publication/suppression filters still apply.
        await PostCollectionPostgres.Sql(db, """
            insert into findings_active(id,rule_code,title,severity,created_at,first_seen_utc,last_seen_utc,assigned_to,actor,target,evidence_count,status,repeat_count,updated_at) select n,rule_code,title,severity,created_at,first_seen_utc,last_seen_utc,assigned_to,'synthetic-actor','synthetic-object',0,status,repeat_count,updated_at from findings_active cross join generate_series(228,233) n where id=1;
            insert into finding_entities values(228,'synthetic-group','container_entity'),(229,'synthetic-group','container_entity'),(230,'synthetic-group','container_entity'),(231,'synthetic-group','container_entity'),(232,'synthetic-group','container_entity'),(233,'synthetic-group','container_entity');
            insert into semantic_suppressions(id,kind,state,expires_at,semantic_type)
                values(1,'suppression','active',now()+interval '1 day','synthetic-rule');
            update findings_active set status='closed' where id=233;
            """, Ct);
        const string queue = """["queue","synthetic-rule","synthetic-actor","synthetic-object",["synthetic-group"],"2026-10-01"]""";
        var queueRows = await repository.FindingsAsync(Query(queue), access, Ct);
        Assert.Equal(new long[] { 229, 228 }, queueRows["items"]!.AsArray().Select(r => N(r!["id"])));
        var filtered = await repository.FindingsAsync(Query(queue) with { BeforeId = 229 }, access, Ct);
        Assert.Equal(228, N(Assert.Single(filtered["items"]!.AsArray())!["id"])); Assert.Equal(2, filtered["summary"]!.AsArray().Sum(r => N(r!["count"])));
    }

    sealed class OnlyFinding(IHomeSummaryRepository repository, int id) : IHomeSummaryRepository
    {
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
            repository.ReadAsync(sql.Contains("population as materialized") ? sql.Replace("is_semantic_finding_published_v1(findings.id)", $"is_semantic_finding_published_v1(findings.id) and findings.id={id}") : sql, parameters, ct);
    }

    [Fact]
    public async Task HomeSidLookupRequiresCompleteSingleDomainWitnessesAndRetainsHistoricalNames()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, FixtureSql + IdentityFixtureSql, Ct);
        // Missing, incomplete and mixed-domain evidence cannot authorize a name lookup.
        async Task<JsonObject> Read(int id) => await Home(new OnlyFinding(new HomeSummaryRepository(new Database(pg.ConnectionString)), id));
        foreach (var (id, state) in new[] { (193, "unverified"), (197, "unverified"), (198, "unverified"), (7, "no_match") })
        {
            var data = await Read(id); var group = data["groups"]![0]!;
            Assert.Equal(1, N(data["total"]));
            Assert.Equal("", group["objects"]![0]!["name"]!.ToString());
            Assert.Equal(state, group["objects"]![0]!["name_state"]!.ToString());
        }
        await PostCollectionPostgres.Sql(db, """
            insert into ad_context_entity_aliases values(7,'object_sid','s-1-5-21-100000001-200000002-300000003-1101',1);
            insert into ad_context_runs values('synthetic-run',7,'completed','2026-08-01T00:00:00Z');
            insert into ad_context_sections values('synthetic-run','directory_accounts','complete');
            insert into ad_context_entity_versions values(1,'synthetic-run','directory_accounts',
                '{"identity":{"kind":"ad_user","object_sid":"S-1-5-21-100000001-200000002-300000003-1101"},"attributes":{"display_name":"S-1-5-21-100000001-200000002-300000003-1101"}}',
                '2026-08-01T00:00:00Z',null);
            """, Ct);
        var named = (await Read(7))["groups"]![0]!["objects"]![0]!;
        Assert.Equal(Member, named["name"]!.ToString()); Assert.Equal("named", named["name_state"]!.ToString());
        Assert.Equal(Member, named["identifier"]!.ToString());
        Assert.Equal("synthetic-run", named["source"]!["source_run_id"]!.ToString()); Assert.Equal(7, N(named["source"]!["event_db_id"]));
        await PostCollectionPostgres.Sql(db, """
            insert into ad_context_entity_aliases select domain_id,alias_type,normalized_value,2 from ad_context_entity_aliases;
            insert into ad_context_entity_versions select 2,source_run_id,source_section,attributes_json,valid_from_utc,valid_to_utc from ad_context_entity_versions;
            """, Ct);
        var ambiguous = (await Read(7))["groups"]![0]!["objects"]![0]!;
        Assert.Equal("", ambiguous["name"]!.ToString()); Assert.Equal("ambiguous", ambiguous["name_state"]!.ToString());
    }

    [Fact]
    public async Task OptionalDetailedLabelsFailAfterMandatoryReadsAndPreserveFindingAndSummary()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, FixtureSql + IdentityFixtureSql + """
            alter table finding_entities add column entity_id bigint,add column entity_type text;
            create table finding_status_history(id bigint,finding_id bigint,old_status text,new_status text,changed_at timestamptz,changed_by text,note text);
            drop table ad_context_entity_aliases;
            """, Ct);
        var repository = new ProblemRepository(new Database(pg.ConnectionString), TimeProvider.System);
        var data = await repository.FindingsAsync(Query("[\"finding\",7]") with { Compact = false }, ProblemLifecycleTests.Access("security.queue"), Ct);
        var row = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(7, N(row["id"])); Assert.Equal(1, data["summary"]!.AsArray().Sum(r => N(r!["count"])));
        Assert.Equal("unavailable", row["identity_context"]!["snapshot_state"]!.ToString());
        Assert.DoesNotContain("ad_context_entity_aliases", data.ToJsonString());
    }

    const string IdentityFixtureSql = """
        create table servers(id bigint,hostname text); insert into servers values(11,'server.example.test');
        create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
        create table ad_context_entity_versions(entity_id bigint,source_run_id text,source_section text,attributes_json jsonb,valid_from_utc timestamptz,valid_to_utc timestamptz);
        create table ad_context_runs(run_id text,domain_id bigint,status text,observed_at_utc timestamptz);
        create table ad_context_sections(run_id text,section_name text,status text);
        """;

    const string FixtureSql = """
        create table findings_active(id bigint,rule_code text,title text,severity text,created_at timestamptz,first_seen_utc text,last_seen_utc text,assigned_to text,actor text,target text,evidence_count bigint,status text,repeat_count int,updated_at timestamptz);
        create table finding_evidence(finding_id bigint,event_id bigint,evidence_role text,note text);
        create table events_v2_core(id bigint,event_id int,domain_id bigint,server_id bigint,time_created_utc timestamptz,target_user_sid text,channel_id int,provider_id int,target_domain_id bigint,subject_domain_id bigint,target_user_name text,ip_address text,workstation_name text,event_record_id bigint,subject_user_name text,subject_user_sid text);
        create table event_facts_v2(event_id bigint,membership_member_sid text);
        create table storage_v2_channel(id int,value text); insert into storage_v2_channel values(1,'Security'),(2,'Application');
        create table storage_v2_domain_name(id bigint,value text);
        create table storage_v2_provider(id int,value text); insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing'),(2,'Synthetic-Other-Provider');
        create view finding_event_details337 as
            select fe.finding_id,e.id as event_db_id,e.event_id,e.domain_id,e.server_id,e.time_created_utc,
                e.target_user_sid,f.membership_member_sid,c.value as channel,p.value as identity_provider,
                e.event_record_id,'server.example.test'::text as hostname,fe.evidence_role,fe.note,
                e.subject_user_sid,e.subject_user_name,null::text as subject_domain_name,
                e.target_user_name,null::text as target_domain_name,e.ip_address,e.workstation_name
            from finding_evidence fe join events_v2_core e on e.id=fe.event_id
            left join event_facts_v2 f on f.event_id=e.id
            left join storage_v2_channel c on c.id=e.channel_id left join storage_v2_provider p on p.id=e.provider_id;
        create table domains(id bigint,fqdn text); insert into domains values(7,'example.test'),(8,'other.example.test');
        create table finding_entities(finding_id bigint,display_name text,entity_role text);
        create table auth_users(id bigint,username text);
        create table semantic_suppressions(id bigint,finding_id bigint,kind text,responsible_user_id bigint,
            state text,expires_at timestamptz,semantic_type text not null);
        create table semantic_control_audit(id bigint,action text,actor text,occurred_at timestamptz,details jsonb);
        create table runtime_worker_heartbeats(worker_name text,status text,phase text,heartbeat_at timestamptz,expected_interval_seconds int,details_json jsonb);
        create table findings_refresh_state(pipeline_name text,last_status text,last_error text);
        create function is_semantic_finding_published_v1(bigint) returns boolean language sql as $$select $1<>230$$;
        create function semantic_finding_in_domains_v265(bigint,bigint[]) returns boolean language sql as $$select $1<>231 and ($2 is null or 7=any($2))$$;
        create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as $$select $1=232$$;
        create function semantic_finding_review_v160(bigint) returns jsonb language sql as $$select null::jsonb$$;
        create function finding_decoy_context(bigint) returns jsonb language sql as $$select null::jsonb$$;
        insert into findings_active select n,'synthetic-rule','Synthetic membership',case when n<=188 then 'critical' else 'high' end,
            at::timestamptz,at,at,null,null,
            case when n<=188 or n=190 then 'S-1-5-21-100000001-200000002-300000003-1101' else 'S-1-5-21-100000001-200000002-300000003-1101-'||n end,
            case when n in (193,198) then 2 else 1 end,'new',0,at::timestamptz
            from generate_series(1,210) n cross join lateral (select case when n=190 then '2026-10-02T00:30:00Z' else '2026-10-01T23:30:00Z' end as at) t;
        insert into finding_evidence(finding_id,event_id) select id,id from findings_active where id<>197;
        insert into events_v2_core(id,event_id,domain_id,server_id,time_created_utc,target_user_sid,channel_id,provider_id) select id,4728,case when id=191 then 8 else 7 end,case when id=192 then 12 else 11 end,created_at,
            case when id=189 then 'S-1-5-21-100000001-200000002-300000003-512-9' else 'S-1-5-21-100000001-200000002-300000003-512' end,
            case when id=194 then 2 else 1 end,case when id=196 then null when id=195 then 2 else 1 end from findings_active where id<>197;
        insert into event_facts_v2 select id,target from findings_active where id<>197;
        insert into finding_evidence(finding_id,event_id) values(198,1001);
        insert into events_v2_core(id,event_id,domain_id,server_id,time_created_utc,target_user_sid,channel_id,provider_id) select 1001,event_id,8,server_id,time_created_utc,target_user_sid,channel_id,provider_id from events_v2_core where id=198;
        insert into event_facts_v2 select 1001,membership_member_sid from event_facts_v2 where event_id=198;
        update findings_active set target=repeat('"',2048) where id=210;
        update events_v2_core set event_id=4624 where id=210;
        alter table findings_active add column fingerprint text,add column source text;
        create table semantic_security_scenarios(scenario_key bytea,scenario_kind text,partition_key text,strict_keys_json jsonb);
        """;
}
