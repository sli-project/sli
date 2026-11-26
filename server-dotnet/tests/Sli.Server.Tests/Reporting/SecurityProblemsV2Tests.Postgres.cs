using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class SecurityProblemsV2Tests
{
    sealed class Database(string connectionString) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new NpgsqlConnection(connectionString); await db.OpenAsync(ct); return db; }
    }
    sealed class Pg : IAsyncDisposable
    {
        readonly PostCollectionPostgres cluster = new(canonicalSchema: true);
        internal NpgsqlConnection Db = null!;
        internal ProblemRepository Repository => new(new Database(cluster.ConnectionString), TimeProvider.System);
        internal ProblemRepository Configured(IConfiguration configuration) => new(new Database(cluster.ConnectionString),TimeProvider.System,configuration);
        internal SecurityProblemEvidence Evidence => new(new Sli.Server.Semantic.SemanticDatabase(new Database(cluster.ConnectionString)));
        internal static async Task<Pg> Start()
        {
            var p = new Pg();
            try {
                await p.cluster.StartAsync(Ct); p.Db = await p.cluster.OpenAsync(Ct);
                await p.Sql("""
                    create table findings_active(id bigint,fingerprint text,source text,rule_code text default 'semantic.synthetic',status text default 'new',severity text default 'low',
                      repeat_count integer default 0,last_seen_utc text default '2026-10-01T12:00:00Z',updated_at timestamptz default now(),
                      created_at timestamptz default '2026-10-03T00:00:00Z',domain_id bigint default 7,published boolean default true,suppressed_until timestamptz,
                      title text default 'Audit policy was changed',summary text,why_it_matters text,recommended_action text,actor text,target text,
                      first_seen_utc text,evidence_count integer default 0,assigned_to text);
                    create table auth_users(id bigint,username text); insert into auth_users values(1,'fixture-user');
                    create table semantic_security_scenarios(scenario_key bytea,scenario_kind text,partition_key text,strict_keys_json jsonb);
                    create table semantic_suppressions(id bigint,finding_id bigint,kind text,responsible_user_id bigint,
                      state text,expires_at timestamptz,semantic_type text not null);
                    create table semantic_control_audit(id bigint,action text,actor text,occurred_at timestamptz,details jsonb);
                    create table runtime_worker_heartbeats(worker_name text,status text,phase text,heartbeat_at timestamptz,expected_interval_seconds int,details_json jsonb);
                    create table findings_refresh_state(pipeline_name text,last_status text,last_error text);
                    create table finding_entities(finding_id bigint,entity_id bigint,entity_type text,display_name text,entity_role text);
                    create table finding_evidence(id bigint,finding_id bigint,event_id bigint,created_at timestamptz default '2026-10-01T00:00:00Z',evidence_role text,note text);
                    create table storage_v2_channel(id bigint,value text);
                    create table servers(id bigint,domain_id bigint,hostname text);
                    create table domains(id bigint,netbios_name text,fqdn text);
                    insert into domains values(7,'EXAMPLE','example.test');
                    create table ad_context_entity_aliases(domain_id bigint,entity_id bigint,alias_type text,normalized_value text);
                    create table ad_context_entity_versions(id bigint,entity_id bigint,source_run_id uuid,source_section text,
                        attributes_json jsonb,valid_from_utc timestamptz,valid_to_utc timestamptz);
                    create table ad_context_runs(run_id uuid,domain_id bigint,status text,observed_at_utc timestamptz);
                    create table ad_context_sections(run_id uuid,section_name text,status text);
                    create table finding_event_details337(finding_id bigint,event_db_id bigint,event_id int,time_created_utc timestamptz,
                        domain_id bigint,server_id bigint,target_user_sid text,membership_member_sid text,channel text,identity_provider text,
                        target_domain_name text,target_user_name text,subject_user_name text,ip_address text,workstation_name text,
                        event_record_id bigint,hostname text,evidence_role text,note text);
                    create table finding_status_history(id bigint,finding_id bigint,old_status text,new_status text,changed_at timestamptz,changed_by text,note text);
                    create function is_semantic_finding_published_v1(bigint) returns boolean language sql as $$select published from findings_active where id=$1$$;
                    create function semantic_finding_in_domains_v265(bigint,bigint[]) returns boolean language sql as $$select $2 is null or domain_id=any($2) from findings_active where id=$1$$;
                    create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as $$select coalesce(suppressed_until>statement_timestamp(),false) from findings_active where id=$1$$;
                    create function semantic_finding_review_v160(bigint) returns jsonb language sql as $$select '{"bucket":"machine_account"}'::jsonb$$;
                    create function finding_decoy_context(bigint) returns jsonb language sql as $$select '{"decoy_id":"00000000-0000-4000-8000-000000000003","decoy_revision":1}'::jsonb$$;
                    create function read_file_acl_finding_resources_v265(bigint,bigint[]) returns jsonb language sql as $$select '[]'::jsonb$$;
                    insert into findings_active(id) select generate_series(1,30);
                    insert into findings_active(id,severity,status,repeat_count,suppressed_until) values(99,'critical','repeated',4,now()+interval '1 day');
                    insert into findings_active(id,severity) values(98,'critical');
                    insert into findings_active(id,severity,status,repeat_count) values(97,'high','active',2);
                    insert into findings_active(id,severity,domain_id) values(96,'high',8);
                    insert into findings_active(id,severity,published) values(95,'critical',false);
                    insert into findings_active(id,status) values(94,'closed');
                    insert into findings_active(id) values(93),(92),(91);
                    update findings_active set rule_code='other.rule' where id=92;
                    update findings_active set created_at='2026-10-07T00:00:00Z' where id=91;
                    insert into semantic_suppressions values
                      (1,98,'risk_acceptance',1,'active',now()+interval '1 day','semantic.synthetic'),
                      (2,97,'risk_acceptance',1,'active',now()-interval '1 day','semantic.synthetic'),
                      (3,null,'suppression',null,'active',now()+interval '1 day','semantic.synthetic');
                    insert into finding_entities(finding_id,entity_id) select id,case when id=93 then 8 else 9 end from findings_active;
                    """);
                string migration = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(),
                    "config/postgres_migrations/395_problem_account_identity.sql"), Ct);
                int begin = migration.IndexOf("create function public.password_problem_facts395", StringComparison.Ordinal);
                int end = migration.IndexOf("create function public.notification_password_facts395", StringComparison.Ordinal);
                await p.Sql("create role adlog_user;\n" + migration[begin..end]);
                return p;
            } catch { await p.DisposeAsync(); throw; }
        }
        internal Task Sql(string sql) => PostCollectionPostgres.Sql(Db, sql, Ct);
        internal async Task<JsonArray> Rows(string sql, params (string Key, object? Value)[] args)
        {
            await using var command = new NpgsqlCommand("select to_jsonb(r) from (" + sql + ") r", Db);
            foreach (var (key, value) in args) {
                var parameter = new NpgsqlParameter(key, value ?? DBNull.Value); if (value is null) parameter.NpgsqlDbType = NpgsqlDbType.Unknown;
                command.Parameters.Add(parameter);
            }
            var rows = new JsonArray(); await using var reader = await command.ExecuteReaderAsync(Ct);
            while (await reader.ReadAsync(Ct)) rows.Add(JsonNode.Parse(reader.GetString(0))); return rows;
        }
        public async ValueTask DisposeAsync() { if (Db is not null) await Db.DisposeAsync(); await cluster.DisposeAsync(); }
    }
    static long Total(JsonObject page) => page["summary"]!.AsArray().Sum(r => r!["count"]!.GetValue<long>());

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ThreePublishedFindingsHaveOneQueueRowAndTheSameHomeTotal(bool nativeEntity)
    {
        await using var pg = await Pg.Start();
        await pg.Sql("""
            delete from findings_active;
            insert into findings_active(id,rule_code,target,actor,first_seen_utc,last_seen_utc)
            select n,'semantic.qw.agent-tamper','dc.example.test',case when n=1 then 'EXAMPLE\operator' end,
                '2026-11-11T08:00:00Z','2026-11-'||(10+n)::text||'T08:00:00Z' from generate_series(1,3) n;
            insert into findings_active(id,rule_code,target,first_seen_utc,last_seen_utc,severity)
            select n,'semantic.qw.agent-tamper','dc.example.test','2026-11-11T08:00:00Z','2026-11-13T09:00:00Z','critical' from generate_series(4,7) n;
            update findings_active set published=false where id=4;
            update findings_active set suppressed_until=now()+interval '1 day' where id=5;
            update findings_active set domain_id=8 where id=6;
            insert into semantic_suppressions values
                (4,7,'risk_acceptance',1,'active',now()+interval '1 day','semantic.qw.agent-tamper'),
                (5,null,'suppression',null,'active',now()+interval '1 day','semantic.qw.agent-tamper');
            """);
        if (nativeEntity) await pg.Sql("""
            update findings_active set target=null,actor=null,fingerprint='semantic:'||encode(sha256(id::text::bytea),'hex');
            insert into semantic_security_scenarios
            select sha256(id::text::bytea),'qw.agent-tamper','synthetic-source',
                jsonb_build_object('entity','synthetic-computer','episode','episode-'||id) from findings_active;
            """);
        var query = new FindingQuery(null, null, null, null, null, null, null, [7], 50, false) {
            Compact = true, PageQueue = true, GroupQueue = true, Population = "open"
        };
        var queue = await pg.Repository.FindingsAsync(query, Access, Ct);
        var row = Assert.Single(queue["items"]!.AsArray());
        Assert.Equal(3, row!["occurrence_count"]!.GetValue<long>());
        Assert.Equal(DateTimeOffset.Parse("2026-11-13T08:00:00Z"), DateTimeOffset.Parse(row["last_seen_utc"]!.ToString()));
        foreach (bool identity in new[] { false, true }) {
            var home = Assert.Single(await pg.Rows(HomeDecisionSql.Groups(identity), ("ids", new long[] { 7 }), ("from", null), ("to", null), ("since", null)));
            Assert.Equal(Total(queue), home!["total_problems"]!.GetValue<long>());
            Assert.Equal(3, home["occurrence_count"]!.GetValue<long>());
        }
        string cohort = row["problem_cohort"]!.ToJsonString();
        _ = ProblemCohorts.Parse(cohort);
        var members = await pg.Repository.FindingsAsync(query with { GroupQueue = false, Cohort = cohort }, Access, Ct);
        Assert.Equal(3, members["items"]!.AsArray().Count);
    }

    [Fact]
    public async Task PopulationAndSummaryApplyEntityRiskDomainsAndCreationCohortBeforeLimit()
    {
        await using var pg = await Pg.Start();
        foreach (bool cohort in new[] { false, true }) foreach (string? risk in new string?[] { null, "accepted", "all" }) {
            var q = new FindingQuery(null, null, null, null, null, risk, 9, [7], 1, false) {
                Compact = true, PageQueue = true,
                RuleCode = cohort ? "semantic.synthetic" : null,
                CreatedFrom = cohort ? "2026-10-01T07:00:00+07:00" : null, CreatedTo = cohort ? "2026-10-07T07:00:00+07:00" : null
            };
            var page = await pg.Repository.FindingsAsync(q, Access, Ct);
            long ordinary = cohort ? 32 : 34; // 30 new, expired risk, closed; optional other rule/end boundary.
            long expected = risk == "accepted" ? 1 : ordinary + (risk == "all" ? 1 : 0);
            Assert.Equal(expected, Total(page)); Assert.Single(page["items"]!.AsArray());
            Assert.Equal(risk == "accepted" || risk == "all" ? 98 : 97, Ids(page)[0]); Assert.Equal(expected > 1, page["has_more"]!.GetValue<bool>());
        }
        foreach (long[] domains in new long[][] { [7], [7, 8] }) {
            var page = await pg.Repository.FindingsAsync(new(null, null, null, null, null, null, null, domains, 1, false) { Compact = true, PageQueue = true }, Access, Ct);
            Assert.Equal(domains.Length == 1 ? 35 : 36, Total(page));
        }
        var exact = await pg.Repository.FindingsAsync(new(null, null, null, null, null, null, null, [7], 1, false) { FindingId = 7, Compact = true, PageQueue = true }, Access, Ct);
        Assert.Equal([7L], Ids(exact)); Assert.Equal(1, Total(exact)); Assert.False(exact["has_more"]!.GetValue<bool>());
    }

    [Fact]
    public async Task ScopedAttentionCombinesExactIdEntityCohortAndExpiredRisk()
    {
        await using var pg = await Pg.Start();
        var q = new FindingQuery(null, null, null, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", null, 9, [7], 5, false) {
            FindingId = 97, Population = "attention", RuleCode = "semantic.synthetic", CreatedFrom = "2026-10-01T00:00:00Z", CreatedTo = "2026-10-07T00:00:00Z", Compact = true, PageQueue = true
        };
        var page = await pg.Repository.FindingsAsync(q, Access, Ct); Assert.Equal([97L], Ids(page)); Assert.Equal(1, Total(page));
        Assert.Equal("repeated", page["items"]![0]!["status"]!.ToString()); Assert.Equal("expired", page["items"]![0]!["risk_acceptance"]!["state"]!.ToString());
        foreach (var changed in new[] { q with { Domains = [8] }, q with { EntityId = 8 }, q with { FindingId = 95 }, q with { RuleCode = "other.rule" }, q with { CreatedTo = "2026-10-03T00:00:00Z" }, q with { From = "2026-10-01T12:00:01Z" }, q with { Risk = "accepted" }, q with { Cohort = "[\"finding\",7]" } }) {
            var empty = await pg.Repository.FindingsAsync(changed, Access, Ct); Assert.Empty(Ids(empty)); Assert.Equal(0, Total(empty));
        }
        var cohort = await pg.Repository.FindingsAsync(q with { Cohort = "[\"finding\",97]" }, Access, Ct); Assert.Equal([97L], Ids(cohort)); Assert.Equal(1, Total(cohort));
    }

    [Fact]
    public async Task CompactReaderMapsCanonicalDecoyReferenceWithoutRegistryOrOptionalEnrichment()
    {
        await using var pg = await Pg.Start(); await pg.Sql("update findings_active set rule_code='semantic.qw.account-decoy' where id=7; drop table finding_event_details337; drop table finding_entities; drop table finding_status_history");
        var page = await pg.Repository.FindingsAsync(new(null, null, null, null, null, null, null, null, 1, false) { FindingId = 7, Compact = true }, Access, Ct);
        var row = page["items"]![0]!; Assert.Equal("00000000-0000-4000-8000-000000000003", row["decoy_id"]!.ToString()); Assert.Equal(1, row["decoy_revision"]!.GetValue<int>()); Assert.Null(row["decoy_label"]);
        Assert.Null(row["evidence"]); Assert.Null(row["identity_context"]); Assert.Null(row["linked_case"]);
        // No decoy_label_versions or identity/case tables exist in this cluster.
    }

    [Fact]
    public async Task HomeSqlRanksTheWholeScopedAttentionPopulationBeforeLimitAndRestoresExpiredSuppression()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("delete from findings_active where id between 91 and 98");
        async Task<JsonArray> Rows(string sql) => await pg.Rows(sql, ("ids", new long[] { 7 }), ("from", "2026-10-01T00:00:00Z"), ("to", "2026-10-02T00:00:00Z"), ("all_statuses", false));
        var before = await Rows(HomeSummarySql.Problems); Assert.Equal(6, before.Count); Assert.DoesNotContain(before, r => r!["id"]!.GetValue<long>() == 99);
        Assert.Equal(30, (await Rows(HomeSummarySql.Counts)).Sum(r => r!["count"]!.GetValue<long>()));
        await pg.Sql("update findings_active set suppressed_until=now()-interval '1 second' where id=99");
        var after = await Rows(HomeSummarySql.Problems); Assert.Equal(99, after[0]!["id"]!.GetValue<long>()); Assert.Equal(6, after.Count);
        Assert.Equal(31, (await Rows(HomeSummarySql.Counts)).Sum(r => r!["count"]!.GetValue<long>()));
        await pg.Sql("insert into findings_active(id,severity,status,repeat_count,last_seen_utc) values(101,'critical','repeated',5,'2026-10-01T11:00:00Z'),(102,'critical','repeated',5,'2026-10-01T11:00:00Z'),(103,'critical','repeated',4,'2026-10-01T13:00:00Z'),(104,'critical','repeated',100,'2026-10-02T00:00:00Z')");
        Assert.Equal(new long[] { 102, 101, 103, 99 }, (await Rows(HomeSummarySql.Problems)).Take(4).Select(r => r!["id"]!.GetValue<long>()));
    }

    [Fact]
    public async Task EvidencePagesAllSeventyCopiesWithSealedContextWithoutExpiredSourceOrLinks()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("""
            insert into finding_event_details337(finding_id,event_db_id,event_id,time_created_utc,event_record_id,hostname,channel,evidence_role,domain_id)
                select 7,n,4719,'2026-10-01T00:00:00Z',n,'dc.example.test','Security','semantic_scenario',7 from generate_series(1,70) n;
            """);
        var c = Context(O("""{"status":"new","population":"attention","cohort":"[\"finding\",7]"}"""), 20) with { DomainIds = [7] };
        var reader = new SecurityProblemsReader(pg.Repository, pg.Evidence); var seen = new List<long>(); int pages = 0;
        do {
            var page = await reader.DetailAsync(c, "7", Ct); pages++; Assert.Equal(70, page["filtered_count"]!.GetValue<long>());
            seen.AddRange(page["items"]!.AsArray().Select(r => r!["evidence_id"]!.GetValue<long>()));
            Assert.Equal("ok",page["state"]!.ToString()); Assert.Equal(0,page["coverage"]!["evidence_missing_sources"]!.GetValue<int>());
            if (!page["has_more"]!.GetValue<bool>()) { Assert.Null(page["next_cursor"]); break; }
            c = c with { Paging = c.Paging with { Cursor = page["next_cursor"]!.ToString() } };
        } while (true);
        Assert.Equal(Enumerable.Range(1,70).Select(n => (long)n), seen); Assert.Equal(4, pages);
        await pg.Sql("update findings_active set published=false where id=7; drop table finding_event_details337");
        Assert.Equal(404, (await Assert.ThrowsAsync<ReportRequestException>(() => reader.DetailAsync(c, "7", Ct))).Status);
    }

    [Fact]
    public async Task Event_details_show_retained_account_and_source_only_with_field_access()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("""
            insert into finding_event_details337(finding_id,event_db_id,event_id,time_created_utc,evidence_role,
                event_record_id, target_user_name, subject_user_name, ip_address, workstation_name, hostname, channel, identity_provider)
            values (7,1,4625,'2026-10-01T00:00:00Z','primary',42,'bad�name','SYSTEM','203.0.113.5','client.example.test','dc.example.test','Security','Microsoft-Windows-Security-Auditing'),
                   (7,2,4728,'2026-10-01T00:00:01Z','primary',43,'Administrators','admin','-','client.example.test','dc.example.test',null,null);
            """);
        var c = Context() with { FieldAccess = _ => true };
        var page = await pg.Evidence.PageAsync(c, 7, null, Ct);
        var events = page["items"]!.AsArray();
        Assert.Equal("bad�name", events[0]!["account"]!.GetValue<string>());
        Assert.Equal("203.0.113.5", events[0]!["source"]!.GetValue<string>());
        Assert.Equal("Security:Microsoft-Windows-Security-Auditing:4625.title", events[0]!["event_title_code"]!.GetValue<string>());
        Assert.Equal(42, events[0]!["event_record_id"]!.GetValue<long>());
        Assert.Equal("admin", events[1]!["account"]!.GetValue<string>());
        Assert.Equal("client.example.test", events[1]!["source"]!.GetValue<string>());

        var restricted = await pg.Evidence.PageAsync(c with { FieldAccess = fields => !fields.Contains("identity_basic") }, 7, null, Ct);
        Assert.Null(restricted["items"]![0]!["account"]);
        Assert.Equal("203.0.113.5", restricted["items"]![0]!["source"]!.GetValue<string>());
        restricted = await pg.Evidence.PageAsync(c with { FieldAccess = fields => !fields.Contains("technical") }, 7, null, Ct);
        Assert.Null(restricted["items"]![0]!["source"]);
        Assert.Equal("bad�name", restricted["items"]![0]!["account"]!.GetValue<string>());
    }

    [Fact]
    public async Task Source_clock_ahead_does_not_hide_a_preserved_evidence_copy()
    {
        await using var pg=await Pg.Start();
        await pg.Sql("insert into finding_event_details337(finding_id,event_db_id,time_created_utc,evidence_role) values(7,101,now()+interval '1 day','primary')");
        var page=await pg.Evidence.PageAsync(Context(),7,null,Ct);
        Assert.Equal(101,Assert.Single(page["items"]!.AsArray())!["event_db_id"]!.GetValue<long>());
        Assert.Equal(1,page["total"]!.GetValue<long>());
    }

    [Theory]
    [InlineData("{\"after_id\":1}")]
    [InlineData("{\"version\":2,\"watermark\":\"2026-11-01T00:00:00Z\",\"position\":{\"storage_kind\":\"core_event\",\"native_key\":\"00000000000000000001\"}}")]
    public async Task Retired_link_positions_are_rejected_before_reading_copied_events(string json)
    {
        await using var pg=await Pg.Start();
        var error=await Assert.ThrowsAsync<ReportRequestException>(()=>pg.Evidence.PageAsync(Context(),7,O(json),Ct));
        Assert.Equal("invalid_cursor",error.Message);
    }

    [Fact]
    public async Task Evidence_keyset_keeps_distinct_roles_and_times_for_the_same_event()
    {
        await using var pg=await Pg.Start();
        await pg.Sql("""
            insert into finding_event_details337(finding_id,event_db_id,event_id,time_created_utc,evidence_role,channel)
                values(7,1,4719,'2026-10-01T00:00:00Z','primary','Security'),
                      (7,1,4719,'2026-10-01T00:00:00Z','secondary','Security'),
                      (7,1,4719,'2026-10-02T00:00:00Z','primary','Security'),
                      (7,2,4719,'2026-10-01T00:00:00Z','primary','Security');
            """);
        JsonObject? cursor=null;var seen=new List<string>();
        do {
            var page=await pg.Evidence.PageAsync(Context(limit:1),7,cursor,Ct);
            var item=Assert.Single(page["items"]!.AsArray())!;
            seen.Add(item["event_db_id"]+":"+item["evidence_role"]+":"+DateTimeOffset.Parse(item["time_created_utc"]!.ToString()).Day);
            if(!page["has_more"]!.GetValue<bool>())break;
            cursor=new() { ["version"]=2,["position"]=page["next_position"]!.DeepClone(),["watermark"]=page["watermark"]!.DeepClone() };
            Assert.True(seen.Count<5);
        } while(true);
        Assert.Equal(new[]{"1:primary:1","1:secondary:1","1:primary:2","2:primary:1"},seen);
    }

    [Fact]
    public async Task EvidenceReaderClampsPagesUsesKeysetAndDistinguishesExactAndCappedCounts()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("insert into finding_event_details337(finding_id,event_db_id,time_created_utc,evidence_role) select 7,n,'2026-10-01T00:00:00Z','semantic_scenario' from generate_series(1,10001) n");
        foreach (var (limit, expected) in new[] { (0,1), (1,1), (20,20), (200,200), (1000,200) }) {
            var cursor=new JsonObject { ["version"]=2,["watermark"]="2026-11-01T00:00:00Z",
                ["position"]=new JsonObject { ["storage_kind"]="core_event",["native_key"]="[500,\"2026-10-01T00:00:00Z\",\"semantic_scenario\"]" } };
            var page = await pg.Evidence.PageAsync(Context(limit: limit), 7, cursor, Ct);
            Assert.Equal(expected, page["items"]!.AsArray().Count); Assert.Equal(501, page["items"]![0]!["evidence_id"]!.GetValue<long>()); Assert.True(page["has_more"]!.GetValue<bool>());
            Assert.Null(page["total"]); Assert.Equal(10001, page["total_lower_bound"]!.GetValue<long>());
        }
        foreach (int count in new[] { 10000, 70, 0 }) {
            await pg.Sql("delete from finding_event_details337 where event_db_id>" + count);
            var page = await pg.Evidence.PageAsync(Context(), 7, null, Ct); Assert.Equal(count, page["total"]!.GetValue<long>()); Assert.False(page.ContainsKey("total_lower_bound"));
            if (count == 0) { Assert.Empty(page["items"]!.AsArray()); Assert.False(page["has_more"]!.GetValue<bool>()); }
        }
    }

    [Fact]
    public async Task LinkedCasesAreAuthorizedAndAnUnavailableLinkTableDoesNotBreakTheQueue()
    {
        await using var pg = await Pg.Start();
        await pg.Sql("""
            create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,
                actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
            create table event_cold_facts(like event_hot);
            create table investigations(id bigint,public_id text,status text);
            create table investigation_finding_links(finding_id bigint,investigation_id bigint);
            create table investigation_events(investigation_id bigint,event_db_id bigint);
            create table investigation_evidence_refs(investigation_id bigint,source_domain_id bigint,reference_id text);
            insert into investigations values(4,null,'active'); insert into investigation_finding_links values(7,4);
            insert into investigation_evidence_refs values(4,7,'fixture-reference');
            """);
        var decision = Access.Decision;
        var caseAccess = new ProblemAccess(decision with { Reports = [..decision.Reports, decision.Reports[0] with { ReportKey = "investigations.workspace" }] });
        var q = new FindingQuery(null,null,null,null,null,null,null,null,1,false) { FindingId=7 };
        var linked = await pg.Repository.FindingsAsync(q, caseAccess, Ct); Same(O("""{"id":4,"public_id":null,"status":"active"}"""), linked["items"]![0]!["linked_case"]);
        var unlinked = await pg.Repository.FindingsAsync(q with { FindingId=8 }, caseAccess, Ct); Assert.Null(unlinked["items"]![0]!["linked_case"]);
        var denied = await pg.Repository.FindingsAsync(q, Access, Ct); Assert.Null(denied["items"]![0]!["linked_case"]);
        await pg.Sql("""
            insert into servers values(11,7,'dc.example.test');
            insert into investigation_events values(4,101);
            insert into event_hot values(101,now(),4728,7,null,null,null,'dc.example.test',
                '{"$server_id":11,"$channel":"Security"}','{}','{}');
            """);
        Assert.NotNull((await pg.Repository.FindingsAsync(q, caseAccess, Ct))["items"]![0]!["linked_case"]);
        await pg.Sql("update event_hot set time_created_utc=now()-interval '10 days'");
        foreach(int days in new[]{3,21}) {
            var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:Storage:HotRetentionDays"]=days.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }).Build();
            var page=await pg.Configured(configuration).FindingsAsync(q,caseAccess,Ct);
            Assert.Equal(days==21,page["items"]![0]!["linked_case"] is not null);
        }
        await pg.Sql("update event_hot set time_created_utc=now()");
        await pg.Sql("update event_hot set domain_id=8");
        Assert.Null((await pg.Repository.FindingsAsync(q, caseAccess, Ct))["items"]![0]!["linked_case"]);
        await pg.Sql("""
            delete from event_hot;
            create table event_cold_daily(day date,event_kind int,domain_id bigint,method jsonb,event_count bigint);
            insert into event_cold_daily values(current_date-30,4728,7,'{"$server_id":11,"$channel":"Security"}',100);
            """);
        Assert.Null((await pg.Repository.FindingsAsync(q, caseAccess, Ct))["items"]![0]!["linked_case"]);
        await pg.Sql("""
            insert into event_cold_facts values(101,now()-interval '30 days',4728,7,null,null,null,'dc.example.test',
                '{"$server_id":11,"$channel":"Security"}','{}','{}');
            """);
        Assert.NotNull((await pg.Repository.FindingsAsync(q, caseAccess, Ct))["items"]![0]!["linked_case"]);
        await pg.Sql("drop table investigation_finding_links");
        var unavailable = await pg.Repository.FindingsAsync(q, caseAccess, Ct); Assert.Equal([7L], Ids(unavailable)); Assert.Null(unavailable["items"]![0]!["linked_case"]);
    }
}
