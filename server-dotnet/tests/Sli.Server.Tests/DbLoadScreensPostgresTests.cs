using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Problems;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Storage;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests;

public sealed class DbLoadScreensPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Loaded_screen_queries_preserve_results_and_use_bounded_reads()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        output.WriteLine("Seeding disposable PG18: 2600000 queued jobs, 200000 cold facts, 3300 findings, 100 agents / 30000 audit entries");
        await using (var seed = new NpgsqlCommand("""
            insert into servers(id,domain_id,hostname,fqdn,role)
                select 900001,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test';
            select create_event_storage_partitions((current_date-20),(current_date));
            insert into event_cold_facts(event_id,time_created_utc,event_kind,domain_id,actor,target,computer,method,outcome,fields)
            select n,current_date-interval '19 days'+n*interval '0.01 second',
                case when n%100=0 then 4728 else 4625 end,1,'synthetic-actor','synthetic-target','dc01.example.test',
                '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
                '{}','{}' from generate_series(1,200000) n;
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,idempotency_key,status,
                source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
            select ('10000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,n,'normalize_event',1,'synthetic','synthetic-load',
                decode(lpad(to_hex(n),64,'0'),'hex'),'queued',1,1,'synthetic',now(),
                jsonb_build_object('id',n,'server_id',900001,'domain_id',1,'log_source_id',1,'event_id',4625,
                    'time_created_utc',now(),'normalized_hash',encode(sha256(n::text::bytea),'hex'),'migrated_at',now(),'channel','Security')
                from generate_series(1,2600000) n;
            insert into findings(id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc)
            select n,'semantic:'||encode(sha256(('load-finding-'||n)::bytea),'hex'),'semantic.qw.privileged-group-addition','Synthetic finding',
                'new','high','synthetic','synthetic-actor','object-'||(n%1000),1,now()::text,now()::text
                from generate_series(1,3300) n;
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
            select n,n,now(),4728,1,'synthetic-actor','dc01.example.test',
                '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","$principals":{"SubjectUserSid":"S-1-5-21-100000001-200000002-300000003-1001"}}',
                '{}','{}',sha256(n::text::bytea),'primary' from generate_series(1,3300) n;
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            select md5('load-scenario-'||n)::uuid,'synthetic','control_gap',sha256(('load-identity-'||n)::bytea),sha256(('load-scenario-'||n)::bytea),
                'synthetic','{}',300,'Synthetic scenario','Synthetic load',now(),now(),'low' from generate_series(1,3300) n;
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-load',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            select md5('load-observation-'||n)::uuid,sha256(('load-observation-'||n)::bytea),'synthetic','synthetic','unknown','Synthetic load',now(),'synthetic-'||n
                from generate_series(1,3300) n;
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            select md5('load-evaluation-'||n)::uuid,'synthetic-load',1,'control_health',md5('load-observation-'||n)::uuid,
                (md5('load-observation-'||n)::uuid)::text,'enabled',sha256(('load-evaluation-'||n)::bytea),'completed',now() from generate_series(1,3300) n;
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            select md5('load-evaluation-'||n)::uuid,md5('load-scenario-'||n)::uuid,'enabled','low',1,1,false,'low',1,'unknown',1 from generate_series(1,3300) n;
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            select md5('load-scenario-'||n)::uuid,n,md5('load-evaluation-'||n)::uuid,'semantic:'||encode(sha256(('load-finding-'||n)::bytea),'hex'),1 from generate_series(1,3300) n;
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules)
            select md5('load-agent-'||n)::uuid,md5('load-host-'||n)::uuid,encode(sha256(('load-key-'||n)::bytea),'hex'),'dc'||n||'.example.test','[]'
                from generate_series(1,100) n;
            insert into sli_agent_audit(action,actor,target,details)
            select 'issue','synthetic',md5('load-agent-'||(n%100+1))::uuid::text,jsonb_build_object('agent_version','synthetic-'||n)
                from generate_series(1,30000) n;
            analyze;
            """, db) { CommandTimeout = 0 }) await seed.ExecuteNonQueryAsync(ct);
        await using var reader = await fixture.Pg.OpenAsync(ct, "adlog_user");
        // Use the same application role as the screens, with normal planner settings.
        var period = new AdPeriod(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-20), TimeSpan.Zero), DateTimeOffset.UtcNow);
        var ad = AdSecurityQuery.Create(new("security",false,false,1,period,50,new(),null));
        var category = await Plan(reader,"domain categories",ad.CategorySql,ct,ad.CategoryArgs.Select((v,i)=>((i+1).ToString(),v!)).ToArray());
        var page = await Plan(reader,"domain page",ad.SelectSql,ct,ad.Args.Select((v,i)=>((i+1).ToString(),v!)).ToArray());
        var findings = ProblemRepository.FindingsQueries(new(null,null,null,null,null,null,null,null,50,false) { PageQueue=true, GroupQueue=true });
        var problems=await Plan(reader,"problems page",findings.Page,ct,findings.Arguments.Select(p=>(p.Key,p.Value!)).ToArray());
        await Plan(reader,"problems summary",findings.Summary,ct,findings.Arguments.Select(p=>(p.Key,p.Value!)).ToArray());
        var sources=await Plan(reader,"source agents",InstallationService.Sql("setup-agents.sql"),ct);
        await Plan(reader,"home groups",HomeDecisionSql.Groups(true,allDomains:true),ct,
            ("from",DBNull.Value),("to",DBNull.Value),("since",DBNull.Value),("cohort_zone","UTC"));
        var repository=new ProblemRepository(new Connections(fixture),TimeProvider.System);
        var access=ProblemLifecycleTests.Access("security.queue",fields:["security","identity_basic"]);
        var request=new FindingQuery(null,null,null,null,null,null,null,null,50,false) { PageQueue=true,GroupQueue=true,Compact=true };
        var requestWatch=Stopwatch.StartNew();
        var queue=await repository.FindingsAsync(request,access,ct);
        output.WriteLine("problems page + counters: {0:F1} ms",requestWatch.Elapsed.TotalMilliseconds);
        Assert.Equal(50,queue["items"]!.AsArray().Count);
        Assert.True(queue["has_more"]!.GetValue<bool>());
        Assert.Equal(1000,queue["summary"]!.AsArray().Sum(r=>r!["count"]!.GetValue<long>()));
        Assert.Equal(3300,queue["summary"]!.AsArray().Sum(r=>r!["occurrences"]!.GetValue<long>()));
        var agents=await AdJson.ReadAsync(reader,InstallationService.Sql("setup-agents.sql"),ct);
        Assert.Equal(100,agents.Count);
        var agent=Assert.Single(agents,a=>a["registration_host_name"]!.ToString()=="dc1.example.test");
        Assert.Equal("synthetic-30000",agent["agent_version"]!.ToString());
        await PostCollectionPostgres.Sql(db,"""
            insert into semantic_suppressions(semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by)
            values('semantic.qw.privileged-group-addition',1,'subject_sid','S-1-5-21-100000001-200000002-300000003-1002',
                'Synthetic load exception',now()+interval '1 day','synthetic');
            """,ct);
        Assert.Equal(false,await Scalar(reader,"select ("+ProblemRepository.Suppressed+") from findings_active findings where findings.id=1",ct));
        await PostCollectionPostgres.Sql(db,"""
            update semantic_suppressions set state='revoked',changed_by='synthetic' where state='active';
            insert into semantic_suppressions(semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by)
            values('semantic.qw.privileged-group-addition',1,'subject_sid','S-1-5-21-100000001-200000002-300000003-1001',
                'Synthetic load exception',now()+interval '1 day','synthetic');
            """,ct);
        Assert.Equal(true,await Scalar(reader,"select ("+ProblemRepository.Suppressed+") from findings_active findings where findings.id=1",ct));
        Assert.Empty((await repository.FindingsAsync(request with { FindingId=1 },access,ct))["items"]!.AsArray());
        await PostCollectionPostgres.Sql(db,"update semantic_suppressions set state='revoked',changed_by='synthetic' where state='active'",ct);
        Assert.Equal(false,await Scalar(reader,"select ("+ProblemRepository.Suppressed+") from findings_active findings where findings.id=1",ct));
        var categories = await ad.CategoriesAsync(reader,ct);
        Assert.Equal("processing_unfinished",categories["authentication"]!["state"]!.ToString());
        Assert.Equal("processing_unfinished",categories["group_membership"]!["state"]!.ToString());
        var rows = await AdJson.ReadAsync(reader,ad.SelectSql,ct,ad.Args.ToArray());
        Assert.Equal(51,rows.Count);
        Assert.Equal(200000,rows[0]["event_db_id"]!.GetValue<long>());
        // Row counts and buffers, rather than a machine-specific wall clock limit,
        // protect the cost of opening a screen as the retained backlog grows.
        Assert.True(Visits(category["Plan"]!,"semantic_processing_outbox")<1000,"Category read traversed the normalization backlog");
        Assert.True(Visits(category["Plan"]!,"event_cold_facts")<=400000,"Category read repeatedly traversed the retained window");
        Assert.True(Visits(page["Plan"]!,"event_cold_facts")<=400000,"Page read traversed the window for every timestamp");
        Assert.True(Visits(sources["Plan"]!,"sli_agent_audit")<=90000,"Source read traversed the journal for every agent");
        Assert.True(Visits(problems["Plan"]!,"findings")<=10000,"Queue rejoined the security-barrier view for every group");
        await PostCollectionPostgres.Sql(db,"""
            grant select,update,delete on semantic_processing_outbox to adlog_storage_lifecycle_delete;
            grant select,insert,update on semantic_producer_coverage to adlog_storage_lifecycle_delete;
            grant select on entity_identity_semantic_replays_v2 to adlog_storage_lifecycle_delete;
            update semantic_processing_outbox set job_id=('00000000-0000-4000-8000-'||lpad(source_event_id::text,12,'0'))::uuid,
                status='completed',completed_at=now()-interval '10 days',created_at=now()-interval '10 days',updated_at=now()-interval '10 days'
                where source_event_id<=1000;
            """,ct);
        using var state=new StorageLifecycleTests.State();
        await using var deletion=NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options="-c role=adlog_storage_lifecycle_delete",CommandTimeout=0 }.ConnectionString);
        var watch=Stopwatch.StartNew();
        var retained=await new SemanticOutboxRetention(deletion,state.Files,"facts-v1").RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        output.WriteLine("outbox retention: {0:F1} ms; selected={1}; deleted={2}",watch.Elapsed.TotalMilliseconds,retained["selected_count"]!,retained["deleted_count"]!);
        Assert.Equal(1000,LifecycleJson.Number(retained,"deleted_count"));
        Assert.Equal(2599000L,await Scalar(db,"select count(*) from semantic_processing_outbox",ct));
        Assert.Equal(true,await Scalar(db,"select decided_ids @> int8range(1,1001) and not decided_ids @> 1001::bigint from semantic_producer_coverage where runtime_mode='facts-v1' and processor_version='synthetic-load'",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Screen_reads_leave_statement_timeout_unchanged_and_follow_request_cancellation()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=await fixture.Pg.OpenAsync(ct);
        var defaultSettings=new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")); defaultSettings.Remove("Command Timeout");
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=defaultSettings.ConnectionString
        }).Build();
        await using(var defaults=await new PostgresConnectionFactory(config).OpenAsync(ct)) Assert.Equal(0,defaults.CommandTimeout);
        // Log executed protocol statements in this disposable cluster. This
        // observes what the reader sends to PostgreSQL, not its source text.
        await PostCollectionPostgres.Sql(admin,"alter system set log_statement='all'",ct);
        await PostCollectionPostgres.Sql(admin,"select pg_reload_conf()",ct);
        var connections=new Connections(fixture,inspectTimeout:true);
        var problems=new ProblemRepository(connections,TimeProvider.System);
        var access=ProblemLifecycleTests.Access("security.queue",fields:["security","identity_basic"]);
        foreach(bool grouped in new[]{false,true}) {
            var result=await problems.FindingsAsync(new(null,null,null,null,null,null,null,null,50,false) {
                PageQueue=true,GroupQueue=grouped,Compact=true },access,ct);
            Assert.Empty(result["items"]!.AsArray());
        }
        await problems.LegacyFindingsAsync("synthetic",50,ct);
        var home=new HomeSummaryRepository(connections);
        var settings=Assert.Single(await home.ReadAsync("select current_setting('statement_timeout') as timeout,current_setting('transaction_read_only') as read_only",new Dictionary<string,object?>(),ct));
        Assert.Equal("17s",settings["timeout"]!.ToString()); Assert.Equal("on",settings["read_only"]!.ToString());
        Assert.Single(await home.ReadAsync("select 1 as value from pg_sleep(3.1)",new Dictionary<string,object?>(),ct));
        // With the former eight-second lifetime, the second read failed even
        // though it was quick. The repository must have no cumulative deadline.
        await Task.Delay(TimeSpan.FromSeconds(8.1),ct);
        Assert.Single(await home.ReadAsync("select 1 as value",new Dictionary<string,object?>(),ct));
        using(var cancel=CancellationTokenSource.CreateLinkedTokenSource(ct)) {
            var pending=home.ReadAsync("select 1 as value from pg_sleep(60)",new Dictionary<string,object?>(),cancel.Token);
            cancel.CancelAfter(100);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);
        }
        // Allow the logging collector to flush its own pipe.
        string log=await fixture.Pg.DiagnosticsAsync(ct);
        Assert.Contains("findings_active",log);
        Assert.DoesNotContain("set local statement_timeout",log,StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("set_config('statement_timeout'",log,StringComparison.OrdinalIgnoreCase);
    }

    sealed class Connections(SqlPostgresFixture fixture,bool inspectTimeout=false):IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) {
            var db=new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")) {
                CommandTimeout=inspectTimeout?1:0,Options=inspectTimeout?"-c statement_timeout=17000":null }.ConnectionString);
            await db.OpenAsync(ct); return db;
        }
    }

    static async Task<object?> Scalar(NpgsqlConnection db,string sql,CancellationToken ct) {
        await using var command=new NpgsqlCommand(sql,db) { CommandTimeout=0 }; return await command.ExecuteScalarAsync(ct);
    }

    static double Visits(JsonNode node,string relation) =>
        (node["Relation Name"]?.ToString().StartsWith(relation,StringComparison.Ordinal)==true
            ? (node["Actual Rows"]!.GetValue<double>()+(node["Rows Removed by Filter"]?.GetValue<double>()??0))*node["Actual Loops"]!.GetValue<double>() : 0)
        +(node["Plans"] as JsonArray??[]).Sum(n=>Visits(n!,relation));

    async Task<JsonNode> Plan(NpgsqlConnection db,string name,string sql,CancellationToken ct,params (string Key,object Value)[] args)
    {
        await using var command = new NpgsqlCommand("explain(analyze,buffers,format json) "+sql,db) { CommandTimeout=0 };
        foreach (var (key,value) in args)
            if (int.TryParse(key,out _)) command.Parameters.Add(new() { Value=value });
            else if (value is DBNull) command.Parameters.AddWithValue(key,NpgsqlTypes.NpgsqlDbType.TimestampTz,DBNull.Value);
            else command.Parameters.AddWithValue(key,value);
        var watch=Stopwatch.StartNew();
        var plan=JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)![0]!;
        output.WriteLine("{0}: {1} ms; wall={2:F1} ms; buffers={3}; temp={4}",name,plan["Execution Time"]!,watch.Elapsed.TotalMilliseconds,
            plan["Plan"]!["Shared Hit Blocks"]!,plan["Plan"]!["Temp Written Blocks"]!);
        void Nodes(JsonNode node) {
            if (node["Relation Name"] is not null && node["Actual Loops"]!.GetValue<double>()>0
                && node["Actual Rows"]!.GetValue<double>()+(node["Rows Removed by Filter"]?.GetValue<double>()??0)>0)
                output.WriteLine("  {0} {1}: rows={2}; loops={3}; removed={4}",node["Node Type"]!,node["Relation Name"]!,node["Actual Rows"]!,node["Actual Loops"]!,node["Rows Removed by Filter"]?.ToString()??"0");
            foreach(var child in node["Plans"] as JsonArray??[]) Nodes(child!);
        }
        Nodes(plan["Plan"]!); return plan;
    }
}
