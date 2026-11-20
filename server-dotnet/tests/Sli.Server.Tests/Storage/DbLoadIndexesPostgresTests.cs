using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class DbLoadIndexesPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Migrated_queries_preserve_rows_and_retention_coverage_at_load()
    {
        var ct = TestContext.Current.CancellationToken;
        bool stand = Environment.GetEnvironmentVariable("SLI_DB_LOAD_SCALE") == "stand";
        int allocations = stand ? 15_000_000 : 15_000, jobs = stand ? 2_600_000 : 2600;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 376);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "set statement_timeout=0; set lock_timeout=0; set jit=off", ct);
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(db, ct);
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await ShortEventWriter.WriteAsync(db, tx, rows, ct); await tx.CommitAsync(ct);
        }
        await ProblemQueuePagingTests.SeedPopulation(db, ct);
        output.WriteLine("Seeding allocations, retained events and outbox");
        await Sql(db, """
            select public.create_event_storage_partitions((now() at time zone 'UTC')::date-48,(now() at time zone 'UTC')::date);
            insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
            select 1000000+n,900001,c.id,1000000+n,date_trunc('day',now())-(n%49)*interval '1 day',sha256('synthetic-load'::bytea)
            from generate_series(1,@allocations) n cross join storage_v2_channel c where c.value='Security';
            with template as materialized (select method,outcome from event_hot where event_id<1000000 order by event_id limit 1)
            insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256,event_record_id)
            select a.id,a.time_created_utc,4625,1,'synthetic-user','synthetic-target','192.0.2.1','dc.example.test',
                h.method,h.outcome,'{}',a.normalized_hash,a.event_record_id
            from storage_v2_event_identity_allocations a
            cross join template h
            where a.id>1000000 and a.id<=1000000+@hot;
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
                idempotency_key,status,completed_at,created_at,updated_at,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
            select md5('load-'||n)::uuid,1000000+n,case when n=@jobs then 'normalize_event' else 'assemble_action' end,1,'synthetic','synthetic-load',
                sha256(('load-'||n)::bytea),case when n%10=0 then 'queued' else 'completed' end,
                case when n%10<>0 then now()-interval '30 days' end,now()-interval '31 days',now()-interval '30 days',
                1,1,'synthetic',now()-interval '31 days',jsonb_build_object('id',1000000+n,'server_id',900001,'domain_id',1,'log_source_id',1,
                    'event_id',4625,'time_created_utc','2026-09-01Z','normalized_hash',encode(sha256('synthetic-load'::bytea),'hex'),
                    'migrated_at','2026-09-01Z','channel','Security')
            from generate_series(1,@jobs) n;
            insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
                values('facts-v1','synthetic-load',int8multirange(int8range(1,@first,'[)'),int8range(@last+1,1000001+@jobs,'[)')));
            analyze storage_v2_event_identity_allocations; analyze event_hot; analyze semantic_processing_outbox;
            analyze finding_event_copies337; analyze semantic_suppressions; analyze findings;
            """, ct, ("allocations", allocations), ("jobs", jobs), ("hot",Math.Min(jobs,4900)),
                ("first",rows.Min(r=>r.EventId)), ("last",rows.Max(r=>r.EventId)));
        await Sql(db,"""
            update finding_event_copies337 set event_kind=4719,
                method=jsonb_set(method,'{$principals}',case finding_id
                    when 1 then '{"SubjectUserSid":"S-1-5-18"}'::jsonb
                    when 2 then '{"SubjectUserSid":"S-1-5-21-100000001-200000002-300000003-1101","SubjectUserName":"synthetic$"}'::jsonb
                    else '{"SubjectUserSid":"S-1-5-21-100000001-200000002-300000003-1101","SubjectUserName":"synthetic-user"}'::jsonb end)
            where finding_id<=4;
            update findings set rule_code='semantic.qw.audit-disabled' where id=5;
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
            select c.finding_id,10000000+n,c.time_created_utc,case when n%100=0 then 4719 else 4625 end,c.domain_id,
                c.actor,c.computer,c.method,c.outcome,c.fields,c.source_sha256,c.evidence_role
            from finding_event_copies337 c cross join generate_series(1,@witnesses) n where c.finding_id=5;
            analyze finding_event_copies337;
            """,ct,("witnesses",stand?20000:2000));
        var reviewBefore=await JsonRows(db,"select id,semantic_finding_review_v160(id) as hint from findings where id<=4 order by id",[],ct);
        Assert.Equal("system_account",reviewBefore[0]!["hint"]!["bucket"]!.ToString());
        Assert.Equal("machine_account",reviewBefore[1]!["hint"]!["bucket"]!.ToString());
        output.WriteLine($"Synthetic load: allocations={allocations}, outbox={jobs}, hot samples={Math.Min(jobs,4900)}, populated hot days=49 (plus empty precreated partitions)");
        var query = new FindingQuery(null,null,null,null,null,null,null,null,50,false) { GroupQueue=true,PageQueue=true,Compact=true,Risk="all",Suppressed=true };
        var (page, summary, args) = ProblemRepository.FindingsQueries(query);
        string prefix = ProblemRepository.FindingsQueries(query, populationOnly:true).Page;
        string bundle = prefix + $"select (select jsonb_agg(to_jsonb(p)) from ({page[prefix.Length..]}) p) as items,(select jsonb_agg(to_jsonb(s)) from ({summary[prefix.Length..]}) s) as summary";
        const string pending = "select exists(select 1 from semantic_processing_outbox where job_kind='normalize_event' and status in ('queued','leased'))";
        await Measure(db,"before pending",pending,[],ct);
        await Measure(db,"before problems",bundle,args,ct);
        await Measure(db,"before decisions",SemanticProducerBackfill.SelectionSql,DecisionArgs(),ct);
        var decisionsBefore=await JsonRows(db,SemanticProducerBackfill.SelectionSql,DecisionArgs(),ct);
        // Only the three real importer-attested fixture rows are candidates.
        // Bulk SQL rows without packet proof must stay outside semantic reads.
        Assert.Equal(rows.Select(r=>r.EventId).Order(),decisionsBefore.Select(n=>n!["id"]!.GetValue<long>()));
        var before = await JsonRows(db,bundle,args,ct);
        // The former two-statement reader rejoined findings_active for every
        // representative instead of sharing the materialized admitted population.
        string Previous(string sql)=>sql.Replace("with queue_findings as materialized (select * from findings_active),","with ")
            .Replace("from queue_findings findings","from findings_active findings");
        var separatePage = await JsonRows(db,Previous(page),args,ct);
        var separateSummary = await JsonRows(db,Previous(summary),args,ct);
        Assert.True(JsonNode.DeepEquals(separatePage,JsonNode.Parse(before[0]!["items"]!.ToString())));
        Assert.Equal(separateSummary.Select(x=>x!.ToJsonString()).Order(),JsonNode.Parse(before[0]!["summary"]!.ToString())!.AsArray().Select(x=>x!.ToJsonString()).Order());
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/377_db_load_indexes.sql"),null,ct);
        await Measure(db,"after pending",pending,[],ct);
        await Measure(db,"after problems",bundle,args,ct);
        await Measure(db,"after problems warm",bundle,args,ct);
        await Measure(db,"after decisions",SemanticProducerBackfill.SelectionSql,DecisionArgs(),ct);
        Assert.True(JsonNode.DeepEquals(decisionsBefore,await JsonRows(db,SemanticProducerBackfill.SelectionSql,DecisionArgs(),ct)));
        Assert.True(JsonNode.DeepEquals(before,await JsonRows(db,bundle,args,ct)));
        Assert.True(JsonNode.DeepEquals(reviewBefore,await JsonRows(db,"select id,semantic_finding_review_v160(id) as hint from findings where id<=4 order by id",[],ct)));
        // Rollback preserves every source/job/decision and removes only the new capability.
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/377_db_load_indexes.rollback.sql"),null,ct);
        await using (var check = new NpgsqlCommand("select count(*) from semantic_processing_outbox",db)) Assert.Equal((long)jobs,await check.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/377_db_load_indexes.sql"),null,ct);
        using var state = new StorageLifecycleTests.State();
        await using var deletion = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) { Options="-c role=adlog_storage_lifecycle_delete",CommandTimeout=0 }.ConnectionString);
        var watch=Stopwatch.StartNew();
        var retained=await new Sli.Server.Storage.Lifecycle.SemanticOutboxRetention(deletion,state.Files,"facts-v1").RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        output.WriteLine($"retention batch: {watch.Elapsed.TotalMilliseconds:F3} ms, selected={retained["selected_count"]}, deleted={retained["deleted_count"]}");
        Assert.True(retained["schema_ready"]!.GetValue<bool>()); Assert.True(retained["deleted_count"]!.GetValue<long>()>0);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    static Dictionary<string,object?> DecisionArgs()=>new() { ["mode"]="facts-v1",["version"]="synthetic-load",["limit"]=10 };
    async Task Measure(NpgsqlConnection db,string label,string sql,Dictionary<string,object?> args,CancellationToken ct)
    {
        await using var command=Command(db,"explain (analyze,buffers,format json) "+sql,args);
        var plan=JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)![0]!;
        output.WriteLine($"{label}: {plan["Execution Time"]} ms; planning {plan["Planning Time"]} ms");
        foreach(var node in Nodes(plan).Where(n=>(n["Actual Loops"]?.GetValue<double>()??0)>0 &&
            (n["Relation Name"]?.ToString() is "semantic_processing_outbox" or "storage_v2_event_identity_allocations" or "finding_event_copies337"
             || n["Node Type"]?.ToString()=="CTE Scan" || (n["Actual Total Time"]?.GetValue<double>()??0)>100)).Take(14))
            output.WriteLine($"  {node["Node Type"]} {node["Relation Name"] ?? node["CTE Name"]} {node["Index Name"]}: ms={node["Actual Total Time"]}, rows={node["Actual Rows"]}, loops={node["Actual Loops"]}, filtered={node["Rows Removed by Filter"]}, buffers={node["Shared Hit Blocks"]}/{node["Shared Read Blocks"]}");
    }
    static NpgsqlCommand Command(NpgsqlConnection db,string sql,Dictionary<string,object?> args)
    {
        var command=new NpgsqlCommand(sql,db) { CommandTimeout=0 };
        foreach(var (name,value) in args) {
            if(sql.Contains("$1",StringComparison.Ordinal))command.Parameters.Add(new(){Value=value??DBNull.Value});
            else command.Parameters.AddWithValue(name,value??DBNull.Value);
        }
        return command;
    }
    static IEnumerable<JsonObject> Nodes(JsonNode node)
    {
        if(node is JsonObject obj) { yield return obj; foreach(var child in obj.Select(p=>p.Value).OfType<JsonNode>()) foreach(var nested in Nodes(child)) yield return nested; }
        else if(node is JsonArray array) foreach(var child in array.OfType<JsonNode>()) foreach(var nested in Nodes(child)) yield return nested;
    }
    static async Task<JsonArray> JsonRows(NpgsqlConnection db,string sql,Dictionary<string,object?> args,CancellationToken ct)
    {
        await using var command=Command(db,"select to_jsonb(r) from ("+sql+") r",args);
        var result=new JsonArray(); await using var reader=await command.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct))result.Add(JsonNode.Parse(reader.GetString(0)));
        return result;
    }
    static async Task Sql(NpgsqlConnection db,string sql,CancellationToken ct,params (string Key,object Value)[] args)
    {
        await using var command=Command(db,sql,args.ToDictionary(x=>x.Key,x=>(object?)x.Value)); await command.ExecuteNonQueryAsync(ct);
    }
}
