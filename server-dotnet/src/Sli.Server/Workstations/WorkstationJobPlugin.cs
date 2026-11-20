using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using W= Sli.Server.Workstations.Ws;
namespace Sli.Server.Workstations;

public sealed class WorkstationJobPlugin:ICoreJobPlugin
{
    readonly Func<WorkstationHistory?> historyFactory;
    readonly Func<WorkstationPurgeRun> auditFactory;
    public WorkstationJobPlugin():this(()=>WorkstationHistory.Configured(),()=>new()) { }
    internal WorkstationJobPlugin(Func<WorkstationHistory?> historyFactory,Func<WorkstationPurgeRun> auditFactory)
    {this.historyFactory=historyFactory;this.auditFactory=auditFactory;}
    public void Register(CoreJobPluginCatalog catalog)
    {
        catalog.Add("sli.workstations","workstations.evidence-retention",new(StageRetention,PublishRetention),Schedule);
        catalog.Add("sli.workstations","workstations.overview-project",new(StageProjection,PublishProjection));
    }
    static object?[] Fence(JsonObject job)=>[Guid.Parse(W.Text(job,"job_id")!),Guid.Parse(W.Text(job,"lease_token")!),W.Number(job,"lease_generation")];
    static JsonObject Outcome(bool partial)=>new(){["status"]=partial?"partial":"success",["coverage_state"]="not_proven",["continuation"]=null};
    static int Limit(JsonObject job,int cap)
    {long n=W.Number(job["budget"],"max_records");if(n<1)throw new WorkstationException("workstation_projection_batch_invalid");return (int)Math.Min(n,cap);}
    internal static bool Inventory(JsonObject job)=>(W.Text(job,"source_instance_id")??"").StartsWith("workstations:inventory:",StringComparison.Ordinal);
    internal static bool Drains(JsonObject job)=>W.Text(job,"plugin_id")=="sli.workstations"
        &&W.Text(job,"source_instance_id")=="workstations:projection"&&W.Text(job,"handler_id")=="workstations.overview-project";
    internal static (JsonObject Pinned,string Partition) Pin(JsonObject handler,JsonObject source,string generation)=>
        (new(){["generation"]=source["projection_progress"] is {} progress?generation+":"+progress:generation,["input_range"]=new JsonArray(),["policy_revision"]=source["revision"]?.DeepClone(),["continuation"]=null},Inventory(source)?W.Text(source,"source_instance_id")!:W.Text(handler,"handler_id")!);
    static async Task Schedule(NpgsqlConnection db,CoreJobQueue queue,CoreJobRegistry registry,string profile,CancellationToken ct)
    {
        if(profile!="light")return;
        bool projection=Environment.GetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_PROJECTION")=="1";
        bool retention=Environment.GetEnvironmentVariable("SLI_CORE_JOB_WORKSTATIONS_RETENTION")=="1";
        if((!projection&&!retention)||!await EnabledAsync(db,ct))return;
        var sources=new List<(string Handler,JsonObject Source)>();
        async Task Source(string reader,string handler)
        {
            var rows=await W.Rows(db,"select public."+reader+"() as source",ct);
            foreach(var row in rows)if(row["source"] is JsonObject source)sources.Add((handler,source));
        }
        // Primary history owns the seven-day lane, including projection cleanup.
        if(Environment.GetEnvironmentVariable("ADLOG_HISTORY_READ_MODE")!="primary"&&retention)await Source("read_workstation_retention_job_source_v1","workstations.evidence-retention");
        if(projection){await Source("read_workstation_projection_job_source_v1","workstations.overview-project");await Source("read_workstation_inventory_job_sources_v1","workstations.overview-project");}
        foreach(var (_,source) in sources)
            if(W.Text(source,"source_instance_id")=="workstations:projection")source["projection_progress"]=(string?)await W.Scalar(db,"select public.read_workstation_projection_progress_v322()",ct);
        var now=(DateTimeOffset)(await W.Scalar(db,"select clock_timestamp()",ct) is DateTime at?new DateTimeOffset(at):throw new WorkstationException("workstation_job_clock_invalid"));
        foreach(var (handler,source) in sources)
            foreach(var spec in CoreJobScheduler.Create(registry,profile,source,now,Pin))
                if(W.Text(spec,"handler_id")==handler)
                {
                    if(source["projection_progress"] is {} progress)spec["schedule_key"]=CoreJobJson.Digest(new JsonArray(spec["schedule_key"]!.DeepClone(),progress.DeepClone()));
                    await queue.EnqueueAsync(spec,ct);
                }
    }
    internal static async Task<bool> EnabledAsync(NpgsqlConnection db,CancellationToken ct)=>
        await W.Scalar(db,"select public.workstation_runtime_enabled_v376()",ct) is true;
    static async Task<JsonObject> InventoryInput(NpgsqlConnection db,JsonObject job,CancellationToken ct)
    {
        if(W.Text(job,"handler_id")!="workstations.overview-project"||Limit(job,100)!=100)throw new WorkstationException("workstation_inventory_budget_invalid");
        var raw=await W.Scalar(db,"select public.read_workstation_inventory_input_v1(@p0,@p1,@p2)::text",ct,Fence(job));
        return raw is string s&&JsonNode.Parse(s) is JsonObject snapshot?snapshot:throw new WorkstationException("workstation_inventory_input_invalid");
    }
    static async Task<JsonObject> StageProjection(NpgsqlConnection db,JsonObject job,CancellationToken ct)
    {
        if(Inventory(job))
        {
            var input=await InventoryInput(db,job,ct);var page=input["page"]!;var result=Outcome(page["more"]!.GetValue<bool>());
            result["inventory_source_sha256"]=input["source_sha256"]!.DeepClone();result["inventory_ids"]=page["attempted_ids"]!.DeepClone();result["inventory_deferred"]=page["deferred"]!.DeepClone();return result;
        }
        ValidateProjection(job);int limit=Limit(job,100);
        var config=await WorkstationEvaluators.LoadPolicy(db,ct);var identities=WorkstationEvaluators.Identities(config);
        var refresh=await W.Rows(db,"select i.station_id from sli_plugin_workstations.station_inventory i left join sli_plugin_workstations.station_summary s using(station_id) where s.station_id is null or s.protection='{}'::jsonb or (s.protection->>'next_refresh_at')::timestamptz<clock_timestamp() order by i.station_id limit @p0",ct,Math.Max(1,limit/4));
        int remaining=limit-refresh.Count;
        var pending=remaining==0?[]:await W.Rows(db,PendingSql,ct,identities.Keys.ToArray(),identities.Values.ToArray(),remaining);
        var output=Outcome(refresh.Count+pending.Count==limit);output["work_ids"]=new JsonArray(pending.Select(p=>p["work_id"]!.DeepClone()).ToArray());output["protection_refresh_ids"]=new JsonArray(refresh.Select(p=>p["station_id"]!.DeepClone()).ToArray());return output;
    }
    const string StationJoin="join sli_plugin_workstations.station_inventory s on (q.kind='station_inventory' and s.station_id=q.station_id) or (q.kind<>'station_inventory' and s.agent_key=q.agent_key)";
    // Each consumer seeks its existing partial index, then probes queue/station
    // keys. Only the small per-consumer pages enter the final deduplication.
    internal const string PendingSql="""
        select page.work_id from (
            select picked.work_id,row_number() over (partition by consumer.key,consumer.version order by picked.work_id) as ordinal
            from unnest(@p0::text[],@p1::integer[]) consumer(key,version)
            cross join lateral (
                select r.work_id from sli_plugin_workstations.projection_receipts r
                join sli_plugin_workstations.projection_work q using(work_id)
                where r.projector_key=consumer.key and r.projection_version=consumer.version and r.applied_at is null
                  and (q.kind='station_inventory' and exists(select 1 from sli_plugin_workstations.station_inventory s where s.station_id=q.station_id)
                    or q.kind<>'station_inventory' and exists(select 1 from sli_plugin_workstations.station_inventory s where s.agent_key=q.agent_key))
                order by r.work_id limit @p2
            ) picked
        ) page
        group by page.work_id order by min(page.ordinal),page.work_id limit @p2
        """;
    static void ValidateProjection(JsonObject job)
    {if(W.Text(job,"source_instance_id")!="workstations:projection"||W.Text(job,"handler_id")!="workstations.overview-project")throw new WorkstationException("workstation_projection_job_invalid");}
    static async Task SetFence(NpgsqlConnection db,JsonObject job,CancellationToken ct)
    {await W.Scalar(db,"select set_config('sli.job_id',@p0,true),set_config('sli.job_token',@p1,true),set_config('sli.job_generation',@p2,true)",ct,W.Text(job,"job_id"),W.Text(job,"lease_token"),W.Number(job,"lease_generation").ToString(System.Globalization.CultureInfo.InvariantCulture));}
    static async Task PublishProjection(NpgsqlConnection db,JsonObject job,JsonObject result,CancellationToken ct)
    {
        if(W.Text(result,"status") is "blocked" or "cancelled")return;
        if(Inventory(job))
        {
            var input=await InventoryInput(db,job,ct);var page=input["page"]!;
            if(!JsonNode.DeepEquals(input["source_sha256"],result["inventory_source_sha256"]))throw new WorkstationException("workstation_inventory_input_changed");
            if(!JsonNode.DeepEquals(page["attempted_ids"],result["inventory_ids"])||!JsonNode.DeepEquals(page["deferred"],result["inventory_deferred"]))throw new WorkstationException("workstation_inventory_page_changed");
            await W.Scalar(db,"select public.publish_workstation_inventory_v1(@p0,@p1,@p2,@p3,@p4::jsonb,@p5)",ct,[..Fence(job),W.Text(input,"source_sha256"),page["rows"]!,page["next_cursor"]?.ToString()]);return;
        }
        await PublishProjectionBatch(db,job,result,ct);
    }
    internal static async Task<JsonObject> DrainAsync(NpgsqlConnection db,CoreJobQueue queue,JsonObject job,JsonObject first,CancellationToken ct,
        Func<int,Task>? committed=null,Func<Task>? publishing=null)
    {
        ValidateProjection(job);
        var batch=first;long pages=0,processed=0;
        while(true)
        {
            ct.ThrowIfCancellationRequested();
            if(!await EnabledAsync(db,ct))throw new WorkstationException("agent_plugin_disabled");
            int preparation=0;
            Dictionary<string,int> identities=[];
            // Registration takes the exclusive consumer lock also used by the
            // inbox INSERT trigger. Release it before backfill and evaluation.
            await queue.ApplyBatchAsync(job,batch,async token=> {
                await SetFence(db,job,token);
                var policy=await WorkstationEvaluators.LoadPolicy(db,token);
                identities=WorkstationEvaluators.Identities(policy);
                await RegisterConsumers(db,identities,token);
            },ct);
            await queue.ApplyBatchAsync(job,batch,async token=> {
                await SetFence(db,job,token);
                preparation=await PrepareConsumers(db,identities,Limit(job,100),token,register:false)+await Backfill(db,Limit(job,100),token);
            },ct);
            (int Progress,int Processed) outcome=default;
            await queue.ApplyBatchAsync(job,batch,async token=> {
                outcome=await PublishProjectionBatch(db,job,batch,token,prepare:false);
                if(publishing is not null)await publishing();
            },ct);
            pages++;processed+=outcome.Processed;
            if(committed is not null)await committed(outcome.Processed);
            if(preparation+outcome.Progress==0)break;
            batch=await StageProjection(db,job,ct);
        }
        var result=Outcome(false);result["pages"]=pages;result["processed"]=processed;
        return new(){["status"]=await queue.PublishAsync(job,result,_=>Task.CompletedTask,ct),["pages"]=pages,["processed"]=processed};
    }
    static async Task<(int Progress,int Processed)> PublishProjectionBatch(NpgsqlConnection db,JsonObject job,JsonObject result,CancellationToken ct,bool prepare=true)
    {
        ValidateProjection(job);int limit=Limit(job,100);
        var ids=(result["work_ids"] as JsonArray??throw new WorkstationException("workstation_projection_input_invalid")).Select(n=>n!.GetValue<long>()).ToArray();
        var refresh=(result["protection_refresh_ids"] as JsonArray??new()).Select(n=>n!.GetValue<string>()).ToArray();
        if(ids.Length+refresh.Length>limit||ids.Any(n=>n<1)||ids.Distinct().Count()!=ids.Length||refresh.Distinct().Count()!=refresh.Length)throw new WorkstationException("workstation_projection_input_invalid");
        await SetFence(db,job,ct);
        if(await W.Scalar(db,"select pg_try_advisory_xact_lock(hashtext('workstations.overview'))",ct) is not true)return (0,0);
        var policy=await WorkstationEvaluators.LoadPolicy(db,ct);var identities=WorkstationEvaluators.Identities(policy);
        int progress=prepare?await PrepareConsumers(db,identities,limit,ct)+await Backfill(db,limit,ct):0;
        // The budget bounds immutable inputs, not consumers: every pending
        // projector for these inputs advances together in the same transaction.
        var receipts=ids.Length==0?[]:await W.Rows(db,"select q.work_id,s.station_id,r.projector_key,r.projection_version,r.payload_sha256 from sli_plugin_workstations.projection_work q join sli_plugin_workstations.projection_receipts r using(work_id) "+StationJoin+" where r.applied_at is null and (r.projector_key,r.projection_version) in (select * from unnest(@p0::text[],@p1::integer[])) and q.work_id=any(@p2) order by q.work_id,r.projector_key,r.projection_version for update of r skip locked",ct,identities.Keys.ToArray(),identities.Values.ToArray(),ids);
        var facts=ids.Length==0?[]:await W.Rows(db,"select work_id,kind,source_id,payload,payload_sha256,encode(sha256(convert_to(payload::text,'UTF8')),'hex') as actual_sha256 from sli_plugin_workstations.projection_work where work_id=any(@p0)",ct,ids);
        var byId=facts.ToDictionary(f=>W.Number(f,"work_id"));
        foreach(var fact in facts)
            if(W.Text(fact,"actual_sha256")!=W.Text(fact,"payload_sha256"))throw new WorkstationException("workstation_projection_input_conflict");
        foreach(var row in receipts)
        {
            var fact=byId[W.Number(row,"work_id")];
            if(W.Text(row,"payload_sha256")!=W.Text(fact,"payload_sha256"))throw new WorkstationException("workstation_projection_input_conflict");
            string station=W.Text(row,"station_id")!,key=W.Text(row,"projector_key")!;int version=(int)W.Number(row,"projection_version");
            await WorkstationEvaluators.Apply(db,key,station,fact,policy,ct);
        }
        if(receipts.Count>0)
        {
            await W.Exec(db,"""
                update sli_plugin_workstations.projection_receipts r set applied_at=now()
                from unnest(@p0::bigint[],@p1::text[],@p2::integer[]) page(work_id,key,version)
                where r.work_id=page.work_id and r.projector_key=page.key and r.projection_version=page.version and r.applied_at is null
                """,ct,receipts.Select(r=>W.Number(r,"work_id")).ToArray(),receipts.Select(r=>W.Text(r,"projector_key")!).ToArray(),receipts.Select(r=>(int)W.Number(r,"projection_version")).ToArray());
            var checkpoints=receipts.GroupBy(r=>(Key:W.Text(r,"projector_key")!,Station:W.Text(r,"station_id")!,Version:(int)W.Number(r,"projection_version"))).ToArray();
            await W.Exec(db,"""
                insert into sli_plugin_workstations.projection_checkpoints(projector_key,partition_key,projection_version,committed_position,revision)
                select key,station,version,jsonb_build_object('processed_count',n),n
                from unnest(@p0::text[],@p1::text[],@p2::integer[],@p3::integer[]) page(key,station,version,n)
                on conflict(projector_key,partition_key) do update set projection_version=excluded.projection_version,
                    committed_position=jsonb_build_object('processed_count',(projection_checkpoints.committed_position->>'processed_count')::bigint+(excluded.committed_position->>'processed_count')::bigint),
                    revision=projection_checkpoints.revision+excluded.revision,updated_at=now()
                """,ct,checkpoints.Select(g=>g.Key.Key).ToArray(),checkpoints.Select(g=>g.Key.Station).ToArray(),checkpoints.Select(g=>g.Key.Version).ToArray(),checkpoints.Select(g=>g.Count()).ToArray());
        }
        foreach(string station in refresh)await WorkstationEvaluators.RefreshProtection(db,station,ct);
        return (progress+receipts.Count+refresh.Length,receipts.Count);
    }
    static Task<int> RegisterConsumers(NpgsqlConnection db,Dictionary<string,int> identities,CancellationToken ct)=>
        W.Exec(db,"select sli_plugin_workstations.register_projection_consumer(key,version) from unnest(@p0::text[],@p1::integer[]) consumer(key,version)",ct,identities.Keys.ToArray(),identities.Values.ToArray());
    static async Task<int> PrepareConsumers(NpgsqlConnection db,Dictionary<string,int> identities,int limit,CancellationToken ct,bool register=true)
    {
        if(register)await RegisterConsumers(db,identities,ct);
        return Convert.ToInt32(await W.Scalar(db,"""
            with consumers as materialized (
                select c.* from sli_plugin_workstations.projection_consumers c
                join unnest(@p0::text[],@p1::integer[]) active(key,version) on c.projector_key=active.key and c.projection_version=active.version
                where not c.backfill_complete order by c.projector_key,c.projection_version for update of c skip locked
            ), page as materialized (
                select c.projector_key,c.projection_version,q.work_id,q.payload_sha256 from consumers c cross join lateral (
                    select work_id,payload_sha256 from sli_plugin_workstations.projection_work where work_id>c.backfill_position order by work_id limit @p2
                ) q
            ), seeded as (
                insert into sli_plugin_workstations.projection_receipts(work_id,projector_key,projection_version,payload_sha256)
                select work_id,projector_key,projection_version,payload_sha256 from page on conflict do nothing
            ), advanced as (
                update sli_plugin_workstations.projection_consumers c set
                    backfill_position=coalesce((select max(p.work_id) from page p where p.projector_key=c.projector_key and p.projection_version=c.projection_version),c.backfill_position),
                    backfill_complete=(select count(*) from page p where p.projector_key=c.projector_key and p.projection_version=c.projection_version)<@p2
                from consumers active where c.projector_key=active.projector_key and c.projection_version=active.projection_version returning 1
            ) select count(*) from advanced
            """,ct,identities.Keys.ToArray(),identities.Values.ToArray(),limit));
    }
    static async Task<int> Backfill(NpgsqlConnection db,int limit,CancellationToken ct)
    {
        if(await W.Scalar(db,"select pg_try_advisory_xact_lock(hashtext('workstations.backfill'))",ct) is not true)return 0;
        foreach(var (table,key) in new[]{("observations","id"),("protection_state","agent_key"),("station_inventory","station_id")})
        {
            var checkpoint=(await W.Rows(db,"select committed_position from sli_plugin_workstations.projection_checkpoints where projector_key='workstations.backfill' and partition_key=@p0",ct,table)).SingleOrDefault();var position=checkpoint?["committed_position"] as JsonObject??new();
            if(position["complete"]?.GetValue<bool>()==true)continue;
            var rows=await W.Rows(db,$"select {key} as source_key from sli_plugin_workstations.{table} s where {key}>@p0 order by {key} limit @p1",ct,W.Text(position,"last_key")??"",limit);
            await W.Exec(db,"select sli_plugin_workstations.backfill_projection_input(@p0,key) from unnest(@p1::text[]) source(key)",ct,table,rows.Select(r=>W.Text(r,"source_key")!).ToArray());
            await W.Exec(db,"insert into sli_plugin_workstations.projection_checkpoints(projector_key,partition_key,projection_version,committed_position) values('workstations.backfill',@p0,1,jsonb_build_object('last_key',@p1::text,'complete',@p2)) on conflict(projector_key,partition_key) do update set committed_position=excluded.committed_position,revision=projection_checkpoints.revision+1,updated_at=now()",ct,table,rows.Count>0?W.Text(rows[^1],"source_key"):W.Text(position,"last_key")??"",rows.Count<limit);return rows.Count+1;
        }
        return 0;
    }
    internal static int RetentionDays(string value)
    {value=value.Trim();if(value.Length==0||!value.All(c=>c is >= '0' and <= '9')||!int.TryParse(value,out int n)||n is <1 or >3650)throw new WorkstationException("workstation_retention_days_invalid");return n;}
    static async Task<int> Days(NpgsqlConnection db,CancellationToken ct)
    {var setting=await W.Scalar(db,"select value from public.platform_settings where key='workstations.evidence_retention_days'",ct);return RetentionDays(setting is string s?s:Environment.GetEnvironmentVariable("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS") is {Length:>0} v?v:"90");}
    static DateTimeOffset RetentionNow(JsonObject job)
    {if(W.Text(job,"source_instance_id")!="workstations:history")throw new WorkstationException("workstation_retention_input_invalid");return W.Time(W.Text(job,"available_at_utc"));}
    static async Task<JsonObject> StageRetention(NpgsqlConnection db,JsonObject job,CancellationToken ct)
    {
        var now=RetentionNow(job);int days=await Days(db,ct);
        var rows=await W.Rows(db,"select observation.* from sli_plugin_workstations.observations observation where family in ('processes','usb') and observed_at<@p0 and not exists(select 1 from sli_plugin_workstations.observation_holds h where h.observation_id=observation.id) order by observed_at,id limit @p1",ct,now.AddDays(-days),Limit(job,50));
        var candidates=new JsonObject();foreach(var row in rows){W.NormalizeTransport(row);candidates[W.Text(row,"id")!]=W.Hash(row);}
        var result=Outcome(rows.Count==50);result["retention_days"]=days;result["candidates"]=candidates;return result;
    }
    async Task PublishRetention(NpgsqlConnection db,JsonObject job,JsonObject result,CancellationToken ct)
    {
        if(W.Text(result,"status") is "blocked" or "cancelled")return;
        var now=RetentionNow(job);var candidates=result["candidates"]?.AsObject()??throw new WorkstationException("workstation_retention_budget_invalid");
        int limit=Limit(job,50);if(candidates.Count>limit||candidates.Any(p=>!W.IsHash(p.Key)||!W.IsHash(p.Value?.ToString())))throw new WorkstationException("workstation_retention_budget_invalid");
        using var history=historyFactory()??throw new IOException("workstation_history_unavailable");
        var audit=auditFactory();int days=0,selected=0,deleted=0;long bytes=0;
        try
        {
            await SetFence(db,job,ct);days=await Days(db,ct);if(days!=W.Number(result,"retention_days"))throw new WorkstationException("workstation_retention_plan_changed");
            var rows=await W.Rows(db,"select observation.*,pg_column_size(observation) as purge_row_bytes from sli_plugin_workstations.observations observation where family in ('processes','usb') and observed_at<@p0 and observation.id=any(@p1) and not exists(select 1 from sli_plugin_workstations.observation_holds h where h.observation_id=observation.id) order by observed_at,id for update skip locked limit @p2",ct,now.AddDays(-days),candidates.Select(p=>p.Key).ToArray(),limit);
            selected=rows.Count;if(rows.Count!=candidates.Count)throw new WorkstationException("workstation_retention_plan_changed");
            foreach(var row in rows)
            {
                long rowBytes=W.Number(row,"purge_row_bytes");row.Remove("purge_row_bytes");W.NormalizeTransport(row);string hash=W.Hash(row);
                if(hash!=candidates[W.Text(row,"id")!]?.ToString())throw new WorkstationException("workstation_history_receipt_mismatch");
                if(W.Hash(row["observation"])!=W.Text(row,"observation_sha256"))throw new WorkstationException("workstation_observation_hash_mismatch");
                if(W.Sha(W.Text(row,"source_xml")!)!=W.Text(row["observation"],"source_sha256"))throw new WorkstationException("workstation_source_hash_mismatch");
                WorkstationHistory.Validate(row);
                if(await history.PreserveAsync(row,ct)!=hash)throw new WorkstationException("workstation_history_receipt_mismatch");
                if(await W.Exec(db,"delete from sli_plugin_workstations.observations where id=@p0 and observation_sha256=@p1",ct,W.Text(row,"id"),W.Text(row,"observation_sha256"))!=1)throw new WorkstationException("workstation_delete_count_mismatch");
                if((await W.Rows(db,"select id from sli_plugin_workstations.observations where id=@p0",ct,W.Text(row,"id"))).Count!=0)throw new WorkstationException("workstation_delete_readback_mismatch");
                deleted++;bytes+=rowBytes;
            }
        }
        catch(Exception error){audit.Finish(selected,deleted,bytes,days,now.AddDays(-days),error);throw;}
        audit.Finish(selected,deleted,bytes,days,now.AddDays(-days));
    }
}
