using System.Text.Json.Nodes;
using System.Text;
using System.Xml.Linq;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using Sli.Server.Infrastructure;

namespace Sli.Server.Workstations;

public interface IWorkstationReports
{
    Task<JsonObject> ReadAsync(WorkstationRequest request,AccessFacts facts,AccessDecision access,CancellationToken ct);
}

public sealed class WorkstationReports:IWorkstationReports
{
    readonly IPostgresConnectionFactory connections;
    readonly Func<WorkstationHistory?> historyFactory;
    public WorkstationReports(IPostgresConnectionFactory connections,IConfiguration configuration):this(connections,()=>WorkstationHistory.Configured(configuration)) { }
    internal WorkstationReports(IPostgresConnectionFactory connections,Func<WorkstationHistory?> historyFactory)
    {this.connections=connections;this.historyFactory=historyFactory;}
    internal const string EventNamesSql="select wanted.agent_key,recent.source_xml from unnest(@p0::text[]) wanted(agent_key) cross join (values ('logons'),('processes'),('usb'),('protection')) families(family) cross join lateral (select o.source_xml from sli_plugin_workstations.observations o where o.agent_key=wanted.agent_key and o.family=families.family order by o.observed_at desc,o.id desc limit 1) recent";
    static readonly string StationResources=new StreamReader(typeof(WorkstationReports).Assembly.GetManifestResourceStream("Sli.Server.Workstations.station-resources.sql")!).ReadToEnd();
    public async Task<JsonObject> ReadAsync(WorkstationRequest request,AccessFacts facts,AccessDecision access,CancellationToken ct)
    {
        try
        {
            WorkstationPredicate? scope=null;
            if(!request.Overview)
            {
                try{scope=WorkstationAgentScope.Build(facts,access,reportKey:request.Key,reportOnly:true);}
                catch(AgentControlException)
                {
                    if(request.Parameters.Text("agent_key") is not null)throw new WorkstationException("workstation_scope_denied",403);
                    var period=request.Parameters["period"]!;
                    return WorkstationReportContract.Result(request.Key,coverage:new(){["state"]="not_proven",["reason"]="workstation_scope_empty"},
                        window:new(){["from_utc"]=Ws.Stamp(Ws.Time(period.Text("from_utc"))),["to_utc"]=Ws.Stamp(Ws.Time(period.Text("to_utc")))},limitations:ScopeLimitations());
                }
            }
            await using var db=await connections.OpenAsync(ct);
            await using var tx=await db.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead,ct);
            await Ws.Exec(db,"set transaction read only",ct);
            var result=request.Overview?await Overview(db,request,facts,access,ct):await Family(db,request,scope!,ct);
            await tx.CommitAsync(ct);return result;
        }
        catch(NpgsqlException error)when(!request.Overview)
        {
            string reason=error.SqlState switch {"57014"=>"source_timeout","42P01"=>"source_not_initialized","42501"=>"source_access_denied",_=>"source_unavailable"};
            return WorkstationReportContract.Result(request.Key,"error",coverage:new(){["state"]="error",["reason"]=reason},limitations:new(new JsonObject{["code"]=reason,["text"]=WorkstationReportContract.Message("reports.workstations."+reason)["text"]!.DeepClone()}));
        }
    }
    static async Task<List<JsonObject>> Query(NpgsqlConnection db,string sql,WorkstationPredicate predicate,CancellationToken ct,params object?[] args)
    {
        await using var cmd=Ws.Command(db,"select to_jsonb(ws_row)::text from ("+sql+") ws_row",args);
        foreach(var p in predicate.Parameters)cmd.Parameters.Add(new NpgsqlParameter(p.ParameterName,p.Value));
        return await Ws.Rows(cmd,ct);
    }
    static WorkstationPredicate Selection(WorkstationRequest r,AccessFacts facts,AccessDecision access)
    {
        var scope=WorkstationAgentScope.Build(facts,access,inventory:true,reportKey:r.Key);
        string predicate=scope.Sql;var p=scope.Parameters.ToList();
        string Add(object value){string key="selection"+p.Count;p.Add(new(key,value));return "@"+key;}
        if(r.Parameters.Text("search") is {} search)
        {
            string term=Add("%"+search.Replace("\\","\\\\").Replace("%","\\%").Replace("_","\\_")+"%");
            predicate+="""
             and exists(select 1 from (
                select s.metadata->>'display_name' as value
                union all select m.last_interactive_login#>>'{account,name}'
                union all select concat_ws(chr(92),m.last_interactive_login#>>'{account,domain}',m.last_interactive_login#>>'{account,name}') where m.last_interactive_login#>>'{account,name}' is not null
                union all select value from jsonb_array_elements_text(case when jsonb_typeof(s.metadata->'ip_addresses')='array' then s.metadata->'ip_addresses' else '[]'::jsonb end)
             ) search_values where search_values.value ilike
            """+" "+term+")";
        }
        if(r.Parameters.Text("ou") is {} ou)predicate+=" and s.metadata->>'ou_path'="+Add(ou);
        var domain=r.Parameters["domain"]??r.Parameters["domain_id"];
        if(domain is not null)predicate+=" and s.domain_id="+Add(domain.GetValue<long>());
        if(r.RowId is not null)predicate+=" and s.station_id="+Add(r.RowId);
        return new(predicate,p);
    }
    async Task<JsonObject> Overview(NpgsqlConnection db,WorkstationRequest r,AccessFacts facts,AccessDecision access,CancellationToken ct)
    {
        var scope=Selection(r,facts,access);
        string basis=StationResources+", visible as materialized (select s.*,m.protection,m.health,m.last_interactive_login,m.as_of_utc from sli_plugin_workstations.station_inventory s left join sli_plugin_workstations.station_summary m using(station_id) where "+scope.Sql+"), observed as materialized (select f.* from sli_plugin_workstations.check_findings f join visible v using(station_id) where f.status='active') ";
        if(r.RowId is not null&&r.Parameters["finding_id"] is not null)return await Evidence(db,r,basis,scope,ct);
        var summary=(await Query(db,basis+"select count(*) as total,count(agent_key) as agent_stations,(select count(distinct station_id) from observed) as observed_stations,exists(select 1 from sli_plugin_workstations.station_inventory) as inventory_built,transaction_timestamp() as as_of from visible",scope,ct)).Single();
        bool built=summary["inventory_built"]!.GetValue<bool>();
        if(r.RowId is not null&&summary.Number("total")==0)throw new WorkstationException("workstation_access_denied",403);
        var observed=await Query(db,basis+"select check_id,count(distinct station_id) as stations from observed group by check_id",scope,ct);
        var checks=new JsonArray(Enumerable.Range(1,10).Select(n=>(JsonNode)WorkstationReportContract.Check($"C{n:00}",observed.FirstOrDefault(c=>c.Text("check_id")==$"C{n:00}")?.Number("stations"))).ToArray());
        string restriction="";var values=new List<object?>();
        if(r.Parameters.Text("check_id") is {} check){restriction+=" and exists(select 1 from observed f where f.station_id=v.station_id and f.check_id=@p0)";values.Add(check);}
        long preceding=0;string? previous=null;
        if(r.Cursor is not null&&r.RowId is null)
        {
            string before=restriction+" and v.station_id<=@p"+values.Count;
            var backwards=await Query(db,basis+"select v.station_id from visible v where true "+before+" order by v.station_id desc limit @p"+(values.Count+1),scope,ct,[..values,r.Cursor,r.Limit+1]);
            preceding=(await Query(db,basis+"select count(*) as n from visible v where true "+before,scope,ct,[..values,r.Cursor])).Single().Number("n");
            if(backwards.Count>r.Limit)previous=backwards[^1].Text("station_id");
        }
        long? filtered=built?(r.Parameters["check_id"] is null?summary.Number("total"):(await Query(db,basis+"select count(distinct station_id) as n from observed where check_id=@p0",scope,ct,r.Parameters.Text("check_id"))).Single().Number("n")):null;
        if(r.Cursor is not null&&r.RowId is null){restriction+=" and v.station_id>@p"+values.Count;values.Add(r.Cursor);}
        var rows=await Query(db,basis+"select v.*,(select count(distinct check_id) from observed f where f.station_id=v.station_id) as observed_checks from visible v where true "+restriction+" order by v.station_id limit @p"+values.Count,scope,ct,[..values,r.Limit+1]);
        bool more=rows.Count>r.Limit;rows=rows.Take(r.Limit).ToList();
        var now=Ws.Time(summary.Text("as_of"));
        await Devices(db,rows,now,ct);
        var findings=r.RowId is null?[]:await Query(db,basis+"select id,station_id,check_id,rule_version,revision,reason_code,reason_params,quality,evidence_refs,last_observed_at,subject_ref from observed order by check_id,id limit 101",scope,ct);
        foreach(var f in findings)FindingCard(f,r.RowId!);
        var ous=await Query(db,basis+"select distinct metadata->>'ou_path' as value from visible where nullif(metadata->>'ou_path','') is not null order by value limit 101",scope,ct);
        var result=WorkstationReportContract.Result(r.Key,items:Ws.Array(rows),coverage:new(){["state"]="partial",["completeness"]="not_proven",["population_status"]=!built?"inventory_pending":summary.Number("agent_stations")==0?"no_agents":summary.Number("observed_stations")==0?"awaiting_observations":"partial",["card_findings_has_more"]=findings.Count>100},window:r.Parameters["period"]?.DeepClone() as JsonObject??new());
        result["window"]!["generated_at_utc"]=summary["as_of"]!.DeepClone();result["filtered_count"]=filtered;result["has_more"]=more;result["next_cursor"]=more?rows[^1]["station_id"]!.DeepClone():null;
        result["collections"]=new JsonObject{["checks"]=checks,["findings"]=Ws.Array(findings.Take(100)),["paging"]=new JsonArray(new JsonObject{["start"]=preceding+1,["has_previous"]=preceding>0,["previous_cursor"]=previous})};
        result["metrics"]=new JsonArray(new JsonObject{["key"]="stations",["label"]="workstations.overview.stations",["value"]=built?summary["total"]!.DeepClone():null,["quality"]=built?"observed":"unknown"},new JsonObject{["key"]="observed",["label"]="workstations.overview.observed",["value"]=built?summary["observed_stations"]!.DeepClone():null,["quality"]=built?"observed":"unknown"});
        result["filter_options"]!["ou"]=new JsonArray(ous.Take(100).Select(o=>(JsonNode)new JsonObject{["value"]=o["value"]!.DeepClone(),["label"]=o["value"]!.DeepClone()}).ToArray());return result;
    }
    static async Task Devices(NpgsqlConnection db,List<JsonObject> rows,DateTimeOffset now,CancellationToken ct)
    {
        if(rows.Count==0)return;
        var counts=await Ws.Rows(db,"""
            with selected as (select unnest(@p0::text[]) as station_id), boundaries as (
                select d.station_id,min(d.first_seen_at) as history_start_at from sli_plugin_workstations.device_seen d join selected s using(station_id) where d.first_seen_at<@p1 group by d.station_id
            ), counts as (
                select d.station_id,count(distinct d.device_key) as value from sli_plugin_workstations.device_seen_occurrences d join selected s using(station_id) where d.observed_at>=@p2 and d.observed_at<@p1 group by d.station_id
            ) select s.station_id,b.history_start_at,coalesce(c.value,0) as value from selected s left join boundaries b using(station_id) left join counts c using(station_id)
            """,ct,rows.Select(r=>r.Text("station_id")!).ToArray(),now,now.AddDays(-7));
        foreach(var row in rows)
        {
            var d=counts.Single(c=>c.Text("station_id")==row.Text("station_id"));bool known=d["history_start_at"] is not null;
            row["devices"]=new JsonObject{["devices_7d"]=Ws.Count(known?d.Number("value"):null,known?"at_least":"unknown"),["window_start_at"]=Ws.Stamp(now.AddDays(-7)),["window_end_at"]=Ws.Stamp(now),["history_start_at"]=d["history_start_at"]?.DeepClone(),["baseline_status"]="unknown",["quality"]=Ws.Quality(known?"partial":"not_collected",known?"device_history_incomplete":"not_collected")};
        }
    }
    internal static void FindingCard(JsonObject row,string station)
    {
        var subject=row["subject_ref"] as JsonObject;row.Remove("subject_ref");
        if(row.Text("check_id")!="C04"||subject?.Text("kind")!="workstation_process_observation"||subject.Text("station_id")!=station)return;
        row["process_details"]=new JsonObject{["path"]=WorkstationEvaluators.Bounded(subject.Text("path"),512),["process_id"]=Sli.Server.Agents.Consumer.WorkstationLogonProjection.ProcessId(subject.Text("process_id")),["signature_status"]=subject.Text("signature_status")=="not_received"?"not_received":"unknown",["current_state"]="unknown"};
        if(subject["file_measurement"] is JsonObject measurement)
            try{WorkstationEvaluators.ValidateMeasurement(measurement);row["process_details"]!["file_measurement"]=measurement.DeepClone();}catch(WorkstationException){}
    }
    async Task<JsonObject> Evidence(NpgsqlConnection db,WorkstationRequest r,string basis,WorkstationPredicate scope,CancellationToken ct)
    {
        var finding=(await Query(db,basis+"select f.evidence_refs,v.agent_key from observed f join visible v using(station_id) where f.id=@p0",scope,ct,r.Parameters.Text("finding_id"))).SingleOrDefault();
        if(finding is null)throw new WorkstationException("workstation_access_denied",403);
        int index=(int)r.Parameters.Number("evidence_index")-1;
        if(finding["evidence_refs"] is not JsonArray refs||index<0||index>=Math.Min(refs.Count,100)||refs[index] is not JsonObject reference||reference.Text("kind") is not("workstation_observation" or "protection_snapshot"))throw new WorkstationException("workstation_evidence_invalid");
        if(finding.Text("agent_key") is not {} key||reference.Text("agent_key")!=key)throw new WorkstationException("workstation_access_denied",403);
        var items=new List<JsonObject>();string evidenceSource="postgres_exact";
        if(reference.Text("kind")=="workstation_observation")
        {
            var records=await Ws.Rows(db,"select id,agent_key,family,observed_at,observation,observation_sha256,source_xml from sli_plugin_workstations.observations where agent_key=@p0 and id=@p1 limit 2",ct,key,reference.Text("observation_id"));
            if(records.Count==1)items.Add(ObservationEvidence(records[0],reference));
            else
            {
                try
                {
                    using var adapter=historyFactory();
                    if(adapter is null)throw new IOException("workstation_history_unavailable");
                    var archived=await adapter.FindEvidenceAsync(key,reference.Text("observation_id")!,ct);
                    if(archived is not null){items.Add(ObservationEvidence(archived,reference));evidenceSource="clickhouse_exact";}
                }
                catch(Exception error)when(error is HttpRequestException or IOException)
                {return WorkstationReportContract.Result(r.Key,"error",coverage:new(){["state"]="blocked",["reason"]="workstation_history_unavailable"});}
            }
        }
        else
        {
            var record=(await Ws.Rows(db,"select observed_at,state,state_sha256 from sli_plugin_workstations.protection_state where agent_key=@p0 and state_sha256=@p1 and observed_at=@p2 limit 1",ct,key,reference.Text("sha256"),Ws.Time(reference.Text("observed_at")))).SingleOrDefault();
            if(record is not null)
            {
                if(Ws.Hash(record["state"])!=reference.Text("sha256"))throw new WorkstationException("workstation_evidence_mismatch");
                items.Add(new JsonObject{["storage_kind"]="protection_snapshot",["state"]=record["state"]!.DeepClone(),["observed_at"]=record["observed_at"]!.DeepClone(),["source_sha256"]=record["state_sha256"]!.DeepClone()});
            }
        }
        return WorkstationReportContract.Result(r.Key,items.Count==0?"not_collected":"ok",Ws.Array(items),new(){["state"]=items.Count==0?"not_collected":"available",["source"]=evidenceSource});
    }
    internal static JsonObject ObservationEvidence(JsonObject row,JsonObject reference)
    {
        if(row["observation"] is not JsonObject body||row.Text("source_xml") is not {} xml||row.Text("id")!=reference.Text("observation_id")||row.Text("agent_key")!=reference.Text("agent_key")||body.Text("agent_key")!=row.Text("agent_key")||Ws.Hash(body)!=row.Text("observation_sha256")||Ws.Sha(xml)!=reference.Text("source_sha256")||body.Text("source_sha256")!=reference.Text("source_sha256"))throw new WorkstationException("workstation_evidence_mismatch");
        var item=Ws.Pick(row,"id","family","observed_at","source_xml","observation_sha256");item["storage_kind"]="workstation_observation";item["source_sha256"]=reference["source_sha256"]?.DeepClone();return item;
    }
    static JsonArray ScopeLimitations()=>new(new JsonObject{["code"]="workstation_scope_unresolved",["text"]="Область одного из разрешений не поддерживается или некорректна; доступ по нему не предоставлен."});
    internal static async Task<string[]> AgentKeysAsync(NpgsqlConnection db,AccessFacts facts,AccessDecision access,string reportKey,CancellationToken ct)
    {
        WorkstationPredicate predicate;
        try{predicate=WorkstationAgentScope.Build(facts,access,reportKey:reportKey,reportOnly:true);}
        catch(AgentControlException){predicate=new("FALSE",[]);}
        return await AgentKeysAsync(db,predicate,ct);
    }
    static async Task<string[]> AgentKeysAsync(NpgsqlConnection db,WorkstationPredicate predicate,CancellationToken ct)
    {
        var keys=(await Query(db,WorkstationAgentReader.Resources+"select distinct a.agent_key from registered a where "+predicate.Sql+" order by a.agent_key limit 501",predicate,ct)).Select(x=>x.Text("agent_key")!).ToArray();
        if(keys.Length>500)throw new WorkstationException("workstation_scope_invalid");
        return keys;
    }
    async Task<JsonObject> Family(NpgsqlConnection db,WorkstationRequest r,WorkstationPredicate predicate,CancellationToken ct)
    {
        var keys=await AgentKeysAsync(db,predicate,ct);
        if(r.Parameters.Text("agent_key") is {} selected){if(!keys.Contains(selected))throw new WorkstationException("workstation_scope_denied",403);keys=[selected];}
        var period=r.Parameters["period"]!.AsObject();var start=Ws.Time(period.Text("from_utc"));var end=Ws.Time(period.Text("to_utc"));
        var window=new JsonObject{["from_utc"]=Ws.Stamp(start),["to_utc"]=Ws.Stamp(end)};
        if(keys.Length==0)return WorkstationReportContract.Result(r.Key,coverage:new(){["state"]="not_proven",["reason"]="workstation_scope_empty"},window:window,limitations:predicate.UnresolvedScope?ScopeLimitations():new(new JsonObject{["code"]="workstation_scope_empty",["text"]="В разрешённой области нет сопоставленных агентов рабочих станций."}));
        var states=new List<JsonObject>();string eventCursor=r.Cursor??"";
        if(r.Family=="protection")
        {
            states=await Ws.Rows(db,"select id,agent_key,entity_id,ad_computer_id,null::integer as event_id,observed_at,'security.protection.state'::text as semantic_type,state->'components' as facts,jsonb_build_object('snapshot',true,'state',state->>'state') as quality,state_sha256 as observation_sha256 from sli_plugin_workstations.protection_state where agent_key=any(@p0) order by id limit 500",ct,(object)keys);
            if(r.Cursor is not null){if(states.Any(s=>s.Text("id")==r.Cursor)){eventCursor="";states=states.Where(s=>string.CompareOrdinal(s.Text("id"),r.Cursor)>0).ToList();}else states=[];}
        }
        string evidence=r.RowId is not null?",source_xml,observation->>'source_sha256' as source_sha256":"";
        string storage=r.Family=="usb"?" and observation->'facts'->>'storage_evidence'='true'":"";
        string exact=r.RowId is not null?" and id=@p6":"";
        var args=new List<object?>{keys,r.Family,start,end,r.RowId is not null?"":eventCursor,r.Limit+1};if(r.RowId is not null)args.Add(r.RowId);
        var rows=await Ws.Rows(db,"with candidates as "+(r.Family=="processes"?"not materialized":"materialized")+" (select id from sli_plugin_workstations.observations where agent_key=any(@p0) and family=@p1 and observed_at>=@p2 and observed_at<@p3 and id>@p4"+storage+exact+"), page as materialized (select id from candidates order by id limit @p5) select id,agent_key,entity_id,ad_computer_id,event_id,observed_at,observation->>'semantic_type' as semantic_type,observation->'facts' as facts,observation->'quality' as quality,observation_sha256"+evidence+" from sli_plugin_workstations.observations join page using(id) order by id",ct,args.ToArray());
        string history="not_applicable";var limitations=predicate.UnresolvedScope?ScopeLimitations():new JsonArray();
        var coldEnd=ColdEnd(end,DateTimeOffset.UtcNow);
        if(start<coldEnd)
        {
            history="unavailable";
            try
            {
                using var adapter=historyFactory();
                if(adapter is not null){rows=Merge(rows,await adapter.ReadAsync(keys,r.Family,start,coldEnd,r.RowId is null?eventCursor:"",r.Limit+1,r.RowId,ct),r.Limit+1);history="loaded";}
            }
            catch(WorkstationException){return WorkstationReportContract.Result(r.Key,"error",coverage:new(){["state"]="blocked",["reason"]="workstation_history_receipt_mismatch"});}
            catch(Exception e)when(e is HttpRequestException or IOException or OperationCanceledException){if(ct.IsCancellationRequested)throw;}
            if(history=="unavailable")limitations.Add(new JsonObject{["code"]="history_unavailable",["text"]="Постоянная история недоступна; показаны только доступные данные PostgreSQL."});
        }
        rows=states.Concat(rows).Take(r.Limit+1).ToList();
        if(r.RowId is not null&&rows.Count==0)throw new WorkstationException("report_row_not_found",404);
        bool more=r.RowId is null&&rows.Count>r.Limit;rows=rows.Take(r.Limit).ToList();
        if(rows.Any(row=>row["quality"].Text("storage")=="compact_session"))limitations.Add(new JsonObject{["code"]="compact_sessions",["text"]="Старые 4624/4634 свёрнуты в сессии. Полный XML хранится только для доказательных цепочек; неоднозначные пары отмечены отдельно."});
        var names=await Names(db,keys,ct);foreach(var row in rows){names.TryGetValue(row.Text("agent_key")!,out var name);row["host_name"]=name?.Text("name");row["host_name_source"]=name?.Text("source")??"unknown";}
        limitations.Add(new JsonObject{["code"]="coverage_unverified",["text"]="Покрытие сбора не подтверждено. USB-события не доказывают чтение или копирование файлов."});
        var result=WorkstationReportContract.Result(r.Key,items:Ws.Array(rows),coverage:new(){["state"]="not_proven",["completeness"]="not_proven",["reason"]="agent_import_state_unknown",["continuity_reason"]="collection_continuity_not_proven",["history"]=history,["ad_enrichment"]="per_observation"},window:window,limitations:limitations);
        result["has_more"]=more;result["next_cursor"]=more?rows[^1]["id"]!.DeepClone():null;return result;
    }
    internal static List<JsonObject> Merge(List<JsonObject> hot,List<JsonObject> cold,int limit)
    {
        var merged=hot.ToDictionary(r=>r.Text("id")!);
        foreach(var row in cold)
        {
            if(merged.TryGetValue(row.Text("id")!,out var previous))
            {
                if(previous["quality"].Text("storage")=="compact_session"||row["quality"].Text("storage")=="compact_session")
                {
                    if(new[]{"id","agent_key","entity_id","ad_computer_id","event_id","observation_sha256"}.Any(k=>previous[k]?.ToString()!=row[k]?.ToString())||Ws.Time(previous.Text("observed_at"))!=Ws.Time(row.Text("observed_at")))throw new WorkstationException("workstation_history_receipt_mismatch");
                    if(previous["quality"].Text("storage")!="compact_session")continue;
                }
                else {var a=(JsonObject)previous.DeepClone();var b=(JsonObject)row.DeepClone();a.Remove("observed_at");b.Remove("observed_at");if(!JsonNode.DeepEquals(a,b)||Ws.Time(previous.Text("observed_at"))!=Ws.Time(row.Text("observed_at")))throw new WorkstationException("workstation_history_receipt_mismatch");}
            }
            merged[row.Text("id")!]=row;
        }
        return merged.OrderBy(p=>p.Key,StringComparer.Ordinal).Take(limit).Select(p=>p.Value).ToList();
    }
    internal static DateTimeOffset ColdEnd(DateTimeOffset end,DateTimeOffset now)=>end<now.AddDays(-7)?end:now.AddDays(-7);
    static async Task<Dictionary<string,JsonObject>> Names(NpgsqlConnection db,string[] keys,CancellationToken ct)
    {
        var names=new Dictionary<string,JsonObject>();
        var rows=await Ws.Rows(db,"""
            select a.id::text as agent_id,a.assigned_modules,a.registration_host_name,enrolled.host_name as enrolled_name from sli_agents a left join lateral (
                select coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
                from sli_agent_audit issued join sli_agent_group_approval_links c on issued.actor='enrollment:'||c.enrollment_token_id::text join sli_agent_group_requests r on r.id=c.request_id join ad_context_entity_versions v on v.id=r.computer_version_id where issued.target=a.id::text and issued.action='issue' order by issued.id desc limit 1
            ) enrolled on true where a.id::text=any(@p0)
            """,ct,(object)keys);
        foreach(var row in rows)
        {
            string? name=AgentControlJson.HumanName(row.Text("enrolled_name"));string source="ad_enrollment";
            if(name is null){name=AgentControlJson.ReportedName(row.Text("registration_host_name"));source="agent_reported";}
            if(name is null){var candidates=(row["assigned_modules"] as JsonArray??new()).OfType<JsonObject>().Where(m=>(m.Text("module_id") is "sli.windows.ad-dc" or "sli.workstations")&&m["config"] is JsonObject).Select(m=>AgentControlJson.HumanName(m["config"].Text("source_name"))).Where(s=>s is not null).Distinct().ToArray();name=candidates.Length==1?candidates[0]:null;source="module_config";}
            names[row.Text("agent_id")!]=new(){["name"]=name,["source"]=name is null?"unknown":source};
        }
        var missing=keys.Where(k=>!names.TryGetValue(k,out var n)||n["name"] is null).ToArray();
        if(missing.Length>0)
        {
            var events=await Ws.Rows(db,EventNamesSql,ct,(object)missing);
            foreach(var group in events.GroupBy(e=>e.Text("agent_key")!))
            {
                var candidates=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                foreach(var e in group)
                {
                    if(e.Text("source_xml") is not {} sourceXml||Encoding.UTF8.GetByteCount(sourceXml)>1048576)continue;
                    try
                    {
                        var xml=Sli.Agent.Core.EventXml.ParseBounded(sourceXml);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
                        if(AgentControlJson.ReportedName(xml.Element(ns+"System")?.Element(ns+"Computer")?.Value) is {} name)candidates.TryAdd(name,name);
                    }
                    catch(Sli.Agent.Core.EventXmlException){}
                }
                if(candidates.Count==1)names[group.Key]=new(){["name"]=candidates.Values.Single(),["source"]="event_reported"};
            }
        }
        return names;
    }
}
