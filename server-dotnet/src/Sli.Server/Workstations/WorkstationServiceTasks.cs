using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    static readonly Dictionary<int,string> ServiceChanges=new(){[4697]="installed",[7045]="installed",[4698]="created",[4699]="deleted",[4700]="enabled",[4701]="disabled",[4702]="updated"};
    internal static JsonObject? ServiceEvent(JsonObject row,string station)
    {
        int number=(int)row.Number("event_id");if(!ServiceChanges.TryGetValue(number,out var change)||!(number==7045?Native(row,"processes",number,"System","Service Control Manager"):Native(row,"processes",number)))return null;
        if(!Ws.IsHash(row.Text("id")))throw new WorkstationException("workstation_c05_observation_id_invalid");
        var o=row["observation"]!;var f=o["facts"]!;string kind=number is 4697 or 7045?"service":"task";
        string? Exact(string key,int limit=512)=>Bounded(f.Text(key),limit);
        var actor=Account(station,null);
        if(number!=7045){string? raw=Exact("process_user_sid");actor=Account(station,raw is not null&&System.Text.RegularExpressions.Regex.IsMatch(raw,@"\AS-1-\d+(?:-\d+)+\z",System.Text.RegularExpressions.RegexOptions.IgnoreCase)&&raw.ToUpperInvariant()!="S-1-0-0"?raw:null,Exact("process_user_name"),Exact("process_user_domain"));}
        string? content=Exact("task_content",8192);
        return new(){["id"]=row["id"]!.DeepClone(),["agent_key"]=row["agent_key"]!.DeepClone(),["event_id"]=number,["kind"]=kind,["name"]=Exact(kind+"_name"),["change"]=change,["at"]=Ws.Stamp(Ws.Time(row.Text("observed_at"))),["program"]=Exact("service_file",2048),["run_as"]=Exact("service_account"),["start_type"]=Exact("service_start_type"),["content_sha256"]=content is null?null:Ws.Hash(JsonValue.Create(content)),["actor"]=actor,["generation"]=Bounded(o.Text("generation"),512),["record_id"]=o["record_id"]?.GetValueKind()==System.Text.Json.JsonValueKind.Number&&o.Number("record_id")>=0?o["record_id"]!.DeepClone():null,["ref"]=Ref(row)};
    }
    static JsonArray? Configuration(JsonObject item)
    {
        string[] fields=item.Text("kind")=="service"?["program","run_as","start_type"]:["content_sha256"];
        return fields.All(k=>item.Text(k) is {Length:>0})?new JsonArray(new[]{JsonValue.Create(item.Text("kind"))}.Concat(fields.Select(k=>item[k]!.DeepClone())).ToArray()):null;
    }
    static string? PairKey(JsonObject item,string station)=>item.Text("kind")=="service"&&item.Text("name") is {Length:>0} name&&Configuration(item) is {} config?Ws.Hash(new JsonArray("workstations.C05",1,station,item.Text("agent_key"),item.Text("at"),name,config)):null;
    static string ServiceEpisode(string station,JsonObject item)=>Ws.Hash(new JsonArray("workstations.C05",1,station,item.Text("id")));
    internal static (List<(string Id,List<JsonObject> Items,string Dedup)> Groups,List<string> Superseded) ServiceEpisodes(List<JsonObject> events,string station)
    {
        var groups=new List<(string,List<JsonObject>,string)>();var buckets=new Dictionary<string,List<JsonObject>>();var superseded=new List<string>();
        foreach(var item in Order(events).Where(i=>i.Text("change") is "installed" or "created"))
        {if(PairKey(item,station) is {} key){if(!buckets.TryGetValue(key,out var list))buckets.Add(key,list=[]);list.Add(item);}else groups.Add((ServiceEpisode(station,item),[item],"separate"));}
        foreach(var (key,items) in buckets)
        {
            if(Math.Max(items.Count(i=>i.Number("event_id")==4697),items.Count(i=>i.Number("event_id")==7045))==1)groups.Add((key,items,items.Count==2?"exact_pair":"single"));
            else{superseded.Add(key);groups.AddRange(items.Select(i=>(ServiceEpisode(station,i),new List<JsonObject>{i},"ambiguous")));}
        }
        return(groups,superseded);
    }
    internal static JsonObject ServiceFinding(string id,List<JsonObject> items,string dedup,List<JsonObject> events,string station,DateTimeOffset detected)
    {
        var first=Order(items).First();var actor=items.FirstOrDefault(i=>i.Number("event_id")!=7045)?["actor"]??first["actor"]!;
        var deletion=Order(events).FirstOrDefault(i=>first.Text("kind")=="task"&&first.Text("name") is {Length:>0} name&&i.Text("name")==name&&i.Text("change")=="deleted"&&After(i,first));
        var refs=new JsonArray(Order(items).Select(i=>i["ref"]!.DeepClone()).ToArray());if(deletion is not null)refs.Add(deletion["ref"]!.DeepClone());var config=Configuration(first);
        var p=new JsonObject{["object_kind"]=first["kind"]!.DeepClone(),["object_name"]=first["name"]?.DeepClone(),["change"]=first["change"]!.DeepClone(),["program"]=first["program"]?.DeepClone(),["run_as"]=first["run_as"]?.DeepClone(),["start_type"]=first["start_type"]?.DeepClone(),["content_sha256"]=first["content_sha256"]?.DeepClone(),["created_at"]=first["at"]!.DeepClone(),["deleted_at"]=deletion?["at"]?.DeepClone(),["history_start_at"]=Order(events).First()["at"]!.DeepClone(),["baseline_status"]="unknown",["current_presence"]="unknown",["dedup_status"]=dedup,["common_cause_id"]=config is null?null:Ws.Hash(new JsonArray("workstations.C05","configuration",config)),["common_cause_basis"]=config is null?"unknown":"matching_configuration"};
        foreach(string key in new[]{"sid","name","domain","status"})p["actor_"+key]=actor[key]?.DeepClone();
        var subject=new JsonObject{["kind"]="workstation_"+first.Text("kind"),["station_id"]=station,["name"]=first["name"]?.DeepClone()};
        var finding=Finding("C05",station,id,subject,p,refs,Ws.Time(first.Text("at")),detected,qualityReason:"service_task_baseline_unknown");finding["subject_id"]=first.Text("name") is null?null:Ws.Hash(new JsonArray(first.Text("kind"),first.Text("name")));finding["condition_sha256"]=Ws.Hash(new JsonArray(p.DeepClone(),refs.DeepClone()));finding["status"]=deletion is null?"active":"resolved";finding["last_observed_at"]=(deletion??first)["at"]!.DeepClone();finding["resolved_at"]=deletion is null?null:Ws.Stamp(detected);return finding;
    }
    static async Task ServiceTasks(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind")!="observations"||ServiceEvent(fact["payload"]!.AsObject(),station) is not {} current)return;
        var now=await Now(db,ct);string kind=current.Text("kind")!;
        var rows=await Ws.Rows(db,"select payload from sli_plugin_workstations.projection_work where kind='observations' and agent_key=@p0 and payload->>'family'='processes' and payload->>'event_id'=any(@p1) and payload->'observation'->'facts'->>@p2 is not distinct from @p3::text order by work_id limit 201",ct,current.Text("agent_key"),kind=="service"?new[]{"4697","7045"}:["4698","4699","4700","4701","4702"],kind+"_name",current.Text("name"));
        if(rows.Count>200)throw new WorkstationException("workstation_c05_history_too_large");
        var events=rows.Select(r=>ServiceEvent(r["payload"]!.AsObject(),station)).OfType<JsonObject>().ToDictionary(e=>e.Text("id")!);events[current.Text("id")!]=current;
        string changeKind=kind+"_"+current.Text("change");
        await Ws.Insert(db,"station_changes",new(){["id"]=Ws.Hash(new JsonArray("workstations.C05","change",station,current.Text("id"))),["station_id"]=station,["change_kind"]=changeKind,["event_at"]=current["at"]!.DeepClone(),["detected_at"]=Ws.Stamp(now),["actor_ref"]=current["actor"]!.DeepClone(),["subject_ref"]=new JsonObject{["kind"]="workstation_"+kind,["station_id"]=station,["name"]=current["name"]?.DeepClone()},["reason_code"]=changeKind,["reason_params"]=new JsonObject(),["quality"]=Ws.Quality("partial","service_task_baseline_unknown"),["evidence_refs"]=new JsonArray(current["ref"]!.DeepClone())},"on conflict(id) do nothing",ct);
        var (groups,superseded)=ServiceEpisodes(events.Values.ToList(),station);
        foreach(string id in superseded)await Ws.Exec(db,"update sli_plugin_workstations.check_findings set status='resolved',resolved_at=@p0,materially_changed_at=@p0,revision=revision+1,reason_params=reason_params||'{\"superseded_by_native_episodes\":true}'::jsonb where id=@p1 and status='active'",ct,now,id);
        foreach(var (id,items,dedup) in groups)await Ws.Insert(db,"check_findings",ServiceFinding(id,items,dedup,events.Values.ToList(),station,now),"""
            on conflict(id) do update set condition_sha256=excluded.condition_sha256,status=excluded.status,last_observed_at=excluded.last_observed_at,materially_changed_at=excluded.materially_changed_at,reason_params=excluded.reason_params,evidence_refs=excluded.evidence_refs,
            resolved_at=case when check_findings.status='resolved' and excluded.status='resolved' then check_findings.resolved_at else excluded.resolved_at end,
            revision=check_findings.revision+1 where check_findings.condition_sha256<>excluded.condition_sha256
            """,ct);
    }
}
