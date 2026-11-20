using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    internal static readonly string[] Components=["antivirus_enabled","real_time_protection_enabled","behavior_monitor_enabled","ioav_protection_enabled","nis_enabled","tamper_protected"];
    static JsonObject NullComponents()=>new(Components.Select(k=>new KeyValuePair<string,JsonNode?>(k,null)));
    static JsonObject SnapshotRef(JsonObject row)=>new(){["kind"]="protection_snapshot",["agent_key"]=row["agent_key"]?.DeepClone(),["observed_at"]=Ws.Stamp(Ws.Time(row.Text("observed_at"))),["sha256"]=row["state_sha256"]?.DeepClone()};
    static JsonObject State(JsonObject snapshot)
    {
        if(snapshot["state"] is not JsonObject s||s.Count!=2||s.Text("state") is not("available" or "unavailable")||s["components"] is not JsonObject components||components.Count!=6||Components.Any(k=>!components.ContainsKey(k)||components[k] is not null&&(components[k]!.GetValueKind() is not(JsonValueKind.True or JsonValueKind.False)||s.Text("state")=="unavailable")))throw new WorkstationException("workstation_protection_state_invalid");
        if(Ws.Hash(s)!=snapshot.Text("state_sha256"))throw new WorkstationException("workstation_protection_snapshot_conflict");return s;
    }
    internal static JsonObject EvaluateProtection(JsonObject? snapshot,DateTimeOffset now,string stationType="unknown")
    {
        DateTimeOffset? observed=null;var components=NullComponents();var unknown=Components.ToList();var disabled=new List<string>();string status="not_collected";
        if(snapshot is not null)
        {
            var state=State(snapshot);observed=Ws.Time(snapshot.Text("observed_at"));components=(JsonObject)state["components"]!.DeepClone();unknown=Components.Where(k=>components[k] is null).ToList();disabled=Components.Where(k=>components[k]?.GetValue<bool>()==false).ToList();
            status=observed>now||state.Text("state")=="unavailable"?"unavailable":now-observed>TimeSpan.FromHours(24)?"stale":unknown.Count>0?"partial":"complete";
        }
        bool stale=observed is not null&&now-observed>TimeSpan.FromHours(24),known=status is "complete" or "partial";
        string? reason=status switch{"partial"=>"coverage_incomplete","stale"=>"data_stale","unavailable"=>"source_missing","not_collected"=>"not_collected",_=>null};
        var quality=Ws.Quality(status,reason);
        var summary=new JsonObject{["observed_at"]=observed is null?null:Ws.Stamp(observed.Value),["quality"]=quality.DeepClone(),["components"]=known?components.DeepClone():NullComponents(),["last_known_components"]=components.DeepClone(),["disabled_components"]=new JsonArray((known?disabled:[]).Select(k=>(JsonNode?)JsonValue.Create(k)).ToArray()),["unknown_components"]=new JsonArray((known?unknown:Components.ToList()).Select(k=>(JsonNode?)JsonValue.Create(k)).ToArray()),["next_refresh_at"]=observed is not null&&!stale?Ws.Stamp(observed>now?observed.Value:observed.Value.AddHours(24)):null};
        JsonObject Check(string key,JsonObject q,JsonObject count,JsonObject? p)
        {
            var check=WorkstationReportContract.Check(key,null);check["quality"]=q;check["counts"]!["stations"]=count;check["reasons"]=p is null?new JsonArray():new JsonArray(new JsonObject{["code"]=key=="C01"?"protection_disabled":"protection_stale",["message_key"]="workstations.reasons."+(key=="C01"?"protection_disabled":"protection_stale"),["params"]=p});return check;
        }
        var c01=Check("C01",quality,known&&unknown.Count<6?Ws.Count(disabled.Count>0?1:0,status=="complete"?"exact":"at_least"):Ws.Count(null,"unknown"),known&&disabled.Count>0?new(){["components"]=string.Join(", ",disabled)}:null);
        var c09Quality=observed is not null&&observed<=now?Ws.Quality("complete"):(JsonObject)quality.DeepClone();
        var c09=Check("C09",c09Quality,c09Quality.Text("status")=="complete"?Ws.Count(stale?1:0,"exact"):Ws.Count(null,"unknown"),stale?new(){["age_hours"]=(long)Math.Floor((now-observed!.Value).TotalHours)}:null);
        return new(){["summary"]=summary,["checks"]=new JsonArray(c01,c09),["severities"]=new JsonObject{["C01"]="high",["C09"]=stationType=="server"?"medium":"low"}};
    }
    static async Task ProtectionFinding(NpgsqlConnection db,string station,JsonObject check,string severity,JsonObject? snapshot,DateTimeOffset now,CancellationToken ct)
    {
        string key=check.Text("check_id")!;
        var previous=(await Ws.Rows(db,"select * from sli_plugin_workstations.check_findings where station_id=@p0 and check_id=@p1 and rule_version=1 order by first_detected_at desc,id desc limit 1 for update",ct,station,key)).SingleOrDefault();
        bool observedActive=check["reasons"]!.AsArray().Count>0,observedClear=check["quality"].Text("status")=="complete"&&check["counts"]!["stations"].Text("relation")=="exact"&&check["counts"]!["stations"].Number("value")==0;
        if(!observedActive&&(previous is null||previous.Text("status")=="resolved"))return;
        bool active=observedActive||!observedClear,observed=observedActive||observedClear;
        var p=observedActive?check["reasons"]![0]!["params"]!.DeepClone():previous!["reason_params"]!.DeepClone();var quality=check["quality"]!.DeepClone();
        string condition=Ws.Hash(new JsonArray(key,p["components"]?.DeepClone(),quality.DeepClone(),severity,active));
        if(active&&(previous is null||previous.Text("status")=="resolved"))
        {
            string episode=Ws.Hash(new JsonArray(key,station,SnapshotRef(snapshot!))),id=Ws.Hash(new JsonArray(key,1,station,episode));
            var finding=Finding(key,station,id,null,p.AsObject(),new(SnapshotRef(snapshot!)),Ws.Time(snapshot!.Text("observed_at")),now,qualityReason:null);
            finding.Remove("subject_ref");finding.Remove("subject_id");finding["episode_id"]=episode;finding["condition_sha256"]=condition;finding["severity"]=severity;finding["quality"]=quality;
            await Ws.Insert(db,"check_findings",finding,"on conflict(id) do nothing",ct);return;
        }
        await Ws.Exec(db,"""
            update sli_plugin_workstations.check_findings set revision=revision+case when condition_sha256<>@p0 then 1 else 0 end,
            materially_changed_at=case when condition_sha256<>@p0 then @p1 else materially_changed_at end,
            condition_sha256=@p0,status=@p2,severity=@p3,last_observed_at=@p4,resolved_at=@p5,
            reason_params=@p6::jsonb,quality=@p7::jsonb,evidence_refs=@p8::jsonb where id=@p9
            """,ct,condition,now,active?"active":"resolved",severity,observed&&snapshot is not null?Ws.Time(snapshot.Text("observed_at")):Ws.Time(previous!.Text("last_observed_at")),active?(object)DBNull.Value:now,p,quality,observed&&snapshot is not null?new JsonArray(SnapshotRef(snapshot)):previous!["evidence_refs"]!,previous!.Text("id"));
    }
    internal static async Task RefreshProtection(NpgsqlConnection db,string station,CancellationToken ct)
    {
        var now=new DateTimeOffset((DateTime)(await Ws.Scalar(db,"select clock_timestamp()",ct))!);
        var row=(await Ws.Rows(db,"select i.station_type,p.id,p.agent_key,p.observed_at,p.state,p.state_sha256 from sli_plugin_workstations.station_inventory i left join sli_plugin_workstations.protection_state p on p.agent_key=i.agent_key where i.station_id=@p0",ct,station)).SingleOrDefault()??throw new WorkstationException("workstation_projection_station_missing");
        var snapshot=row["observed_at"] is null?null:row;var result=EvaluateProtection(snapshot,now,row.Text("station_type")!);
        foreach(var check in result["checks"]!.AsArray().OfType<JsonObject>())await ProtectionFinding(db,station,check,result["severities"].Text(check.Text("check_id")!)!,snapshot,now,ct);
        await Ws.Exec(db,"""
            insert into sli_plugin_workstations.station_summary(station_id,protection,as_of_utc) values(@p0,@p1::jsonb,@p2)
            on conflict(station_id) do update set protection=excluded.protection,as_of_utc=excluded.as_of_utc,
            revision=station_summary.revision+case when station_summary.protection<>excluded.protection then 1 else 0 end,updated_at=now()
            """,ct,station,result["summary"]!,now);
    }
    static async Task Protection(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind") is not("protection_state" or "station_inventory"))return;
        var now=await Now(db,ct);
        if(fact.Text("kind")=="protection_state")
        {
            var current=fact["payload"]!.AsObject();
            var row=(await Ws.Rows(db,"select payload from sli_plugin_workstations.projection_work where kind='protection_state' and agent_key=@p0 and work_id<(select work_id from sli_plugin_workstations.projection_work where kind='protection_state' and source_id=@p1) order by work_id desc limit 1",ct,current.Text("agent_key"),fact.Text("source_id"))).SingleOrDefault();
            if(row?["payload"] is JsonObject previous&&Ws.Time(previous.Text("observed_at"))<Ws.Time(current.Text("observed_at")))
            {
                var before=State(previous);var after=State(current);
                if(before.Text("state")=="available"&&after.Text("state")=="available")
                foreach(var (direction,old,next) in new[]{("enabled",false,true),("disabled",true,false)})
                {
                    var changed=Components.Where(k=>before["components"]![k]?.GetValue<bool>()==old&&after["components"]![k]?.GetValue<bool>()==next).ToArray();if(changed.Length==0)continue;
                    string kind="protection_"+direction;
                    var change=new JsonObject{["id"]=Ws.Hash(new JsonArray(station,fact.Text("source_id"),kind)),["station_id"]=station,["change_kind"]=kind,["event_at"]=Ws.Stamp(Ws.Time(current.Text("observed_at"))),["detected_at"]=Ws.Stamp(now),["reason_code"]=kind,["reason_params"]=new JsonObject{["components"]=string.Join(", ",changed),["previous_observed_at"]=Ws.Stamp(Ws.Time(previous.Text("observed_at"))),["observed_at"]=Ws.Stamp(Ws.Time(current.Text("observed_at")))},["quality"]=Ws.Quality("complete"),["evidence_refs"]=new JsonArray(SnapshotRef(previous),SnapshotRef(current))};
                    await Ws.Insert(db,"station_changes",change,"on conflict(id) do nothing",ct);
                }
            }
        }
        await RefreshProtection(db,station,ct);
    }
}
