using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    static DateTimeOffset Bucket(DateTimeOffset at)=>new(at.Year,at.Month,at.Day,at.Hour,at.Minute/5*5,0,TimeSpan.Zero);
    internal static JsonObject? FailureEvent(JsonObject row)
    {
        if(!Native(row,"logons",4625))return null;
        var o=row["observation"]!;string? target=Bounded(o["roles"].Text("affected_entity"),512),source=Bounded(o["roles"].Text("source_ip"),512);
        if(source is not null){if(!IPAddress.TryParse(source,out var ip))return null;source=ip.IsIPv4MappedToIPv6?ip.MapToIPv4().ToString():ip.ToString();}
        else if(o["facts"]?["logon_type"]?.ToString()=="2")source="local";
        if(target is null||source is null)return null;if(!Ws.IsHash(row.Text("id")))throw new WorkstationException("workstation_c03_observation_id_invalid");
        return new(){["id"]=row["id"]!.DeepClone(),["at"]=Ws.Stamp(Ws.Time(row.Text("observed_at"))),["target"]=Sli.Server.Agents.Registry.UnicodeCaseFold.Fold(target),["source"]=source,["direction"]="on_station",["ref"]=Ref(row)};
    }
    internal static List<JsonObject> FailureBuckets(List<JsonObject> events,string station,DateTimeOffset start,DateTimeOffset detected)
    {
        if(events.Count>1000)throw new WorkstationException("workstation_c03_window_too_large");
        if(events.Any(e=>e.Text("direction") is not("on_station" or "from_station")))throw new WorkstationException("workstation_c03_direction_invalid");
        var findings=new List<JsonObject>();
        foreach(var group in events.GroupBy(e=>(Direction:e.Text("direction")!,Target:e.Text("target")!,Source:e.Text("source")!)).OrderBy(g=>g.Key.Direction,StringComparer.Ordinal).ThenBy(g=>g.Key.Target,StringComparer.Ordinal).ThenBy(g=>g.Key.Source,StringComparer.Ordinal))
        {
            var ordered=group.GroupBy(e=>e.Text("id")).Select(g=>g.Last()).OrderBy(e=>Ws.Time(e.Text("at"))).ThenBy(e=>e.Text("id"),StringComparer.Ordinal).ToArray();
            int left=0;var peaks=new SortedDictionary<DateTimeOffset,(int Count,int Left,int Right)>();
            for(int right=0;right<ordered.Length;right++)
            {
                var at=Ws.Time(ordered[right].Text("at"));while(Ws.Time(ordered[left].Text("at"))<=at.AddMinutes(-5))left++;
                var block=Bucket(at);int count=right-left+1;
                if(block>=start&&block<start.AddMinutes(10)&&count>=20&&(!peaks.TryGetValue(block,out var peak)||count>peak.Count))peaks[block]=(count,left,right);
            }
            foreach(var (block,peak) in peaks)
            {
                var first=ordered[peak.Left];var last=ordered[peak.Right];var lastAt=Ws.Time(last.Text("at"));var (direction,target,source)=group.Key;
                string episode=Ws.Hash(new JsonArray("workstations.C03",1,station,direction,target,source,Ws.Stamp(block)));
                var subject=new JsonObject{["kind"]="workstation_account",["station_id"]=station,["identity_key"]=target,["ad_entity_id"]=null};
                var p=new JsonObject{["count"]=peak.Count,["count_relation"]="at_least",["window_minutes"]=5,["threshold"]=20,["direction"]=direction,["source"]=source,["window_start"]=Ws.Stamp(lastAt.AddMinutes(-5)),["window_end"]=Ws.Stamp(lastAt),["bucket_start"]=Ws.Stamp(block),["bucket_end"]=Ws.Stamp(block.AddMinutes(5)),["evidence_sampled"]=peak.Count>20};
                var refs=new JsonArray(ordered.Skip(peak.Left).Take(Math.Min(peak.Right-peak.Left+1,20)).Select(e=>e["ref"]!.DeepClone()).ToArray());
                var finding=Finding("C03",station,episode,subject,p,refs,Ws.Time(first.Text("at")),detected);finding["subject_id"]=Ws.Hash(new JsonArray(station,target));finding["last_observed_at"]=Ws.Stamp(lastAt);findings.Add(finding);
            }
        }
        return findings;
    }
    static async Task PasswordFailures(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind")!="observations"||FailureEvent(fact["payload"]!.AsObject()) is not {} current)return;
        var row=fact["payload"]!.AsObject();await RequireAgent(db,station,row,ct);var start=Bucket(Ws.Time(current.Text("at")));
        var rows=await Ws.Rows(db,"select id,agent_key,family,event_id,observed_at,observation from sli_plugin_workstations.observations where agent_key=@p0 and family='logons' and event_id=4625 and observed_at>@p1 and observed_at<@p2 order by observed_at,id limit 1001",ct,row.Text("agent_key"),start.AddMinutes(-5),start.AddMinutes(10));
        if(rows.Count>1000)throw new WorkstationException("workstation_c03_window_too_large");
        var events=rows.Select(FailureEvent).OfType<JsonObject>().Where(e=>e.Text("target")==current.Text("target")&&e.Text("source")==current.Text("source")).ToList();var detected=await Now(db,ct);
        foreach(var finding in FailureBuckets(events,station,start,detected))await Ws.Insert(db,"check_findings",finding,"""
            on conflict(id) do update set condition_sha256=excluded.condition_sha256,fact_at=excluded.fact_at,last_observed_at=excluded.last_observed_at,materially_changed_at=excluded.materially_changed_at,reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,revision=check_findings.revision+1 where check_findings.condition_sha256<>excluded.condition_sha256
            """,ct);
    }
}
