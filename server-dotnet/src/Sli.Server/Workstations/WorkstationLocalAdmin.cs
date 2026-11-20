using System.Text.Json.Nodes;
using Npgsql;
namespace Sli.Server.Workstations;
internal static partial class WorkstationEvaluators
{
    const string Administrators="S-1-5-32-544";
    internal static JsonObject? AdminEvent(JsonObject row,string station)
    {
        int n=(int)row.Number("event_id");var o=row["observation"]!;var f=o["facts"]!;
        if(n is not(4732 or 4733)||!Native(row,"protection",n)||(f.Text("group_sid")??f.Text("group"))!=Administrators)return null;
        if(!Ws.IsHash(row.Text("id")))throw new WorkstationException("workstation_c02_observation_id_invalid");
        string? actor=Sid(f.Text("actor_sid"));if(actor is null){string? role=o["roles"].Text("actor");actor=Sid(role?.StartsWith("sid:",StringComparison.Ordinal)==true?role[4..]:role);}
        return new(){["id"]=row["id"]!.DeepClone(),["agent_key"]=row["agent_key"]!.DeepClone(),["event_id"]=n,["at"]=Ws.Stamp(Ws.Time(row.Text("observed_at"))),["generation"]=Bounded(o.Text("generation"),512),["record_id"]=o["record_id"]?.GetValueKind()==System.Text.Json.JsonValueKind.Number&&o.Number("record_id")>=0?o["record_id"]!.DeepClone():null,["member"]=Account(station,Sid(f.Text("member_sid")??f.Text("member")),Bounded(f.Text("member_name"),512)),["actor"]=Account(station,actor,Bounded(f.Text("actor_name"),512),Bounded(f.Text("actor_domain"),512)),["ref"]=Ref(row)};
    }
    static bool After(JsonObject later,JsonObject earlier)
    {
        var a=Ws.Time(later.Text("at"));var b=Ws.Time(earlier.Text("at"));if(a!=b)return a>b;
        return later.Text("generation") is {Length:>0} g&&g==earlier.Text("generation")&&later["record_id"] is not null&&earlier["record_id"] is not null&&later.Number("record_id")>earlier.Number("record_id");
    }
    static IOrderedEnumerable<JsonObject> Order(IEnumerable<JsonObject> items)=>items.OrderBy(e=>Ws.Time(e.Text("at"))).ThenBy(e=>e.Text("generation")??"",StringComparer.Ordinal).ThenBy(e=>e.Number("record_id")).ThenBy(e=>e.Text("id"),StringComparer.Ordinal);
    internal static JsonObject AdminFinding(JsonObject addition,JsonObject? removal,string station,DateTimeOffset detected,DateTimeOffset historyStart)
    {
        string episode=Ws.Hash(new JsonArray("workstations.C02",1,station,addition["member"].Text("sid"),addition.Text("id")));
        var p=new JsonObject{["actor_sid"]=addition["actor"]!["sid"]?.DeepClone(),["actor_name"]=addition["actor"]!["name"]?.DeepClone(),["actor_domain"]=addition["actor"]!["domain"]?.DeepClone(),["actor_status"]=addition["actor"]!["status"]?.DeepClone(),["group_sid"]=Administrators,["history_start_at"]=Ws.Stamp(historyStart),["baseline_status"]="unknown",["current_membership"]="unknown",["added_at"]=addition["at"]!.DeepClone(),["removed_at"]=removal?["at"]?.DeepClone()};
        var refs=new JsonArray(addition["ref"]!.DeepClone());if(removal is not null)refs.Add(removal["ref"]!.DeepClone());
        var finding=Finding("C02",station,episode,addition["member"]!.DeepClone().AsObject(),p,refs,Ws.Time(addition.Text("at")),detected,qualityReason:"local_admin_baseline_unknown");
        finding["subject_id"]=addition["member"]!["sid"]?.DeepClone();finding["status"]=removal is null?"active":"resolved";finding["last_observed_at"]=(removal??addition)["at"]!.DeepClone();finding["resolved_at"]=removal is null?null:Ws.Stamp(detected);return finding;
    }
    static async Task LocalAdmin(NpgsqlConnection db,string station,JsonObject fact,CancellationToken ct)
    {
        if(fact.Text("kind")!="observations"||AdminEvent(fact["payload"]!.AsObject(),station) is not {} current)return;
        var now=await Now(db,ct);bool added=current.Number("event_id")==4732;string kind=added?"local_admin_added":"local_admin_removed";
        var change=new JsonObject{["id"]=Ws.Hash(new JsonArray("workstations.C02","change",station,current.Text("id"))),["station_id"]=station,["change_kind"]=kind,["event_at"]=current["at"]!.DeepClone(),["detected_at"]=Ws.Stamp(now),["actor_ref"]=current["actor"]!.DeepClone(),["subject_ref"]=current["member"]!.DeepClone(),["reason_code"]=kind,["reason_params"]=new JsonObject(),["quality"]=Ws.Quality("partial","local_admin_baseline_unknown"),["evidence_refs"]=new JsonArray(current["ref"]!.DeepClone())};
        await Ws.Insert(db,"station_changes",change,"on conflict(id) do nothing",ct);
        if(current["member"].Text("sid") is not {} member)return;
        var rows=await Ws.Rows(db,"select id,agent_key,family,event_id,observed_at,observation from sli_plugin_workstations.observations where agent_key=@p0 and family='protection' and event_id in (4732,4733) and upper(coalesce(observation->'facts'->>'member_sid',observation->'facts'->>'member'))=@p1 and coalesce(observation->'facts'->>'group_sid',observation->'facts'->>'group')=@p2 order by observed_at,id limit 1001",ct,current.Text("agent_key"),member,Administrators);
        if(rows.Count>1000)throw new WorkstationException("workstation_c02_history_too_large");
        var events=Order(rows.Select(r=>AdminEvent(r,station)).OfType<JsonObject>()).ToArray();var removals=events.Where(e=>e.Number("event_id")==4733).ToArray();
        foreach(var addition in events.Where(e=>e.Number("event_id")==4732))
        {
            var finding=AdminFinding(addition,removals.FirstOrDefault(r=>After(r,addition)),station,now,Ws.Time(events[0].Text("at")));
            await Ws.Insert(db,"check_findings",finding,"""
                on conflict(id) do update set subject_ref=excluded.subject_ref,condition_sha256=excluded.condition_sha256,status=excluded.status,last_observed_at=excluded.last_observed_at,materially_changed_at=excluded.materially_changed_at,reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,
                resolved_at=case when check_findings.status='resolved' and excluded.status='resolved' then check_findings.resolved_at else excluded.resolved_at end,
                revision=check_findings.revision+1 where check_findings.condition_sha256<>excluded.condition_sha256
                """,ct);
        }
    }
}
