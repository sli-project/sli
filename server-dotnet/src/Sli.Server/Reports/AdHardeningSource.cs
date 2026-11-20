using System.Data;
using System.Text.Json.Nodes;
using System.Text;
using System.Security.Cryptography;
using Sli.Agent.Protocol;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic.Detections;

namespace Sli.Server.Reports;

public sealed record AdHardeningSnapshots(IReadOnlyList<JsonObject> Items,bool Truncated);
public interface IAdHardeningSource { Task<AdHardeningSnapshots> LoadAsync(long[]? domainIds,CancellationToken ct); }

public sealed class AdHardeningSource(IPostgresConnectionFactory connections):IAdHardeningSource
{
    public async Task<AdHardeningSnapshots> LoadAsync(long[]? domainIds,CancellationToken ct)
    {
        if(domainIds is {Length:0})return new([],false);
        await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(IsolationLevel.RepeatableRead,ct);var sql=new DetectionSql(db,tx);
        await sql.Execute("set transaction read only",ct);await sql.Execute("set local statement_timeout='10s'",ct);
        var result=await Load(sql,domainIds,ct);await tx.CommitAsync(ct);return result;
    }
    internal static async Task<AdHardeningSnapshots> Load(IDetectionSql sql,long[]? domainIds,CancellationToken ct)
    {
        if(domainIds is {Length:0})return new([],false);
        var runs=await sql.Rows("""
            /* ad_hardening_published_runs */
            select d.id as domain_id,r.run_id::text,r.observed_at_utc,s.source_state,r.mode,
              (select jsonb_object_agg(section_name,jsonb_build_object('status',status,'record_count',record_count))
               from public.ad_context_sections where run_id=r.run_id and section_name in ('directory_accounts','directory_group_graph')) as sections
            from public.domains d
            left join lateral(select manifest_id from public.ad_snapshot_manifests where domain_id=d.id order by slot_start_utc desc limit 1)m on true
            left join public.ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id and s.family='ad_context_base'
            left join public.ad_context_runs r on r.run_id::text=s.source_id and r.domain_id=d.id and r.bundle_sha256=s.payload_sha256 and r.status='completed'
            where (@domains::bigint[] is null or d.id=any(@domains::bigint[])) order by d.id limit 101
            """,ct,("domains",domainIds));
        var snapshots=new List<JsonObject>();foreach(var run in runs.Take(100)){
            if(run["run_id"]==null||run["observed_at_utc"]==null){snapshots.Add(new(){["available"]=false});continue;}
            var at=D.Time(run["observed_at_utc"]);var args=new (string,object?)[]{("run",Guid.Parse(D.Text(run["run_id"]))),("domain",run["domain_id"]!.GetValue<long>()),("at",at)};
            var entities=await sql.Rows("""
                /* ad_hardening_snapshot_entities */
                select v.attributes_json,encode(evidence.integrity_sha256,'hex') as integrity_sha256
                from public.ad_context_entity_versions v join public.entities_v2 entity on entity.id=v.entity_id
                join public.ad_context_evidence evidence on evidence.source_run_id=@run
                  and evidence.locator_json->>'record_key'=v.attributes_json->>'record_key'
                where entity.domain_id=@domain and v.source_section in ('directory_accounts','directory_group_graph')
                  and v.valid_from_utc<=@at and (v.valid_to_utc is null or v.valid_to_utc>@at)
                order by v.entity_id,v.source_section limit 10001
                """,ct,args);
            var relations=await sql.Rows("""
                /* ad_hardening_snapshot_memberships */
                select v.attributes_json,encode(evidence.integrity_sha256,'hex') as integrity_sha256
                from public.ad_context_relation_versions v join public.ad_context_evidence evidence
                  on evidence.source_run_id=@run and evidence.locator_json->>'record_key'=v.relation_key
                where v.domain_id=@domain and v.source_section='directory_group_graph' and v.relation_kind='member_of'
                  and v.valid_from_utc<=@at and (v.valid_to_utc is null or v.valid_to_utc>@at)
                order by v.relation_key limit 10001
                """,ct,args);
            var objects=Verified(entities.Take(10000),at);var edges=Verified(relations.Take(10000),at);var sections=run["sections"] as JsonObject??new();
            bool complete=entities.Count<=10000&&relations.Count<=10000&&sections.Select(p=>p.Key).ToHashSet().SetEquals(["directory_accounts","directory_group_graph"])&&sections.All(p=>D.Text(p.Value?["status"])=="complete")&&sections.Sum(p=>p.Value?["record_count"]?.GetValue<int>()??0)==objects.Count+edges.Count&&D.Text(run["mode"]) is "full" or "reconcile";
            snapshots.Add(new(){["available"]=true,["domain_id"]=run["domain_id"]!.DeepClone(),["run_id"]=run["run_id"]!.DeepClone(),["observed_at_utc"]=D.Stamp(at),["objects"]=D.Array(objects,n=>n.DeepClone()),["edges"]=D.Array(edges,n=>new JsonArray(n["source_record_key"]!.DeepClone(),n["target_record_key"]!.DeepClone())),["complete"]=complete});
        }return new(snapshots,runs.Count>100);
    }
    internal static IReadOnlyList<JsonObject> Verified(IEnumerable<JsonObject> rows,DateTimeOffset observed)
    {
        var records=new List<JsonObject>();foreach(var row in rows){var record=row["attributes_json"]!.AsObject();var reconstructed=(JsonObject)record.DeepClone();reconstructed["observed_at_utc"]=D.Stamp(observed).Replace("+00:00","Z",StringComparison.Ordinal);string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(reconstructed,ensureAscii:false))));if(hash==D.Text(row["integrity_sha256"]))records.Add(record);}return records;
    }
}

public static class AdHardeningReport
{
    public static JsonObject Render(AdHardeningSnapshots data,DateTimeOffset now,bool english=false,string? severity=null,string? query=null,string? ruleCode=null,Func<long,string,bool>? fieldAllowed=null)
    {
        var available=data.Items.Where(s=>s["available"]?.GetValue<bool>()==true).ToArray();bool partial=data.Truncated||available.Length!=data.Items.Count||available.Any(s=>s["complete"]?.GetValue<bool>()!=true),stale=available.Any(s=>now-D.Time(s["observed_at_utc"])>TimeSpan.FromHours(48)||D.Time(s["observed_at_utc"])>now);var rows=new JsonArray();
        JsonObject Message(string code,IReadOnlyDictionary<string,object?>? parameters=null)=>new(){["code"]=code,["params"]=System.Text.Json.JsonSerializer.SerializeToNode(parameters??new Dictionary<string,object?>()),["text"]=DetectionMessages.Text(code,english,parameters)};
        foreach(var snapshot in available)foreach(var node in AdHardening.Evaluate(snapshot)){
            var row=node!.AsObject();long domain=row["domain_id"]!.GetValue<long>();bool identity=fieldAllowed?.Invoke(domain,"identity_basic")??true,technical=fieldAllowed?.Invoke(domain,"technical")??true;
            if(severity!=null&&D.Text(row["severity"])!=severity||ruleCode!=null&&D.Text(row["rule_code"])!=ruleCode)continue;
            if(query!=null&&(!identity||!string.Join(' ',row["objects"]!.AsArray().Select(D.Text)).Contains(query,StringComparison.OrdinalIgnoreCase)))continue;
            var messages=new JsonObject();var parameters=new Dictionary<string,object?>{["count"]=row["count"]!.GetValue<int>(),["threshold"]=row["threshold"]?.GetValue<int>()??0};string check=D.Text(row["check"]);
            foreach(string field in new[]{"title","what","why","action"}){string code="security.problems.ad_hardening."+check+"."+field;if(check=="laps"&&row["laps_none_found"]?.GetValue<bool>()==true&&field=="what")code="security.problems.ad_hardening.laps.none_found";messages[field]=Message(code,parameters);row[field]=messages[field]!["text"]!.DeepClone();}
            messages["list_note"]=Message("security.problems.ad_hardening."+(row["objects_truncated"]!.GetValue<bool>()?"list_truncated":"list_complete"),parameters);row["list_note"]=messages["list_note"]!["text"]!.DeepClone();row["presentation_messages"]=messages;
            if(!identity)row.Remove("objects");if(!technical){row.Remove("source_run_id");row.Remove("domain_id");}row.Remove("laps_none_found");rows.Add(row.DeepClone());
        }
        var notes=new JsonArray();foreach(string suffix in new[]{"limitation"}.Concat(partial?new[]{"partial"}:[]).Concat(stale?new[]{"stale"}:[])){var m=Message("security.problems.ad_hardening."+suffix);notes.Add(new JsonObject{["code"]=m["code"]!.DeepClone(),["text"]=m["text"]!.DeepClone(),["presentation_messages"]=new JsonObject{["text"]=m}});}
        string state=available.Length==0?"not_collected":partial||stale?"partial":rows.Count>0?"ok":"empty";
        return new(){["contract_id"]="sli.report-result.v2",["report_key"]="security.problems",["state"]=state,["state_message"]=Message("reports.state."+state),["state_details"]=new JsonObject{["reason"]=state=="not_collected"?"collection_not_confirmed":state=="partial"?"coverage_incomplete":"query_completed",["stage"]="query",["limitations"]=notes.DeepClone()},["items"]=new JsonArray(),["has_more"]=false,["next_cursor"]=null,["filtered_count"]=rows.Count,["metrics"]=new JsonArray(),["series"]=new JsonObject(),["coverage"]=new JsonObject{["available_snapshots"]=available.Length,["missing_snapshots"]=data.Items.Count-available.Length,["source_truncated"]=data.Truncated,["stale"]=stale,["service_password_days"]=365,["admin_group_members"]=5,["inactive_privileged_days"]=90},["filter_options"]=new JsonObject(),["limitations"]=notes,["window"]=new JsonObject(),["collections"]=new JsonObject{["ad_hardening"]=rows}};
    }
}
