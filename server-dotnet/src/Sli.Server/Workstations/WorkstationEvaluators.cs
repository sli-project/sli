using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Agents.Consumer;
namespace Sli.Server.Workstations;

internal static partial class WorkstationEvaluators
{
    const string SecurityProvider="Microsoft-Windows-Security-Auditing";
    internal static Dictionary<string,int> Identities(JsonObject? config)=>new()
    { ["workstations.C02"]=1,["workstations.C05"]=1,["workstations.C06"]=1,["workstations.protection"]=1,["workstations.last-interactive-login"]=1,["workstations.C07"]=config is null?1:(int)config.Number("version")+1,["workstations.C03"]=1,["workstations.C04"]=1 };
    internal static async Task Apply(NpgsqlConnection db,string key,string station,JsonObject fact,JsonObject? config,CancellationToken ct)
    {
        switch(key)
        {
            case "workstations.C02":await LocalAdmin(db,station,fact,ct);break;
            case "workstations.C05":await ServiceTasks(db,station,fact,ct);break;
            case "workstations.C06":await Device(db,station,fact,ct);break;
            case "workstations.protection":await Protection(db,station,fact,ct);break;
            case "workstations.last-interactive-login":await LastLogin(db,station,fact,ct);break;
            case "workstations.C07":await LogonPolicy(db,station,fact,config,ct);break;
            case "workstations.C03":await PasswordFailures(db,station,fact,ct);break;
            case "workstations.C04":
                if(fact.Text("kind")!="observations")return;
                var row=fact["payload"]!.AsObject();var finding=ProcessFinding(row,station,await Now(db,ct));if(finding is null)return;
                await RequireAgent(db,station,row,ct);await Ws.Insert(db,"check_findings",finding,"on conflict(id) do nothing",ct);break;
            default:throw new WorkstationException("workstation_projection_evaluator_invalid");
        }
    }
    static async Task<DateTimeOffset> Now(NpgsqlConnection db,CancellationToken ct)=>new((DateTime)(await Ws.Scalar(db,"select transaction_timestamp()",ct))!);
    static bool Native(JsonObject row,string family,int number,string channel="Security",string provider=SecurityProvider)=>row.Text("family")==family&&row.Number("event_id")==number&&string.Equals(row["observation"].Text("channel"),channel,StringComparison.OrdinalIgnoreCase)&&string.Equals(row["observation"].Text("provider_name"),provider,StringComparison.OrdinalIgnoreCase);
    static async Task RequireAgent(NpgsqlConnection db,string station,JsonObject row,CancellationToken ct)
    {if(await Ws.Scalar(db,"select agent_key from sli_plugin_workstations.station_inventory where station_id=@p0",ct,station) is not string key||key!=row.Text("agent_key"))throw new WorkstationException("workstation_projection_input_conflict");}
    internal static string? Bounded(string? value,int bytes)
    {value=value?.Trim();return string.IsNullOrEmpty(value)||value=="-"||Encoding.UTF8.GetByteCount(value)>bytes?null:value;}
    static JsonObject Ref(JsonObject row)=>new(){["kind"]="workstation_observation",["observation_id"]=row["id"]?.DeepClone(),["agent_key"]=row["agent_key"]?.DeepClone(),["source_sha256"]=row["observation"]?["source_sha256"]?.DeepClone()};
    static JsonObject Finding(string check,string station,string id,JsonObject? subject,JsonObject parameters,JsonArray refs,DateTimeOffset at,DateTimeOffset detected,string? reason=null,string? qualityReason="coverage_incomplete")
    {
        return new(){["id"]=id,["station_id"]=station,["check_id"]=check,["rule_version"]=1,["subject_id"]=null,["subject_ref"]=subject,["episode_id"]=id,["condition_sha256"]=Ws.Hash(new JsonArray(subject?.DeepClone(),parameters.DeepClone(),refs.DeepClone())),["status"]="active",["severity"]=int.Parse(check[1..])<=3?"high":"medium",["fact_at"]=Ws.Stamp(at),["first_detected_at"]=Ws.Stamp(detected),["last_observed_at"]=Ws.Stamp(at),["materially_changed_at"]=Ws.Stamp(detected),["reason_code"]=reason??WorkstationReportContract.Reasons[int.Parse(check[1..])-1],["reason_params"]=parameters,["quality"]=Ws.Quality("partial",qualityReason),["evidence_refs"]=refs};
    }
    static string? Sid(string? value)=>value is not null&&Regex.IsMatch(value,@"\AS-1-\d{1,15}(?:-\d{1,10}){1,15}\z",RegexOptions.IgnoreCase)&&value.ToUpperInvariant()!="S-1-0-0"?value.ToUpperInvariant():null;
    static JsonObject Account(string station,string? sid,string? name=null,string? domain=null)=>new(){["kind"]="workstation_account",["station_id"]=station,["sid"]=sid,["name"]=name,["domain"]=domain,["status"]=sid is not null||name is not null?"observed":"unknown",["ad_entity_id"]=null};
    internal static string? PathCategory(string? path)
    {
        if(path is null||Encoding.UTF8.GetByteCount(path) is <1 or >512||!Regex.IsMatch(path,@"\A[A-Za-z]:\\"))return null;
        var parts=path[3..].Split('\\');
        if(parts.Any(p=>p.Length==0||p is "." or ".."||p.EndsWith(' ')||p.EndsWith('.')||p.Contains('~')||Regex.IsMatch(p,@"\A(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\z",RegexOptions.IgnoreCase)||p.Any(c=>c<32||c==127||"/:\"<>|?*%".Contains(c))))return null;
        var lower=parts.Select(p=>p.ToLowerInvariant()).ToArray();
        if(parts.Length>=3&&lower[0]=="windows"&&lower[1]=="temp"||parts.Length>=6&&lower[0]=="users"&&lower[2]=="appdata"&&lower[3]=="local"&&lower[4]=="temp")return "temporary";
        return parts.Length>=3&&lower[0]=="users"&&lower[1]=="public"?"public":null;
    }
    internal static void ValidateMeasurement(JsonObject m)
    {
        string[] keys=["scope","observed_at_utc","status","reason","sha256_before","sha256_after","identity_before","identity_after","signer_sha256","kind"];
        void Invalid()=>throw new WorkstationException("workstation_signature_measurement_invalid");
        if(m.Count!=keys.Length||keys.Any(k=>!m.ContainsKey(k))||m.Text("scope")!="file_at_measurement")Invalid();
        if(m.Text("observed_at_utc") is not {Length:<=40} time)throw new WorkstationException("workstation_signature_timestamp_invalid");else _=Ws.Time(time);
        if(m.Text("status")=="unavailable")
        {if(m.Text("reason") is not("timeout" or "unsupported" or "unsafe_path" or "too_large" or "changed" or "verification_failed")||keys.Skip(4).Any(k=>m[k] is not null))Invalid();}
        else if(m.Text("status") is "signed" or "unsigned")
        {
            if(m["reason"] is not null||!Ws.IsHash(m.Text("sha256_before"))||!Ws.IsHash(m.Text("identity_before"))||!JsonNode.DeepEquals(m["sha256_before"],m["sha256_after"])||!JsonNode.DeepEquals(m["identity_before"],m["identity_after"]))Invalid();
            if(m.Text("status")=="signed"?(m.Text("kind") is not("embedded" or "catalog")||!Ws.IsHash(m.Text("signer_sha256"))):(m.Text("kind")!="none"||m["signer_sha256"] is not null))Invalid();
        }
        else Invalid();
    }
    internal static JsonObject? ProcessFinding(JsonObject row,string station,DateTimeOffset detected)
    {
        if(!Native(row,"processes",4688))return null;
        var body=row["observation"]!;var facts=body["facts"]!;string? path=facts.Text("process_name"),category=PathCategory(path);if(category is null)return null;
        if(!Ws.IsHash(row.Text("id"))||row.Text("agent_key") is not {Length:>0 and <=256} agent||body["source_sha256"] is not null&&!Ws.IsHash(body.Text("source_sha256")))throw new WorkstationException("workstation_c04_source_invalid");
        string id=Ws.Hash(new JsonArray("workstations.C04",1,station,agent,row.Text("id")));
        var subject=new JsonObject{["kind"]="workstation_process_observation",["station_id"]=station,["observation_id"]=row["id"]!.DeepClone(),["path"]=path,["process_id"]=WorkstationLogonProjection.ProcessId(facts.Text("process_id")),["current_state"]="unknown",["signature_status"]="not_received",["signature_message_key"]="workstations.process.signature_not_received"};
        if(body["file_signature"] is JsonNode capsule)
        {
            if(capsule is not JsonObject c||c.Count!=5||new[]{"contract","record_id","source_sha256","path","measurement"}.Any(k=>!c.ContainsKey(k))||c.Text("contract")!="sli.workstation-file-signature.v1"||!JsonNode.DeepEquals(c["record_id"],body["record_id"])||c.Text("source_sha256")!=body.Text("source_sha256")||c.Text("path")!=path||c["measurement"] is not JsonObject measurement)throw new WorkstationException("workstation_signature_binding_invalid");
            ValidateMeasurement(measurement);subject["file_measurement"]=measurement.DeepClone();subject["signature_status"]="unknown";subject.Remove("signature_message_key");
        }
        foreach(string field in new[]{"process_user_sid","process_user_name","process_user_domain"})subject[field]=Bounded(facts.Text(field),512);
        var p=new JsonObject{["path"]=path,["path_category"]=category,["path_policy_version"]=1,["signature_status"]=subject["signature_status"]!.DeepClone()};
        var finding=Finding("C04",station,id,subject,p,new(Ref(row)),Ws.Time(row.Text("observed_at")),detected);finding["subject_id"]=row["id"]!.DeepClone();return finding;
    }
}
