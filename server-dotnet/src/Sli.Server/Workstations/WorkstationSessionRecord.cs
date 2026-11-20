using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Workstations;

// Compact session inputs retain identity and observed endpoints, never event XML
// or the original observation. The effective view folds unambiguous endpoints.
internal static class WorkstationSessionRecord
{
    static readonly string[] Fields=["contract","id","agent_key","entity_id","ad_computer_id","family","event_id","observed_at","observation_sha256","source_sha256","session_uid","session_principal","generation","logon_type","account"];
    internal static bool IsSession(JsonObject row)=>row.Number("event_id") is 4624 or 4634;
    internal static JsonObject Compact(JsonObject row)
    {
        WorkstationHistory.Validate(row);
        if(!IsSession(row)||row.Text("family")!="logons")throw new WorkstationException("workstation_session_invalid");
        var body=row["observation"]!;
        var payload=Ws.Pick(row,"id","agent_key","entity_id","ad_computer_id","family","event_id","observed_at","observation_sha256");
        payload["contract"]="sli.workstation-session.v1";
        payload["source_sha256"]=body["source_sha256"]!.DeepClone();
        payload["session_principal"]=body["roles"]?.Text("session_principal") is {Length:>0} principal&&!string.IsNullOrWhiteSpace(principal)?principal:null;
        payload["generation"]=body.Text("generation") is {Length:>0} generation&&!string.IsNullOrWhiteSpace(generation)?generation:null;
        // Missing source session identity must never join unrelated logons.
        payload["session_uid"]=Ws.Hash(new JsonArray(row.Text("agent_key"),payload.Text("generation"),payload.Text("session_principal"),
            payload.Text("session_principal") is null||payload.Text("generation") is null?row.Text("id"):null));
        payload["logon_type"]=body["facts"]?["logon_type"]?.ToString();
        var account=new JsonObject();
        foreach(string k in new[]{"name","domain","sid"})account[k]=body["facts"]?.Text("logon_user_"+k);
        payload["account"]=account;
        Validate(payload);return payload;
    }
    static void Validate(JsonObject row)
    {
        if(row.Count!=Fields.Length||Fields.Any(k=>!row.ContainsKey(k))||row.Text("contract")!="sli.workstation-session.v1"
            ||row.Text("family")!="logons"||!IsSession(row)||!Ws.IsHash(row.Text("id"))||!Ws.IsHash(row.Text("session_uid"))
            ||!Ws.IsHash(row.Text("observation_sha256"))||!Ws.IsHash(row.Text("source_sha256"))
            ||row.Text("agent_key") is not {Length:>0 and <=256}||row.Number("entity_id")<=0
            ||row["ad_computer_id"] is not null&&row.Number("ad_computer_id")<=0
            ||row["account"] is not JsonObject account||account.Count!=3||new[]{"name","domain","sid"}.Any(k=>!account.ContainsKey(k))
            ||new[]{"session_principal","generation","logon_type"}.Any(k=>row[k] is not null&&row.Text(k) is not {Length:<=1024})
            ||account.Any(p=>p.Value is not null&&p.Value is not JsonValue||p.Value is not null&&account.Text(p.Key) is not {Length:<=256}))
            throw new WorkstationException("workstation_history_receipt_mismatch");
        _=Ws.Time(row.Text("observed_at"));
        string expected=Ws.Hash(new JsonArray(row.Text("agent_key"),row.Text("generation"),row.Text("session_principal"),
            row.Text("session_principal") is null||row.Text("generation") is null?row.Text("id"):null));
        if(expected!=row.Text("session_uid"))throw new WorkstationException("workstation_history_receipt_mismatch");
    }
    internal static JsonObject Record(JsonObject row)
    {
        Validate(row);var record=Ws.Pick(row,"id","agent_key","entity_id","ad_computer_id","family","event_id");
        record["observed_at"]=Ws.Time(row.Text("observed_at")).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff",CultureInfo.InvariantCulture);
        record["payload_sha256"]=Ws.Hash(row);record["payload_json"]=CanonicalJson.Serialize(row);return record;
    }
    internal static JsonObject Decode(JsonObject record)
    {
        try
        {
            var row=JsonNode.Parse(record.Text("payload_json")!)!.AsObject();var actual=(JsonObject)record.DeepClone();
            foreach(string k in new[]{"entity_id","ad_computer_id","event_id"})if(actual[k] is not null&&long.TryParse(actual[k]!.ToString(),out long n))actual[k]=n;
            actual["observed_at"]=DateTimeOffset.Parse(record.Text("observed_at")!,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff",CultureInfo.InvariantCulture);
            if(!JsonNode.DeepEquals(Record(row),actual))throw new WorkstationException("workstation_history_receipt_mismatch");return row;
        }
        catch(Exception error)when(error is System.Text.Json.JsonException or InvalidOperationException or FormatException or ArgumentException)
        {throw new WorkstationException("workstation_history_receipt_mismatch");}
    }
    internal static JsonObject ReportRow(JsonObject row,bool evidence)
    {
        Validate(row);
        var item=Ws.Pick(row,"id","agent_key","entity_id","ad_computer_id","event_id","observed_at","observation_sha256");
        item["semantic_type"]=row.Number("event_id")==4624?"authentication.session.created":"authentication.session.ended";
        item["facts"]=new JsonObject { ["session_uid"]=row["session_uid"]!.DeepClone(),["session_principal"]=row["session_principal"]?.DeepClone(),
            ["state"]=row.Number("event_id")==4624?"open":"orphan_logoff",["logon_type"]=row["logon_type"]?.DeepClone(),["account"]=row["account"]!.DeepClone() };
        foreach(string k in new[]{"name","domain","sid"})item["facts"]!["logon_user_"+k]=row["account"]![k]?.DeepClone();
        item["quality"]=new JsonObject { ["coverage"]="not_proven",["storage"]="compact_session",["raw_event_retained"]=false };
        if(evidence){item["source_xml"]=null;item["source_sha256"]=row["source_sha256"]!.DeepClone();}
        return item;
    }
    internal static void Fold(JsonObject report,JsonObject[] endpoints)
    {
        var logons=endpoints.Where(r=>r.Number("event_id")==4624).ToArray();var logoffs=endpoints.Where(r=>r.Number("event_id")==4634).ToArray();
        DateTimeOffset? start=logons.Length==1?Ws.Time(logons[0].Text("observed_at")):null;
        DateTimeOffset? end=logoffs.Length==1?Ws.Time(logoffs[0].Text("observed_at")):null;
        string state=logons.Length==1&&logoffs.Length==1&&end>=start?"closed":logons.Length==1&&logoffs.Length==0?"open":logons.Length==0&&logoffs.Length==1?"orphan_logoff":"ambiguous";
        var facts=report["facts"]!.AsObject();facts["state"]=state;
        facts["logon_time_utc"]=start is {} s?Ws.Stamp(s):null;facts["logoff_time_utc"]=end is {} e?Ws.Stamp(e):null;
        facts["duration_s"]=state=="closed"?(long)(end!.Value-start!.Value).TotalSeconds:null;
        if(logons.Length==1)
        {
            facts["account"]=logons[0]["account"]!.DeepClone();facts["logon_type"]=logons[0]["logon_type"]?.DeepClone();
            foreach(string k in new[]{"name","domain","sid"})facts["logon_user_"+k]=logons[0]["account"]![k]?.DeepClone();
        }
    }
}
