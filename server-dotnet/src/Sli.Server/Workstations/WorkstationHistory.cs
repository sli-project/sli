using System.Text;
using System.Text.Json.Nodes;
using System.Globalization;
using Sli.Agent.Protocol;
namespace Sli.Server.Workstations;

// The PostgreSQL publisher is the only caller allowed to delete a preserved row.
public sealed class WorkstationHistory:IDisposable
{
    readonly HttpClient client;
    readonly bool ownsClient;
    public WorkstationHistory(HttpClient client,Uri endpoint,bool ownsClient=false) { this.client=client; this.ownsClient=ownsClient; }

    internal Task EnsureSchemaAsync(CancellationToken ct)
    {
        throw new WorkstationException("module_disabled", 503);
    }
    internal static bool Family(string? family)=>family is "processes" or "usb" or "logons" or "protection";
    static readonly string[] Fields=["id","agent_key","entity_id","ad_computer_id","family","event_id","observed_at","observation","observation_sha256","source_xml"];
    public static WorkstationHistory? Configured(IConfiguration? config=null) => null;
    internal static WorkstationHistory? Configured(IConfiguration? config,Func<string,string?> environment) => null;
    static bool Integer(JsonObject row,string key)=>row[key]?.GetValueKind()==System.Text.Json.JsonValueKind.Number&&long.TryParse(row[key]!.ToJsonString(),out _);
    internal static void Validate(JsonObject row)
    {
        if(row.Count!=Fields.Length||Fields.Any(k=>!row.ContainsKey(k))||!Family(row.Text("family"))||!Ws.IsHash(row.Text("id"))||row.Text("agent_key") is not {Length:>0 and <=256} key||key.Trim()!=key||!Integer(row,"entity_id")||row.Number("entity_id")<=0||row["ad_computer_id"] is not null&&(!Integer(row,"ad_computer_id")||row.Number("ad_computer_id")<=0)||!Integer(row,"event_id")||row.Number("event_id")<=0||row.Text("source_xml") is not {} xml||Encoding.UTF8.GetByteCount(xml) is <1 or >1048576||row["observation"] is not JsonObject body||Ws.Hash(body)!=row.Text("observation_sha256")||Ws.Sha(xml)!=body.Text("source_sha256"))throw new WorkstationException("workstation_history_receipt_mismatch");
        _=Ws.Time(row.Text("observed_at"));
    }
    static string ChTime(DateTimeOffset t)=>t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff",CultureInfo.InvariantCulture);
    internal static JsonObject Record(JsonObject row)
    {
        Validate(row);var record=Ws.Pick(row,"id","agent_key","entity_id","ad_computer_id","family","event_id");
        record["observed_at"]=ChTime(Ws.Time(row.Text("observed_at")));record["payload_sha256"]=Ws.Hash(row);record["payload_json"]=CanonicalJson.Serialize(row);return record;
    }
    internal static JsonObject Decode(JsonObject record)
    {
        try
        {
            var row=JsonNode.Parse(record.Text("payload_json")!)!.AsObject();var expected=Record(row);var actual=(JsonObject)record.DeepClone();
            actual["observed_at"]=ChTime(DateTimeOffset.Parse(record.Text("observed_at")!,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal));
            foreach(string key in new[]{"entity_id","ad_computer_id","event_id"})if(actual[key] is not null&&long.TryParse(actual[key]!.ToString(),out long n))actual[key]=n;
            if(!JsonNode.DeepEquals(actual,expected))throw new WorkstationException("workstation_history_receipt_mismatch");return row;
        }
        catch(Exception e)when(e is System.Text.Json.JsonException or InvalidOperationException or FormatException or ArgumentException){throw new WorkstationException("workstation_history_receipt_mismatch");}
    }
    public Task<string> PreserveAsync(JsonObject row,CancellationToken ct,bool evidence=false)
    {
        throw new WorkstationException("module_disabled", 503);
    }
    public Task<List<JsonObject>> ReadAsync(string[] keys,string family,DateTimeOffset start,DateTimeOffset end,string cursor,int limit,string? exact,CancellationToken ct)
    {
        throw new WorkstationException("module_disabled", 503);
    }
    internal Task<JsonObject?> FindEvidenceAsync(string key,string id,CancellationToken ct)
    {
        throw new WorkstationException("module_disabled", 503);
    }
    internal static JsonObject ReportRow(JsonObject row,bool evidence)
    {
        var item=Ws.Pick(row,"id","agent_key","entity_id","ad_computer_id","event_id","observed_at","observation_sha256");
        foreach(string k in new[]{"semantic_type","facts","quality"})item[k]=row["observation"]?[k]?.DeepClone();
        if(evidence){item["source_xml"]=row["source_xml"]!.DeepClone();item["source_sha256"]=row["observation"]!["source_sha256"]!.DeepClone();}return item;
    }
    public void Dispose(){if(ownsClient)client.Dispose();}
}
