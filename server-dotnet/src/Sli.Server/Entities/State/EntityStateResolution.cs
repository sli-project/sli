using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Agent.Core;

namespace Sli.Server.Entities.State;

// Source entity_state_model.resolve_current; event ID and rule version break time ties.
internal static class EntityStateResolution
{
    internal static (string Action,JsonObject Result) Resolve(JsonObject? current,JsonObject candidate)
    {
        if(current is null)return ("insert",(JsonObject)candidate.DeepClone());
        int order=Compare(current,candidate);
        if(order>0)return ("older",(JsonObject)current.DeepClone());
        if(order<0)return ("replace",(JsonObject)candidate.DeepClone());
        if(Coerce(current["status"])==Coerce(candidate["status"]))return ("same",(JsonObject)current.DeepClone());
        var result=(JsonObject)candidate.DeepClone();result["status"]="unknown";result["projection_status"]="conflict";
        var values=new[]{Coerce(current["status"]),Coerce(candidate["status"])}.Distinct(StringComparer.Ordinal).OrderBy(x=>x,Comparer<string>.Create(CompareCodePoints));
        result["conflict_statuses"]=new JsonArray(values.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());return ("conflict",result);
    }
    private static int Compare(JsonObject a,JsonObject b)
    {
        int c=Time(a).CompareTo(Time(b));if(c!=0)return c;
        c=Number(a,"source_event_db_id").CompareTo(Number(b,"source_event_db_id"));return c!=0?c:CompareCodePoints(Text(a,"rule_version"),Text(b,"rule_version"));
    }
    private static DateTime Time(JsonObject obj)
    {
        string value=Sli.Server.Agents.Control.AgentControlJson.Strip(Text(obj,"observed_at_utc"));
        return PythonIsoDateTime.TryParse(value.Replace("Z","+00:00",StringComparison.Ordinal),out var parsed) && parsed.IsAware && parsed.TryToUtc(out var utc) ? utc.UtcDateTime : DateTime.MinValue;
    }
    private static BigInteger Number(JsonObject obj,string key)=>obj[key] is null?BigInteger.Zero:PythonInteger(obj[key]);
    internal static BigInteger PythonInteger(JsonNode? node)
    {
        if(JsonRead.TryInteger(node,out var n))return n;
        if(JsonRead.TryString(node,out var text) && PythonInt.TryParse(text,out n))return n;
        if(node is JsonValue) {
            using var doc=JsonDocument.Parse(node.ToJsonString());
            var value=doc.RootElement;
            if(value.ValueKind is JsonValueKind.True or JsonValueKind.False)return value.GetBoolean()?BigInteger.One:BigInteger.Zero;
            if(value.ValueKind==JsonValueKind.Number && value.TryGetDouble(out var number) && double.IsFinite(number))return new BigInteger(number);
        }
        throw new InvalidDataException("entity_state_payload_invalid");
    }
    internal static string Text(JsonObject obj,string key)
    {
        var value=obj[key];
        if(value is null)return "";
        if(value is JsonValue) {
            using var doc=JsonDocument.Parse(value.ToJsonString());var scalar=doc.RootElement;
            if(scalar.ValueKind==JsonValueKind.False || scalar.ValueKind==JsonValueKind.Number && scalar.TryGetDouble(out var number) && number==0)return "";
        }
        if(value is JsonArray a && a.Count==0 || value is JsonObject o && o.Count==0)return "";
        return Coerce(value);
    }
    internal static string Coerce(JsonNode? value)=>Sli.Gpo.SnapshotModel.GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(value));
    private static int CompareCodePoints(string a,string b)
    {
        var x=a.EnumerateRunes().GetEnumerator();var y=b.EnumerateRunes().GetEnumerator();
        while(true){bool hasX=x.MoveNext(),hasY=y.MoveNext();if(!hasX||!hasY)return hasX?1:hasY?-1:0;int c=x.Current.Value.CompareTo(y.Current.Value);if(c!=0)return c;}
    }
}
