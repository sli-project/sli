using System.Net;
using System.Text.Json.Nodes;
namespace Sli.Server.Storage.EventReports;

internal static class EventSearchProjection
{
    internal static JsonObject History(JsonObject row)
    {
        var result=(JsonObject)row.DeepClone();
        result["provider"]=row["provider_name"]?.DeepClone(); result["ip"]=row["ip_address"]?.DeepClone(); result["reason"]=row["result_code"]?.DeepClone();
        string? provider=EventSearchInput.String(result["provider"]),channel=EventSearchInput.String(result["channel"]),status=EventSearchInput.String(result["reason"]);
        long id=EventReadService.Long(row,"event_id");
        result["action"]=provider=="Microsoft-Windows-Security-Auditing" && channel=="Security" && id is 4624 or 4625 ? "authentication.logon":null;
        result["outcome"]=provider=="Microsoft-Windows-Security-Auditing" && channel=="Security" ? id is 4625 or 4771 or 6273?"failure":id is 4624 or 6272?"success":id==4776 && !string.IsNullOrWhiteSpace(status)?new[]{"0","0x0","0x00000000","00000000"}.Contains(status.Trim().ToLowerInvariant())?"success":"failure":null:null;
        foreach(string f in new[]{"task_identity","process_identity","file_identity"}) result[f]=null;
        result["group_identity_complete"]=false; result["title"]=EventListProjection.Title(result);
        if(result["ip"] is not null) result["ip"]=IPAddress.TryParse(result["ip"]!.ToString(),out var ip)?ip.ToString():null;
        return result;
    }
    internal static void Complete(JsonObject fields)
    {
        if(!fields.ContainsKey("group_identity_complete")) return;
        bool complete=EventSearchPolicy.GroupFields.All(fields.ContainsKey) && fields["action"]?.ToString()=="authentication.logon" && fields["outcome"]?.ToString() is "success" or "failure" &&
            !string.IsNullOrWhiteSpace(fields["logon_type"]?.ToString()) && (fields["event_id"]?.ToString()!="4625" || !string.IsNullOrWhiteSpace(fields["reason"]?.ToString())) &&
            EventSearchInput.Integer(fields["server_id"],1,long.MaxValue) && EventSearchInput.Integer(fields["domain_id"],1,long.MaxValue) && IPAddress.TryParse(fields["ip"]?.ToString(),out _) &&
            fields["source_station"] is JsonArray { Count:>0 } && fields["account"] is JsonArray a && new[]{"actor","target"}.All(r=>a.Any(p=>p?["role"]?.ToString()==r && EventSearchInput.Integer(p?["entity_id"],1,long.MaxValue)));
        fields["group_identity_complete"]=complete;
    }
    internal static bool MatchesLinks(EventSearchInput input,JsonObject fields)
    {
        foreach(var c in input.Conditions.Where(c=>c.Field is "account" or "source_station" or "related_object"))
        {
            var raw=fields[c.Field] as JsonArray ?? [];
            var values=c.Field=="account"?raw.Where(p=>c.Role=="any" || p?["role"]?.ToString()==c.Role).Select(p=>p!["entity_id"]!.ToJsonString()).ToHashSet():raw.Select(p=>p!.ToJsonString()).ToHashSet();
            bool hit=c.Values.Any(v=>values.Contains(v.ToJsonString()));
            if(c.Operator=="exists" && values.Count==0 || c.Operator=="missing" && values.Count>0 || c.Operator is "eq" or "in" && !hit || c.Operator=="not_in" && hit) return false;
        }
        return !input.ExcludeMachine || !(fields["account_kind"] as JsonArray ?? []).Any(p=>(input.AccountRole=="any" || p?["role"]?.ToString()==input.AccountRole) && p?["kind"]?.ToString() is "machine" or "system");
    }
    internal static string GroupKey(SearchEvent ev)
    {
        if(ev.Fields["group_identity_complete"]?.ToString()!="true" || !EventSearchPolicy.GroupFields.All(ev.Fields.ContainsKey))
            return EventSearchPolicy.Hash(new JsonObject { ["version"]="evsearch.group.v1",["singleton"]=ev.Id });
        var identity=new JsonObject(); foreach(string f in EventSearchPolicy.GroupFields) identity[f]=ev.Fields[f]?.DeepClone();
        identity["account"]=new JsonArray((ev.Fields["account"] as JsonArray ?? []).Select(p=>(Role:p!["role"]!.ToString(),Id:p["entity_id"]!.GetValue<long>())).Distinct().OrderBy(p=>p.Role,StringComparer.Ordinal).ThenBy(p=>p.Id).Select(p=>new JsonArray(JsonValue.Create(p.Role),JsonValue.Create(p.Id)) as JsonNode).ToArray());
        foreach(string key in new[]{"source_station","related_object"}) identity[key]=new JsonArray((identity[key] as JsonArray ?? []).Select(p=>p!.GetValue<long>()).Distinct().Order().Select(p=>JsonValue.Create(p) as JsonNode).ToArray());
        identity["ip"]=IPAddress.Parse(identity["ip"]!.ToString()).ToString();
        return EventSearchPolicy.Hash(new JsonObject { ["version"]="evsearch.group.v1",["identity"]=identity });
    }
}
