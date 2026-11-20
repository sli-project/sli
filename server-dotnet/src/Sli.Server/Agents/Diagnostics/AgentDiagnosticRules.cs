using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access.Administration;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Diagnostics;

public sealed record AgentRemovalResult(Guid CommandId,string State,string? Reason);

public static class AgentDiagnosticRules
{
    internal static string? Text(JsonNode? n)=>n is JsonValue v&&v.TryGetValue<string>(out var s)?s:null;
    internal static bool Keys(JsonObject o,params string[] keys)=>o.Select(p=>p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(keys);
    internal static Dictionary<string,string[]> Query(string raw)
        =>(raw.StartsWith('?')?raw[1..]:raw).Split('&').Select(p=>p.Split('=',2)).Where(p=>p.Length==2)
        .Select(p=>(Key:WebUtility.UrlDecode(p[0]),Value:WebUtility.UrlDecode(p[1]))).Where(p=>p.Value.Length>0)
        .GroupBy(p=>p.Key,StringComparer.Ordinal).ToDictionary(g=>g.Key,g=>g.Select(p=>p.Value).ToArray(),StringComparer.Ordinal);
    public static long RevocationCursor(string query)
    {
        try
        {
            var q=Query(query);
            if(q.Keys.Any(k=>k!="after")||q.TryGetValue("after",out var values)&&values.Length!=1)throw new FormatException();
            var n=AssignmentValidation.Integer(JsonSerializer.SerializeToElement(q.GetValueOrDefault("after",["0"])[0]));
            if(n<0||n>long.MaxValue)throw new FormatException();return(long)n;
        }
        catch(Exception e)when(e is AssignmentValidationException or InvalidOperationException or FormatException or OverflowException)
        {throw new AgentControlException("invalid_revocation_cursor");}
    }
    public static AgentRemovalResult RemovalResult(JsonNode? body)
    {
        if(body is not JsonObject o||!Keys(o,"command_id","state","reason"))throw new AgentControlException("agent_removal_result_invalid");
        Guid command=AgentControlJson.Id(JsonSerializer.SerializeToElement(o["command_id"]));
        string? state=Text(o["state"]),reason=Text(o["reason"]);
        if(state is not("state_cleaned" or "cleanup_failed")||state=="state_cleaned"&&o["reason"] is not null
            ||state=="cleanup_failed"&&reason is not("agent_removal_requires_admin" or "agent_removal_unmanaged" or "agent_removal_cleanup_failed"))
            throw new AgentControlException("agent_removal_result_invalid");
        return new(command,state,reason);
    }
}
