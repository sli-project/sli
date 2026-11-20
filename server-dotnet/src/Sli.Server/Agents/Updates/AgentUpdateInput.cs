using System.Text.Json.Nodes;
using System.Net;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;
internal sealed record AgentUpdateInput(string Sha256,string Status,string? Reason,string Version)
{
    private static readonly HashSet<string> Reasons=new(StringComparer.Ordinal) {
        "agent_update_verification_failed","agent_update_stage_failed","agent_update_start_failed","agent_update_self_check_failed","agent_update_timeout",
        "agent_update_incompatible_version","agent_update_incompatible_platform","agent_update_incompatible_api","agent_update_insufficient_disk",
        "agent_update_download_failed","agent_update_msi_required" };
    internal static string? Text(JsonNode? value)=>value is JsonValue v && v.TryGetValue<string>(out var text)?text:null;
    internal static string Digest(JsonNode? value)
    {
        string? text=Text(value);
        if(text is null || text.Length!=64 || text.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))throw new AgentControlException("agent_package_invalid");
        return text;
    }
    internal static AgentUpdateInput Parse(JsonObject body)
    {
        string sha=Digest(body["sha256"]);string? status=Text(body["status"]),reason=Text(body["reason"]),version=Text(body["version"]);
        if(status is not ("updated" or "rejected" or "rolled_back") ||
            (body["reason"] is not null && (reason is null || !Reasons.Contains(reason))) || (status=="updated")!=(body["reason"] is null) ||
            version is null || !Regex.IsMatch(version,@"\A[0-9]+\.[0-9]+\.[0-9]+\z",RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1)) ||
            body.Count!=4 || !body.ContainsKey("sha256") || !body.ContainsKey("status") || !body.ContainsKey("reason") || !body.ContainsKey("version"))
            throw new AgentControlException("agent_update_result_invalid");
        return new(sha,status,reason,version);
    }
    internal static string PackageQuery(string query)
    {
        // Source parse_qs drops empty values, combines decoded exact names and
        // rejects nonblank extra names/repetitions. No path is derived from it.
        var pairs=(query.StartsWith('?')?query[1..]:query).Split('&').Select(p=>p.Split('=',2)).Where(p=>p.Length==2)
            .Select(p=>(Key:WebUtility.UrlDecode(p[0]),Value:WebUtility.UrlDecode(p[1]))).Where(p=>p.Value.Length>0).ToArray();
        if(pairs.Length!=1 || pairs[0].Key!="sha256")throw new AgentControlException("agent_package_invalid");
        return Digest(JsonValue.Create(pairs[0].Value));
    }
}
