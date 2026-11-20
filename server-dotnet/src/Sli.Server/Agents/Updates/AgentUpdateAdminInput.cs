using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Updates;
internal sealed record AgentWaveSelection(string Sha256,int BatchSize,int Threshold,Guid? Group,Guid[]? Ids);
internal static class AgentUpdateAdminInput
{
    internal static JsonObject Body(JsonElement value,string error)
    {if(value.ValueKind!=JsonValueKind.Object)throw new AgentControlException(error);return AgentClientJson.FromElement(value)!.AsObject();}
    internal static Guid Id(JsonNode? value)=>AgentControlJson.Id(JsonSerializer.SerializeToElement(value));
    internal static AgentWaveSelection Wave(JsonElement value)
    {
        var body=Body(value,"agent_update_wave_invalid");bool group=body.ContainsKey("group_token_id");
        string[] keys=[group?"group_token_id":"agent_ids","sha256","batch_size","error_threshold"];
        if(body.Count!=4 || !keys.All(body.ContainsKey))throw new AgentControlException("agent_update_wave_invalid");
        string sha=AgentUpdateInput.Digest(body["sha256"]);
        static int Number(JsonNode? item,int min,int max) {
            if(item is null)throw new AgentControlException("agent_update_wave_invalid");using var d=JsonDocument.Parse(item.ToJsonString());
            if(d.RootElement.ValueKind!=JsonValueKind.Number || !d.RootElement.TryGetInt32(out int n) || n<min || n>max)throw new AgentControlException("agent_update_wave_invalid");return n;
        }
        int size=Number(body["batch_size"],1,100),threshold=Number(body["error_threshold"],0,1000);
        if(group)return new(sha,size,threshold,Id(body["group_token_id"]),null);
        if(body["agent_ids"] is not JsonArray array || array.Count is <1 or >1000)throw new AgentControlException("agent_update_wave_invalid");
        Guid[] ids=array.Select(Id).OrderBy(id=>id.ToString("D"),StringComparer.Ordinal).ToArray();
        if(ids.Distinct().Count()!=ids.Length)throw new AgentControlException("agent_update_wave_invalid");return new(sha,size,threshold,null,ids);
    }
    internal static Guid? WaveQuery(string query)
    {
        var pairs=(query.StartsWith('?')?query[1..]:query).Split('&').Select(p=>p.Split('=',2)).Where(p=>p.Length==2)
            .Select(p=>(Key:WebUtility.UrlDecode(p[0]),Value:WebUtility.UrlDecode(p[1]))).Where(p=>p.Value.Length>0).ToArray();
        if(pairs.Length==0)return null;
        if(pairs.Length!=1 || pairs[0].Key!="wave_id")throw new AgentControlException("agent_update_wave_invalid");return AgentControlJson.Id(pairs[0].Value);
    }
}
