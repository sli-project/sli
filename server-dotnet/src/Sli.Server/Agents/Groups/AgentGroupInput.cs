using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Groups;

internal sealed record GroupCreate(int Ttl,int Maximum);
internal sealed record GroupBinding(Guid Host,string? Instance,string Fingerprint,long Computer);
internal sealed record OnboardingInput(Guid Token,Guid Template,long Version,Guid[]? Ids,Dictionary<Guid,GroupBinding> Bindings,string Mode);

internal static class AgentGroupInput
{
    internal static string? Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s)?s:null;
    internal static JsonElement Element(JsonNode? node) => JsonSerializer.SerializeToElement(node);
    internal static Guid Id(JsonNode? node)
    {
        if(node?.GetValueKind()==JsonValueKind.String)return AgentControlJson.Id(Text(node));
        if(node?.GetValueKind()==JsonValueKind.Number)return AgentControlJson.Id(Element(node));
        throw new AgentControlException("invalid_agent_identity");
    }
    internal static long Integer(JsonNode? node,long min,long max,string error)
    {
        if(node?.GetValueKind()!=JsonValueKind.Number)throw new AgentControlException(error);
        var e=Element(node);
        if(!e.TryGetInt64(out long n) || n<min || n>max)throw new AgentControlException(error);
        return n;
    }
    internal static long Positive(JsonNode? node)=>Integer(node,1,long.MaxValue,"invalid_group_enrollment_scope");
    internal static long Version(JsonNode? node)=>Integer(node,1,9007199254740991,"invalid_agent_template");
    internal static long[] Ids(JsonNode? node,int max)
    {
        if(node is not JsonArray list || list.Count>max)throw new AgentControlException("invalid_group_enrollment_scope");
        return list.Select(Positive).Distinct().Order().ToArray();
    }
    internal static bool Shape(JsonObject obj,params string[] keys)=>obj.Count==keys.Length && keys.All(obj.ContainsKey);
    internal static bool Allowed(JsonObject obj,params string[] keys)=>obj.All(p=>keys.Contains(p.Key,StringComparer.Ordinal));
    internal static string? Instance(JsonNode? node)
    {
        if(node is null)return null;
        string? s=Text(node);
        if(!AgentControlJson.Matches(s,@"\A[a-z0-9][a-z0-9_-]{0,47}\z"))throw new AgentControlException("invalid_agent_instance_name");
        return s;
    }
    internal static GroupCreate Create(JsonObject body)
    {
        if(!Allowed(body,"ttl_seconds","max_uses","group_id","domain_id","ou_entity_ids","computer_entity_ids","template_id","template_version","auto_approve","trusted_bindings"))throw new AgentControlException("invalid_group_enrollment_scope");
        int ttl=(int)Integer(body.ContainsKey("ttl_seconds")?body["ttl_seconds"]:JsonValue.Create(3600),60,604800,"invalid_enrollment_ttl");
        int maximum=(int)Integer(body["max_uses"],1,10000,"invalid_group_enrollment_limit");
        return new(ttl,maximum);
    }
    internal static (Guid Group,Guid Token) Filter(JsonNode? node)
    {
        if(node is not JsonObject b || !Shape(b,"group_id","token_id"))throw new AgentControlException("invalid_agent_batch_filter");
        return(Id(b["group_id"]),Id(b["token_id"]));
    }
    internal static GroupBinding Binding(JsonNode? node,string error,bool withRequest)
    {
        var keys=withRequest?new[]{"request_id","host_id","instance_name","key_fingerprint","computer_entity_id"}:new[]{"host_id","instance_name","key_fingerprint","computer_entity_id"};
        if(node is not JsonObject b || !Shape(b,keys) || !AgentControlJson.Matches(Text(b["key_fingerprint"]),@"\A[0-9a-f]{64}\z"))throw new AgentControlException(error);
        // Onboarding checks the computer type before UUID/instance conversion;
        // group attestation and trusted rules perform that check afterwards.
        if(error=="invalid_agent_batch_approval")_=Integer(b["computer_entity_id"],1,long.MaxValue,error);
        return new(Id(b["host_id"]),Instance(b["instance_name"]),Text(b["key_fingerprint"])!,Positive(b["computer_entity_id"]));
    }
    internal static Dictionary<Guid,GroupBinding> Bindings(JsonNode? node,bool onboarding)
    {
        string error=onboarding?"invalid_agent_batch_approval":"invalid_agent_batch_evidence";
        if(node is not JsonArray list || list.Count>1000 || (!onboarding && list.Count==0))throw new AgentControlException(error);
        var result=new Dictionary<Guid,GroupBinding>();
        foreach(var item in list)
        {
            // Shape/fingerprint precede request UUID in the source.
            if(item is not JsonObject b || !Shape(b,"request_id","host_id","instance_name","key_fingerprint","computer_entity_id") || !AgentControlJson.Matches(Text(b["key_fingerprint"]),@"\A[0-9a-f]{64}\z"))throw new AgentControlException(error);
            if(onboarding)_=Integer(b["computer_entity_id"],1,long.MaxValue,error);
            var id=Id(b["request_id"]);
            if(result.ContainsKey(id))throw new AgentControlException(error);
            result.Add(id,Binding(b,error,true));
        }
        return result;
    }
    internal static OnboardingInput Onboarding(JsonObject b)
    {
        string? mode=Text(b["mode"]);
        if(!Allowed(b,"token_id","template_id","template_version","mode","request_ids","evidence") || mode is not("selected" or "rule"))throw new AgentControlException("invalid_agent_batch_approval");
        var token=Id(b["token_id"]);var template=Id(b["template_id"]);long version=Version(b["template_version"]);Guid[]? ids=null;
        if(mode=="selected")
        {
            if(b["request_ids"] is not JsonArray list || list.Count is <1 or >1000)throw new AgentControlException("invalid_agent_batch_approval");
            ids=list.Select(Id).OrderBy(x=>x.ToString(),StringComparer.Ordinal).ToArray();
            if(ids.Distinct().Count()!=ids.Length)throw new AgentControlException("invalid_agent_batch_approval");
        }
        else if(b["request_ids"] is not null)throw new AgentControlException("invalid_agent_batch_approval");
        return new(token,template,version,ids,Bindings(b["evidence"],true),mode!);
    }
}
