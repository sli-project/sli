using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Groups;

internal static class AgentTemplatePolicy
{
    internal static JsonObject Normalize(JsonNode? modules,JsonNode? control)
    {
        try
        {
            var collection=AgentPolicyStore.NormalizeCollectionPolicy(AgentGroupInput.Element(control));
            if(modules is not JsonArray items || items.Count>1)throw new InvalidOperationException();
            var normalized=new JsonArray();
            foreach(var item in items)
            {
                if(item is not JsonObject assignment || !AgentGroupInput.Shape(assignment,"module_id","enabled","config")
                    || AgentGroupInput.Text(assignment["module_id"])!="sli.workstations"
                    || assignment["enabled"]?.GetValueKind() is not(JsonValueKind.True or JsonValueKind.False)
                    || assignment["config"] is not JsonObject raw)throw new InvalidOperationException();
                var config=(JsonObject)raw.DeepClone();config["policy_revision"]="1";
                config=AgentModuleAssignmentRules.NormalizeWorkstation(config);
                normalized.Add(new JsonObject{["module_id"]="sli.workstations",["enabled"]=assignment["enabled"]!.DeepClone(),["config"]=config});
            }
            // Source configured_modules(collection_enabled=False) has only the
            // heartbeat and this optional bundled workstation. No external
            // plugin hook/source-bound module can enter this portable profile.
            var policy=new JsonObject{["assigned_modules"]=normalized,["collection_policy"]=JsonNode.Parse(collection.GetRawText())};
            if(CanonicalJson.Length(policy)>60*1024-2048)throw new InvalidOperationException();
            return policy;
        }
        catch(Exception error)when(error is AgentException or AgentControlException or ProtocolException or InvalidOperationException or ArgumentException or FormatException or OverflowException or JsonException)
        {throw new AgentControlException("invalid_agent_template");}
    }
    internal static string Hash(JsonObject policy)=>Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(policy)));
}
