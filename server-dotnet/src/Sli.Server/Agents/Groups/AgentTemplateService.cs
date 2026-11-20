using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using static Sli.Server.Agents.Groups.AgentGroupStore;

namespace Sli.Server.Agents.Groups;

public sealed class AgentTemplateService(IAgentControlAudit audit)
{
    internal static (Guid Id,long Expected,JsonObject Policy,string Hash) Prepare(JsonElement input)
    {
        var body=AgentClientJson.FromElement(input) as JsonObject;
        if(body is null || !AgentGroupInput.Allowed(body,"template_id","expected_version","assigned_modules","collection_policy"))throw new AgentControlException("invalid_agent_template");
        long expected=AgentGroupInput.Integer(body["expected_version"],0,9007199254740990,"invalid_agent_template");
        Guid id=body.ContainsKey("template_id")?AgentGroupInput.Id(body["template_id"]):Guid.NewGuid();
        var policy=AgentTemplatePolicy.Normalize(body["assigned_modules"],body["collection_policy"]);string hash=AgentTemplatePolicy.Hash(policy);
        return(id,expected,policy,hash);
    }
    public async Task<JsonElement> SaveAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        var (id,expected,policy,hash)=Prepare(input);
        await Scalar(c,t,"select pg_advisory_xact_lock(hashtext(@key))",ct,("key","sli-agent-template:"+id));
        long current=(long)(await Scalar(c,t,"select coalesce(max(version),0) from sli_agent_policy_templates where id=@id",ct,("id",id)))!;
        if(current!=expected)throw new AgentControlException("agent_template_version_conflict",409);
        long version=current+1;
        await Execute(c,t,"insert into sli_agent_policy_templates(id,version,assigned_modules,collection_policy,policy_sha256) values(@id,@version,@modules::jsonb,@control::jsonb,@hash)",ct,("id",id),("version",version),("modules",policy["assigned_modules"]!.ToJsonString()),("control",policy["collection_policy"]!.ToJsonString()),("hash",hash));
        await audit.AppendAsync(c,t,"template_save",actor,id.ToString(),new{result="saved",version,policy_sha256=hash},ct);
        return JsonSerializer.SerializeToElement(new{id,version,policy_sha256=hash});
    }
    public async Task<JsonElement> ListAsync(NpgsqlConnection c,NpgsqlTransaction t,string actor,CancellationToken ct)
    {
        var rows=await Rows(c,t,"select distinct on(id) id,version,assigned_modules,collection_policy,policy_sha256,created_at from sli_agent_policy_templates order by id,version desc limit 100",ct);
        await audit.AppendAsync(c,t,"template_list",actor,"templates",new{result="listed"},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(rows)});
    }
}
