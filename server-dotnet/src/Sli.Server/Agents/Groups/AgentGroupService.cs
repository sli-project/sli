using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;
using Sli.Server.Auth.Lifecycle;
using static Sli.Server.Agents.Groups.AgentGroupStore;

namespace Sli.Server.Agents.Groups;

public sealed partial class AgentGroupService(ICredentialTokens credentials,IAgentControlAudit audit)
{
    private static JsonObject Body(JsonElement input)=>Sli.Server.Agents.ClientControl.AgentClientJson.FromElement(input) as JsonObject ?? throw new AgentControlException("json_object_required");
    private Task Audit(NpgsqlConnection c,NpgsqlTransaction t,string action,string actor,string target,object details,CancellationToken ct)=>audit.AppendAsync(c,t,action,actor,target,details,ct);

    public async Task<JsonElement> CreateAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        var b=Body(input);var parsed=AgentGroupInput.Create(b);Guid group;long domain;long[] ous;
        if(b.ContainsKey("group_id"))
        {
            if(b.ContainsKey("domain_id") || b.ContainsKey("ou_entity_ids"))throw new AgentControlException("invalid_group_enrollment_scope");
            group=AgentGroupInput.Id(b["group_id"]);
            var rows=await Rows(c,t,"select * from sli_agent_enrollment_groups where id=@id",ct,("id",group));
            if(rows.Count==0)throw new AgentControlException("agent_group_not_found",404);
            domain=Long(rows[0],"domain_id");ous=rows[0]["ou_entity_ids"]!.AsArray().Select(x=>x!.GetValue<long>()).ToArray();
        }
        else
        {
            domain=AgentGroupInput.Positive(b["domain_id"]);ous=AgentGroupInput.Ids(b.ContainsKey("ou_entity_ids")?b["ou_entity_ids"]:new JsonArray(),128);
            foreach(long ou in ous)_=await AgentGroupDirectory.ResolveAsync(c,t,ou,domain,true,ct);
            group=Guid.NewGuid();await Execute(c,t,"insert into sli_agent_enrollment_groups(id,domain_id,ou_entity_ids) values(@id,@domain,@ous)",ct,("id",group),("domain",domain),("ous",ous));
        }
        foreach(long ou in ous)_=await AgentGroupDirectory.ResolveAsync(c,t,ou,domain,true,ct);
        long[] selected=AgentGroupInput.Ids(b.ContainsKey("computer_entity_ids")?b["computer_entity_ids"]:new JsonArray(),1000);
        var scope=new JsonObject{["domain_id"]=domain,["ou_entity_ids"]=JsonSerializer.SerializeToNode(ous),["computer_entity_ids"]=JsonSerializer.SerializeToNode(selected)};
        foreach(long computer in selected)_=await AgentGroupDirectory.CheckScope(c,t,scope,computer,ct);
        var policy=new JsonObject();
        if(b.ContainsKey("template_id") || b.ContainsKey("template_version"))
        {
            policy["template_id"]=AgentGroupInput.Id(b["template_id"]).ToString();policy["template_version"]=AgentGroupInput.Version(b["template_version"]);
            _=await Template(c,t,policy,ct);
        }
        bool auto=false;
        if(b.ContainsKey("auto_approve"))
        {
            var kind=b["auto_approve"]?.GetValueKind();
            if(kind is not(JsonValueKind.True or JsonValueKind.False))throw new AgentControlException("invalid_agent_auto_approval");
            auto=kind==JsonValueKind.True;
        }
        var bindingNode=b.ContainsKey("trusted_bindings")?b["trusted_bindings"]:new JsonArray();
        if(bindingNode is not JsonArray bindings || bindings.Count>1000 || (!auto && bindings.Count>0))throw new AgentControlException("invalid_agent_auto_approval");
        if(auto)
        {
            if(policy.Count==0 || bindings.Count==0)throw new AgentControlException("invalid_agent_auto_approval");
            var normalized=new JsonArray();var seen=new HashSet<(Guid,string?)>();
            foreach(var item in bindings)
            {
                var binding=AgentGroupInput.Binding(item,"invalid_agent_auto_approval",false);
                if(!seen.Add((binding.Host,binding.Instance)))throw new AgentControlException("invalid_agent_auto_approval");
                _=await AgentGroupDirectory.CheckScope(c,t,scope,binding.Computer,ct);
                normalized.Add(new JsonObject{["host_id"]=binding.Host.ToString(),["instance_name"]=binding.Instance,["key_fingerprint"]=binding.Fingerprint,["computer_entity_id"]=binding.Computer});
            }
            policy["auto_approve"]=true;policy["trusted_bindings"]=normalized;
        }
        string raw=credentials.NewSessionToken();var id=Guid.NewGuid();var now=AgentControlJson.Now();var expires=now.AddSeconds(parsed.Ttl);
        await Execute(c,t,"insert into sli_agent_group_tokens(id,token_hash,created_at,expires_at,max_uses,domain_id,ou_entity_ids,group_id,computer_entity_ids,enrollment_policy) values(@id,@hash,@now,@expiry,@max,@domain,@ous,@group,@selected,@policy::jsonb)",ct,("id",id),("hash",credentials.Digest(raw)),("now",now),("expiry",expires),("max",parsed.Maximum),("domain",domain),("ous",ous),("group",group),("selected",selected),("policy",policy.ToJsonString()));
        await Audit(c,t,"group_token_create",actor,id.ToString(),new{result="created",group_id=group,ttl_seconds=parsed.Ttl,max_uses=parsed.Maximum},ct);
        return JsonSerializer.SerializeToElement(new{id,group_id=group,token=raw,expires_at=AgentControlJson.Stamp(expires,true),max_uses=parsed.Maximum});
    }
    public async Task<JsonElement> ListAsync(NpgsqlConnection c,NpgsqlTransaction t,string actor,CancellationToken ct)
    {
        var rows=await Rows(c,t,"select id,created_at,expires_at,max_uses,uses_count,domain_id,ou_entity_ids,revoked_at,group_id,computer_entity_ids,coalesce((enrollment_policy->>'auto_approve')::boolean,false) as auto_approve from sli_agent_group_tokens order by created_at desc,id limit 100",ct);
        await Audit(c,t,"group_token_list",actor,"group_tokens",new{result="listed"},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(rows)});
    }
    public async Task<JsonElement> RevokeAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        Guid id=AgentGroupInput.Id(Body(input)["id"]);
        if(await Scalar(c,t,"update sli_agent_group_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where id=@id returning id",ct,("id",id)) is null)throw new AgentControlException("enrollment_token_not_found",404);
        await Execute(c,t,"update sli_agent_enrollment_tokens e set revoked_at=coalesce(e.revoked_at,clock_timestamp()) from sli_agent_group_approval_links a join sli_agent_group_requests r on r.id=a.request_id where e.id=a.enrollment_token_id and r.token_id=@id and e.used_at is null",ct,("id",id));
        await Execute(c,t,"update sli_agent_group_requests r set status='cancelled' from sli_agent_group_approval_links a join sli_agent_enrollment_tokens e on e.id=a.enrollment_token_id where r.id=a.request_id and r.token_id=@id and r.status='approved' and e.used_at is null",ct,("id",id));
        await Execute(c,t,"update sli_agent_group_requests set status='cancelled' where token_id=@id and status='pending'",ct,("id",id));
        await Audit(c,t,"group_token_revoke",actor,id.ToString(),new{result="revoked"},ct);return JsonSerializer.SerializeToElement(new{status="revoked"});
    }
    private static async Task<JsonObject?> Template(NpgsqlConnection c,NpgsqlTransaction t,JsonObject policy,CancellationToken ct)
    {
        if(!policy.ContainsKey("template_id"))return null;
        var rows=await Rows(c,t,"select * from sli_agent_policy_templates where id=@id and version=@version",ct,("id",Guid.Parse(Text(policy,"template_id"))),("version",Long(policy,"template_version")));
        return rows.FirstOrDefault()??throw new AgentControlException("agent_template_not_found",404);
    }
}
