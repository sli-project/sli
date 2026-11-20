using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;
using static Sli.Server.Agents.Groups.AgentGroupStore;

namespace Sli.Server.Agents.Groups;

public sealed partial class AgentGroupService
{
    public async Task<JsonElement> PendingAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        var (group,token)=AgentGroupInput.Filter(Body(input));
        var rows=await Rows(c,t,"select r.id,r.host_id,r.instance_name,r.key_fingerprint,r.computer_entity_id,r.computer_version_id from sli_agent_group_requests r join sli_agent_group_tokens t on t.id=r.token_id where t.group_id=@group and t.id=@token and r.status='pending' order by r.id limit 1001",ct,("group",group),("token",token));
        await Audit(c,t,"group_pending_list",actor,group.ToString(),new{token_id=token,result="listed"},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(rows.Take(1000)),["has_more"]=rows.Count>1000});
    }
    public async Task<JsonElement> ProgressAsync(NpgsqlConnection c,NpgsqlTransaction t,string? tokenText,string actor,CancellationToken ct)
    {
        var token=AgentControlJson.Id(tokenText);
        var rows=await Rows(c,t,"select r.id,r.host_id,r.instance_name,r.key_fingerprint,r.computer_entity_id,r.computer_version_id,r.status,a.id as agent_id,a.last_seen,c.template_id,c.template_version,a.applied_policy_revision from sli_agent_group_requests r left join sli_agent_group_approval_links link on link.request_id=r.id left join sli_agent_onboarding_copies c on c.enrollment_token_id=link.enrollment_token_id left join sli_agent_audit issued on issued.actor='enrollment:' || link.enrollment_token_id::text and issued.action='issue' left join sli_agents a on a.id=issued.target::uuid where r.token_id=@token order by r.created_at,r.id limit 1000",ct,("token",token));
        foreach(var row in rows)row["deployment_status"]=row["agent_id"] is null?Text(row,"status"):row["last_seen"] is null?"registered":"signaled";
        await Audit(c,t,"onboarding_list",actor,token.ToString(),new{result="listed",count=rows.Count},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(rows)});
    }
    public async Task<JsonElement> ApproveAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        var b=Body(input);
        if(!AgentGroupInput.Shape(b,"filter","evidence"))throw new AgentControlException("invalid_agent_batch_filter");
        var (groupId,tokenId)=AgentGroupInput.Filter(b["filter"]);
        var bindings=AgentGroupInput.Bindings(b["evidence"],false);
        var group=(await Rows(c,t,"select * from sli_agent_group_tokens where id=@token and group_id=@group for update",ct,("token",tokenId),("group",groupId))).FirstOrDefault()??throw new AgentControlException("enrollment_token_not_found",404);
        var requests=await Requests(c,t,tokenId,bindings.Keys.ToArray(),ct);await LockHosts(c,t,requests,ct);
        var byId=requests.ToDictionary(x=>Id(x,"id"));var results=new List<JsonObject>();
        foreach(var (id,binding) in bindings.OrderBy(x=>x.Key.ToString(),StringComparer.Ordinal))
        {
            byId.TryGetValue(id,out var row);string reason="request_not_pending",status="rejected";
            if(row is not null && Text(row,"status")=="approved"){status="already_approved";reason="already_approved";}
            else if(row is not null && Text(row,"status")=="pending")
            {
                if(!Available(group,AgentControlJson.Now(),60))reason="batch_unavailable";
                else if(binding!=Binding(row))reason="key_identity_unverified";
                else if(!await Eligible(c,t,group,binding.Computer,ct))reason="directory_scope_rejected";
                else
                {
                    var template=await Template(c,t,group["enrollment_policy"]!.AsObject(),ct);
                    if(template is not null)
                    {
                        var prepared=await Prepare(c,t,group,row,template,actor,ct);
                        if(prepared is not null){results.Add(prepared);continue;}
                        reason="host_conflict_or_expired";
                    }
                    else if(await HostConflict(c,t,binding,ct) || !Available(group,AgentControlJson.Now(),60))reason="host_conflict_or_expired";
                    else
                    {
                        var now=AgentControlJson.Now();var expires=Expiry(group,now);
                        if(expires>=now.AddSeconds(60))
                        {
                            var credential=await InsertCredential(c,t,row,now,expires,ct);
                            await Audit(c,t,"token_create",actor,credential.Id.ToString(),new{group_id=groupId,ttl_seconds=(int)(expires-now).TotalSeconds},ct);
                            await Execute(c,t,"insert into sli_agent_group_approvals(request_id,enrollment_token_id) values(@request,@token)",ct,("request",id),("token",credential.Id));
                            await MarkApproved(c,t,id,ct);
                            await Audit(c,t,"group_approval",actor,id.ToString(),new{result="approved",group_id=groupId,token_id=tokenId},ct);
                            results.Add(Approved(id,credential.Raw,expires));continue;
                        }
                        reason="batch_unavailable";
                    }
                }
            }
            await Audit(c,t,"group_approval",actor,id.ToString(),new{result=status,reason,group_id=groupId,token_id=tokenId},ct);
            results.Add(Decision(id,status,reason));
        }
        await Audit(c,t,"group_approval_batch",actor,groupId.ToString(),new{token_id=tokenId,result="processed",approved=Count(results,"approved"),rejected=Count(results,"rejected")},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(results)});
    }
    public async Task<JsonElement> OnboardAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,string actor,CancellationToken ct)
    {
        var b=AgentGroupInput.Onboarding(Body(input));
        var group=(await Rows(c,t,"select * from sli_agent_group_tokens where id=@id for update",ct,("id",b.Token))).FirstOrDefault()??throw new AgentControlException("enrollment_token_not_found",404);
        var template=(await Template(c,t,new JsonObject{["template_id"]=b.Template.ToString(),["template_version"]=b.Version},ct))!;
        var rows=await Requests(c,t,b.Token,b.Ids,ct);
        if(rows.Count>1000)throw new AgentControlException("agent_batch_size_limit");
        var byId=rows.ToDictionary(x=>Id(x,"id"));var candidates=b.Ids??byId.Keys.OrderBy(x=>x.ToString(),StringComparer.Ordinal).ToArray();
        await LockHosts(c,t,rows,ct);var results=new List<JsonObject>();
        foreach(Guid id in candidates)
        {
            byId.TryGetValue(id,out var row);string status="rejected",reason="request_not_pending";
            if(row is not null && Text(row,"status")=="approved"){status="already_approved";reason="already_approved";}
            else if(row is not null && Text(row,"status")=="pending")
            {
                if(!Available(group,AgentControlJson.Now(),60))reason="batch_unavailable";
                else if(!b.Bindings.TryGetValue(id,out var binding) || binding!=Binding(row))reason="key_identity_unverified";
                else if(!await Eligible(c,t,group,binding.Computer,ct))reason="directory_scope_rejected";
                else
                {
                    var prepared=await Prepare(c,t,group,row,template,actor,ct);
                    if(prepared is not null){results.Add(prepared);continue;}
                    reason="host_conflict_or_expired";
                }
            }
            await Audit(c,t,"onboarding_decision",actor,id.ToString(),new{result=status,reason,token_id=b.Token,domain_id=Long(group,"domain_id"),ou_entity_ids=group["ou_entity_ids"]},ct);
            results.Add(Decision(id,status,reason));
        }
        await Audit(c,t,"onboarding_batch",actor,b.Token.ToString(),new{result="processed",mode=b.Mode,domain_id=Long(group,"domain_id"),ou_entity_ids=group["ou_entity_ids"],approved=Count(results,"approved"),rejected=Count(results,"rejected")},ct);
        return AgentControlJson.Element(new JsonObject{["items"]=Array(results)});
    }
    private static Task<List<JsonObject>> Requests(NpgsqlConnection c,NpgsqlTransaction t,Guid token,Guid[]? ids,CancellationToken ct)=>ids is null
        ?Rows(c,t,"select * from sli_agent_group_requests where token_id=@token and status='pending' order by id limit 1001 for update",ct,("token",token))
        :Rows(c,t,"select * from sli_agent_group_requests where token_id=@token and id=any(@ids) order by id for update",ct,("token",token),("ids",ids));
    private static async Task LockHosts(NpgsqlConnection c,NpgsqlTransaction t,List<JsonObject> rows,CancellationToken ct)
    {foreach(Guid host in rows.Where(x=>Text(x,"status")=="pending").Select(x=>Id(x,"host_id")).Distinct().OrderBy(x=>x.ToString(),StringComparer.Ordinal))await LockHost(c,t,host,ct);}
    private static async Task<bool> Eligible(NpgsqlConnection c,NpgsqlTransaction t,JsonObject group,long computer,CancellationToken ct)
    {try{_=await AgentGroupDirectory.CheckScope(c,t,group,computer,ct);return true;}catch(AgentControlException){return false;}}
    private static DateTimeOffset Expiry(JsonObject group,DateTimeOffset now)=>Time(group,"expires_at")<now.AddSeconds(900)?Time(group,"expires_at"):now.AddSeconds(900);
    private async Task<(Guid Id,string Raw)> InsertCredential(NpgsqlConnection c,NpgsqlTransaction t,JsonObject row,DateTimeOffset now,DateTimeOffset expiry,CancellationToken ct)
    {
        var id=Guid.NewGuid();string raw=credentials.NewSessionToken();var binding=Binding(row);
        await Execute(c,t,"insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at,instance_name) values(@id,@hash,@host,@fp,@now,@expiry,@instance)",ct,("id",id),("hash",credentials.Digest(raw)),("host",binding.Host),("fp",binding.Fingerprint),("now",now),("expiry",expiry),("instance",binding.Instance));
        return(id,raw);
    }
    private static async Task MarkApproved(NpgsqlConnection c,NpgsqlTransaction t,Guid request,CancellationToken ct)=>_=await Execute(c,t,"update sli_agent_group_requests set status='approved' where id=@id",ct,("id",request));
    private async Task<JsonObject?> Prepare(NpgsqlConnection c,NpgsqlTransaction t,JsonObject group,JsonObject row,JsonObject template,string actor,CancellationToken ct)
    {
        if(await HostConflict(c,t,Binding(row),ct) || !Available(group,AgentControlJson.Now(),60))return null;
        var now=AgentControlJson.Now();var expires=Expiry(group,now);var credential=await InsertCredential(c,t,row,now,expires,ct);Guid request=Id(row,"id");
        await Execute(c,t,"insert into sli_agent_onboarding_copies(enrollment_token_id,request_id,template_id,template_version) values(@token,@request,@template,@version)",ct,("token",credential.Id),("request",request),("template",Id(template,"id")),("version",Long(template,"version")));
        await MarkApproved(c,t,request,ct);
        await Audit(c,t,"onboarding_decision",actor,request.ToString(),new{result="approved",token_id=Text(group,"id"),domain_id=Long(group,"domain_id"),ou_entity_ids=group["ou_entity_ids"],template_id=Text(template,"id"),template_version=Long(template,"version"),policy_sha256=Text(template,"policy_sha256")},ct);
        return Approved(request,credential.Raw,expires);
    }
    private static JsonObject Decision(Guid id,string status,string reason)=>new(){["request_id"]=id.ToString(),["status"]=status,["reason"]=reason};
    private static int Count(List<JsonObject> results,string status)=>results.Count(x=>Text(x,"status")==status);
}
