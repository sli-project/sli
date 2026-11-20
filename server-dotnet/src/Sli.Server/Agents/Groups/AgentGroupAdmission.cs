using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using static Sli.Server.Agents.Groups.AgentGroupStore;

namespace Sli.Server.Agents.Groups;

public sealed class AgentGroupAuditedRejection : Exception
{
    public AgentGroupAuditedRejection():base("group_enrollment_rejected"){}
}

public sealed partial class AgentGroupService
{
    public async Task<JsonObject> SubmitAsync(NpgsqlConnection c,NpgsqlTransaction t,JsonElement input,CancellationToken ct)
    {
        var b=Body(input);string target="group_tokens",actor="enrollment:group";
        JsonObject group;Guid host;string? instance;long computer,version;string fp;
        try
        {
            string? token=AgentGroupInput.Text(b["token"]);
            if(!AgentControlJson.Matches(token,@"\A[A-Za-z0-9_-]{43}\z"))throw Rejected();
            var groups=await Rows(c,t,"select * from sli_agent_group_tokens where token_hash=@hash for update",ct,("hash",credentials.Digest(token!)));
            group=groups.FirstOrDefault()??throw Rejected();target=Text(group,"id");actor="enrollment:"+target;
            if(!Available(group,AgentControlJson.Now()) || !AgentGroupInput.Allowed(b,"token","host_id","instance_name","csr_pem","computer_entity_id"))throw Rejected();
            host=AgentGroupInput.Id(b["host_id"]);instance=AgentGroupInput.Instance(b["instance_name"]);computer=AgentGroupInput.Positive(b["computer_entity_id"]);
            var csr=AgentCertificateAuthority.ParseCsr(AgentGroupInput.Text(b["csr_pem"]),host);
            fp=Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
            var previous=await Rows(c,t,"select id,host_id,computer_entity_id,status from sli_agent_group_requests where token_id=@token and key_fingerprint=@fp and instance_name is not distinct from @instance",ct,("token",Guid.Parse(target)),("fp",fp),("instance",instance));
            if(previous.FirstOrDefault() is {} row)
            {
                if(Id(row,"host_id")!=host || Long(row,"computer_entity_id")!=computer || Text(row,"status")=="cancelled")throw Rejected();
                row["key_fingerprint"]=fp;row["instance_name"]=instance;
                if(Text(row,"status")=="approved" && !AutoEnabled(group))return await Release(c,t,group,row,actor,false,ct);
                var approved=await AutoApprove(c,t,group,row,actor,ct);
                if(approved is not null)return approved;
                if(Text(row,"status")!="pending")throw Rejected();
                await Audit(c,t,"group_request",actor,target,new{result="replayed",request_id=Text(row,"id")},ct);
                return new(){["request_id"]=Text(row,"id"),["status"]="pending"};
            }
            version=await AgentGroupDirectory.CheckScope(c,t,group,computer,ct);
            await LockHost(c,t,host,ct);
            if(await HostConflict(c,t,new(host,instance,fp,computer),ct))throw Rejected();
            if(await Scalar(c,t,"update sli_agent_group_tokens set uses_count=uses_count+1 where id=@id and revoked_at is null and expires_at>clock_timestamp() and uses_count<max_uses returning id",ct,("id",Guid.Parse(target))) is null)throw Rejected();
        }
        catch(Exception error)when(error is AgentControlException or AgentCertificateException)
        {
            // Source audited denial commits only this bounded result. Never
            // include any claimed name, CSR, raw credential or credential hash.
            await Audit(c,t,"group_request",actor,target,new{result="rejected"},ct);
            throw new AgentGroupAuditedRejection();
        }
        var request=Guid.NewGuid();
        await Execute(c,t,"insert into sli_agent_group_requests(id,token_id,host_id,instance_name,key_fingerprint,computer_entity_id,computer_version_id) values(@id,@token,@host,@instance,@fp,@computer,@version)",ct,("id",request),("token",Guid.Parse(target)),("host",host),("instance",instance),("fp",fp),("computer",computer),("version",version));
        await Audit(c,t,"group_request",actor,target,new{result="pending",request_id=request},ct);
        var fresh=new JsonObject{["id"]=request.ToString(),["host_id"]=host.ToString(),["instance_name"]=instance,["key_fingerprint"]=fp,["computer_entity_id"]=computer,["status"]="pending"};
        // Outside the audited-denial catch: failures while preparing a NEW
        // automatic approval roll back request/capacity as source does.
        return await AutoApprove(c,t,group,fresh,actor,ct)??new JsonObject{["request_id"]=request.ToString(),["status"]="pending"};
    }
    private static AgentControlException Rejected()=>new("group_enrollment_rejected",401);
    private static bool AutoEnabled(JsonObject group)=>group["enrollment_policy"] is JsonObject p && p["auto_approve"] is {} n && Sli.Server.Auth.Lifecycle.AuthJsonBody.Truthy(AgentGroupInput.Element(n));
    private async Task<JsonObject?> AutoApprove(NpgsqlConnection c,NpgsqlTransaction t,JsonObject group,JsonObject row,string actor,CancellationToken ct)
    {
        if(!AutoEnabled(group))return null;
        var policy=group["enrollment_policy"]!.AsObject();var binding=Binding(row);
        if(!policy["trusted_bindings"]!.AsArray().Any(n=>AgentGroupInput.Binding(n,"invalid_agent_auto_approval",false)==binding))return null;
        _=await AgentGroupDirectory.CheckScope(c,t,group,binding.Computer,ct);
        if(!Available(group,AgentControlJson.Now(),60))throw Rejected();
        await LockHost(c,t,binding.Host,ct);
        if(!Available(group,AgentControlJson.Now(),60))throw Rejected();
        var result=Text(row,"status")=="approved"?await Release(c,t,group,row,actor,true,ct):await Prepare(c,t,group,row,(await Template(c,t,policy,ct))!,actor,ct);
        if(result is null)throw Rejected();
        await Audit(c,t,"group_auto_approval",actor,Text(row,"id"),new{result="approved",token_id=Text(group,"id")},ct);
        return result;
    }
    private async Task<JsonObject> Release(NpgsqlConnection c,NpgsqlTransaction t,JsonObject group,JsonObject row,string actor,bool automatic,CancellationToken ct)
    {
        if(!automatic)
        {
            _=await AgentGroupDirectory.CheckScope(c,t,group,Long(row,"computer_entity_id"),ct);
            await LockHost(c,t,Id(row,"host_id"),ct);
        }
        var now=AgentControlJson.Now();if(!automatic && !Available(group,now,60))throw Rejected();
        var expires=Time(group,"expires_at")<now.AddSeconds(900)?Time(group,"expires_at"):now.AddSeconds(900);string raw=credentials.NewSessionToken();
        string sql=automatic
            ?"update sli_agent_enrollment_tokens e set token_hash=@hash,created_at=@now,expires_at=@expiry from sli_agent_onboarding_copies a where a.enrollment_token_id=e.id and a.request_id=@request and e.used_at is null and e.revoked_at is null returning e.id"
            :"update sli_agent_enrollment_tokens e set token_hash=@hash,created_at=@now,expires_at=@expiry from sli_agent_group_approval_links a where a.enrollment_token_id=e.id and a.request_id=@request and e.host_id=@host and e.key_fingerprint=@fp and e.instance_name is not distinct from @instance and e.used_at is null and e.revoked_at is null and @groupExpiry>clock_timestamp()+interval '60 seconds' returning e.id";
        if(await Scalar(c,t,sql,ct,("hash",credentials.Digest(raw)),("now",now),("expiry",expires),("request",Id(row,"id")),("host",Id(row,"host_id")),("fp",Text(row,"key_fingerprint")),("instance",AgentGroupInput.Text(row["instance_name"])),("groupExpiry",Time(group,"expires_at"))) is null)throw Rejected();
        if(!automatic)await Audit(c,t,"group_approval_delivery",actor,Text(row,"id"),new{result="approved",token_id=Text(group,"id")},ct);
        return Approved(Id(row,"id"),raw,expires);
    }
}
