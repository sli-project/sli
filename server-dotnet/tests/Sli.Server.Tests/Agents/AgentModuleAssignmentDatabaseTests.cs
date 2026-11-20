using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentModuleAssignmentDatabaseTests
{
    [Fact]
    public async Task AssignmentsPublishHistoryBindingsAndRetainedPolicyInOneRollback()
    {
        var ct=TestContext.Current.CancellationToken;
        string path=Environment.GetEnvironmentVariable("SLI_MODULE_ASSIGNMENT_PRIVATE_PLAN") ?? throw new InvalidOperationException("private owned plan required");
        var plan=JsonNode.Parse(await File.ReadAllTextAsync(path,ct))!.AsObject();
        var binding=OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal(binding.RunId.ToString("D"),plan["run_id"]!.GetValue<string>());
        Assert.Equal(binding.Side,plan["side"]!.GetValue<string>());
        var first=Guid.Parse(plan["agent_one"]!.GetValue<string>());var second=Guid.Parse(plan["agent_two"]!.GetValue<string>());
        var firstHost=Guid.Parse(plan["host_one"]!.GetValue<string>());var secondHost=Guid.Parse(plan["host_two"]!.GetValue<string>());
        var source=Guid.Parse(plan["snapshot_source"]!.GetValue<string>());
        string domainSid=plan["domain_sid"]!.GetValue<string>();Assert.Matches(@"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+\z",domainSid);
        Assert.NotEqual(first,second);Assert.NotEqual(firstHost,secondHost);
        await using var owned=await SyntheticDatabase.BorrowAsync(binding,ct);
        await using var db=await owned.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using (var who=new NpgsqlCommand("select current_user",db,tx)) Assert.Equal("adlog_user",await who.ExecuteScalarAsync(ct));
        foreach(var (agent,host) in new[] { (first,firstHost),(second,secondHost) })
        {
            await using var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,status) values(@id,@host,@fp,'active')",db,tx);
            seed.Parameters.AddWithValue("id",agent);seed.Parameters.AddWithValue("host",host);
            seed.Parameters.AddWithValue("fp",Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(agent.ToString()))));await seed.ExecuteNonQueryAsync(ct);
        }
        var service=new AgentModuleAssignmentService(new AgentControlAudit());
        async Task<JsonElement> Assign(Guid agent,string module,JsonObject config,long revision,bool enabled=true)
        {
            var body=JsonSerializer.SerializeToElement(new { agent_id=agent,module_id=module,enabled,config,expected_revision=revision });
            return await service.AssignAsync(db,tx,body,"session:1",ct);
        }
        var ws=await Assign(first,"sli.workstations",new JsonObject(),1);Assert.Equal(2,ws.GetProperty("policy_revision").GetInt64());
        var config=new JsonObject { ["source_instance_id"]=source.ToString(),["domain_sid"]=domainSid,["domain_dns"]="example.test",["scope"]="domain" };
        var snap=await Assign(second,"sli.gpo-snapshot",config,1);Assert.Equal(2,snap.GetProperty("policy_revision").GetInt64());
        var conflict=await Assert.ThrowsAsync<AgentControlException>(()=>Assign(first,"sli.gpo-snapshot",config,2));Assert.Equal("agent_snapshot_collector_conflict",conflict.Message);
        var updated=await Assign(second,"sli.gpo-snapshot",config,2,false);Assert.Equal(3,updated.GetProperty("policy_revision").GetInt64());
        var stale=await Assert.ThrowsAsync<AgentControlException>(()=>Assign(second,"sli.gpo-snapshot",config,2));Assert.Equal("agent_policy_revision_conflict",stale.Message);
        var mutated=(JsonObject)config.DeepClone();mutated["scope"]="changed";
        var immutable=await Assert.ThrowsAsync<AgentControlException>(()=>Assign(second,"sli.gpo-snapshot",mutated,3));Assert.Equal("agent_snapshot_binding_immutable",immutable.Message);
        var file=new JsonObject { ["source_kind"]="workstation",["roots"]=new JsonArray(new JsonObject { ["collection_scope_id"]="scope:test",["share_name"]="",["path"]="C:\\synthetic",["important"]=false,["sacl"]=new JsonObject { ["trustee_sids"]=new JsonArray("S-1-1-0"),["inherit_files"]=true,["inherit_directories"]=true } }) };
        var retained=await Assign(first,"sli.file-audit",file,2);Assert.Equal(3,retained.GetProperty("policy_revision").GetInt64());
        await tx.SaveAsync("failed_audit",ct);
        var failedService=new AgentModuleAssignmentService(new FailAfterAudit());
        var failBody=JsonSerializer.SerializeToElement(new { agent_id=first,module_id="sli.workstations",enabled=true,config=new JsonObject(),expected_revision=3 });
        await Assert.ThrowsAsync<InvalidOperationException>(()=>failedService.AssignAsync(db,tx,failBody,"session:1",ct));
        await tx.RollbackAsync("failed_audit",ct);
        await using (var verifyRetention=new NpgsqlCommand("select sli_plugin_file_audit.retain_assignment_policy(@agent,\u0027session\u0027,1)",db,tx))
        { verifyRetention.Parameters.AddWithValue("agent",first);await verifyRetention.ExecuteNonQueryAsync(ct); }
        await using (var check=new NpgsqlCommand("""
            select (select count(*) from sli_agent_policy_history where agent_id=@first),
                   (select count(*) from sli_agent_snapshot_bindings where agent_id=@second),
                   (select count(*) from sli_agent_snapshot_policies where agent_id=@second),
                   (select count(*) from sli_agent_audit where target in (@first::text,@second::text) and action='module_assign')
            """,db,tx))
        {
            check.Parameters.AddWithValue("first",first);check.Parameters.AddWithValue("second",second);
            await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(3,reader.GetInt64(0));Assert.Equal(1,reader.GetInt64(1));Assert.Equal(2,reader.GetInt64(2));Assert.Equal(4,reader.GetInt64(3));
        }
        await tx.RollbackAsync(ct);
        await using var absent=new NpgsqlCommand("select count(*) from sli_agents where id=any(@ids)",db);
        absent.Parameters.AddWithValue("ids",new[] { first,second });Assert.Equal(0L,await absent.ExecuteScalarAsync(ct));
    }
    private sealed class FailAfterAudit : IAgentControlAudit
    {
        public async Task AppendAsync(NpgsqlConnection db,NpgsqlTransaction tx,string action,string actor,string target,object details,CancellationToken ct)
        {
            await new AgentControlAudit().AppendAsync(db,tx,action,actor,target,details,ct);
            throw new InvalidOperationException("synthetic audit failure");
        }
    }}
