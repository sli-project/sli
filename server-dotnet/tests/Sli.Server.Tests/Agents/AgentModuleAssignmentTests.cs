using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Xunit;
using Microsoft.Extensions.DependencyInjection;

namespace Sli.Server.Tests.Agents;
public sealed class AgentModuleAssignmentTests
{
    [Fact]
    public void NewWorkstationRoleWithEmptySettingsUsesOnlyPassportEvents()
    {
        var request = AgentModuleAssignmentService.ReadConfig(default, 4);
        var policy = AgentModuleAssignmentRules.NormalizeWorkstation(request, useCollectionBaseline: true);

        Assert.Equal("4", policy["policy_revision"]!.GetValue<string>());
        var events = Assert.IsType<JsonArray>(policy["allow_event_ids"]).Select(value => value!.GetValue<int>()).ToArray();
        Assert.Contains(4688, events);
        Assert.Contains(6416, events);
        Assert.DoesNotContain(4104, events);
        Assert.True(policy["families"]!["logons"]!.GetValue<bool>());
        Assert.True(policy["families"]!["local_admins"]!.GetValue<bool>());
        Assert.True(policy["families"]!["protection"]!.GetValue<bool>());
        Assert.True(policy["families"]!["processes"]!.GetValue<bool>());
        Assert.True(policy["families"]!["usb"]!.GetValue<bool>());
    }

    [Fact]
    public void WorkstationCollectionBaselinePreservesExplicitAndExistingSettings()
    {
        var custom = new JsonObject
        {
            ["policy_revision"] = "5",
            ["allow_event_ids"] = new JsonArray(4688),
        };
        var chosen = AgentModuleAssignmentRules.NormalizeWorkstation(custom, useCollectionBaseline: true);
        Assert.Equal(4688, Assert.Single(chosen["allow_event_ids"]!.AsArray())!.GetValue<int>());
        Assert.True(chosen["families"]!["processes"]!.GetValue<bool>());

        var existing = AgentModuleAssignmentRules.NormalizeWorkstation(new JsonObject { ["policy_revision"] = "5" });
        Assert.Null(existing["allow_event_ids"]);
        Assert.True(existing["families"]!["processes"]!.GetValue<bool>());
    }
    [Fact]
    public void SnapshotBindingRetainsIdentityAndRejectsChanges()
    {
        var old=JsonNode.Parse("""{"source_instance_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","domain_sid":"S-1-5-21-100000001-200000001-300000001","domain_dns":"example.test","scope":"OU=Example","policy_revision":"1"}""")!.AsObject();
        var next=(JsonObject)old.DeepClone(); next["policy_revision"]="2";
        Assert.True(AgentModuleAssignmentRules.SameSnapshotIdentity(old,next));
        next["scope"]="OU=Other";
        Assert.False(AgentModuleAssignmentRules.SameSnapshotIdentity(old,next));
    }
    [Theory]
    [InlineData(1,1,2)]
    [InlineData(41,41,42)]
    public void RevisionAdvancesOnlyFromExpected(long current,long expected,long result)
        => Assert.Equal(result,AgentModuleAssignmentRules.NextRevision(current,expected));
    [Fact]
    public void StaleAndExhaustedRevisionsFail()
    {
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.NextRevision(2,1));
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.NextRevision(9007199254740991,9007199254740991));
    }
    [Fact]
    public void WorkstationAssignmentNormalizesSourceDefaultsAndFilters()
    {
        var input=JsonNode.Parse("""{"policy_revision":"3","allow_process_paths":["C:\\\\Tools\\\\Straße"],"family_filters":{"processes":{"deny_event_ids":[4688]}}}""")!.AsObject();
        var actual=AgentModuleAssignmentRules.NormalizeWorkstation(input);
        Assert.Equal("c://tools//strasse",actual["allow_process_paths"]![0]!.GetValue<string>());
        Assert.Equal(32,actual["batch_size"]!.GetValue<int>());
        Assert.True(actual["families"]!["protection"]!.GetValue<bool>());
        Assert.Equal(10,actual["rate_limits"]!["4104"]!.GetValue<long>());
        Assert.NotNull(actual["family_filters"]!["processes"]!["allow_process_paths"]);
    }    [Fact]
    public void BundledPluginAdmissionWorksWithoutRuntimeOrLockDirectory()
    {
        using var lease=AgentAssignmentPluginAdmission.Enter("sli.ad",null,null);
        Assert.NotNull(lease);
    }
    [Fact]
    public void PluginAdmissionRejectsExistingDrainFence()
    {
        var root=Path.Combine(Path.GetTempPath(),"sli-plugin-test-"+Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root,"sli.ad"));
        File.WriteAllText(Path.Combine(root,"sli.ad","draining.json"),"{}");
        try { Assert.Throws<InvalidOperationException>(()=>AgentAssignmentPluginAdmission.Enter("sli.ad",root,null)); }
        finally { Directory.Delete(root,true); }
    }    private static JsonObject FilePolicy()
    {
        var dir=new DirectoryInfo(Path.GetDirectoryName(SourcePath())!);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","file-audit-scenarios.json"))) dir=dir.Parent;
        var vectors=JsonNode.Parse(File.ReadAllText(Path.Combine(dir!.FullName,"agent-dotnet","tests","vectors","file-audit-scenarios.json")))!.AsArray();
        return (JsonObject)vectors.OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter")["config"]!.DeepClone();
    }
    [Fact]
    public void ServerFileAuditAndSecurityWorkstationConflict()
    {
        var file=FilePolicy();file["source_kind"]="server";
        var modules=new JsonArray(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=file },new JsonObject { ["module_id"]="sli.workstations",["enabled"]=true,["config"]=new JsonObject() });
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.ValidateChannelOwnership(modules));
        modules.RemoveAt(1);AgentModuleAssignmentRules.ValidateChannelOwnership(modules);
    }
    [Fact]
    public void WorkstationFileAuditRequiresWorkstations()
    {
        var file=FilePolicy();file["source_kind"]="workstation";file["roots"]![0]!["share_name"]="";
        var modules=new JsonArray(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=file });
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.ValidateChannelOwnership(modules));
        modules.Add(new JsonObject { ["module_id"]="sli.workstations",["enabled"]=true,["config"]=new JsonObject() });
        AgentModuleAssignmentRules.ValidateChannelOwnership(modules);
    }
    [Fact]
    public void PasswordDomainUsesSourceDnsGrammar()
    {
        Assert.Equal("example.test",AgentModuleAssignmentRules.NormalizeDomain("\u001cEXAMPLE.Test \u001f"));
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.NormalizeDomain("example"));
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.NormalizeDomain("-bad.example"));
    }    [Theory]
    [InlineData("{}")]
    [InlineData("{\"module_id\":\"sli.workstations\",\"enabled\":1}")]
    [InlineData("{\"module_id\":\"unknown\",\"enabled\":true}")]
    [InlineData("{\"module_id\":\"sli.gpo-snapshot\",\"enabled\":true}")]
    public async Task InvalidAssignmentShapeFailsBeforeDatabase(string json)
    {
        var service=new AgentModuleAssignmentService(new AgentControlAudit());
        var error=await Assert.ThrowsAsync<AgentControlException>(()=>service.AssignAsync(null!,null!,System.Text.Json.JsonDocument.Parse(json).RootElement,"session:1",TestContext.Current.CancellationToken));
        Assert.Equal("invalid_agent_module_assignment",error.Message);
    }    [Fact]
    public void WorkstationPoliciesMatchFrozenPythonVectors()
    {
        string file=Path.Combine(Path.GetDirectoryName(SourcePath())!,"workstation-assignment-source.json");
        foreach(var vector in JsonNode.Parse(File.ReadAllText(file))!.AsArray())
        {
            var input=vector!["input"]!.AsObject();
            if (vector["ok"]!.GetValue<bool>()) Assert.True(JsonNode.DeepEquals(vector["result"],AgentModuleAssignmentRules.NormalizeWorkstation(input)),input.ToJsonString());
            else Assert.ThrowsAny<Exception>(()=>AgentModuleAssignmentRules.NormalizeWorkstation(input));
        }
    }
    private static string SourcePath([System.Runtime.CompilerServices.CallerFilePath] string path="")=>path;    [Fact]
    public void NpsPythonWhitespaceCannotBeAnIdentity()
    {
        var nps=JsonNode.Parse("""{"source_instance_id":"id","source_name":"\u001c","connect_address":"host","event_generation":"1"}""")!.AsObject();
        Assert.ThrowsAny<Exception>(()=>AgentModuleAssignmentRules.NormalizeNps("sli.vpn-nps",nps));
    }    [Fact]
    public void AuditPolicyHashUsesPythonDefaultSeparatorsAndEscaping()
    {
        var value=JsonNode.Parse("""{"z":"Straße","a":[1,true,null,"x,y:z"]}""")!;
        var method=typeof(AgentModuleAssignmentService).GetMethod("PythonJson",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        var text=(string)method.Invoke(null,[value])!;
        Assert.Equal("2e7f152f4f3ea0b41a77694a782cb6cc468e6b65c3d00bcb42ccfd3ac6beeb64",Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(text))));
    }    [Fact]
    public void ExternalPluginGenerationIsNotMistakenForBundledHook()
    {
        var root=Path.Combine(Path.GetTempPath(),"sli-plugin-test-"+Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root,"sli.ad"));
        File.WriteAllText(Path.Combine(root,"sli.ad","active.json"),"{}");
        try { Assert.Equal("plugin_generation_unavailable",Assert.Throws<InvalidOperationException>(()=>AgentAssignmentPluginAdmission.Enter("sli.ad",root,null)).Message); }
        finally { Directory.Delete(root,true); }
    }    [Fact]
    public void ProductionDependencyInjectionResolvesAssignmentService()
    {
        var services=new ServiceCollection();services.AddAgentControl();
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<AgentModuleAssignmentService>());
    }    [Fact]
    public void ValidSourceAstralWorkstationPolicySurvivesOwnershipValidation()
    {
        var config=new JsonObject { ["allow_process_paths"]=new JsonArray(new string[] { string.Concat(Enumerable.Repeat("😀",512)) }.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray()) };
        var normalized=AgentModuleAssignmentRules.NormalizeWorkstation(config);
        var modules=new JsonArray(new JsonObject { ["module_id"]="sli.workstations",["enabled"]=true,["config"]=normalized });
        AgentModuleAssignmentRules.ValidateChannelOwnership(modules);
    }    [Theory]
    [InlineData("sli.file-audit")]
    [InlineData("sli.workstations")]
    [InlineData("sli.windows.ad-dc")]
    [InlineData("sli.windows.ad-dc-history")]
    [InlineData("sli.vpn-nps")]
    [InlineData("sli.radius-accounting")]
    [InlineData("sli.ad-snapshot")]
    [InlineData("sli.gpo-snapshot")]
    public void ExistingAssignmentMissingEnabledIsDisabled(string module)
    {
        var list=new JsonArray(new JsonObject { ["module_id"]=module });
        AgentModuleAssignmentRules.ValidateChannelOwnership(list);
        list.Add(new JsonObject { ["module_id"]=module });
        Assert.Equal("agent_channel_owner_conflict",Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.ValidateChannelOwnership(list)).Message);
    }
    [Theory]
    [InlineData("sli.file-audit")]
    [InlineData("sli.workstations")]
    [InlineData("sli.windows.ad-dc")]
    [InlineData("sli.windows.ad-dc-history")]
    [InlineData("sli.vpn-nps")]
    [InlineData("sli.radius-accounting")]
    [InlineData("sli.ad-snapshot")]
    [InlineData("sli.gpo-snapshot")]
    public void ExistingAssignmentExplicitNullOrNonBoolEnabledFails(string module)
    {
        var item=new JsonObject { ["module_id"]=module,["enabled"]=null };
        var list=new JsonArray(item);
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.ValidateChannelOwnership(list));
        item["enabled"]=1;
        Assert.Throws<AgentControlException>(()=>AgentModuleAssignmentRules.ValidateChannelOwnership(list));
    }
    [Fact]
    public void RawDuplicateModuleConfigUsesLastDecodedMemberRecursively()
    {
        using var json=System.Text.Json.JsonDocument.Parse("""{"policy_revision":"3","batch_size":8,"batch_size":32,"family_filters":{"processes":{"deny_event_ids":[],"deny_event_ids":[4688]}},"unused":[{"a":1,"\u0061":2},true,null,1.5]}""");
        var config=AgentModuleAssignmentService.ReadConfig(json.RootElement,4);
        Assert.Equal("4",config["policy_revision"]!.GetValue<string>());
        Assert.Equal(32,config["batch_size"]!.GetValue<int>());
        Assert.Equal(4688,config["family_filters"]!["processes"]!["deny_event_ids"]![0]!.GetValue<int>());
        Assert.Equal(2,config["unused"]![0]!["a"]!.GetValue<int>());
        Assert.True(config["unused"]![1]!.GetValue<bool>());
        Assert.Null(config["unused"]![2]);
        Assert.Equal(1.5,config["unused"]![3]!.GetValue<double>());
    }
    [Fact]
    public void DuplicateValidConfigFlowsThroughSourceWorkstationNormalization()
    {
        using var json=System.Text.Json.JsonDocument.Parse("""{"policy_revision":"3","batch_size":32,"batch_size":32}""");
        var config=AgentModuleAssignmentService.ReadConfig(json.RootElement,4);
        var normalized=AgentModuleAssignmentRules.NormalizeWorkstation(config);
        Assert.Equal(32,normalized["batch_size"]!.GetValue<int>());
        Assert.Equal("4",normalized["policy_revision"]!.GetValue<string>());
    }    [Fact]
    public void DuplicateConfigChangedFieldsUseDecodedUniqueKeys()
    {
        using var json=System.Text.Json.JsonDocument.Parse("""{"batch_size":8,"batch_size":32,"families":{},"\u0066amilies":{}}""");
        var fields=AgentModuleAssignmentService.ChangedFields(json.RootElement);
        Assert.Equal(new[]{"batch_size","families"},fields.Select(x=>x!.GetValue<string>()));
    }
    [Theory]
    [InlineData("{\"module_id\":\"sli.workstations\",\"enabled\":true,\"enabled\":null}","invalid_agent_module_assignment")]
    [InlineData("{\"module_id\":\"sli.workstations\",\"enabled\":true,\"config\":{},\"config\":null}","invalid_agent_module_assignment")]
    [InlineData("{\"agent_id\":\"bad\",\"module_id\":\"sli.workstations\",\"enabled\":null,\"enabled\":true}","invalid_agent_identity")]
    [InlineData("{\"agent_id\":\"bad\",\"module_id\":\"sli.workstations\",\"enabled\":true,\"config\":null,\"config\":{}}","invalid_agent_identity")]
    public async Task DuplicateOuterMembersPreserveShapeAndIdentityPrecedence(string raw,string expected)
    {
        using var body=System.Text.Json.JsonDocument.Parse(raw);
        var service=new AgentModuleAssignmentService(new AgentControlAudit());
        var error=await Assert.ThrowsAsync<AgentControlException>(()=>service.AssignAsync(null!,null!,body.RootElement,"session:1",TestContext.Current.CancellationToken));
        Assert.Equal(expected,error.Message);
    }}
