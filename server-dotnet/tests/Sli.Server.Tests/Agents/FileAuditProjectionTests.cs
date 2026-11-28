using System.Reflection;
using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;

namespace Sli.Server.Tests.Agents;

public class FileAuditProjectionTests
{
    private static Type Projection => typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditEvidence")!;
    [Fact]
    public void NativeFactsPreserveBoundsAndOutcomeWithoutUnreviewedFields()
    {
        Assert.NotNull(Projection);
        var row = JsonNode.Parse("{\"channel\":\"Security\",\"provider_name\":\"Microsoft-Windows-Security-Auditing\",\"event_id\":4670,\"keywords\":\"0x8020000000000000\"}")!.AsObject();
        var data = new JsonObject { ["OldSd"]="D:(A;;FR;;;SY)", ["NewSd"]="D:(A;;FA;;;SY)", ["AccessMask"]="0x2", ["ProcessId"]="0xffffffffffffffff", ["ObjectName"]=new string('a',4097), ["Unreviewed"]="secret" };
        var facts=(JsonObject)Projection.GetMethod("NativeFacts")!.Invoke(null,[row,data])!;
        Assert.Equal("success",facts["outcome"]!.GetValue<string>());
        Assert.Equal(2UL,facts["access_mask"]!.GetValue<ulong>());
        Assert.Equal(ulong.MaxValue,facts["server_process_id"]!.GetValue<ulong>());
        Assert.Null(facts["object_name"]); Assert.Null(facts["Unreviewed"]);
        Assert.Equal("D:(A;;FR;;;SY)",facts["old_sd"]!.GetValue<string>());
        row["provider_name"]="unknown";
        Assert.Empty((JsonObject)Projection.GetMethod("NativeFacts")!.Invoke(null,[row,data])!);
    }
    [Fact]
    public void IdentityUsesPythonAsciiJsonAndIgnoresEventVersion()
    {
        Assert.NotNull(Projection);
        var method=Projection.GetMethod("EvidenceKey")!;
        var args=new object[]{"00000000-0000-4000-8000-000000000001","хост","gen",42L,4663,0};
        var first=(string)method.Invoke(null,args)!;
        args[5]=1;
        Assert.Equal(first,method.Invoke(null,args));
        Assert.Equal("c97ca2ce8b83a9fcd7f8e211ea4270035bfe8acddd5c776ab3406d20fef14034",first);
    }
    [Fact]
    public void ObservationPreservesSourcePathFactsAndEvidence()
    {
        var dir=new FileInfo(typeof(FileAuditProjectionTests).Assembly.Location).Directory;
        while(dir is not null && !File.Exists(Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","file-audit-scenarios.json"))) dir=dir.Parent;
        Assert.NotNull(dir);
        var vectors=JsonNode.Parse(File.ReadAllText(Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","file-audit-scenarios.json")))!.AsArray();
        var fixture=vectors.OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
        var packet=JsonNode.Parse(fixture["steps"]![0]!["payload_canonical"]!.GetValue<string>())!.AsObject();
        var row=packet["records"]![0]!["payload"]!.AsObject();
        var policy=Sli.Agent.Core.FileAuditPolicy.Parse(fixture["config"]!.AsObject());
        var type=typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditObservation")!;
        var host=fixture["host_id"]!.GetValue<string>();
        var result=(JsonObject)type.GetMethod("Build")!.Invoke(null,[row,policy,"00000000-0000-4000-8000-000000000001",host,"synthetic-generation","1","agent-workstation-event:test:1"])!;
        Assert.Equal("C:\\synthetic\\item",result["path"]!.GetValue<string>());
        Assert.Equal("scope:one",result["scopes"]![0]!["collection_scope_id"]!.GetValue<string>());
        Assert.Equal(65536UL,result["facts"]!["access_mask"]!.GetValue<ulong>());
        Assert.Equal("2026-10-07T00:00:00.123456+00:00",result["observed_at"]!.GetValue<string>());
        Assert.Equal("agent-workstation-event:test:1",result["core_evidence_ref"]!.GetValue<string>());
        var correlation=type.Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditCorrelation")!;
        var actions=(JsonArray)correlation.GetMethod("ProjectActions")!.Invoke(null,[result,new JsonArray(),"unknown"])!;
        Assert.Equal("delete_right",actions[0]!["operation"]!.GetValue<string>());
        Assert.Equal("partial",actions[0]!["correlation_state"]!.GetValue<string>());
    }
    private static JsonObject Item(int record,int id,string? path,ulong mask=0x10000) => new() {
        ["evidence_key"]=$"e{record}",["core_evidence_ref"]=$"r{record}",["agent_id"]="a",["source_instance_id"]="h",["generation"]="g",["policy_revision"]="1",
        ["record_id"]=record,["event_id"]=id,["observed_at"]=$"2026-10-07T00:00:{record:00}+00:00",["path"]=path,["excluded"]=false,
        ["scopes"]=new JsonArray(new JsonObject { ["collection_scope_id"]="scope",["share_name"]="",["important"]=true }),
        ["facts"]=new JsonObject { ["outcome"]="success",["subject_user_sid"]="S-1-1-0",["logon_id_numeric"]=16,["server_process_id"]=8,["handle_id"]=68,["access_mask"]=mask } };
    [Fact]
    public void DeleteAndRenameRequireLiveUnambiguousHandleEvidence()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditCorrelation")!;
        var project=type.GetMethod("ProjectActions")!;
        JsonArray Run(JsonObject item,params JsonObject[] prior)=>(JsonArray)project.Invoke(null,[item,new JsonArray(prior.Select(x=>x.DeepClone()).ToArray()),"unknown"])!;
        var open=Item(1,4656,"C:\\synthetic\\old"); var previous=Item(2,4663,"C:\\synthetic\\old");
        var deletion=Run(Item(3,4660,null),open,previous);
        Assert.Equal("delete",deletion[0]!["operation"]!.GetValue<string>());
        Assert.Equal("C:\\synthetic\\old",deletion[0]!["path"]!.GetValue<string>());
        Assert.Equal("handle_context",deletion[0]!["evidence"]![1]!["role"]!.GetValue<string>());
        var renamed=Run(Item(3,4663,"C:\\synthetic\\new",0x80),open,previous);
        Assert.Equal("rename",renamed[0]!["operation"]!.GetValue<string>());
        Assert.Equal(3,renamed[0]!["evidence"]!.AsArray().Count);
        Assert.Empty(Run(open));
        var write=Assert.Single(Run(Item(2,4663,"C:\\synthetic\\old",2),open))!;
        Assert.Equal("write",write["operation"]!.GetValue<string>());
        Assert.Contains(write["evidence"]!.AsArray(), edge => edge!["evidence_key"]!.GetValue<string>()=="e1");
        var denied = open.DeepClone().AsObject();
        denied["facts"]!["outcome"]="failure";
        Assert.Equal("failure",Assert.Single(Run(denied))!["outcome"]!.GetValue<string>());
        var conflicting=Item(2,4663,"C:\\synthetic\\other");
        Assert.Empty(Run(Item(3,4660,null),open,conflicting));
        var close=Item(2,4658,null);
        Assert.Empty(Run(Item(3,4660,null),open,close));
        Assert.Empty(Run(Item(4,4663,"C:\\synthetic\\new",0x80),open,previous,Item(3,4658,null)));
    }

    [Theory]
    [InlineData(4663, 68)]
    [InlineData(4656, 69)]
    public void RenamePairsNativeDeleteWithImmediateDestination(int eventId, int handle)
    {
        const string oldPath = @"C:\synthetic\doc-001.txt";
        var previous = Item(1,4663,oldPath);
        var target = Item(2,eventId,oldPath+".locked",0x80);
        target["observed_at"] = "2026-10-07T00:00:01.003+00:00";
        target["facts"]!["handle_id"] = handle;
        var action = Assert.Single(FileAuditCorrelation.ProjectActions(target,new JsonArray(previous.DeepClone()),"file"))!;
        Assert.Equal("rename",action["operation"]!.ToString());
        Assert.Equal(oldPath+".locked",action["path"]!.ToString());
        Assert.Equal(oldPath,action["old_path"]!.ToString());
        Assert.Contains(action["evidence"]!.AsArray(), edge => edge!["evidence_key"]!.ToString()=="e1");

        var unrelated = target.DeepClone().AsObject();
        unrelated["path"] = @"C:\synthetic\other.txt";
        unrelated["facts"]!["handle_id"] = 69;
        Assert.DoesNotContain(FileAuditCorrelation.ProjectActions(unrelated,new JsonArray(previous.DeepClone()),"file"),
            row => row!["operation"]!.ToString()=="rename");
    }

    [Fact]
    public void MassWriteRuleRequiresEvidenceAndDistinctFiles()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditActivityRules");
        Assert.NotNull(type);
        var config=JsonNode.Parse("{\"roots\":[{\"collection_scope_id\":\"scope\",\"path\":\"C:\\\\synthetic\",\"important\":true}],\"service_account_exclusions\":[],\"mass_operation_files\":2,\"mass_operation_seconds\":300}")!.AsObject();
        JsonObject Action(string id,string path)=>new() { ["action_id"]=id,["agent_id"]="a",["source_instance_id"]="h",["collection_scope_id"]="scope",["subject_sid"]="S-1-1-0",["operation"]="write",["outcome"]="success",["evidence"]=new JsonArray("e"),["path"]=path,["object_type"]="file",["correlation_state"]="complete",["observed_at"]="2026-10-07T00:00:00+00:00" };
        var actions=new JsonArray(Action("one","C:\\synthetic\\one"),Action("two","C:\\synthetic\\two"));
        var result=(JsonArray)type.GetMethod("Evaluate")!.Invoke(null,[actions,config,"a","h",new JsonArray(),null])!;
        Assert.Single(result);
        Assert.Equal("file-audit.mass-write",result[0]!["rule_code"]!.GetValue<string>());
        Assert.Equal(2,result[0]!["details"]!["distinct_files"]!.GetValue<int>());
        var renamed=Action("rename",@"C:\synthetic\one.locked");
        renamed["operation"]="rename";
        renamed["old_path"]=@"C:\synthetic\one";
        var deleted=Action("delete",@"C:\synthetic\two");
        deleted["operation"]="delete";
        var mixed=new JsonArray(actions[0]!.DeepClone(),renamed,deleted);
        var mixedResult=Assert.Single(FileAuditActivityRules.Evaluate(mixed,config,"a","h",new JsonArray(),null))!;
        Assert.Equal(2,mixedResult["details"]!["distinct_files"]!.GetValue<int>());
        Assert.Equal(3,mixedResult["action_ids"]!.AsArray().Count);
        var calendar=JsonNode.Parse("{\"timezone\":\"UTC\",\"weekdays\":[0,1,2,3,4],\"start\":\"09:00\",\"end\":\"17:00\",\"excluded_dates\":[],\"exceptions\":[]}")!.AsObject();
        var outside=(JsonArray)type.GetMethod("Evaluate")!.Invoke(null,[actions,config,"a","h",new JsonArray(),calendar])!;
        Assert.Equal(2,outside.OfType<JsonObject>().Count(x=>x["rule_code"]!.GetValue<string>()=="file-audit.out-of-hours"));
    }    [Fact]
    public void CalendarAcceptsPythonIsoWeekAndTruncatesFractionalMicroseconds()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.FileAudit.WorkingTime")!;
        var calendar=JsonNode.Parse("{\"timezone\":\"UTC\",\"weekdays\":[0,1,2,3,4],\"start\":\"09:00\",\"end\":\"17:00\",\"excluded_dates\":[],\"exceptions\":[{\"subject_sid\":\"S-1-1-0\",\"start_utc\":\"2026-W44-7T02:00:00.0000009+00:00:00\",\"end_utc\":\"20261101T030000+000000\",\"reason\":\"synthetic\"}]}")!.AsObject();
        var zone=type.GetMethod("Validate")!.Invoke(null,[calendar]); Assert.NotNull(zone);
        object?[] args=["2026-11-01T02:00:00+00:00","S-1-1-0",calendar,zone,null];
        Assert.False((bool)type.GetMethod("Outside")!.Invoke(null,args)!);
        calendar["exceptions"]![0]!["start_utc"]="2026-W44-7T00:00:00+00:00:00";
        Assert.NotNull(type.GetMethod("Validate")!.Invoke(null,[calendar]));
        calendar["exceptions"]![0]!["start_utc"]="2026-11-01T00:00:00";
        Assert.Throws<System.Reflection.TargetInvocationException>(()=>type.GetMethod("Validate")!.Invoke(null,[calendar]));
        calendar["exceptions"]![0]!["start_utc"]="2026-11-01T00:00:00+01:00";
        Assert.Throws<System.Reflection.TargetInvocationException>(()=>type.GetMethod("Validate")!.Invoke(null,[calendar]));
    }
    [Theory]
    [InlineData("0x١",1UL)]
    [InlineData("٠x١",1UL)]
    [InlineData("0x_١f",31UL)]
    [InlineData("0b١٠",2UL)]
    [InlineData("0o٧",7UL)]
    public void PythonBaseZeroAcceptsUnicodeDecimalDigitsAfterPrefixes(string value,ulong expected)
    {
        var row=JsonNode.Parse("{\"channel\":\"Security\",\"provider_name\":\"Microsoft-Windows-Security-Auditing\",\"event_id\":4663,\"keywords\":\"0x8020000000000000\"}")!.AsObject();
        var facts=(JsonObject)Projection.GetMethod("NativeFacts")!.Invoke(null,[row,new JsonObject { ["AccessMask"]=value }])!;
        Assert.Equal(expected,facts["access_mask"]!.GetValue<ulong>());
        var ingress=typeof(Sli.Server.Agents.Ingress.AgentFileAuditValidator).Assembly.GetType("Sli.Server.Agents.Ingress.AgentFileAuditEvents")!;
        Assert.True((bool)ingress.GetMethod("PositiveNumber",BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,[value])!);
        if(expected==1) {
            var observation=Item(1,4663,"C:\\synthetic\\item",1); observation["facts"]=facts.DeepClone();
            var correlation=ingress.Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditCorrelation")!;
            var actions=(JsonArray)correlation.GetMethod("ProjectActions")!.Invoke(null,[observation,new JsonArray(),"unknown"])!;
            Assert.Equal("read",actions[0]!["operation"]!.GetValue<string>());
        }
    }
    [Theory]
    [InlineData("0x__١")]
    [InlineData("0b٢")]
    [InlineData("0x١_")]
    [InlineData("0x_١_")]
    public void PythonBaseZeroRejectsInvalidPrefixGrammar(string value)
    {
        var row=JsonNode.Parse("{\"channel\":\"Security\",\"provider_name\":\"Microsoft-Windows-Security-Auditing\",\"event_id\":4663}")!.AsObject();
        var facts=(JsonObject)Projection.GetMethod("NativeFacts")!.Invoke(null,[row,new JsonObject { ["AccessMask"]=value }])!;
        Assert.Null(facts["access_mask"]);
    }}
