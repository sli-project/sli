using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditReviewTests
{
    private static Type Type(string name)=>typeof(FileAuditResult).Assembly.GetType("Sli.Server.Agents.FileAudit."+name)!;
    private static bool Truth(JsonNode? value)=>(bool)Type("FileAuditAdEnrichment").GetMethod("PythonTruthy",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[value])!;
    [Theory]
    [InlineData("null",false)] [InlineData("false",false)] [InlineData("0",false)] [InlineData("0.0",false)] [InlineData("\"\"",false)] [InlineData("[]",false)] [InlineData("{}",false)]
    [InlineData("\"CN=Unresolved\"",true)] [InlineData("7",true)] [InlineData("-1.5",true)] [InlineData("[1]",true)] [InlineData("{\"x\":0}",true)]
    public void UnresolvedMarkersFollowPythonTruthiness(string json,bool expected)=>Assert.Equal(expected,Truth(JsonNode.Parse(json)));
    [Theory]
    [InlineData("00000000-0000-4000-8000-000000000001",true)] [InlineData("uuid:00000000-0000-4000-8000-000000000001",true)]
    [InlineData("urn:uuid:00000000-0000-4000-8000-000000000001",true)] [InlineData("(00000000-0000-4000-8000-000000000001)",false)]
    public void ScanIdMatchesPythonUuid(string input,bool expected)
    {
        var method=Type("FileAuditResult").GetMethod("Uuid",BindingFlags.NonPublic|BindingFlags.Static)!;Assert.Equal(expected,method.Invoke(null,[JsonValue.Create(input)]));
    }
    [Fact]
    public void DuplicateAdminMembersUseRecursiveLastValue()
    {
        using var doc=JsonDocument.Parse("""{"agents":[],"agents":[{"agent_id":"old","agent_id":"new"}]}""");
        var type=typeof(FileAuditResult).Assembly.GetType("Sli.Server.Compatibility.PythonJson")!;
        var result=(JsonObject)type.GetMethod("FromElement",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[doc.RootElement])!;
        Assert.Equal("new",result["agents"]![0]!["agent_id"]!.GetValue<string>());
    }
    [Fact]
    public void UnresolvedMembershipSuppressesEffectivePermission()
    {
        var config=JsonNode.Parse("""{"source_kind":"workstation","roots":[{"collection_scope_id":"s","path":"C:\\data"}],"service_account_exclusions":[]}""")!.AsObject();
        var snapshot=JsonNode.Parse("""{"agent_id":"a","source_instance_id":"h","collection_scope_id":"s","snapshot_id":"snap","snapshot_sha256":"hash","observed_at_utc":"2026-01-01T00:00:00+00:00","completeness":"complete","share":{"path":"C:\\data","dacl":"D:(A;;FR;;;WD)","complete":true},"local_groups":{"complete":true,"groups":[]},"objects":[{"path":"C:\\data\\file","dacl":"D:(A;;FW;;;S-1-5-21-1-2-3-1100)"}]}""")!.AsObject();
        var unresolved=JsonValue.Create("CN=Unresolved")!;
        var principal=new JsonObject { ["kind"]="user",["enabled"]=false,["group_sids"]=new JsonArray(),["complete"]=!Truth(unresolved) };
        var principals=new JsonObject { ["S-1-5-21-1-2-3-1100"]=principal };var results=FileAuditPermissionRules.Evaluate(snapshot,config,principals);
        Assert.Equal(2,results.Count);foreach(var item in results) { Assert.False(item!["details"]!["membership_complete"]!.GetValue<bool>());Assert.Null(item["details"]!["effective_smb_mask"]);Assert.Equal("requires_review",item["details"]!["effective_smb_state"]!.GetValue<string>()); }
    }
}
