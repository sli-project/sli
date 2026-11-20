using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentClientDuplicateJsonTests
{
    private static JsonObject Agent()=>JsonNode.Parse("""
        {"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","policy_revision":4,"applied_policy_revision":2,
        "applied_collection_state":"active","collection_policy":{"state":"drain"},"rights_probe":{"pending":{"request_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}}}
        """)!.AsObject();
    private static JsonNode? Body(string text) {using var document=JsonDocument.Parse(text,new JsonDocumentOptions { MaxDepth=1000 });return AgentClientJson.FromElement(document.RootElement);}
    [Fact]
    public void TopLevelDuplicateReportUsesLastMemberAndKeepsJsonTypes()
    {
        var body=Body("""{"applied_policy_revision":5,"applied_policy_revision":4,"collection_state":"paused","runtime_handoff_supported":false,"runtime_handoff_supported":true}""");
        var result=AgentClientPolicy.Report(Agent(),body,new DateTimeOffset(2026,11,3,1,2,3,TimeSpan.Zero));
        Assert.Equal(4,result.AppliedRevision);Assert.Equal("paused",result.AppliedState);Assert.True(result.Acknowledged);
        Assert.True(result.Probe["runtime_handoff_supported"]!.GetValue<bool>());
        var lastWrong=Body("""{"applied_policy_revision":4,"applied_policy_revision":4.0,"collection_state":"paused"}""");
        Assert.Equal("invalid_agent_policy_revision",Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(Agent(),lastWrong,DateTimeOffset.UtcNow)).Message);
    }
    [Fact]
    public void NestedProbeAndDiagnosticArrayObjectsUseLastMemberRecursively()
    {
        var body=Body("""
            {"applied_policy_revision":4,"collection_state":"paused","rights_probe":{"request_id":"wrong","request_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","status":"denied","status":"allowed"},
            "eventlog_diagnostics":[{"channel":"Wrong","channel":"Security","policy_revision":99,"policy_revision":4,"observed_at_utc":"2026-11-03T00:00:00Z",
            "error":{"exception_class":"OSError","winerror":"bad","winerror":5,"hresult":null,"channel":"Security","record_id":null,"bookmark_present":false,"stage":"read"}}]}
            """);
        var result=AgentClientPolicy.Report(Agent(),body,DateTimeOffset.UtcNow);
        Assert.Equal("allowed",result.ProbeResult!["status"]!.GetValue<string>());Assert.False(result.Probe.ContainsKey("pending"));
        Assert.Equal(5,result.Probe["eventlog_diagnostics"]!["items"]![0]!["error"]!["winerror"]!.GetValue<int>());
        var independent=Body("""
            {"delivery_diagnostics":[{"module_id":"Wrong","module_id":"sli.workstations","packet_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","sequence":"1",
            "error_code":"agent_sequence_gap","receipt_status":"retry_later","http_status":true,"http_status":200,"observed_at_utc":"2026-11-03T00:00:00Z","resolved_at_utc":null}]}
            """);
        Assert.Null(AgentClientPolicy.Report(Agent(),independent,DateTimeOffset.UtcNow).AppliedRevision);
    }
    [Fact]
    public void MaterializationPreservesRootTypeDepthAndEscapedMemberNameSemantics()
    {
        Assert.Null(Body("null"));Assert.IsType<JsonArray>(Body("[]"));
        Assert.Equal("invalid_agent_policy_report",Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(Agent(),Body("[]"),DateTimeOffset.UtcNow)).Message);
        var escaped=Body("""{"applied_policy_revision":5,"\u0061pplied_policy_revision":4,"collection_state":"paused"}""");
        Assert.Equal(4,AgentClientPolicy.Report(Agent(),escaped,DateTimeOffset.UtcNow).AppliedRevision);
        Assert.ThrowsAny<JsonException>(()=>Body(new string('[',1001)+"0"+new string(']',1001)));
    }
}
