using System.Text.Json.Nodes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentClientDiagnosticsTests
{
    [Fact]
    public void SourceBoundedDiagnosticsAcceptOnlyAllowlistedStructuredEvidence()
    {
        var eventlog=JsonNode.Parse("""
            [{"channel":"Security","observed_at_utc":"2026-W45-2T01:02:03+01:00:30","policy_revision":4,
            "error":{"exception_class":"OSError","winerror":5,"hresult":-2147024891,"channel":"Security","record_id":null,"bookmark_present":false,"stage":"read"}}]
            """)!.AsArray();
        AgentClientDiagnostics.ValidateEventLog(eventlog,4);
        foreach(var bad in new[]{"{\"extra\":\"secret\"}","false","1"}) {
            var copy=(JsonArray)eventlog.DeepClone();copy[0]!["error"]=JsonNode.Parse(bad);
            Assert.Equal("invalid_agent_eventlog_diagnostics",Assert.Throws<AgentControlException>(()=>AgentClientDiagnostics.ValidateEventLog(copy,4)).Message);
        }
        var boolCount=(JsonArray)eventlog.DeepClone();boolCount[0]!["error"]!["record_id"]=true;
        Assert.Throws<AgentControlException>(()=>AgentClientDiagnostics.ValidateEventLog(boolCount,4));
        Assert.Throws<AgentControlException>(()=>AgentClientDiagnostics.ValidateEventLog(new JsonArray(eventlog[0]!.DeepClone(),eventlog[0]!.DeepClone()),4));
        var delivery=JsonNode.Parse("""
            [{"module_id":"sli.workstations","packet_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","sequence":"9223372036854775807",
            "error_code":"agent_sequence_gap","receipt_status":"retry_later","http_status":200,"observed_at_utc":"2026-W45-2T01:02:03+00:00:00","resolved_at_utc":null}]
            """)!.AsArray();
        AgentClientDiagnostics.ValidateDelivery(delivery);
        foreach(var field in new[]{"error_code","receipt_status","sequence","packet_id"}) {
            var copy=(JsonArray)delivery.DeepClone();copy[0]![field]="synthetic-invalid";
            Assert.Throws<AgentControlException>(()=>AgentClientDiagnostics.ValidateDelivery(copy));
        }
        delivery[0]!["resolved_at_utc"]="2026-11-03T01:02:02Z";Assert.Throws<AgentControlException>(()=>AgentClientDiagnostics.ValidateDelivery(delivery));
    }
}
