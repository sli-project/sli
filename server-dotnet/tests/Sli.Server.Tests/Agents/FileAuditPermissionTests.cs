using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;

namespace Sli.Server.Tests.Agents;
public class FileAuditPermissionTests
{
    [Fact]
    public void EvaluatesBroadGrantAndRejectsUnknownAce()
    {
        var config=JsonNode.Parse("""{"source_kind":"server","roots":[{"collection_scope_id":"scope:one","path":"C:\\data"}],"service_account_exclusions":[]}""")!.AsObject();
        var snapshot=JsonNode.Parse("""{"agent_id":"a","source_instance_id":"s","collection_scope_id":"scope:one","snapshot_id":"snapshot","snapshot_sha256":"hash","observed_at_utc":"2026-01-01T00:00:00+00:00","completeness":"complete","share":{"path":"C:\\data","dacl":"D:(A;;FR;;;WD)","complete":true},"local_groups":{"complete":true,"groups":[]},"objects":[{"path":"C:\\data\\file","dacl":"D:(A;;FW;;;WD)"}]}""")!.AsObject();
        var findings=FileAuditPermissionRules.Evaluate(snapshot,config,new JsonObject());
        Assert.Single(findings);
        Assert.Equal("file-audit.broad-write", findings[0]!["rule_code"]!.GetValue<string>());
        Assert.Equal("62b29d0fdef5b22426d73cfca1af8479e7c0ef59ecc3d4c0e6de65cf840e726b", findings[0]!["result_id"]!.GetValue<string>());
        Assert.Null(findings[0]!["details"]!["effective_smb_mask"]);
        snapshot["objects"]![0]!["dacl"]="D:(XA;;FA;;;WD;(condition))";
        findings=FileAuditPermissionRules.Evaluate(snapshot,config,new JsonObject());
        Assert.Single(findings);
        Assert.Equal("unsupported_descriptor",findings[0]!["details"]!["reason"]!.GetValue<string>());
    }
}

