using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditResultTests
{
    [Fact]
    public void FailedScopeAllowsNoInventedMasksAndRejectsStaleCommand()
    {
        var config=JsonNode.Parse("""{"policy_revision":"2","source_kind":"workstation","roots":[{"collection_scope_id":"scope","path":"C:\\data","share_name":"","important":false,"sacl":{"trustee_sids":["S-1-1-0"],"inherit_files":true,"inherit_directories":true}}]}""")!.AsObject();
        var command=JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-command.v1","command_id":"cmd","action":"check","policy_revision":"2","collection_scope_ids":["scope"]}""")!.AsObject();
        var report=JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-result.v1","command_id":"cmd","policy_revision":"2","action":"check","observed_at_utc":"2026-01-01T00:00:00+00:00","scopes":[{"collection_scope_id":"scope","state":"failed","reason_code":"unknown","required_masks":{},"actual_masks":{}}],"snapshots":[],"ownership_remaining":false}""")!.AsObject();
        Assert.True(FileAuditResult.Valid(report,config,command));
        report["scopes"]![0]!["required_masks"]!["x"]=1; Assert.False(FileAuditResult.Valid(report,config,command));
        report["scopes"]![0]!["required_masks"]!.AsObject().Clear(); report["command_id"]="old"; Assert.False(FileAuditResult.Valid(report,config,command));
    }
    [Fact]
    public void DiagnosticAcceptsOnlyFixedFieldsAndCodesForFailedSingleServerCheck()
    {
        var config = JsonNode.Parse("""{"policy_revision":"2","source_kind":"server","roots":[{"collection_scope_id":"scope","path":"C:\\data","share_name":"synthetic","important":false,"sacl":{"trustee_sids":["S-1-1-0"],"inherit_files":true,"inherit_directories":true}}]}""")!.AsObject();
        var command = JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-command.v1","command_id":"cmd","action":"check","policy_revision":"2","collection_scope_ids":["scope"]}""")!.AsObject();
        var report = JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-result.v1","command_id":"cmd","policy_revision":"2","action":"check","observed_at_utc":"2026-01-01T00:00:00+00:00","scopes":[{"collection_scope_id":"scope","state":"failed","reason_code":"native_unavailable","required_masks":{},"actual_masks":{}}],"snapshots":[],"ownership_remaining":false}""")!.AsObject();
        Assert.True(FileAuditResult.Valid(report, config, command));
        var detail = new JsonObject { ["stage"] = "acl", ["code_kind"] = "win32", ["code"] = 5 };
        report["scopes"]![0]!["read_error"] = detail;
        Assert.True(FileAuditResult.Valid(report, config, command));
        detail["message"] = "private input";
        Assert.False(FileAuditResult.Valid(report, config, command));
        detail.Remove("message");
        detail["code"] = -5;
        Assert.False(FileAuditResult.Valid(report, config, command));
        detail["code"] = 5;
        command["action"] = "apply";
        report["action"] = "apply";
        Assert.False(FileAuditResult.Valid(report, config, command));
    }

    [Fact]
    public void SourceVerifiedInventoryHashAndMasksAreAccepted()
    {
        var value=JsonNode.Parse("""{"config":{"policy_revision":"2","source_kind":"workstation","roots":[{"collection_scope_id":"scope","path":"C:\\data","share_name":"","important":false,"sacl":{"trustee_sids":["S-1-1-0"],"inherit_files":true,"inherit_directories":true}}]},"command":{"contract_id":"sli.file-audit.audit-command.v1","command_id":"cmd","action":"check","policy_revision":"2","collection_scope_ids":["scope"]},"report":{"contract_id":"sli.file-audit.audit-result.v1","command_id":"cmd","policy_revision":"2","action":"check","observed_at_utc":"2026-01-01T00:00:00+00:00","scopes":[{"collection_scope_id":"scope","state":"verified","reason_code":"ok","required_masks":{"0cce921d-69ae-11d9-bed3-505054503030":3,"0cce922f-69ae-11d9-bed3-505054503030":1,"0cce9215-69ae-11d9-bed3-505054503030":3},"actual_masks":{"0cce921d-69ae-11d9-bed3-505054503030":3,"0cce922f-69ae-11d9-bed3-505054503030":1,"0cce9215-69ae-11d9-bed3-505054503030":3}}],"snapshots":[{"contract_id":"sli.file-audit.inventory.v1","collection_scope_id":"scope","policy_revision":"2","observed_at_utc":"2026-01-01T00:00:00+00:00","scan_id":"00000000-0000-4000-8000-000000000001","page_number":0,"has_more":false,"completeness":"complete","unread_objects":0,"share":{"name":"","path":"C:\\data","dacl":"","complete":true},"local_groups":{"complete":true,"groups":[]},"objects":[],"snapshot_sha256":"7e724f2946b376e6f925cf779b8ceeee27981fdfa8f97cb6e104fb2a9d6e4afb","snapshot_id":"58a82162-91d8-5e33-be3c-5db0cb55c221"}],"ownership_remaining":false}}""")!.AsObject();
        Assert.True(FileAuditResult.Valid(value["report"]!.AsObject(),value["config"]!.AsObject(),value["command"]!.AsObject()));
        value["report"]!["snapshots"]![0]!["snapshot_sha256"]="bad";
        Assert.False(FileAuditResult.Valid(value["report"]!.AsObject(),value["config"]!.AsObject(),value["command"]!.AsObject()));
    }
}

