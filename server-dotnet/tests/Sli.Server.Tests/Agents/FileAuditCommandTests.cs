using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditCommandTests
{
    [Fact]
    public void CommandRequiresExactRevisionAndSelectedKnownScopes()
    {
        var cfg=JsonNode.Parse("""{"policy_revision":"2","roots":[{"collection_scope_id":"scope"}]}""")!.AsObject();
        var command=JsonNode.Parse("""{"contract_id":"sli.file-audit.audit-command.v1","command_id":"abc-1","action":"check","policy_revision":"2","collection_scope_ids":["scope"]}""")!.AsObject();
        Assert.True(FileAuditCommand.Valid(command,cfg));
        command["collection_scope_ids"]!.AsArray().Add("other"); Assert.False(FileAuditCommand.Valid(command,cfg));
        command["collection_scope_ids"]!.AsArray().RemoveAt(1); command["policy_revision"]="1"; Assert.False(FileAuditCommand.Valid(command,cfg));
    }
}
