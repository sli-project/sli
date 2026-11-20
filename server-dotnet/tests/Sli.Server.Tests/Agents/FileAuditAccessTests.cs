using System.Text.Json;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Access;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditAccessTests
{
    [Fact]
    public void ScopedDenyPrecedesGlobalAllowAndChecksAllDimensions()
    {
        var scope=JsonDocument.Parse("""{"mode":"restricted","clauses":[{"plugin_ids":["sli.file-audit"],"device_ids":["agent"],"source_instance_ids":["host"],"collection_scope_ids":["scope"]}]}""").RootElement.Clone();
        var decision=new CapabilityDecisionSet(false,new HashSet<string>{"file-audit.audit.manage"},new HashSet<string>(),[new CapabilityPolicy("file-audit.audit.manage","deny",true,false,scope)],new Dictionary<string,JsonElement>());
        Assert.False(FileAuditAccess.Allowed(decision,"admin","session",1,"agent","host","scope"));
        Assert.True(FileAuditAccess.Allowed(decision,"admin","session",1,"agent","host","other"));
        Assert.False(FileAuditAccess.Allowed(decision,"viewer","session",1,"agent","host","other"));
    }
}
