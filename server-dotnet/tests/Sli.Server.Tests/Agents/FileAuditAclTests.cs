using Sli.Server.Agents.FileAudit;
using Xunit;

namespace Sli.Server.Tests.Agents;

public class FileAuditAclTests
{
    [Fact]
    public void UnsupportedDescriptorsNeverProduceGrants()
    {
        Assert.False(FileAuditAcl.Parse("D:(OA;;FA;;;WD)").Complete);
        Assert.False(FileAuditAcl.Parse("D:(A;;FA;;;WD)garbage").Complete);
        Assert.False(FileAuditAcl.Parse("D:(A;X;FA;;;WD)").Complete);
    }

    [Fact]
    public void PreservesAceOrderAndMapsGenericRights()
    {
        var acl = FileAuditAcl.Parse("D:(D;;0x2;;;WD)(A;;GW;;;WD)");
        Assert.True(acl.Complete);
        Assert.Equal(0x120114u, FileAuditAcl.AccessMask(acl.Aces, new HashSet<string> { "S-1-1-0" }));
        var reverse = FileAuditAcl.Parse("D:(A;;GW;;;WD)(D;;0x2;;;WD)");
        Assert.Equal(0x120116u, FileAuditAcl.AccessMask(reverse.Aces, new HashSet<string> { "S-1-1-0" }));
    }
}
