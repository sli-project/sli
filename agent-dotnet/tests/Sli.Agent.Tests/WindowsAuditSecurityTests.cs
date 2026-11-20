using System.Runtime.Versioning;
using System.Security.AccessControl;
using Sli.Agent.Windows;
using Xunit;

namespace Sli.Agent.Tests;

[SupportedOSPlatform("windows")]
public sealed class WindowsAuditSecurityTests
{
    [Theory]
    [InlineData("S:(AU;CISA;WP;;;WD)", true)]
    [InlineData("S:(AU;CISAFA;WP;;;AU)", true)]
    [InlineData("S:(AU;SA;WP;;;WD)", false)]
    [InlineData("S:(AU;CIFA;WP;;;WD)", false)]
    [InlineData("S:(AU;CINPSA;WP;;;WD)", false)]
    [InlineData("S:(AU;CISA;RP;;;WD)", false)]
    [InlineData("S:(OU;CISA;WP;00000000-0000-0000-0000-000000000001;;WD)", false)]
    [InlineData("", false)]
    public void ReadsOnlySuccessfulWritePropertyAuditInheritedByAllDescendants(string sddl, bool expected)
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(expected, WindowsAuditApi.HasDomainRootAudit(sddl));
    }

    [Fact]
    public void AddsOneEntryPreservingExistingAuditAndDoesNotDuplicateIt()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string previous = "S:(AU;SAFA;RP;;;AU)";
        var api = new WindowsAuditApi();
        var applied = api.WithDomainRootAudit(previous);
        var acl = new RawSecurityDescriptor(applied).SystemAcl!;
        Assert.Equal(2, acl.Count);
        Assert.True(new RawSecurityDescriptor(previous).SystemAcl![0].Equals(acl[0]));
        Assert.True(WindowsAuditApi.HasDomainRootAudit(applied));
        Assert.Equal(applied, api.WithDomainRootAudit(applied));
        Assert.True(WindowsAuditApi.HasDomainRootAudit(api.WithDomainRootAudit("")));
    }
}
