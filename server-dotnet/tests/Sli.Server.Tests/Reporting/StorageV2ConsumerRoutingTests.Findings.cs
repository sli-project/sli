using System.Text.Json.Nodes;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class StorageV2ConsumerRoutingTests
{
    sealed class DisabledFindingsDatabase : ISemanticDatabase
    {
        public int Opens;
        public Task<ISemanticSession> OpenAsync(bool write,CancellationToken ct)
        {
            Opens++; throw new InvalidOperationException("private-source-diagnostic");
        }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Disabled_findings_never_seed_or_advance_a_watermark(bool bootstrap)
    {
        var db=new DisabledFindingsDatabase(); var reader=new LegacyFindings(db);
        var result=await reader.EnsureAsync(bootstrap,Ct);
        Assert.Equal("disabled",result["status"]!.ToString()); Assert.Equal("module_disabled",result["reason"]!.ToString());
        Assert.Equal(0,db.Opens);
    }
    [Fact]
    public async Task Disabled_findings_status_does_not_open_storage_or_expose_diagnostics()
    {
        var db=new DisabledFindingsDatabase(); var result=await new LegacyFindings(db).StatusAsync(Ct);
        Assert.Equal("disabled",result["status"]!.ToString()); Assert.Equal("module_disabled",result["reason"]!.ToString());
        Assert.DoesNotContain("private-source-diagnostic",result.ToJsonString()); Assert.Equal(0,db.Opens);
    }
}
