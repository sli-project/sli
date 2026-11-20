using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class InvestigationListTests
{
    [Theory]
    [InlineData(null,50)] [InlineData("bad",50)] [InlineData("-2",1)] [InlineData("1000",100)] [InlineData(" +12 ",12)]
    public void LimitUsesSourceDefaultsAndBounds(string? value,int expected) => Assert.Equal(expected, InvestigationList.Limit(value));

    [Theory]
    [InlineData("2026-01-01 03:00:00.000000", 10800, "2026-01-01 03:00:00+03:00")]
    [InlineData("2026-01-01 03:00:00.123400", 10800, "2026-01-01 03:00:00.123400+03:00")]
    [InlineData("2026-01-01 00:00:00.000000", 0, "2026-01-01 00:00:00+00:00")]
    [InlineData("2026-01-01 01:02:03.000001", -12600, "2026-01-01 01:02:03.000001-03:30")]
    public void TimestampMatchesPythonDatetimeJson(string local,int offsetSeconds,string expected)
        => Assert.Equal(expected,InvestigationList.FormatSessionTimestamp(local,offsetSeconds));

    [Fact]
    public void FilteringOccursAfterLimitAndPreservesOnlyFullyAuthorizedCases()
    {
        var policy = JsonDocument.Parse("{\"kind\":\"domain\",\"ids\":[1]}").RootElement.Clone();
        var caps = new CapabilityComposer().Compose(new AccessFacts(false,"viewer",[],[],
            [JsonDocument.Parse("{\"capability_key\":\"investigations.view\",\"effect\":\"allow\",\"scope_json\":{\"kind\":\"domain\",\"ids\":[1]}}").RootElement.Clone()],[],[],[],[]));
        var grant = new AtomicReportGrant(policy, new HashSet<string>(), new HashSet<string>{"view"},1,1);
        var access = new AccessDecision("viewer",caps,[new("investigations.workspace",true,[grant])]);
        Assert.True(InvestigationList.Allowed(access,"investigations.workspace",[[new("domain",1)]]));
        Assert.False(InvestigationList.Allowed(access,"investigations.workspace",[[new("domain",1)],[new("domain",2)]]));
        Assert.False(InvestigationList.Allowed(access,"investigations.workspace",[[]]));
    }
}
