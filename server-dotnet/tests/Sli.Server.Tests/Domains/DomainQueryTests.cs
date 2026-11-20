using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class DomainQueryTests
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("?", false)]
    [InlineData("?x", false)]
    [InlineData("?x=&x=", false)]
    [InlineData("?x=&x=1", true)]
    [InlineData("?x=+", true)]
    [InlineData("?x=%ZZ", true)]
    [InlineData("?x=1;y=2", true)]
    [InlineData("?=1", true)]
    public void RejectsOnlyQueriesWithNonBlankValues(string? query, bool expected)
    {
        Assert.Equal(expected, DomainQuery.HasParameters(query));
    }
}
