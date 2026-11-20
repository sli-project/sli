using System.Text.Json;
using Sli.Server.Auth.ReportKeys;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ExactEventGenericTextTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidPythonWhitespaceRejectsEntireScopeBeforeMatchingOtherClause(bool metadata)
    {
        object scope = metadata
            ? new { mode = "restricted", decision_id = "\u001c", clauses = new object[] { new { collection_scope_ids = new[] { "ad-domain:7" } } } }
            : new { mode = "restricted", clauses = new object[] { new { collection_scope_ids = new[] { "ad-domain:7" } }, new { plugin_ids = new[] { "\u001cfoo" } } } };
        Assert.False(ExactEventScope.AllowsDomain(JsonSerializer.SerializeToElement(scope), 7));
    }

    [Theory]
    [InlineData(256, true)]
    [InlineData(257, false)]
    public void GenericTextLengthCountsUnicodeCodePoints(int count, bool allowed)
    {
        string text = string.Concat(Enumerable.Repeat("😀", count));
        var scope = JsonSerializer.SerializeToElement(new { mode = "restricted", decision_id = text,
            clauses = new object[] { new { collection_scope_ids = new[] { "ad-domain:7" } }, new { plugin_ids = new[] { text } } } });
        Assert.Equal(allowed, ExactEventScope.AllowsDomain(scope, 7));
    }
}
