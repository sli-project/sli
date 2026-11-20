using Sli.Server.Agents.Registry;
using Xunit;

namespace Sli.Server.Tests.Agents;

public class UnicodeCaseFoldTests
{
    [Fact]
    public void Trims_python_control_whitespace_without_normalizing() => Assert.Equal("ou=strasse", UnicodeCaseFold.TrimAndFold("\u001cou=Stra\u00dfe\u001f"));

    [Theory]
    [InlineData("Stra\u00dfe", "strasse")]
    [InlineData("STRASSE", "strasse")]
    [InlineData("I", "i")]
    [InlineData("\u0130", "i\u0307")]
    [InlineData("\u0131", "\u0131")]
    [InlineData("\ufb03", "ffi")]
    [InlineData("e\u0301", "e\u0301")]
    [InlineData("\u00c9", "\u00e9")]
    public void Matches_frozen_python_full_casefold_without_normalization(string value, string expected)
        => Assert.Equal(expected, UnicodeCaseFold.Fold(value));
}
