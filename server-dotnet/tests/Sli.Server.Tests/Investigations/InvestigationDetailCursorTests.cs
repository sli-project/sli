using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public class InvestigationDetailCursorTests
{
    [Theory]
    [InlineData("1",1L)] [InlineData("00019",19L)] [InlineData("9223372036854775807",long.MaxValue)]
    public void EventCursorAcceptsSourceValues(string input,long expected) => Assert.Equal(expected,InvestigationEvidenceCursor.Event(input));
    [Theory]
    [InlineData("")] [InlineData("0")] [InlineData("-1")] [InlineData(" 1")] [InlineData("١")] [InlineData("9223372036854775808")] [InlineData("00000000000000000001")]
    public void EventCursorRejectsInvalidSourceValues(string input)
    {
        var e=Assert.Throws<InvestigationException>(()=>InvestigationEvidenceCursor.Event(input)); Assert.Equal("invalid_cursor",e.Code); Assert.Equal("Invalid evidence cursor or anchor",e.Message);
    }
    [Fact]
    public void ReferenceCursorRoundTripsUnicodeReference()
    {
        var encoded=InvestigationEvidenceCursor.EncodeReference("vpn_accounting_session",17,"данные");
        Assert.Equal("WyJ2cG5fYWNjb3VudGluZ19zZXNzaW9uIiwxNywiXHUwNDM0XHUwNDMwXHUwNDNkXHUwNDNkXHUwNDRiXHUwNDM1Il0=", encoded);
        var decoded=InvestigationEvidenceCursor.Reference(encoded);
        Assert.Equal(("vpn_accounting_session",17L,"данные"),decoded);
    }
    [Theory]
    [InlineData("")] [InlineData("!!!!")] [InlineData("W10=")] [InlineData("WyJ2cG5fYWNjb3VudGluZ19zZXNzaW9uIiwxLjAsIngiXQ==")] [InlineData("WyJ2cG5fYWNjb3VudGluZ19zZXNzaW9uIix0cnVlLCJ4Il0=")]
    public void ReferenceCursorRejectsInvalidTokens(string input)
    {
        var e=Assert.Throws<InvestigationException>(()=>InvestigationEvidenceCursor.Reference(input));
        Assert.Equal("invalid_cursor",e.Code); Assert.Equal("Invalid reference cursor",e.Message);
    }
    [Theory]
    [InlineData("__5bACIAdgBwAG4AXwBhAGMAYwBvAHUAbgB0AGkAbgBnAF8AcwBlAHMAcwBpAG8AbgAiACwAMQAsACIAeAAiAF0A")]
    [InlineData("77u_WyJ2cG5fYWNjb3VudGluZ19zZXNzaW9uIiwxLCJ4Il0=")]
    public void ReferenceCursorAcceptsPythonJsonByteEncodings(string token)
        => Assert.Equal(("vpn_accounting_session",1L,"x"),InvestigationEvidenceCursor.Reference(token));
}
