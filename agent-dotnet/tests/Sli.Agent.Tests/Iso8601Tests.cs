using Sli.Agent.Protocol;
using Xunit;

namespace Sli.Agent.Tests;

public class Iso8601Tests
{
    [Fact]
    public void FormatsLikePythonIsoformat()
    {
        Assert.Equal("2026-10-07T12:00:00+00:00", Iso8601.Format(new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero)));
        Assert.Equal("2026-10-07T12:00:00.123456+00:00", Iso8601.Format(new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero).AddTicks(1234567)));
        Assert.Equal("2026-10-07T12:00:00.000001+00:00", Iso8601.Format(new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero).AddTicks(10)));
        Assert.Equal("2026-10-07T09:00:00+00:00", Iso8601.Format(new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.FromHours(3))));
    }

    [Theory]
    [InlineData("2026-10-07T12:00:00+00:00", true)]
    [InlineData("2026-10-07T12:00:00Z", true)]
    [InlineData("2026-10-07T12:00:00.5Z", true)]
    [InlineData("2026-10-07 12:00:00+00:00", true)]
    [InlineData("2026-10-07T12:00:00+03:00", false)]
    [InlineData("2026-10-07T12:00:00", false)]
    [InlineData("2026-13-07T12:00:00Z", false)]
    [InlineData("2026-10-07T12:00:00Z\n", false)]
    [InlineData("invalid", false)]
    public void ParsesOnlyZeroOffsetInstants(string text, bool valid) => Assert.Equal(valid, Iso8601.TryParseUtc(text, out _));

    [Fact]
    public void TruncatesToMicroseconds() =>
        Assert.Equal(0, Iso8601.Truncate(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks(7)).Ticks % 10);
}
