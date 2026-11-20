using Sli.Agent.Service;
using Xunit;

namespace Sli.Agent.Tests;

public class BackoffTests
{
    [Fact]
    public void HealthyWaitsTheIntervalButNeverMoreThanAMinute()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), Backoff.Delay(30, 0));
        Assert.Equal(TimeSpan.FromSeconds(60), Backoff.Delay(3600, 0));
    }

    [Theory]
    [InlineData(1, 2.5)]
    [InlineData(3, 8.5)]
    [InlineData(5, 32.5)]
    [InlineData(6, 60)]
    [InlineData(10, 60)]
    public void FailuresBackOffExponentiallyUpToAMinute(int failures, double seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), Backoff.Delay(30, failures, () => 0.5));

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    public void MissingIdentityWaitsFifteenMinutesFromTheFirstFailure(int failures) =>
        Assert.Equal(TimeSpan.FromMinutes(15), Backoff.Delay(60, failures, () => 0, "agent_identity_missing_reenroll_required"));
}
