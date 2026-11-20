using Sli.Server.Hosting;
using Xunit;
namespace Sli.Server.Tests.Domains;
public sealed class DynamicAdmissionTests
{
    [Fact] public void ExactWindowRejectsUntilOldestTimestampExpires()
    {
        double now = 0;
        var gate = new DynamicRequestAdmission(2, () => now);
        Assert.True(gate.Admit("client", "api"));
        now = 0.75; Assert.True(gate.Admit("client", "api"));
        now = 59.999; Assert.False(gate.Admit("client", "api"));
        now = 60; Assert.True(gate.Admit("client", "api"));
        Assert.False(gate.Admit("client", "api"));
        now = 60.75; Assert.True(gate.Admit("client", "api"));
    }
    [Fact] public void CapacityRejectsNewKeysAndExpiresAtMost64PerCall()
    {
        double now = 0;
        var gate = new DynamicRequestAdmission(2, () => now);
        for (int i = 0; i < 16384; i++) Assert.True(gate.Admit(i.ToString(), "api"));
        Assert.False(gate.Admit("overflow", "api"));
        Assert.True(gate.Admit("0", "api"));
        now = 60; Assert.True(gate.Admit("new", "api"));
        Assert.Equal(16321, gate.BucketCount);
        Assert.True(gate.Admit("new2", "api"));
        Assert.Equal(16258, gate.BucketCount);
    }
}
