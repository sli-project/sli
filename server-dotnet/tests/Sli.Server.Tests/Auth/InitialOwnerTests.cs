using Microsoft.Extensions.Configuration;
using Sli.Server.Auth.InitialOwner;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class InitialOwnerTests
{
    [Fact]
    public void CombinedConsoleFlagsSelectReadOnlyCheckWithoutIssuance()
    {
        var command = InitialOwnerCodeConsole.NormalizeMode(new(NewCode: true, CheckOnly: true));
        Assert.True(command.CheckOnly);
        Assert.False(command.NewCode);
    }
    [Theory]
    [InlineData(null, "not-a-password", false)]
    [InlineData("short", "not-a-password", false)]
    [InlineData("abcdefghijkl", "abcdefghijkl", false)]
    [InlineData("abcdef\0ghijkl", "not-a-password", false)]
    [InlineData("🔐🔐🔐🔐🔐🔐", "not-a-password", false)]
    [InlineData("🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐", "not-a-password", true)]
    [InlineData("abcdefghijkl", "different-code", true)]
    public void NewPasswordPolicyUsesPythonCodePointsAndRequiresDistinctPassword(string? password, string code, bool expected) =>
        Assert.Equal(expected, InitialOwnerSetup.ValidNewPassword(password, code));

    [Fact]
    public void PasswordUpperBoundAndDbClockBoundaryMatchSource()
    {
        Assert.True(InitialOwnerSetup.ValidNewPassword(new string('a', 4096), "different-code"));
        Assert.False(InitialOwnerSetup.ValidNewPassword(new string('a', 4097), "different-code"));
        var now = new DateTime(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc);
        Assert.False(InitialOwnerSetup.CodeCurrent(now.AddHours(-24), now));
        Assert.True(InitialOwnerSetup.CodeCurrent(now.AddHours(-24).AddTicks(10), now));
        Assert.True(InitialOwnerSetup.CodeCurrent(now, now));
        Assert.False(InitialOwnerSetup.CodeCurrent(now.AddTicks(10), now));
    }

    [Fact]
    public void ProtectedOperatorPathsAreExplicitAndWindowsFailsClosed()
    {
        Assert.Throws<InvalidOperationException>(() => new ProtectedOwnerCodeStore(new ConfigurationBuilder().Build()));
        if (OperatingSystem.IsLinux()) return;
        var settings = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:InitialOwnerOperator:CodeFile"] = Path.Combine(Path.GetTempPath(), "owned-test-code"),
            ["Sli:InitialOwnerOperator:ReceiptFile"] = Path.Combine(Path.GetTempPath(), "owned-test-receipt")
        }).Build();
        var error = Assert.Throws<UnauthorizedAccessException>(() => new ProtectedOwnerCodeStore(settings).ReadCode());
        Assert.Equal("host_root_required", error.Message);
    }
}
