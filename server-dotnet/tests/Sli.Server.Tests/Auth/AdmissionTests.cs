using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Auth.Lifecycle.Security;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class AdmissionTests
{
    private sealed class Clock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Interlocked.Read(ref timestamp);
        public void Advance(double seconds) => Interlocked.Add(ref timestamp, (long)(seconds * 1000));
    }

    [Fact]
    public void ReservationCountsSuccessfulAndInflightRequestsUntilExactExpiry()
    {
        var clock = new Clock();
        var admission = new LoginSourceAdmission(clock: clock);
        for (int i = 0; i < 8; i++) Assert.True(admission.TryReserve("192.0.2.1").Allowed);
        Assert.Equal(new AdmissionResult(false, 900), admission.TryReserve("192.0.2.1"));
        Assert.True(admission.TryReserve("192.0.2.2").Allowed);
        clock.Advance(899.25);
        Assert.Equal(new AdmissionResult(false, 1), admission.TryReserve("192.0.2.1"));
        clock.Advance(.75);
        Assert.True(admission.TryReserve("192.0.2.1").Allowed);
    }

    [Fact]
    public void ConcurrentReservationsAreAtomic()
    {
        var admission = new LoginSourceAdmission();
        int accepted = 0;
        Parallel.For(0, 100, _ => { if (admission.TryReserve("192.0.2.1").Allowed) Interlocked.Increment(ref accepted); });
        Assert.Equal(8, accepted);
    }

    [Theory]
    [InlineData(-1, -1, 60, 3)]
    [InlineData(9999, 999, 3600, 30)]
    public void ConfiguredBoundsMatchLegacy(int window, int limit, int expectedWindow, int expectedLimit)
    {
        var admission = new LoginSourceAdmission(window, limit, new Clock());
        for (int i = 0; i < expectedLimit; i++) Assert.True(admission.TryReserve("192.0.2.1").Allowed);
        Assert.Equal(new AdmissionResult(false, expectedWindow), admission.TryReserve("192.0.2.1"));
    }

    [Fact]
    public void DiUsesConfigurationRatherThanOptionalConstructorDefaults()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["ADLOG_LOGIN_FAILURE_WINDOW_SECONDS"] = "61", ["ADLOG_MAX_LOGIN_FAILURES"] = "4" }).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<TimeProvider>(new Clock());
        services.AddAuthLoginSecurity();
        using var provider = services.BuildServiceProvider();
        var admission = provider.GetRequiredService<ISourceAdmission>();
        for (int i = 0; i < 4; i++) Assert.True(admission.TryReserve("192.0.2.1").Allowed);
        Assert.Equal(new AdmissionResult(false, 61), admission.TryReserve("192.0.2.1"));
    }

    [Fact]
    public void UnboundedPythonConfigurationIntegersClampBeforeNarrowing()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["ADLOG_LOGIN_FAILURE_WINDOW_SECONDS"] = "9999999999999999999999999", ["ADLOG_MAX_LOGIN_FAILURES"] = "-9999999999999999999999999" }).Build();
        var admission = new LoginSourceAdmission(configuration, new Clock());
        for (int i = 0; i < 3; i++) Assert.True(admission.TryReserve("192.0.2.1").Allowed);
        Assert.Equal(new AdmissionResult(false, 3600), admission.TryReserve("192.0.2.1"));
    }

    [Theory]
    [InlineData(" User.Name ", "c69f268fb43e3b0bd46436177505f548fe105ce296445b5ba5a428f122453429", -4504029320873082679L)]
    [InlineData("\u0130", "fbbdb347060082cf4e72cdc5f02679dd809ebf4e6c601933e858d954a65f5e73", 1191712787806536L)]
    [InlineData("ΟΣ", "37966cce5c2e6c422338daa570937199a5b4644a9aca13f96938a1ef586d9d76", -3188628436080747784L)]
    [InlineData("ΟΣΑ", "aab41f24fca3e3cf500fae3b169ce62709b291f5c0e98c7d0b683fe07fffef5e", 5323874015025107678L)]
    [InlineData("\u001c Alice \u001f", "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90", -6451028459801963439L)]
    [InlineData("\U00010400", "a23c9d4f706b43cc0e93920f92c7fdab975f931599686cfd20667f7464a5e08a", 1418640195222671011L)]
    public void AccountAndAdvisoryKeysMatchPython(string name, string hash, long advisory)
    {
        Assert.Equal(hash, AccountThrottle.AccountKey(name));
        Assert.Equal(advisory, AccountThrottle.AdvisoryKey(hash));
    }

    [Theory]
    [InlineData("\u00aaΣ", "18ddf52af17fc7b8d942db3b723a7b9c9a4f3375076847db7e0dad3e87b6c0cd")]
    [InlineData("Α\u2027Σ", "5eb1b236eab45fe93c34a984689ecc4ac241fa49fa7198c976d0c216757c2666")]
    public void FullLowercaseContextHandlesOtherCasedAndCaseIgnorable(string name, string expected)
        => Assert.Equal(expected, AccountThrottle.AccountKey(name));
}
