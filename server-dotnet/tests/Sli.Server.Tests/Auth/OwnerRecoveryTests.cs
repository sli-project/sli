using System.Diagnostics;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Recovery;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class OwnerRecoveryTests
{
    [Fact]
    public async Task Redirected_console_denies_issuance_before_loading_host_configuration()
    {
        var ct = TestContext.Current.CancellationToken;
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet")
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        foreach (string name in start.Environment.Keys.Where(name =>
            name.StartsWith("SLI", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("ADLOG", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Kestrel", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("ASPNETCORE", StringComparison.OrdinalIgnoreCase)).ToArray())
            start.Environment.Remove(name);
        // These deliberately invalid settings must never be read on the denial path.
        start.Environment["ConnectionStrings__Sli"] = "synthetic-private-invalid-value";
        start.Environment["ADLOG_TLS_CERT_FILE"] = "synthetic-private-invalid-value";
        start.Environment["Sli__HttpMaxConnections"] = "synthetic-private-invalid-value";
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add("owner-recovery");
        start.ArgumentList.Add("--username");
        start.ArgumentList.Add("owned-user");
        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(ct);
        Task<string> stderr = process.StandardError.ReadToEndAsync(ct);
        try { await process.WaitForExitAsync(ct); }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
        }
        Assert.Equal(1, process.ExitCode);
        Assert.Empty(await stdout);
        Assert.Contains((await stderr).Trim(), new[] { "host_root_required", "terminal_required" });
    }

    [Theory]
    [InlineData("--username", "owned-user")]
    [InlineData("--username=owned-user", null)]
    public void ConsoleAcceptsSourceUsernameArgumentForms(string option, string? value)
    {
        string[] args = value is null ? ["owner-recovery", option] : ["owner-recovery", option, value];
        var parsed = OwnerRecoveryConsole.ParseArguments(args);
        Assert.True(parsed.Valid); Assert.False(parsed.Help); Assert.Equal("owned-user", parsed.Username);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public void ConsoleHelpDoesNotRequireUsernameOrPrivilegedIssuance(string option)
    {
        var parsed = OwnerRecoveryConsole.ParseArguments(["owner-recovery", option]);
        Assert.True(parsed.Valid); Assert.True(parsed.Help); Assert.Null(parsed.Username);
    }

    private sealed class Clock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Interlocked.Read(ref timestamp);
        public void Advance(double seconds) => Interlocked.Add(ref timestamp, (long)(seconds * 1000));
    }

    [Fact]
    public async Task FiveFailuresBlockFor900SecondsWithoutResetOnSuccess()
    {
        var clock = new Clock();
        var budget = new OwnerRecoveryAdmission(clock);
        for (int i = 0; i < 4; i++) Assert.Null(await budget.VerifyAsync("192.0.2.10", () => Task.FromResult<Principal?>(null)));
        Assert.NotNull(await budget.VerifyAsync("192.0.2.10", () => Task.FromResult<Principal?>(new("session", 1, "admin"))));
        Assert.Null(await budget.VerifyAsync("192.0.2.10", () => Task.FromResult<Principal?>(null)));
        Assert.Equal(900, (await Assert.ThrowsAsync<LoginThrottledException>(() => budget.VerifyAsync<Principal>("192.0.2.10", () => throw new Exception()))).RetryAfterSeconds);
        clock.Advance(899.25);
        Assert.Equal(1, (await Assert.ThrowsAsync<LoginThrottledException>(() => budget.VerifyAsync<Principal>("192.0.2.10", () => throw new Exception()))).RetryAfterSeconds);
        clock.Advance(.75);
        Assert.Null(await budget.VerifyAsync("192.0.2.10", () => Task.FromResult<Principal?>(null)));
    }

    [Fact]
    public async Task PendingAndCompletedFailuresShareFiveSlotsAndExceptionsReleaseWithoutFailure()
    {
        var budget = new OwnerRecoveryAdmission(TimeProvider.System);
        var gate = new TaskCompletionSource<Principal?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<Principal?>[] pending = Enumerable.Range(0, 5).Select(_ => budget.VerifyAsync("192.0.2.11", () => gate.Task)).ToArray();
        Assert.Equal(1, (await Assert.ThrowsAsync<LoginThrottledException>(() => budget.VerifyAsync<Principal>("192.0.2.11", () => throw new Exception()))).RetryAfterSeconds);
        gate.SetException(new InvalidOperationException("synthetic_error"));
        foreach (var task in pending) await Assert.ThrowsAsync<InvalidOperationException>(() => task);
        Assert.Null(await budget.VerifyAsync("192.0.2.11", () => Task.FromResult<Principal?>(null)));
    }

    [Fact]
    public async Task AddressCardinalityBoundDoesNotEvictInflightAndReleasesCompletedSuccesses()
    {
        var budget = new OwnerRecoveryAdmission(TimeProvider.System);
        var gate = new TaskCompletionSource<Principal?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<Principal?>[] pending = Enumerable.Range(0, 4096).Select(i => budget.VerifyAsync("owned-address-" + i, () => gate.Task)).ToArray();
        Assert.Equal(900, (await Assert.ThrowsAsync<LoginThrottledException>(() => budget.VerifyAsync<Principal>("overflow", () => throw new Exception()))).RetryAfterSeconds);
        gate.SetResult(new("session", 1, "admin"));
        await Task.WhenAll(pending);
        Assert.NotNull(await budget.VerifyAsync("overflow", () => Task.FromResult<Principal?>(new("session", 1, "admin"))));
    }

    [Fact]
    public void HostRootChecksFailClosedOnWindows()
    {
        if (OperatingSystem.IsLinux()) return; // Actual Linux root/TTY requires a separate terminal runtime gate.
        var exception = Assert.Throws<UnauthorizedAccessException>(() => new OwnerRecoveryTerminal().RequireRootInteractiveTerminal());
        Assert.Equal("host_root_required", exception.Message);
    }
}
