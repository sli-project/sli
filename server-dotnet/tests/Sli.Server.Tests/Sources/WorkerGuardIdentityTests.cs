using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed class WorkerGuardIdentityTests
{
    private const string Principal = @"EXAMPLE\operator";
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1000";
    private const string OtherSid = "S-1-5-21-100000001-200000002-300000003-1999";
    private static Dictionary<string, string?> Installation(string principal = Principal, string sid = Sid) => new()
    {
        ["ADLOG_COLLECTION_PRINCIPAL"] = principal, ["ADLOG_COLLECTION_PRINCIPAL_SID"] = sid
    };
    private static WindowsCollectionIdentity Current(string principal = Principal, string sid = Sid,
        bool elevated = true, int session = 1) => new(principal, sid, session, session != 0, elevated);
    private static string[] Reasons(JsonObject result) => result["reasons"]!.AsArray().Select(x => x!.GetValue<string>()).ToArray();
    private static void AssertAccepted(JsonObject result)
    {
        Assert.Equal("ok", result["status"]!.GetValue<string>());
        Assert.Null(result["reason"]);
        Assert.Empty(Reasons(result));
    }
    private static void AssertRejected(JsonObject result, params string[] reasons)
    {
        Assert.Equal("failed", result["status"]!.GetValue<string>());
        Assert.Equal("windows_collection_identity_invalid", result["reason"]!.GetValue<string>());
        Assert.Equal(reasons, Reasons(result));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExactPrincipalSidAndInteractiveSessionAreAcceptedWithoutAdminRequirement(bool elevated)
    {
        var result = WindowsRuntimeIdentity.Verify(Installation().GetValueOrDefault, () => Current(elevated: elevated));
        AssertAccepted(result);
        Assert.Equal(Principal, result["current_principal"]!.GetValue<string>());
        Assert.Equal(Sid, result["current_sid"]!.GetValue<string>());
        Assert.Equal(1, result["session_id"]!.GetValue<int>());
        Assert.True(result["interactive"]!.GetValue<bool>());
        Assert.Equal(elevated, result["elevated"]!.GetValue<bool>());
    }

    [Fact]
    public void SameNameWithDifferentSidIsRejected()
    {
        AssertRejected(WindowsRuntimeIdentity.Verify(Installation().GetValueOrDefault,
            () => Current(sid: OtherSid)), "sid_mismatch");
    }

    [Fact]
    public void ConfiguredIdentityRejectsBothDifferentPrincipalAndSid()
    {
        AssertRejected(WindowsRuntimeIdentity.Verify(Installation(@"OTHER\operator").GetValueOrDefault,
            () => Current(@"OTHER\different", OtherSid)), "principal_mismatch", "sid_mismatch");
    }

    [Fact]
    public void ConfiguredPrototypePrincipalAndSidAreAccepted()
    {
        const string prototype = @"EXAMPLE\\prototype-owner";
        var result = WindowsRuntimeIdentity.Verify(Installation(prototype, OtherSid).GetValueOrDefault,
            () => Current(prototype, OtherSid, elevated: false, session: 2));
        AssertAccepted(result);
        Assert.Equal(prototype, result["expected_principal"]!.GetValue<string>());
        Assert.Equal(OtherSid, result["expected_sid"]!.GetValue<string>());
        Assert.Equal(2, result["session_id"]!.GetValue<int>());
    }

    [Fact]
    public void InstallationIdentityMustBeExplicitlyConfigured()
    {
        AssertRejected(WindowsRuntimeIdentity.Verify(_ => null, () => Current("owner")),
            "expected_principal_missing", "expected_sid_missing", "principal_mismatch", "sid_mismatch");
    }

    [Fact]
    public void ExplicitProtectedIdentityOverridesHostileProcessEnvironment()
    {
        var hostile = Installation(@"OTHER\attacker", OtherSid);
        var result = WindowsRuntimeIdentity.Verify(hostile.GetValueOrDefault,
            () => Current(elevated: false, session: 2), Principal, Sid);
        AssertAccepted(result);
        Assert.Equal(Principal, result["expected_principal"]!.GetValue<string>());
        Assert.Equal(Sid, result["expected_sid"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PartiallyProvidedProtectedPairNeverFallsBackToEnvironment(bool principalOnly)
    {
        var result = WindowsRuntimeIdentity.Verify(_ => throw new InvalidOperationException("must_not_read_env"),
            () => Current(), principalOnly ? Principal : null, principalOnly ? null : Sid);
        AssertRejected(result, principalOnly ? "expected_sid_missing" : "expected_principal_missing",
            principalOnly ? "sid_mismatch" : "principal_mismatch");
    }

    [Fact]
    public void ExpectedValuesAreTrimmedAndIdentityComparisonIgnoresCase()
    {
        AssertAccepted(WindowsRuntimeIdentity.Verify(Installation("  " + Principal.ToLowerInvariant() + "\t", " " + Sid.ToLowerInvariant() + " ").GetValueOrDefault,
            () => Current()));
    }

    [Fact]
    public void NonInteractiveSessionAndProbeErrorsFailClosed()
    {
        AssertRejected(WindowsRuntimeIdentity.Verify(Installation().GetValueOrDefault, () => Current(session: 0)),
            "interactive_session_required");
        AssertRejected(WindowsRuntimeIdentity.Verify(Installation().GetValueOrDefault,
            () => Current() with { Error = "whoami_failed" }), "whoami_failed");
    }

    [Fact]
    public async Task InventoryFailureIsNotReportedAsAnEmptySuccessfulInventory()
    {
        var result = await Inventory(new(1, "", "access denied"));
        Assert.Empty(result.Pids);
        Assert.Equal("process_inventory_failed:exit_1:access denied", result.Error);
        Assert.False(result.RecordedWorkerIsConfirmedGone(12356));
    }

    [Fact]
    public async Task InventoryReturnsExactPythonPidsAndExcludesTheGuardItself()
    {
        var result = await WorkerGuard.RunningPidsForAsync("collection_worker.py", TestContext.Current.CancellationToken,
            (start, _) =>
            {
                Assert.Equal("powershell", start.FileName);
                Assert.False(start.UseShellExecute);
                Assert.True(start.CreateNoWindow);
                Assert.Contains("$ErrorActionPreference='Stop'", start.ArgumentList[^1]);
                Assert.Contains("$_.Name -like 'python*'", start.ArgumentList[^1]);
                Assert.Contains("$_.CommandLine -like '*\\collection_worker.py*'", start.ArgumentList[^1]);
                return Task.FromResult(new WorkerProcessOutput(0, "10\n30\n", ""));
            }, windows: true, currentPid: 30);
        Assert.Equal(new[] { 10 }, result.Pids);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData(12356, null, true)]
    [InlineData(12356, 12356, false)]
    [InlineData(null, null, false)]
    [InlineData(12356, 99999, false)]
    [InlineData(0, null, false)]
    [InlineData(-1, null, false)]
    public void RestartRequiresAValidRecordedPidAndNoRunningWorker(int? recordedPid, int? runningPid, bool allowed)
    {
        var inventory = new WorkerProcessInventory(runningPid is { } pid ? [pid] : [], null);
        Assert.Equal(allowed, inventory.RecordedWorkerIsConfirmedGone(recordedPid));
    }

    [Fact]
    public async Task InventoryExceptionsFailClosedAndCancellationPropagates()
    {
        var result = await WorkerGuard.RunningPidsForAsync("collection_worker.py", TestContext.Current.CancellationToken,
            (_, _) => throw new UnauthorizedAccessException("synthetic-private-detail"), windows: true);
        Assert.Equal("process_inventory_failed:UnauthorizedAccessException", result.Error);
        Assert.False(result.RecordedWorkerIsConfirmedGone(12356));
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WorkerGuard.RunningPidsForAsync("collection_worker.py", stop.Token,
            (_, ct) => Task.FromCanceled<WorkerProcessOutput>(ct), windows: true));
    }

    [Theory]
    [InlineData(1, "fallback\r\nerror", "", "fallback  error")]
    [InlineData(2, "ignored", " denied\r\nnow ", "denied  now")]
    public async Task InventoryFailureKeepsTheReferenceDiagnostic(int exitCode, string stdout, string stderr, string expected)
    {
        var result = await Inventory(new(exitCode, stdout, stderr));
        Assert.Equal($"process_inventory_failed:exit_{exitCode}:" + expected, result.Error);
    }

    [Fact]
    public async Task SuccessfulInventoryIgnoresNonPidLines()
    {
        var result = await Inventory(new(0, " 10\r\ninvalid\n-2\n30\n", ""));
        Assert.Equal(new[] { 10 }, result.Pids); Assert.Null(result.Error);
    }

    [Fact]
    public async Task OtherPlatformsDoNotRunWindowsInventory()
    {
        var result = await WorkerGuard.RunningPidsForAsync("collection_worker.py", TestContext.Current.CancellationToken,
            (_, _) => throw new InvalidOperationException("must_not_run"), windows: false);
        Assert.Empty(result.Pids); Assert.Null(result.Error);
    }

    [Theory]
    [InlineData("worker'; throw 'injection")]
    [InlineData("*collection_worker.py")]
    public async Task ScriptNamesCannotInjectCommandsOrBroadenTheMatch(string script)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => WorkerGuard.RunningPidsForAsync(script, TestContext.Current.CancellationToken,
            (_, _) => throw new InvalidOperationException("must_not_run"), windows: true));
    }

    private static Task<WorkerProcessInventory> Inventory(WorkerProcessOutput output) => WorkerGuard.RunningPidsForAsync(
        "collection_worker.py", TestContext.Current.CancellationToken, (_, _) => Task.FromResult(output), windows: true, currentPid: 30);
}
