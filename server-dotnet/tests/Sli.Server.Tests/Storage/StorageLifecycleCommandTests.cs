using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageLifecycleCommandTests
{
    [Fact] public async Task Once_dispatches_clamped_budgets_and_real_exit_code()
    {
        using var output = new StringWriter(); using var error = new StringWriter(); LifecycleOptions? observed = null;
        int exit = await StorageLifecycleCommand.RunCoreAsync(["--once", "--interval-seconds", "1", "--delete-batch-size", "9999"],
            (options, emit, _) => { observed = options; emit(new JsonObject { ["status"] = "blocked", ["reason"] = "purge_permission_denied" }); return Task.FromResult(2); }, output, error, TestContext.Current.CancellationToken);
        Assert.Equal(new LifecycleOptions(true, 900, 1000), observed); Assert.Equal(2, exit); Assert.Contains("purge_permission_denied", output.ToString()); Assert.Equal("", error.ToString());
    }
    [Theory] [InlineData("--unknown")] [InlineData("--max-batches=1")] [InlineData("--interval-seconds=invalid")] [InlineData("@untrusted-response-file")]
    public async Task Input_errors_never_start_runtime(string argument)
    {
        using var output = new StringWriter(); using var error = new StringWriter(); bool called = false;
        int exit = await StorageLifecycleCommand.RunCoreAsync([argument], (_, _, _) => { called = true; return Task.FromResult(0); }, output, error, TestContext.Current.CancellationToken);
        Assert.NotEqual(0, exit); Assert.False(called);
    }
    [Fact] public async Task Failure_outputs_only_source_free_reason()
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        int exit = await StorageLifecycleCommand.RunCoreAsync(["--once"], (_, _, _) => throw new IOException("password=secret private AD"), output, error, TestContext.Current.CancellationToken);
        Assert.Equal(2, exit); Assert.Contains("purge_verification_or_io_failed", error.ToString()); Assert.DoesNotContain("password", error.ToString()); Assert.Equal("", output.ToString());
    }
    [Fact] public async Task Continuous_role_propagates_shutdown_without_error()
    {
        using var output = new StringWriter(); using var error = new StringWriter(); using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        LifecycleOptions? observed = null;
        int exit = await StorageLifecycleCommand.RunCoreAsync([], async (options, _, ct) => { observed = options; cancel.Cancel(); await Task.Delay(Timeout.Infinite, ct); return 2; }, output, error, cancel.Token);
        Assert.Equal(0, exit); Assert.Equal(new LifecycleOptions(), observed); Assert.Equal("", error.ToString());
    }
}
