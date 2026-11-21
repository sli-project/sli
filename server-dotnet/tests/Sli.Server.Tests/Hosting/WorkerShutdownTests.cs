using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests;

public sealed class WorkerShutdownTests
{
    [Fact]
    public async Task Stop_cancels_work_in_progress_and_returns_zero_after_cleanup()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool cleaned = false;
        var loop = new AdCoordinatorLoop(() => DateTimeOffset.UtcNow, async (_, token) =>
        {
            try
            {
                entered.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return 1;
            }
            finally { cleaned = true; }
        }, (_, _, _) => Task.CompletedTask, Task.Delay);
        var worker = WorkerShutdown.RunAsync(token => loop.RunAsync(false, true, token), stop.Token);

        await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
        await stop.CancelAsync();
        Assert.Equal(0, await worker.WaitAsync(TestContext.Current.CancellationToken));
        Assert.True(cleaned);
    }

    [Fact]
    public async Task Stop_returns_zero_from_running_executor_command()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        using var output = new StringWriter();
        using var errors = new StringWriter();
        var worker = CoreJobCommand.RunAsync(["--profile", "light"], new(), TextReader.Null, output, errors, stop.Token);
        Assert.False(worker.IsCompleted);
        await stop.CancelAsync();
        Assert.Equal(0, await worker.WaitAsync(TestContext.Current.CancellationToken));
        Assert.Empty(errors.ToString());
    }

    [Fact]
    public Task Unrelated_cancellation_remains_a_failure() =>
        Assert.ThrowsAsync<OperationCanceledException>(() => WorkerShutdown.RunAsync(
            _ => throw new OperationCanceledException(), TestContext.Current.CancellationToken));
}
