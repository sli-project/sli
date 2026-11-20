using System.Text.Json.Nodes;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public class CoreJobWorkerTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Empty_queue_reuses_dispatcher_and_limits_source_reads_then_picks_up_work(bool enqueue)
    {
        var clock = new Clock();
        using var stopping = new CancellationTokenSource();
        var session = new Session(clock, enqueue);
        int opened = 0, children = 0, schedules = 0;
        var catalog = new CoreJobPluginCatalog();
        catalog.Add("sli.remote-access", "radius-session-observation", new((_, _, _) => throw new Exception("unused"), (_, _, _, _) => Task.CompletedTask));
        var worker = new CoreJobWorker(catalog);
        await worker.RunAsync("light", false, stopping.Token,
            _ => { opened++; return Task.FromResult<ICoreJobSession>(session); },
            (_, _, _, _) => { schedules++; return Task.CompletedTask; },
            (_, purpose, _, _, _) => { children++; return Task.FromResult(new JsonObject { ["status"] = purpose == "handler" ? "success" : "committed" }); },
            key => key switch { "SLI_CORE_JOB_RADIUS_PILOT" => "1", "SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID" => "synthetic-source", _ => null },
            clock, (pause, _) => { clock.Advance(pause); if (clock.Seconds >= 60) stopping.Cancel(); return Task.CompletedTask; });
        Assert.Equal(1, opened);
        Assert.Equal(2, schedules);
        Assert.Equal(enqueue ? 2 : 0, children);
        Assert.Equal(enqueue ? 1 : 0, session.Completed);
        Assert.True(session.Disposed);
        var empty = session.Claims.Where(at => !enqueue || at != session.PickedAt).ToArray();
        Assert.All(empty.Zip(empty.Skip(1)), pair => Assert.True(pair.Second - pair.First >= 5));
        Console.WriteLine($"synthetic 60s: dispatcher_opens={opened}; schedules={schedules}; child_calls={children}; picked_at={session.PickedAt}s");
    }

    [Fact]
    public async Task Busy_queue_does_not_repeat_source_reads_after_every_job()
    {
        var clock = new Clock();
        using var stopping = new CancellationTokenSource();
        var session = new Session(clock, busy: true);
        int opened = 0, schedules = 0;
        var catalog = Catalog();
        await new CoreJobWorker(catalog).RunAsync("light", false, stopping.Token,
            _ => { opened++; return Task.FromResult<ICoreJobSession>(session); },
            (_, _, _, _) => { schedules++; return Task.CompletedTask; },
            (_, purpose, _, _, _) =>
            {
                if (purpose == "handler") { clock.Advance(TimeSpan.FromSeconds(1)); if (clock.Seconds >= 60) stopping.Cancel(); }
                return Task.FromResult(new JsonObject { ["status"] = purpose == "handler" ? "success" : "committed" });
            }, EnvironmentSetting, clock, (_, _) => throw new Exception("busy queue should not sleep"));
        Assert.Equal(1, opened); Assert.Equal(2, schedules); Assert.Equal(60, session.Completed);
    }

    [Fact]
    public async Task Broken_dispatcher_connection_is_disposed_and_reopened_without_repeated_scheduling()
    {
        var clock = new Clock();
        using var stopping = new CancellationTokenSource();
        var sessions = new List<Session>();
        int schedules = 0;
        await new CoreJobWorker(Catalog()).RunAsync("light", false, stopping.Token,
            _ =>
            {
                var session = new Session(clock, enqueue: false, breakConnection: sessions.Count == 0);
                sessions.Add(session); return Task.FromResult<ICoreJobSession>(session);
            }, (_, _, _, _) => { schedules++; return Task.CompletedTask; },
            (_, _, _, _, _) => throw new Exception("empty queue must not start children"), EnvironmentSetting,
            clock, (pause, _) => { clock.Advance(pause); if (clock.Seconds >= 60) stopping.Cancel(); return Task.CompletedTask; });
        Assert.Equal(2, sessions.Count);
        Assert.All(sessions, session => Assert.True(session.Disposed));
        Assert.Equal(2, schedules);
    }

    private static CoreJobPluginCatalog Catalog()
    {
        var catalog = new CoreJobPluginCatalog();
        catalog.Add("sli.remote-access", "radius-session-observation", new((_, _, _) => throw new Exception("unused"), (_, _, _, _) => Task.CompletedTask));
        return catalog;
    }
    private static string? EnvironmentSetting(string key) => key switch
    { "SLI_CORE_JOB_RADIUS_PILOT" => "1", "SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID" => "synthetic-source", _ => null };

    private sealed class Clock : TimeProvider
    {
        public double Seconds { get; private set; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => (long)(Seconds * TimeSpan.TicksPerSecond);
        public void Advance(TimeSpan by) => Seconds += by.TotalSeconds;
    }

    private sealed class Session(Clock clock, bool enqueue = true, bool busy = false, bool breakConnection = false) : ICoreJobSession
    {
        public List<double> Claims { get; } = [];
        public int Completed { get; private set; }
        public double PickedAt { get; private set; }
        public bool Disposed { get; private set; }
        public Task<object?> CallAsync(string function, object?[] args, CancellationToken ct)
        {
            object? result = true;
            if (function == "claim_core_job_v1")
            {
                Claims.Add(clock.Seconds);
                if (breakConnection && clock.Seconds >= 10) throw new IOException("synthetic disconnect");
                result = null;
                if (busy || enqueue && clock.Seconds >= 15 && Completed == 0)
                {
                    Completed++; PickedAt = clock.Seconds;
                    result = CoreJobTests.Job();
                }
            }
            return Task.FromResult(result);
        }
        public Task BeginAsync(CancellationToken ct) => Task.CompletedTask;
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public Task RollbackAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }
}
