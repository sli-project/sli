using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class PostCollectionLoopTests
{
    private static PostCollectionBatch Batch(int scanned = 0, string? reason = null, int quarantined = 0) => new(scanned, 0,
        reason is null ? new Dictionary<string, int>() : new() { [reason] = 1 }, quarantined);

    [Fact]
    public async Task OnceRunsAllOwnersSeriallyAndRecordsSourceHeartbeat()
    {
        var calls = new List<string>(); JsonObject? output = null;
        Task<PostCollectionBatch> Poll(string owner) { calls.Add(owner); return Task.FromResult(Batch()); }
        var loop = new PostCollectionLoop(_ => Poll("events"), _ => Poll("snapshots"), _ => Poll("accounting"),
            (status, phase, _, _) => { calls.Add(status + ":" + phase); return Task.CompletedTask; }, () => TimeSpan.Zero,
            (_, _) => throw new InvalidOperationException("once cannot delay"), result => output = result);
        Assert.Equal(0, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "running:poll", "running:event_inbox", "events", "running:snapshot_cycles", "snapshots",
            "running:accounting", "accounting", "idle:sleep" }, calls);
        Assert.NotNull(output); Assert.Equal(0, output["snapshots"]!["scanned"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("events", "agent_consumer_unavailable")]
    [InlineData("snapshots", "agent_snapshot_import_unavailable")]
    [InlineData("accounting", "agent_radius_import_failed")]
    public async Task ImportFailureRetainsOtherOwnersAndNeverLogsPrivateDiagnostic(string failure, string safe)
    {
        var calls = new List<string>(); JsonObject? output = null;
        Task<PostCollectionBatch> Poll(string name) { calls.Add(name); return name == failure ? throw new InvalidOperationException("private source and credentials") : Task.FromResult(Batch()); }
        var loop = new PostCollectionLoop(_ => Poll("events"), _ => Poll("snapshots"), _ => Poll("accounting"),
            (status, phase, _, _) => { if (phase == "sleep") Assert.Equal("failed", status); return Task.CompletedTask; }, () => TimeSpan.Zero, Task.Delay, r => output = r);
        Assert.Equal(1, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "events", "snapshots", "accounting" }, calls);
        Assert.Contains(safe, output!.ToJsonString()); Assert.DoesNotContain("private", output.ToJsonString());
    }

    [Fact]
    public async Task FullInboxPagesDrainWithinTheCycleBeforeOtherOwnersRun()
    {
        var elapsed = TimeSpan.Zero;
        int pages = 0;
        var loop = new PostCollectionLoop(_ => {
            pages++;
            elapsed += TimeSpan.FromSeconds(16);
            return Task.FromResult(new PostCollectionBatch(128, 128, new Dictionary<string, int>()));
        }, _ => {
            Assert.Equal(2, pages);
            return Task.FromResult(Batch());
        }, _ => Task.FromResult(Batch()), (_, _, _, _) => Task.CompletedTask, () => elapsed, Task.Delay,
            result => Assert.Equal(256, result["agent_packets"]!["imported"]!.GetValue<int>()));
        Assert.Equal(0, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task BusyInboxDoesNotStarveOwnersOrSpinFailedSnapshotRetry()
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        int events = 0, snapshots = 0, accounting = 0, delays = 0; TimeSpan elapsed = TimeSpan.Zero;
        var loop = new PostCollectionLoop(_ => {
            events++;
            if (events > 3) return Task.FromResult(Batch());
            return Task.FromResult(new PostCollectionBatch(128, 128, new Dictionary<string, int>()));
        },
            _ => { snapshots++; return Task.FromResult(Batch(4, "agent_disabled")); },
            _ => { accounting++; return Task.FromResult(Batch()); }, (_, _, _, _) => Task.CompletedTask, () => elapsed,
            (wait, _) => { delays++; elapsed += wait; if (delays == 4) cancel.Cancel(); return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(new(false, 10), cancel.Token));
        Assert.Equal(7, events); Assert.Equal(4, accounting); Assert.Equal(2, snapshots); Assert.Equal(4, delays);
    }

    [Theory]
    [InlineData("agent_projection_failed")]
    [InlineData("agent_ad_dc_projection_failed")]
    public async Task Durable_receipt_does_not_hide_a_downstream_projection_failure(string reason)
    {
        JsonObject? observed = null;
        string? status = null;
        var loop = new PostCollectionLoop(_ => Task.FromResult(Batch(1, reason)),
            _ => Task.FromResult(Batch()), _ => Task.FromResult(Batch()),
            (state, phase, details, _) => {
                if (phase == "sleep") { status = state; observed = details; }
                return Task.CompletedTask;
            }, () => TimeSpan.Zero, Task.Delay);
        Assert.Equal(1, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
        Assert.Equal("failed", status);
        Assert.Equal(0, (int)observed!["agent_packets"]!["imported"]!);
        Assert.Equal(1, (int)observed["agent_packets"]!["pending_reasons"]![reason]!);
    }

    [Fact]
    public async Task FullSuccessfulSnapshotBatchesDrainAndQuarantineHasWarningHeartbeat()
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        int snapshots = 0, iterations = 0; var statuses = new List<string>();
        var elapsed = TimeSpan.Zero;
        var loop = new PostCollectionLoop(_ => {
            elapsed += TimeSpan.FromSeconds(30);
            return Task.FromResult(Batch(iterations++ == 0 ? 128 : 0, quarantined: 1));
        },
            _ => { snapshots++; return Task.FromResult(Batch(4)); }, _ => Task.FromResult(Batch()),
            (status, phase, _, _) => { if (phase == "sleep") statuses.Add(status); return Task.CompletedTask; },
            () => elapsed, (_, _) => { cancel.Cancel(); return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(new(false, 10), cancel.Token)); Assert.Equal(2, snapshots); Assert.All(statuses, s => Assert.Equal("warning", s));
    }

    [Fact]
    public async Task CancellationBetweenOwnersStopsBeforeNextWrite()
    {
        using var cancel = new CancellationTokenSource();
        var loop = new PostCollectionLoop(_ => { cancel.Cancel(); return Task.FromResult(Batch()); },
            _ => throw new InvalidOperationException("must not publish"), _ => throw new InvalidOperationException("must not import"),
            (_, _, _, _) => Task.CompletedTask, () => TimeSpan.Zero, Task.Delay);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(new(true, 10), cancel.Token));
    }

    [Fact]
    public async Task CleanupFailureStillImportsAndRetriesLater()
    {
        using var cancel = new CancellationTokenSource();
        int cleanups = 0, imports = 0, delays = 0;
        TimeSpan elapsed = TimeSpan.Zero;
        using var diagnostic = new StringWriter();
        var previousError = Console.Error;
        Console.SetError(diagnostic);
        try
        {
            var loop = new PostCollectionLoop(_ => { imports++; return Task.FromResult(Batch()); },
                _ => Task.FromResult(Batch()), _ => Task.FromResult(Batch()),
                (_, _, _, _) => Task.CompletedTask, () => elapsed,
                (_, _) => { elapsed += ++delays == 1 ? TimeSpan.FromSeconds(10) : TimeSpan.FromHours(6); if (delays == 3) cancel.Cancel(); return Task.CompletedTask; },
                cleanup: _ => { cleanups++; throw new InvalidOperationException("synthetic-private-cleanup-diagnostic"); });
            Assert.Equal(0, await loop.RunAsync(new(false, 10), cancel.Token));
            Assert.Equal(3, imports);
            Assert.Equal(2, cleanups);
            Assert.Contains("post_collection_cleanup", diagnostic.ToString());
            Assert.DoesNotContain("synthetic-private", diagnostic.ToString());
        }
        finally { Console.SetError(previousError); }
    }

    [Fact]
    public async Task CleanupCancellationStopsBeforeImport()
    {
        using var cancel = new CancellationTokenSource();
        var loop = new PostCollectionLoop(_ => throw new InvalidOperationException("must not import"),
            _ => Task.FromResult(Batch()), _ => Task.FromResult(Batch()),
            (_, _, _, _) => Task.CompletedTask, () => TimeSpan.Zero, Task.Delay,
            cleanup: token => { cancel.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(new(true, 10), cancel.Token));
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("agent_projection_failed", 0)]
    [InlineData("agent_consumer_unavailable", 0)]
    public async Task LegacyModePreservesInboxThenSnapshotsThenPostJobsThenAccounting(string? inboxFailure, int exit)
    {
        var calls = new List<string>(); JsonObject? output = null; string? status = null;
        Task<PostCollectionBatch> Poll(string name) { calls.Add(name); return Task.FromResult(Batch(reason: name == "events" ? inboxFailure : null)); }
        var loop = new PostCollectionLoop(_ => Poll("events"), _ => Poll("snapshots"), _ => Poll("accounting"),
            (s, phase, _, _) => { if (phase == "sleep") status = s; return Task.CompletedTask; }, () => TimeSpan.Zero,
            (_, _) => throw new InvalidOperationException("once cannot delay"), r => output = r,
            legacy: _ => { calls.Add("legacy"); return Task.FromResult(new Sli.Server.Legacy.LegacyPostResult(2, 2, 0)); });
        Assert.Equal(exit, await loop.RunAsync(new(true, 10, 2), TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "events", "snapshots", "legacy", "accounting" }, calls);
        Assert.Equal(inboxFailure is null ? "idle" : "failed", status);
        Assert.Equal(2, output!["last_result"]!["completed"]!.GetValue<int>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PostJobFailureOrIterationExceptionReturnsNonzeroAndKeepsSafeReason(bool throws)
    {
        int accounting = 0; JsonObject? output = null;
        var loop = new PostCollectionLoop(_ => Task.FromResult(Batch()), _ => Task.FromResult(Batch()),
            _ => { accounting++; return Task.FromResult(Batch()); }, (_, _, _, _) => Task.CompletedTask,
            () => TimeSpan.Zero, Task.Delay, r => output = r,
            legacy: _ => throws ? throw new InvalidOperationException("synthetic-private-bind") :
                Task.FromResult(new Sli.Server.Legacy.LegacyPostResult(1, 0, 1)));
        Assert.Equal(1, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
        Assert.Equal(throws ? 0 : 1, accounting);
        Assert.DoesNotContain("synthetic-private", output!.ToJsonString());
        if (throws) Assert.Equal("post_collection_worker_iteration_failed", (string?)output["last_result"]!["reason"]);
    }

    [Fact]
    public async Task IterationExceptionWaitsEvenForFullInboxAndRetriesNextCycle()
    {
        using var cancel = new CancellationTokenSource(); int attempts = 0, waits = 0, accounting = 0;
        var loop = new PostCollectionLoop(_ => Task.FromResult(Batch(16)), _ => Task.FromResult(Batch()),
            _ => { accounting++; cancel.Cancel(); return Task.FromResult(Batch()); }, (_, _, _, _) => Task.CompletedTask,
            () => TimeSpan.Zero, (_, _) => { waits++; return Task.CompletedTask; },
            legacy: _ => ++attempts == 1 ? throw new InvalidOperationException("synthetic-private-bind") :
                Task.FromResult(new Sli.Server.Legacy.LegacyPostResult(0, 0, 0)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(new(false, 10), cancel.Token));
        Assert.Equal(2, attempts); Assert.Equal(1, waits); Assert.Equal(1, accounting);
    }

    [Theory]
    [InlineData("event_inbox", false)]
    [InlineData("event_inbox", true)]
    [InlineData("snapshot_cycles", false)]
    [InlineData("snapshot_cycles", true)]
    [InlineData("accounting", false)]
    [InlineData("accounting", true)]
    [InlineData("legacy_post_collection", false)]
    [InlineData("legacy_post_collection", true)]
    public async Task LongProcessingKeepsHeartbeatWithoutCancellingWorkAndRetriesMonitorFailure(string stage, bool monitorFails)
    {
        var ct = TestContext.Current.CancellationToken;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var beat = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int eventBeats = 0; bool sleeping = false; int expected = monitorFails ? 3 : 2;
        async Task Work(CancellationToken token) {
            started.SetResult(); await beat.Task.WaitAsync(token); Assert.False(token.IsCancellationRequested);
        }
        async Task<PostCollectionBatch> Poll(string owner, CancellationToken token) {
            if (owner == stage) await Work(token);
            return Batch();
        }
        var loop = new PostCollectionLoop(token => Poll("event_inbox", token), token => Poll("snapshot_cycles", token),
            token => Poll("accounting", token),
            (_, phase, _, _) => {
                Assert.False(sleeping);
                if (phase == stage) {
                    eventBeats++;
                    if (monitorFails && eventBeats == 2) throw new InvalidOperationException("synthetic-private-monitor");
                    if (eventBeats == expected) beat.SetResult();
                }
                if (phase == "sleep") sleeping = true;
                return Task.CompletedTask;
            }, () => TimeSpan.Zero, (_, _) => throw new InvalidOperationException("once cannot delay"),
            legacy: stage == "legacy_post_collection" ? async token => { await Work(token); return new(1, 1, 0); } : null,
            pulseDelay: async (_, token) => {
                await started.Task.WaitAsync(token);
                if (Volatile.Read(ref eventBeats) >= expected) await Task.Delay(Timeout.InfiniteTimeSpan, token);
                else await Task.Yield();
            });
        Assert.Equal(0, await loop.RunAsync(new(true, 10), ct));
        Assert.True(sleeping); Assert.Equal(expected, eventBeats);
    }

    [Fact]
    public async Task ZeroFailureCountDoesNotFailAndCursorSurvivesOutputAndHeartbeat()
    {
        var batch = new PostCollectionBatch(1, 0, new Dictionary<string, int> { ["agent_projection_failed"] = 0 }) {
            Cursor = new() { ["packet_id"] = "synthetic-packet" }, Skipped = 7
        };
        JsonObject? output = null;
        var loop = new PostCollectionLoop(_ => Task.FromResult(batch), _ => Task.FromResult(Batch()), _ => Task.FromResult(Batch()),
            (status, phase, details, _) => {
                if (phase == "accounting") Assert.Equal("synthetic-packet", (string?)details["agent_packets"]!["cursor"]!["packet_id"]);
                if (phase == "sleep") Assert.Equal("idle", status);
                return Task.CompletedTask;
            }, () => TimeSpan.Zero, Task.Delay, r => output = r);
        Assert.Equal(0, await loop.RunAsync(new(true, 10), TestContext.Current.CancellationToken));
        Assert.Equal(7, output!["agent_packets"]!["skipped"]!.GetValue<long>());
        Assert.Equal("synthetic-packet", (string?)output["agent_packets"]!["cursor"]!["packet_id"]);
    }
}
