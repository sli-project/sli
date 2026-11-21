using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageLifecycleTests
{
    internal sealed class State : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sli-lifecycle-" + Guid.NewGuid().ToString("N"));
        internal LifecycleFiles Files { get; }
        internal State() { Directory.CreateDirectory(Path); Files = new(Path); }
        public void Dispose() => Directory.Delete(Path, true);
    }

    internal sealed class Session : ILifecycleSession
    {
        internal List<string> Phases = [];
        internal Queue<JsonObject> InboxResults = new(), ReceiptResults = new(), OutboxResults = new();
        internal List<(DateTime Cutoff, Guid After, int Limit)> InboxCalls = [], ReceiptCalls = [], OutboxCalls = [];
        internal List<DateTime> InboxReceived = [];
        internal List<(string Status, string Phase, int Interval, JsonObject Details)> Beats = [];
        internal bool ProcessLock = true, LostLock;
        internal Func<CancellationToken, Task<JsonObject>>? Partition;
        internal Action<JsonObject>? OnHeartbeat;
        public Task<bool> TryLockAsync(string name, CancellationToken ct) => Task.FromResult(ProcessLock);
        public Task EnsureLocksAsync(CancellationToken ct) { if (LostLock) throw new LifecycleBlocked("storage_lifecycle_lock_lost"); return Task.CompletedTask; }
        public Task ReleaseLockAsync(string name, CancellationToken ct) => Task.CompletedTask;
        public Task HeartbeatAsync(string status, string phase, int interval, JsonObject details, CancellationToken ct) {
            Beats.Add((status, phase, interval, (JsonObject)details.DeepClone())); OnHeartbeat?.Invoke(details); return Task.CompletedTask;
        }
        public Task<JsonObject> ExpirePartitionsAsync(DateTime now, CancellationToken ct) { Phases.Add("partitions"); return Partition?.Invoke(ct) ?? Task.FromResult(new JsonObject()); }
        internal static JsonObject Page(string cursor, Guid after, string status = "complete") => new() {
            ["status"] = status, [cursor] = after.ToString(), ["selected_count"] = 1L, ["deleted_count"] = 0L,
            ["held_count"] = 1L, ["payloads_cleared"] = 0L, ["held_reasons"] = new JsonObject { ["quarantine"] = 1L }
        };
        public Task<JsonObject> RetainInboxAsync(DateTime cutoff, DateTime afterReceivedAt, Guid after, int limit, CancellationToken ct) { Phases.Add("inbox"); InboxCalls.Add((cutoff,after,limit)); InboxReceived.Add(afterReceivedAt); return Task.FromResult(InboxResults.Count>0 ? InboxResults.Dequeue() : Page("last_scanned_packet_id",after)); }
        public Task<JsonObject> RetainReceiptsAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) { Phases.Add("receipts"); ReceiptCalls.Add((cutoff,after,limit)); return Task.FromResult(ReceiptResults.Count>0 ? ReceiptResults.Dequeue() : Page("last_scanned_packet_id",after)); }
        public Task<JsonObject> RetainOutboxAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) { Phases.Add("outbox"); OutboxCalls.Add((cutoff,after,limit)); return Task.FromResult(OutboxResults.Count>0 ? OutboxResults.Dequeue() : Page("last_scanned_job_id",after)); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static readonly DateTime Now = new(2026,11,16,0,0,0,DateTimeKind.Utc);

    [Fact]
    public async Task Cycle_runs_only_partition_and_short_queue_retention()
    {
        using var state = new State(); var session = new Session();
        var result = await new StorageLifecycleWorker(session,state.Files,()=>Now).CycleAsync(new(),TestContext.Current.CancellationToken);
        Assert.Equal("ok", result["status"]?.ToString());
        Assert.Equal(new[] {"inbox","partitions","receipts","outbox"},session.Phases);
        Assert.Equal(Now.AddDays(-7),Assert.Single(session.InboxCalls).Cutoff);
    }
    [Fact]
    public async Task Queues_drain_more_than_fifty_batches_and_aggregate_holds_without_stalling_other_lanes()
    {
        using var state = new State(); var session = new Session();
        for (int n=1;n<=60;n++) session.InboxResults.Enqueue(Session.Page("last_scanned_packet_id",Guid.Parse($"00000000-0000-4000-8000-{n:000000000000}"),"partial"));
        var result = await new StorageLifecycleWorker(session,state.Files,()=>Now).CycleAsync(new(BatchSize:2),TestContext.Current.CancellationToken);
        Assert.Equal(61,session.InboxCalls.Count); Assert.All(session.InboxCalls,c=>Assert.Equal(2,c.Limit));
        Assert.Single(session.ReceiptCalls); Assert.Single(session.OutboxCalls);
        Assert.Equal(61,LifecycleJson.Number(result["agent_inbox_retention"]!["held_reasons"]!.AsObject(),"quarantine"));
    }
    [Fact]
    public async Task Long_inbox_pass_writes_progress_before_completion_and_never_sleeps_between_batches()
    {
        using var state = new State(); var session = new Session();
        for (int n = 1; n <= 21; n++) {
            var page = Session.Page("last_scanned_packet_id", Guid.Parse($"00000000-0000-4000-8000-{n:000000000000}"), "partial");
            page["selected_count"] = 3L; page["deleted_count"] = 1L; page["payloads_cleared"] = 1L;
            session.InboxResults.Enqueue(page);
        }
        var output = new List<JsonObject>();
        var worker = new StorageLifecycleWorker(session, state.Files, () => Now,
            delay: (_, _) => throw new InvalidOperationException("No sleep during a partial pass"));
        Assert.Equal(0, await worker.RunAsync(new(Once: true), r => {
            if (r["status"]?.ToString() == "partial") Assert.Empty(session.ReceiptCalls);
            output.Add((JsonObject)r.DeepClone());
        }, TestContext.Current.CancellationToken));
        var progress = output.Where(r => r["status"]?.ToString() == "partial").ToArray();
        Assert.NotEmpty(progress);
        Assert.All(progress, r => {
            long batches = LifecycleJson.Number(r, "inbox_retention_batches");
            Assert.Equal(batches * 3, LifecycleJson.Number(r, "inbox_rows_scanned"));
            Assert.Equal(batches, LifecycleJson.Number(r, "inbox_rows_deleted"));
            Assert.Equal(batches, LifecycleJson.Number(r, "inbox_payloads_cleared"));
            Assert.NotNull(r["agent_inbox_retention"]?["last_scanned_packet_id"]);
        });
        Assert.Equal("ok", output[^1]["status"]?.ToString());
    }
    [Fact]
    public async Task Inbox_forwards_the_received_cursor_with_microseconds_even_when_packet_ids_decrease()
    {
        using var state = new State(); var session = new Session();
        DateTime first = Now.AddTicks(1234560), last = first.AddTicks(10);
        var a = Guid.Parse("00000000-0000-4000-8000-000000000002");
        var b = Guid.Parse("00000000-0000-4000-8000-000000000001");
        var page = Session.Page("last_scanned_packet_id", a, "partial"); page["last_scanned_received_at"] = LifecycleJson.Iso(first);
        session.InboxResults.Enqueue(page);
        page = Session.Page("last_scanned_packet_id", b); page["last_scanned_received_at"] = LifecycleJson.Iso(last);
        session.InboxResults.Enqueue(page);
        var result = await new StorageLifecycleWorker(session, state.Files, () => Now).CycleAsync(new(), TestContext.Current.CancellationToken);
        Assert.Equal(first, session.InboxReceived[1]); Assert.Equal(a, session.InboxCalls[1].After);
        Assert.Equal(b.ToString(), result["agent_inbox_retention"]?["last_scanned_packet_id"]?.ToString());
        Assert.Equal(last, DateTime.Parse(result["agent_inbox_retention"]!["last_scanned_received_at"]!.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal));
    }
    [Fact]
    public async Task Nonadvancing_queue_cursor_blocks_before_receipt_deletion()
    {
        using var state = new State(); var session = new Session(); session.InboxResults.Enqueue(Session.Page("last_scanned_packet_id",Guid.Empty,"partial"));
        var error=await Assert.ThrowsAsync<LifecycleBlocked>(()=>new StorageLifecycleWorker(session,state.Files).CycleAsync(new(),TestContext.Current.CancellationToken));
        Assert.Equal("inbox_retention_cursor_did_not_advance",error.Message); Assert.Empty(session.ReceiptCalls);
    }
    [Theory] [InlineData("inbox")] [InlineData("receipts")] [InlineData("outbox")]
    public async Task Missing_schema_skips_only_its_queue(string lane)
    {
        using var state = new State(); var session = new Session();
        var queue=lane=="inbox"?session.InboxResults:lane=="receipts"?session.ReceiptResults:session.OutboxResults;
        string key=lane=="receipts"?"receipt":lane;
        queue.Enqueue(LifecycleJson.Result("blocked",key+"_retention_schema_not_ready"));
        var result=await new StorageLifecycleWorker(session,state.Files).CycleAsync(new(),TestContext.Current.CancellationToken);
        Assert.Equal("ok",result["status"]?.ToString()); Assert.Single(session.InboxCalls); Assert.Single(session.ReceiptCalls); Assert.Single(session.OutboxCalls);
    }
    [Fact]
    public async Task Once_persists_watermark_digest_and_source_free_error()
    {
        using var state=new State(); var session=new Session(); JsonObject? output=null;
        Assert.Equal(0,await new StorageLifecycleWorker(session,state.Files,()=>Now).RunAsync(new(Once:true),r=>output=r,TestContext.Current.CancellationToken));
        Assert.Equal("completed",output!["phase"]?.ToString()); Assert.NotNull(output["last_successful_watermark"]);
        string digest=output["result_digest"]!.ToString(); output.Remove("result_digest"); Assert.Equal(digest,LifecycleJson.Hash(output).ToLowerInvariant());
        session.Partition=_=>throw new IOException("password=private AD");
        Assert.Equal(2,await new StorageLifecycleWorker(session,state.Files,()=>Now).RunAsync(new(Once:true),r=>output=r,TestContext.Current.CancellationToken));
        Assert.DoesNotContain("private",output!.ToJsonString()); Assert.Equal("purge_verification_or_io_failed",output["reason"]?.ToString());
        Assert.Equal("complete", output["agent_inbox_retention"]?["status"]?.ToString());
        Assert.NotNull(output["last_successful_watermark"]);
    }
    [Fact]
    public async Task Process_lock_conflict_does_not_touch_storage()
    {
        using var state=new State(); var session=new Session {ProcessLock=false};
        Assert.Equal(9,await new StorageLifecycleWorker(session,state.Files).RunAsync(new(Once:true),_=>{},TestContext.Current.CancellationToken));
        Assert.Empty(session.Phases); Assert.Empty(Directory.GetFiles(state.Path));
    }
    [Fact]
    public async Task Lost_process_lock_blocks_retention()
    {
        using var state=new State(); var session=new Session {LostLock=true};
        await Assert.ThrowsAsync<LifecycleBlocked>(()=>new StorageLifecycleWorker(session,state.Files).CycleAsync(new(),TestContext.Current.CancellationToken));
        Assert.Empty(session.Phases);
    }
    [Fact]
    public async Task Independent_heartbeat_reports_current_phase_inside_a_pending_batch()
    {
        using var state=new State(); var session=new Session();
        var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Partition=async ct=>{ started.SetResult(); await finish.Task.WaitAsync(ct); return new JsonObject(); };
        session.OnHeartbeat=details=>{ if(details["active_phase"]?.ToString()=="partition_retention") finish.TrySetResult(); };
        var worker=new StorageLifecycleWorker(session,state.Files,()=>Now,
            heartbeatDelay:async (_,ct)=>{ await started.Task.WaitAsync(ct); await Task.Yield(); ct.ThrowIfCancellationRequested(); });
        Assert.Equal(0,await worker.RunAsync(new(Once:true),_=>{},TestContext.Current.CancellationToken));
        Assert.Contains(session.Beats,b=>b.Phase=="processing"&&b.Details["active_phase"]?.ToString()=="partition_retention");
    }
    [Fact]
    public async Task Shutdown_cancels_pending_partition_work_without_writing_success()
    {
        using var state=new State(); var session=new Session();
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        session.Partition=async ct=>{ stop.Cancel(); await Task.Delay(Timeout.Infinite,ct); return new JsonObject(); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>new StorageLifecycleWorker(session,state.Files).RunAsync(new(Once:true),_=>Assert.Fail("No finished cycle"),stop.Token));
        Assert.Null(state.Files.Read("storage-lifecycle-last.json"));
    }

}
