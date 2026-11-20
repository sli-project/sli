using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Semantic;

// One in-flight operation per key. Polling never cancels an executing query.
internal sealed class SemanticWork(bool independent = false, int? concurrency = null)
{
    private readonly object admission = new();
    private readonly Queue<TaskCompletionSource> queue = new();
    private int capacity = concurrency is < 1 ? throw new ArgumentOutOfRangeException(nameof(concurrency)) : concurrency ?? int.MaxValue, running;
    internal void SetConcurrency(int limit)
    {
        if (limit < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        lock (admission) { capacity = limit; Admit(); }
    }
    private void Admit()
    {
        while (running < capacity && queue.TryDequeue(out var waiter))
            if (waiter.TrySetResult()) running++;
    }
    private async Task Acquire(CancellationToken ct)
    {
        var waiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = ct.Register(() => waiter.TrySetCanceled(ct));
        lock (admission) { queue.Enqueue(waiter); Admit(); }
        await waiter.Task;
    }
    private readonly ConcurrentDictionary<string, Task<object?>> pending = new();
    private readonly ConcurrentDictionary<string, JsonObject> active = new();
    private readonly ConcurrentDictionary<string, (Task Task, string Started)> observed = new();
    private static readonly AsyncLocal<(SemanticWork Owner, string Key)?> current = new();

    internal async Task<T?> Run<T>(string key, Func<Task<T>> run, CancellationToken ct = default)
    {
        async Task<object?> Execute()
        {
            var previous = current.Value;
            current.Value = (this, key);
            active[key] = new() { ["operation"] = key, ["started_at"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["status"] = "queued" };
            bool acquired = false;
            try {
                // Completed sources join the FIFO tail on their next poll.
                // Sequential --once execution already has only one source at a time.
                if (independent && concurrency is not null) { await Acquire(ct); acquired = true; }
                active[key] = new() { ["operation"] = key, ["started_at"] = active[key]["started_at"].Copy(), ["status"] = "running" };
                return await run();
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) when (ConnectionWait(error)) {
                Console.Error.WriteLine("semantic_operation_waiting:" + new JsonObject {
                    ["operation"] = key, ["reason"] = "database_connections_exhausted", ["sql_state"] = "53300", ["retry"] = "next_poll"
                }.ToJsonString());
                return default;
            }
            catch (Exception error) {
                Console.Error.WriteLine("semantic_operation_failed:" + DetectionDiagnostics.Describe(error, key).ToJsonString());
                throw;
            }
            finally {
                active.TryRemove(key, out _); current.Value = previous;
                if (acquired) lock (admission) { running--; Admit(); }
            }
        }
        if (!independent) { var value = await Execute(); return value is null ? default : (T)value; }
        // Run is called serially for a given key by its owning stage.
        var task = pending.GetOrAdd(key, _ => Execute());
        if (!task.IsCompleted) return default;
        pending.TryRemove(key, out _);
        var result = await task; return result is null ? default : (T)result;
    }

    internal static bool ConnectionWait(Exception error)
    {
        for (Exception? e = error; e is not null; e = e.InnerException)
            if (e is PostgresException { SqlState: "53300" }) return true;
        return false;
    }

    internal static void Progress(JsonObject progress)
    {
        if (current.Value is not { } scope || !scope.Owner.active.TryGetValue(scope.Key, out var old)) return;
        var next = old.DeepClone().AsObject(); next["cursor"] = progress["cursor"].Copy(); next["heartbeat"] = progress["heartbeat"].Copy();
        scope.Owner.active[scope.Key] = next;
    }

    internal static void Query(NpgsqlConnection db, string sql)
    {
        if (current.Value is not { } scope || !scope.Owner.active.TryGetValue(scope.Key, out var old)) return;
        var diagnostic = new DetectionDiagnostics(); diagnostic.Query(sql);
        // Never put SQL text, parameters or source identities in heartbeat.
        scope.Owner.active[scope.Key] = new() { ["operation"] = scope.Key, ["started_at"] = old["started_at"].Copy(),
            ["query"] = diagnostic.Step, ["query_started_at"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["backend_pid"] = db.ProcessID,
            ["cursor"] = old["cursor"].Copy(), ["heartbeat"] = old["heartbeat"].Copy() };
    }

    internal void Track(string key, Task task) => observed[key] = (task, SemanticJson.Stamp(DateTimeOffset.UtcNow));
    internal void Forget(string key) => observed.TryRemove(key, out _);
    internal bool Finished(string key) => observed.TryGetValue(key, out var operation) && operation.Task.IsCompleted;
    internal JsonArray Snapshot() => new(active.Values.Select(value => (JsonNode)value.DeepClone())
        .Concat(observed.Select(pair => (JsonNode)new JsonObject {
            ["operation"] = pair.Key, ["started_at"] = pair.Value.Started,
            ["status"] = pair.Value.Task.IsFaulted ? "error" : pair.Value.Task.IsCanceled ? "canceled" : pair.Value.Task.IsCompleted ? "completed" : "running"
        })).OrderBy(value => value.Text("operation"), StringComparer.Ordinal).ToArray());
    internal async Task Drain()
    {
        // Observe every task at shutdown, including a task whose connection died.
        do {
            await Task.WhenAll(pending.Values.ToArray().Select(async task => { try { await task; } catch { } }));
        } while (pending.Values.Any(task => !task.IsCompleted));
    }
}

internal sealed record SemanticCapacity(int MaxConnections, int Reserved, int Cpu, int OtherServices, int Sources)
{
    internal bool Exhausted => MaxConnections - Reserved - OtherServices - 3 < 1;
    internal static SemanticCapacity Calculate(int maximum, int reserved, int cpu, int observedOther = 0)
    {
        cpu = Math.Max(1, cpu);
        int others = Math.Max(0, observedOther);
        // The semantic session lock/coordinator, heartbeat and outbox pump each own one.
        return new(maximum, reserved, cpu, others, Math.Max(1, Math.Min(cpu, maximum - reserved - others - 3)));
    }
    internal static async Task<SemanticCapacity> ReadAsync(NpgsqlConnection db, int cpu, CancellationToken ct)
    {
        // datid/usename remain visible for other logins without pg_read_all_stats;
        // backend_type is redacted and cannot be used to count their connections.
        await using var command = new NpgsqlCommand("""
            select current_setting('max_connections')::int,
              current_setting('superuser_reserved_connections')::int + coalesce(nullif(current_setting('reserved_connections',true),'')::int,0),
              (select count(*)::int from pg_stat_activity where datid is not null and usename is not null and usename is distinct from session_user)
            """, db) { CommandTimeout = 0 };
        await using var rows = await command.ExecuteReaderAsync(ct); await rows.ReadAsync(ct);
        var capacity = Calculate(rows.GetInt32(0), rows.GetInt32(1), cpu, rows.GetInt32(2));
        if (capacity.Exhausted) Console.Error.WriteLine("semantic_capacity_waiting:database_connections_exhausted:" + capacity.Json().ToJsonString());
        return capacity;
    }
    internal JsonObject Json() => new() { ["max_connections"] = MaxConnections, ["reserved_connections"] = Reserved,
        ["cpu"] = Cpu, ["other_service_slots"] = OtherServices, ["semantic_control_slots"] = 3, ["source_concurrency"] = Sources,
        ["reason"] = Exhausted ? "database_connections_exhausted" : null };
}
