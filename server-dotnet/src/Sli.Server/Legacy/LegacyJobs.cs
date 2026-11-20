using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using System.Text.RegularExpressions;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Legacy;

public sealed record LegacyJobInput(string[] Servers, int Hours = 1, int MaxEvents = 200, NpsCollectionRequest? Nps = null)
{
    public LegacyCollectionRequest[] CollectionRequests { get; init; } = [];
    public IReadOnlyDictionary<string, LegacyAdaptivePlan>? CollectionPlans { get; init; }

    public static LegacyJobInput Parse(JsonElement body, bool collect)
    {
        string server = AuthJsonBody.CredentialString(body, "server");
        if (server.Length == 0) server = "all";
        // Targets are data, including when acquisition is disabled. Bound them before
        // retaining them in a job, audit record, or a report filename.
        if (server.Length > 255 || server.Any(char.IsControl)) throw new AuthInputException("invalid_server");
        return new(server.Equals("all", StringComparison.OrdinalIgnoreCase) ? [] : [server],
            collect ? Integer(body, "hours", 1) : 0,
            collect ? Integer(body, "max_events_per_channel", 200) : 0);
    }

    private static int Integer(JsonElement body, string name, int fallback)
    {
        if (!body.TryGetProperty(name, out var value) || !AuthJsonBody.Truthy(value)) return fallback;
        if (value.ValueKind is JsonValueKind.True) return 1;
        if (value.ValueKind is JsonValueKind.Number && value.TryGetDouble(out double n)
            && double.IsFinite(n) && n >= int.MinValue && n <= int.MaxValue) return (int)n;
        if (value.ValueKind is JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.Integer,
            CultureInfo.InvariantCulture, out int result)) return result;
        // Python's int(payload.get(...) or default) raises ValueError/TypeError;
        // the outer dispatcher returns its standard 500, not a new domain code.
        throw new FormatException("legacy_job_integer_invalid");
    }
}

public sealed class LegacySettings(IConfiguration configuration)
{
    public string? Get(string name) => configuration["Sli:Legacy:" + name] ?? Environment.GetEnvironmentVariable(name);
    public bool Enabled(string name) => Get(name)?.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
    public bool Disabled => (Get("SLI_LEGACY_COLLECTION_DISABLED") ?? "0").Trim() != "0";
    public bool AcquisitionDisabled => !OperatingSystem.IsWindows() || Get("ADLOG_ACQUISITION_DISABLED") == "1";
    public string DataDirectory => Path.GetFullPath(configuration["Sli:DataDirectory"]
        ?? Environment.GetEnvironmentVariable("ADLOG_DATA_DIR") ?? Environment.GetEnvironmentVariable("SLI_DATA_DIR")
        ?? Path.Combine(AppContext.BaseDirectory, "data"));
    public const string DisabledReason = "legacy_collection_disabled";
    public const string DisabledMessage = "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers";
    private string? AgentOwnerBlock => (Get("SLI_AD_DC_AGENT_IMPORT_ENABLED") ?? "0") switch {
        "0" => null, "1" => "ad_dc_agent_collection_owner", _ => "agent_ad_dc_import_config_invalid"
    };
    public string? CollectionBlock => Disabled ? DisabledReason : AcquisitionDisabled ? "acquisition_disabled"
        : AgentOwnerBlock ?? (Enabled("ADLOG_DISABLE_COLLECTION") ? "collection_disabled_by_ADLOG_DISABLE_COLLECTION"
        : !Enabled("ADLOG_ENABLE_POSTGRES_COLLECTION") && !Enabled("ADLOG_POSTGRES_RUNTIME_COLLECTION") ? "postgres_runtime_collection_guard" : null);
    public string? SchedulerBlock => Disabled ? DisabledReason
        : !Enabled("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER") ? "inprocess_scheduler_requires_ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"
        : Enabled("ADLOG_DISABLE_SCHEDULER") ? "scheduler_disabled_by_ADLOG_DISABLE_SCHEDULER" : CollectionBlock;
}

// The Python API keeps manual jobs in process memory; the post-collection queue
// below is the durable boundary. Never mutate a JsonObject shared with a reader.
public sealed class LegacyJobStore
{
    private readonly ConcurrentDictionary<int, JsonObject> jobs = new();
    private int counter;
    public JsonObject Create(string kind, LegacyJobInput input)
    {
        int id = Interlocked.Increment(ref counter);
        string now = DateTimeOffset.UtcNow.ToString("O");
        var job = new JsonObject {
            ["id"] = id, ["kind"] = kind, ["status"] = "queued", ["servers"] = JsonSerializer.SerializeToNode(input.Servers),
            ["hours"] = input.Hours, ["max_events_per_channel"] = input.MaxEvents, ["created_at"] = now, ["updated_at"] = now,
            ["durable_id"] = Guid.NewGuid().ToString("N"), ["message"] = kind.StartsWith("analyze", StringComparison.Ordinal)
                ? "Задача анализа прошлых событий поставлена в очередь." : "Задача сбора поставлена в очередь.",
            ["report_url"] = null, ["analysis_report_url"] = null, ["command_outputs"] = new JsonArray(),
            ["warnings"] = new JsonArray(), ["errors"] = new JsonArray(), ["exit_code"] = null,
            ["stdout_tail"] = "", ["stderr_tail"] = "", ["duration_ms"] = null,
            ["failed_servers"] = new JsonArray(), ["affected_channels"] = new JsonArray(), ["phase"] = "queued",
            ["cycle"] = 0, ["skipped_reason"] = null, ["trace_id"] = null, ["current_server"] = null,
            ["current_channel"] = null, ["channels_in_progress"] = new JsonArray(), ["events_collected"] = 0,
            ["last_progress_at"] = null, ["mode"] = null, ["collection_status"] = null,
            ["analysis_status"] = null, ["report_status"] = null, ["analysis_started_at"] = null,
            ["analysis_finished_at"] = null, ["analysis_error_id"] = null, ["findings_status"] = null,
            ["findings_result"] = null, ["findings_error_id"] = null
        };
        jobs[id] = job;
        return (JsonObject)job.DeepClone();
    }
    public JsonObject? Get(int id) => jobs.TryGetValue(id, out var job) ? (JsonObject)job.DeepClone() : null;
    public int? FindDurable(string durableId) => jobs.Where(pair => pair.Value["durable_id"]?.GetValue<string>() == durableId)
        .Select(pair => (int?)pair.Key).FirstOrDefault();
    public JsonArray List() => new(jobs.OrderByDescending(pair => pair.Key).Select(pair => (JsonNode)pair.Value.DeepClone()).ToArray());
    public void UpdateProgressFromLine(int id, string server, string line)
    {
        string? channel = null;
        long? events = null;
        bool terminal = line.StartsWith("Completed channel:", StringComparison.Ordinal)
            || line.StartsWith("Timed out channel:", StringComparison.Ordinal) || line.StartsWith("Failed channel:", StringComparison.Ordinal);
        if (line.StartsWith("Starting channel:", StringComparison.Ordinal)) channel = line.Split(':', 2)[1].Trim();
        else if (line.StartsWith("Progress channel:", StringComparison.Ordinal) || terminal)
        {
            channel = line.Split(':', 2)[1].Split(" count=", 2)[0];
            if (terminal) channel = channel.Split(" after ", 2)[0].Split(" error=", 2)[0];
            channel = channel.Trim();
            var match = Regex.Match(line, @"(?:partial_)?count=([0-9]+)");
            if (match.Success && long.TryParse(match.Groups[1].Value, out long count)) events = count;
        }
        else if (line.StartsWith("Collection channel status:", StringComparison.Ordinal))
        {
            try { events = Sli.Server.Operations.OpsJson.N(JsonNode.Parse(line.Split(':', 2)[1])?["events_collected"]); }
            catch (JsonException) { }
            catch (InvalidOperationException) { }
        }
        // Output from a remote host is data. Retain bounded identities, never raw lines.
        if (server.Length > 255 || server.Any(char.IsControl) || channel?.Length > 512 || channel?.Any(char.IsControl) == true) return;
        Update(id, job => {
            job["current_server"] = server;
            if (!string.IsNullOrEmpty(channel))
            {
                job["current_channel"] = channel;
                var channels = job["channels_in_progress"]!.AsArray();
                if (!terminal && !channels.Any(c => c?.GetValue<string>() == channel)) channels.Add(channel);
            }
            if (events is {} count) job["events_collected"] = Math.Max(Sli.Server.Operations.OpsJson.N(job["events_collected"]), count);
            job["last_progress_at"] = DateTimeOffset.UtcNow.ToString("O");
        });
    }
    public void Update(int id, Action<JsonObject> update)
    {
        while (jobs.TryGetValue(id, out var previous)) {
            var next = (JsonObject)previous.DeepClone(); update(next); next["updated_at"] = DateTimeOffset.UtcNow.ToString("O");
            if (jobs.TryUpdate(id, next, previous)) return;
        }
    }
}

public sealed record LegacyWork(int Id, bool Collect, LegacyJobInput Input, string Reason = "manual");
public sealed class LegacyWorkQueue
{
    private readonly Channel<LegacyWork> channel = Channel.CreateUnbounded<LegacyWork>(new() { SingleReader = true });
    public void Enqueue(LegacyWork work) { if (!channel.Writer.TryWrite(work)) throw new InvalidOperationException("legacy_queue_closed"); }
    public IAsyncEnumerable<LegacyWork> ReadAsync(CancellationToken ct) => channel.Reader.ReadAllAsync(ct);
}

public interface ILegacyJobs
{
    Task<JsonObject> CreateAsync(bool collect, LegacyJobInput input, CancellationToken ct);
    Task<JsonObject> CreateExternalAsync(LegacyJobInput input, CancellationToken ct);
}

public sealed class LegacyJobs(LegacyJobStore store, LegacyWorkQueue queue, LegacySettings settings,
    ILegacyEnvironment environment, ILegacyAudit audit) : ILegacyJobs
{
    public Task<JsonObject> CreateAsync(bool collect, LegacyJobInput input, CancellationToken ct) => CreateAsync(collect,input,"manual",true,ct);
    internal Task<JsonObject> CreateScheduledAsync(LegacyJobInput input,CancellationToken ct) => CreateAsync(true,input,"scheduled",false,ct);
    public Task<JsonObject> CreateExternalAsync(LegacyJobInput input,CancellationToken ct) => CreateAsync(true,input,"external_worker",false,ct);
    private async Task<JsonObject> CreateAsync(bool collect, LegacyJobInput input, string reason, bool enqueue, CancellationToken ct)
    {
        if (collect && settings.Disabled)
            return new() { ["status"] = "blocked", ["reason"] = LegacySettings.DisabledReason,
                ["message"] = LegacySettings.DisabledMessage, ["collection_allowed"] = false };
        string? durableBlock = collect ? await environment.CollectionBlockAsync(ct) : null;
        if (collect) {
            // A durable security block takes precedence over environment switches.
            if (durableBlock is not null) return new() { ["status"] = "blocked", ["phase"] = "operator_action_required",
                ["reason"] = durableBlock, ["collection_allowed"] = false };
            var guard = await LegacyCollectionAdmission.DiskAsync(environment, ct);
            if (guard["collection_allowed"]?.GetValue<bool>() != true) {
                string guardReason = guard["reason"]?.GetValue<string>() ?? "disk_pressure_guard";
                string status = guardReason == "collection_guard_error" ? "blocked" : "skipped";
                var rejected = new JsonObject { ["kind"] = "collect_all_dc_logs:" + reason, ["status"] = status,
                    ["servers"] = JsonSerializer.SerializeToNode(input.Servers), ["hours"] = input.Hours,
                    ["max_events_per_channel"] = input.MaxEvents, ["created_at"] = DateTimeOffset.UtcNow.ToString("O"),
                    ["updated_at"] = DateTimeOffset.UtcNow.ToString("O"), ["message"] = "Сбор не стартовал: " + guardReason,
                    ["phase"] = "admission", ["skipped_reason"] = guardReason, ["reason"] = guardReason,
                    ["collection_allowed"] = false, ["error_type"] = guard["error_type"]?.DeepClone(), ["disk_guard"] = guard };
                await audit.AppendAsync(reason == "manual" ? "manual_collection_start" : "collection_start:" + reason, status, rejected, ct); return rejected;
            }
        }
        if (input.Servers.Length == 0) input = input with { Servers = await environment.TargetsAsync(ct) };
        var job = store.Create((collect ? "collect_all_dc_logs:" : "analyze_existing_events:") + reason, input);
        int id = job["id"]!.GetValue<int>();
        string? block = collect ? settings.CollectionBlock : null;
        if (block is not null) {
            store.Update(id, j => { j["status"] = "skipped"; j["phase"] = "skipped"; j["skipped_reason"] = block;
                j["mode"] = "runtime_guard"; j["message"] = "Collection is disabled by runtime guard; UI/API remains available."; });
            job = store.Get(id)!;
        }
        if (collect) await audit.AppendAsync(reason == "manual" ? "manual_collection_start" : "collection_start:" + reason, job["status"]!.GetValue<string>(), job, ct);
        if (block is null && enqueue) queue.Enqueue(new(id, collect, input,reason));
        return job;
    }
}

internal static class LegacyCollectionAdmission
{
    internal static async Task<JsonObject> DiskAsync(ILegacyEnvironment environment, CancellationToken ct)
    {
        try { return await environment.DiskGuardAsync(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) { return new() { ["status"] = "blocked", ["phase"] = "admission", ["collection_allowed"] = false,
            ["reason"] = "collection_guard_error", ["error_type"] = error.GetType().Name }; }
    }
}
