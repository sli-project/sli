using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Legacy;

namespace Sli.Server.Agents.Radius;

public sealed record NpsArchivePlan(string ConnectAddress, string? StartTimeUtc,
    IReadOnlyDictionary<string, string> ChannelStartTimes,
    IReadOnlyDictionary<string, long> ChannelAfterRecordIds,
    IReadOnlyDictionary<string, string> ChannelCursorGenerations);

// The NPS boundary is separate from AD/DC endpoint and credential resolution.
// Sources: nps_eventlog_runtime.py and run_dc_log_pilot.py archive planning.
public sealed class NpsPipelineRuntime(CollectionRuntimePipeline pipeline)
{
    private static bool Fqdn(string value) => Regex.IsMatch(value,
        @"\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string ResolveEndpoint(JsonObject registeredRoute, string server, string? connectAddress = null)
    {
        string Text(string field) => CollectionRuntimePipeline.Text(registeredRoute[field])?.Trim() ?? "";
        string registered = Text("source_name");
        if (!Fqdn(registered) || !string.Equals(registered, Text("source_instance_id"), StringComparison.OrdinalIgnoreCase)
            || Text("owner_confirmed_ip").Length == 0 || registeredRoute["event_log_ready"] is not JsonValue ready
            || !ready.TryGetValue<bool>(out var enabled) || !enabled || Text("event_log_adapter") != "windows-eventlog-pywin32")
            throw new InvalidOperationException("nps_eventlog_registered_route_required");
        string requested = server.Trim(), connect = (connectAddress ?? server).Trim();
        if (!Fqdn(requested) || !Fqdn(connect) || !string.Equals(requested, registered, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(connect, registered, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("nps_eventlog_endpoint_invalid");
        return registered;
    }

    public static NpsArchivePlan BuildArchivePlan(string connectAddress, JsonObject channelPlan, bool useRecordIdCursor = true)
    {
        var starts = new Dictionary<string, string>(StringComparer.Ordinal);
        var records = new Dictionary<string, long>(StringComparer.Ordinal);
        var generations = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (channel, node) in channelPlan) {
            if (node is not JsonObject item || CollectionRuntimePipeline.Text(item["start_time_utc"]) is not { } start)
                throw new ArgumentException("collection_plan_start_required");
            starts[channel] = start;
            if (!useRecordIdCursor) continue;
            if (CollectionRuntimePipeline.Number(item["after_record_id"]) is { } record) records[channel] = record;
            if (CollectionRuntimePipeline.Text(item["channel_generation_identity"]) is { Length: > 0 } generation) generations[channel] = generation;
        }
        if (records.ContainsKey("Security") != generations.ContainsKey("Security")) {
            records.Remove("Security"); generations.Remove("Security");
        }
        return new(connectAddress, starts.Values.Order(StringComparer.Ordinal).FirstOrDefault(), starts, records, generations);
    }

    public async Task<NpsArchivePlan> PrepareAsync(JsonObject registeredRoute, string server, string? connectAddress, CancellationToken ct)
    {
        string endpoint = ResolveEndpoint(registeredRoute, server, connectAddress);
        return BuildArchivePlan(endpoint, await pipeline.GetCollectionPlanAsync(server, ["Security"], ct));
    }

    public Task CommitAsync(string server, string collectionStartUtc, JsonObject summary, JsonObject importStats,
        CancellationToken ct, long? jobId = null, string? traceId = null) =>
        pipeline.UpdateCollectionStateAsync(server, collectionStartUtc, summary, importStats, ct,
            requireQueryExhaustion: true, jobId: jobId, traceId: traceId);
}
