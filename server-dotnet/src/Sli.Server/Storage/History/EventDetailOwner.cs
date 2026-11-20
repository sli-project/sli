using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;

namespace Sli.Server.Storage.History;

// Internal raw detail boundary. Caller supplies authorized route, retention cutoff and report projection.
internal sealed class EventDetailOwner(
    Func<long[],CancellationToken,Task<Dictionary<long,JsonObject>>> summaries,
    Func<long[],TimeSpan,CancellationToken,Task<Dictionary<long,JsonObject>>> history,
    Func<long[],CancellationToken,Task<Dictionary<long,string>>> servers,
    Func<Dictionary<long,JsonObject>,TimeSpan,CancellationToken,Task<Dictionary<long,JsonObject>>> archive)
{
    internal async Task<Dictionary<long,JsonObject>> ReadAsync(IEnumerable<long> requested,bool primary,DateTimeOffset cutoff,TimeSpan budget,CancellationToken ct)
    {
        long[] ids = requested.Where(x => x > 0).Distinct().ToArray();
        if (ids.Length == 0) return [];
        if (ids.Length > 100) throw new ArgumentOutOfRangeException(nameof(requested));
        if (budget <= TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(budget);
        var clock = Stopwatch.StartNew();
        var core = await summaries(ids,deadline.Token);
        var historyIds = primary ? ids.Where(id => !core.TryGetValue(id,out var row) || Time(row)<cutoff).ToArray() : [];
        var result = new Dictionary<long,JsonObject>();
        if (historyIds.Length != 0)
        {
            var remaining = budget-clock.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
            Dictionary<long,JsonObject> rows;
            try { rows = await history(historyIds,remaining,deadline.Token); }
            catch (IOException)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (historyIds.Any(id => !core.ContainsKey(id))) throw;
                foreach (long id in historyIds) { var fallback=(JsonObject)core[id].DeepClone(); fallback["source_payload_state"]="archive_unavailable"; result.Add(id,fallback); }
                rows=[];
            }
            if (rows.Count == 0 && historyIds.All(result.ContainsKey)) goto HistoryComplete;
            if (rows.Count != historyIds.Length || historyIds.Any(id => !rows.ContainsKey(id))) throw new InvalidDataException("published_history_event_batch_incomplete");
            foreach (var (id,payload) in rows)
            {
                if (core.TryGetValue(id,out var summary)) EventDetailIdentity.Verify(summary,payload);
                else if (Time(payload) >= cutoff) throw new InvalidDataException("hot_event_absent_from_core");
            }
            long[] serverIds = rows.Values.Select(row => Integer(row,"server_id")).Distinct().ToArray();
            var names = await servers(serverIds,deadline.Token);
            foreach (var (id,payload) in rows)
            {
                if (!names.TryGetValue(Integer(payload,"server_id"),out string? name)) throw new InvalidDataException("history_server_unknown");
                payload["server"] = name; payload.Remove("_history_batch_sha256"); result.Add(id,payload);
            }
        }
        HistoryComplete:
        deadline.Token.ThrowIfCancellationRequested();
        var hot = core.Where(pair => !historyIds.Contains(pair.Key)).ToDictionary(pair => pair.Key,pair => pair.Value);
        if (hot.Count != 0)
        {
            var remaining=budget-clock.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
            var payloads = await archive(hot,remaining,deadline.Token);
            if (payloads.Count != hot.Count || hot.Keys.Any(id => !payloads.ContainsKey(id))) throw new InvalidDataException("event_archive_payload_missing");
            foreach (var (id,payload) in payloads) result.Add(id,payload);
        }
        deadline.Token.ThrowIfCancellationRequested();
        return result;
    }
    static long Integer(JsonObject row,string name) => long.TryParse(row[name]?.ToString(),NumberStyles.Integer,CultureInfo.InvariantCulture,out long n) ? n : throw new InvalidDataException("event_identity_invalid");
    static DateTimeOffset Time(JsonObject row) => SourceTimestamp.Parse(row["time_created_utc"]?.ToString() ?? throw new InvalidDataException("event_timestamp_invalid"),storageV2:true);
}
