using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

internal static partial class OperationsCollector
{
    // A display zero must not turn absent or malformed telemetry into an observation.
    internal static long? TimeoutCount(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue<bool>(out _)) return null;
        if (value.TryGetValue<long>(out long number)) return number >= 0 ? number : null;
        if (value.TryGetValue<int>(out int integer)) return integer >= 0 ? integer : null;
        if (value.TryGetValue<string>(out string? text)
            && Regex.IsMatch(text, @"\A(?:0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant)
            && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out number)) return number;
        return null;
    }

    internal static bool CounterAvailable(JsonObject stats) => TimeoutCount(stats["timeouts_24h"]) is not null
        && (!stats.ContainsKey("timeouts_24h_available") || B(stats["timeouts_24h_available"]));

    internal static JsonObject MergeStats(JsonObject primary, JsonObject fallback)
    {
        if (primary.Count == 0) return (JsonObject)fallback.DeepClone();
        var merged = (JsonObject)primary.DeepClone();
        string[] counters = ["timeouts_24h", "partial_timeouts_24h", "timeouts_24h_available"];
        // Counters come from one source. An observed SQL zero wins over log tails.
        if (!CounterAvailable(primary) && CounterAvailable(fallback))
            foreach (string key in counters) merged[key] = Copy(fallback[key]);
        foreach (var (key, value) in fallback)
            if (!counters.Contains(key) && (merged[key] is null || S(merged[key]) is "0" or "")) merged[key] = Copy(value);
        return merged;
    }

    internal static Dictionary<(string Server, string Channel), JsonObject> LogStats(JsonArray lines, DateTimeOffset now)
    {
        var stats = new Dictionary<(string, string), JsonObject>();
        JsonObject Bucket(string server, string channel)
        {
            var key = (server, channel);
            if (!stats.TryGetValue(key, out var bucket)) stats[key] = bucket = new()
            {
                ["timeouts_24h_available"] = null, ["timeouts_24h"] = 0, ["partial_timeouts_24h"] = 0,
                ["inserted"] = 0, ["skipped"] = 0, ["last_partial_count"] = 0, ["last_status"] = null
            };
            return bucket;
        }
        foreach (var line in lines)
        {
            JsonObject? record;
            try { record = JsonNode.Parse(S(line)) as JsonObject; }
            catch (JsonException) { continue; }
            if (record is null) continue;
            var ts = Time(record["ts"]);
            if (ts < now.AddHours(-24)) continue;
            string server = S(record["server"]);
            if (server.Length == 0) server = Regex.Match(S(record["command"]), @"--server\s+(\S+)").Groups[1].Value;
            if (server.Length == 0) continue;
            string text = string.Join('\n', new[] { "stdout_tail", "stderr_tail", "message", "error" }.Select(k => S(record[k])));
            void Status(Match match, bool timeout)
            {
                var bucket = Bucket(server, match.Groups["channel"].Value.Trim());
                long count = long.TryParse(match.Groups["count"].Value, out var n) ? n : 0;
                bucket["last_status"] = timeout ? count > 0 ? "partial_timeout" : "timeout" : "completed";
                bucket["timeouts_24h_available"] = ts is not null && ts <= now && ts >= now.AddHours(-24)
                    && !(bucket["timeouts_24h_available"] is JsonValue v && v.TryGetValue<bool>(out bool b) && !b);
                if (!timeout) return;
                bucket["timeouts_24h"] = N(bucket["timeouts_24h"]) + 1;
                if (count > 0)
                {
                    bucket["partial_timeouts_24h"] = N(bucket["partial_timeouts_24h"]) + 1;
                    bucket["last_partial_count"] = Math.Max(N(bucket["last_partial_count"]), count);
                }
            }
            foreach (Match match in Regex.Matches(text, @"Timed out channel: (?<channel>.+?) after \d+s(?: partial_count=(?<count>\d+))?")) Status(match, true);
            foreach (Match match in Regex.Matches(text, @"Completed channel: (?<channel>.+?) count=(?<count>\d+)")) Status(match, false);
            foreach (Match match in Regex.Matches(text, @"(?<safe>[A-Za-z0-9_.-]+)\.jsonl: inserted=(?<inserted>\d+), skipped=(?<skipped>\d+)"))
            {
                var bucket = Bucket(server, match.Groups["safe"].Value.Replace('_', ' '));
                foreach (string field in new[] { "inserted", "skipped" })
                    if (long.TryParse(match.Groups[field].Value, out var count)) bucket[field] = N(bucket[field]) + count;
            }
        }
        return stats;
    }
}
