using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;
using Sli.Server.Storage.Archive;

namespace Sli.Server.Storage.History;

// Searches an already authorized metadata selection. Like the source runtime
// facade, this does not fetch cores or fall back to incomplete hot payloads.
internal sealed class EventDeepCandidateReader(ArchiveReader archive)
{
    internal async Task<IReadOnlyList<JsonObject>> SearchAsync(string term, IReadOnlyList<JsonObject> candidates,
        int maxResults = 100, int maxBlocks = 8, IReadOnlyList<string>? accountValues = null, CancellationToken ct = default)
    {
        string needle = UnicodeCaseFold.TrimAndFold(term);
        if (needle.EnumerateRunes().Count() < 2) throw new ArgumentException("archive search term must contain at least two characters",nameof(term));
        if (maxResults is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maxResults),"archive search max_results must be between 1 and 1000");
        if (candidates.Count > 10000) throw new ArgumentException("archive search exceeds candidate limit; narrow the event range",nameof(candidates));
        var payloads = await archive.ReadEventsManyAsync(candidates.Select(row=>ArchiveCodec.Id(row,"event")),maxBlocks,ct);
        var accounts = accountValues?.ToHashSet(StringComparer.Ordinal);
        var matches = new List<JsonObject>();
        foreach (var summary in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var payload = payloads[ArchiveCodec.Id(summary,"event")];
            // Every candidate is verified, including nonmatches after the page fills.
            EventDetailIdentity.Verify(summary,payload);
            string haystack = string.Join("\n",new[]{"message_text","event_data_json","record_xml"}.Select(field=>Text(payload[field])));
            if (!UnicodeCaseFold.Fold(haystack).Contains(needle,StringComparison.Ordinal)) continue;
            if (accounts is not null && !Account(payload["subject_user_name"],accounts) && !Account(payload["target_user_name"],accounts)) continue;
            if (matches.Count >= maxResults) continue;
            var match = (JsonObject)payload.DeepClone();
            match["time_created_utc"] = summary["time_created_utc"]?.DeepClone();
            match["event_record_id"] = summary["event_record_id"]?.DeepClone();
            matches.Add(match);
        }
        return matches;
    }

    static bool Account(JsonNode? node, HashSet<string> accounts) => node is JsonValue value && value.TryGetValue<string>(out var text) && accounts.Contains(text);
    static string Text(JsonNode? node) => node switch
    {
        JsonObject or JsonArray => SourceJson.SerializeSorted(node),
        null => "",
        JsonValue value when value.TryGetValue<bool>(out var flag) => flag ? "True" : "",
        JsonValue value when value.TryGetValue<double>(out var number) && number == 0 => "",
        _ => node.ToString()
    };
}
