using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

public sealed partial record LegacyCollectionSummary
{
    // Collection accounting from run_dc_log_pilot_summary.summarize_channel_status.
    // A saved partial timeout is collected work, unless the reader broke mid-stream.
    public static JsonObject SummarizeChannelStatus(JsonObject summary)
    {
        var channels = (summary["channels"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
        bool Truncated(JsonObject item) => item["continuity"]?["truncated"]?.GetValue<bool>() == true;
        bool Broken(JsonObject item) => item.Text("partial_kind") == "failure"
            || item["cursor_commit_allowed"]?.GetValue<bool>() == false;
        var completed = channels.Where(c => c.Text("status") == "completed" && !Truncated(c)).ToArray();
        var partial = channels.Where(c => c.Text("status") == "partial_timeout" && c.Number("count") > 0 && !Broken(c)
            || c.Text("status") == "completed" && Truncated(c)).ToArray();
        var failed = channels.Where(c => c.Text("status") is "failed" or "timeout"
            || c.Text("status") == "partial_timeout" && (c.Number("count") <= 0 || Broken(c))).ToArray();
        JsonArray Messages(IEnumerable<JsonObject> items) => new(items.Where(c => !string.IsNullOrEmpty(c.Text("error")))
            .Select(c => (JsonNode?)JsonValue.Create($"{c.Text("channel")}: {c.Text("error")}")).ToArray());
        var warnings = Messages(partial);
        foreach (var item in partial.Where(Truncated)) warnings.Add($"{item.Text("channel")}: bounded limit reached before source boundary");
        return new() {
            ["channels_total"] = channels.Length, ["channels_completed"] = completed.Length,
            ["channels_partial"] = partial.Length, ["channels_failed"] = failed.Length,
            ["channels_timeout"] = channels.Count(c => c.Text("status") is "timeout" or "partial_timeout"),
            ["events_collected"] = completed.Concat(partial).Sum(c => c.Number("count")),
            ["all_failed"] = channels.Length > 0 && completed.Length + partial.Length == 0,
            ["partial_failed"] = completed.Length + partial.Length > 0 && failed.Length > 0,
            ["partial_warning"] = partial.Length > 0, ["errors"] = Messages(failed), ["warnings"] = warnings
        };
    }
}
