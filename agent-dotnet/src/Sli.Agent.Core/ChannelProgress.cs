using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// Where one channel stands inside the DC cursor (<c>sli_agent/ad_dc.py: cursor_state</c>). The bookmark is the Windows
/// bookmark XML; the server checks only its type and length, so the agent owns its meaning.
/// </summary>
public sealed record ChannelProgress(long? RecordId, string Bookmark, string Generation, string? SinceUtc = null, string? BeforeUtc = null, bool? Complete = null)
{
    public const int MaxBookmarkCodePoints = 2048;
    public const int MaxGenerationCodePoints = 128;

    public static ChannelProgress Start(string generation) => new(null, string.Empty, generation);

    public JsonObject ToJson()
    {
        var json = new JsonObject
        {
            ["record_id"] = RecordId is { } id ? JsonValue.Create(id) : null,
            ["bookmark"] = Bookmark,
            ["generation"] = Generation,
        };
        if (SinceUtc is not null) json["since_utc"] = SinceUtc;
        if (BeforeUtc is not null) json["before_utc"] = BeforeUtc;
        if (Complete is { } complete) json["complete"] = complete;
        return json;
    }

    public static ChannelProgress FromJson(JsonNode? node)
    {
        static AgentException Invalid() => new("agent_ad_dc_cursor_invalid");

        if (node is not JsonObject obj) throw Invalid();
        var allowed = new HashSet<string> { "record_id", "bookmark", "generation", "since_utc", "before_utc", "complete" };
        if (obj.Any(pair => !allowed.Contains(pair.Key)) || !obj.ContainsKey("record_id") || !obj.ContainsKey("bookmark") || !obj.ContainsKey("generation")) throw Invalid();
        long? recordId = null;
        if (!JsonRead.IsNull(obj["record_id"]))
        {
            if (!JsonRead.TryInteger(obj["record_id"], out var value) || value <= 0 || value > long.MaxValue) throw Invalid();
            recordId = (long)value;
        }
        if (!JsonRead.TryString(obj["bookmark"], out var bookmark) || JsonRead.CodePoints(bookmark) > MaxBookmarkCodePoints
            || (bookmark.Length > 0) != recordId.HasValue) throw Invalid();
        if (!JsonRead.TryString(obj["generation"], out var generation) || generation.Length == 0 || JsonRead.CodePoints(generation) > MaxGenerationCodePoints) throw Invalid();
        string? since = null, before = null;
        if (obj.ContainsKey("since_utc"))
        {
            if (!JsonRead.TryString(obj["since_utc"], out since) || !Iso8601.TryParseUtc(since, out _)) throw Invalid();
        }
        if (obj.ContainsKey("before_utc"))
        {
            if (!JsonRead.TryString(obj["before_utc"], out before) || !Iso8601.TryParseUtc(before, out _)) throw Invalid();
        }
        bool? complete = null;
        if (obj.ContainsKey("complete"))
        {
            if (obj["complete"] is not JsonValue flag || flag.GetValueKind() is not (System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False) || before is null) throw Invalid();
            complete = flag.GetValue<bool>();
        }
        return new ChannelProgress(recordId, bookmark, generation, since, before, complete);
    }
}
