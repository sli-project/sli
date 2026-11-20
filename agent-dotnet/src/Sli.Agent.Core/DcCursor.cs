using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// The cursor token of <c>sli.windows.ad-dc</c>: one durable position for all channels plus the rotation pointer.
/// The server parses it with the same rules, so a malformed token is refused there.
/// </summary>
public sealed class DcCursor
{
    public const string Strategy = "bookmark";
    public const int LegacyChannelCount = 3;
    // Append channels: existing checkpoints retain their original rotation indices.
    public static readonly IReadOnlyList<string> Channels = ["Security", "System", "Directory Service",
        "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "DNS Server"];

    public int Next { get; set; }

    public Dictionary<string, ChannelProgress> Progress { get; } = [];

    public static DcCursor Parse(Cursor cursor)
    {
        static AgentException Invalid() => new("agent_ad_dc_cursor_invalid");

        if (cursor.Strategy != Strategy) throw Invalid();
        var state = new DcCursor();
        if (cursor.Token.Length == 0) return state;
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(cursor.Token);
        }
        catch (JsonException)
        {
            throw Invalid();
        }
        if (root is not JsonObject obj || !JsonRead.HasExactly(obj, "next", "channels") || !JsonRead.TryInteger(obj["next"], out var next)
            || next < 0 || next >= Channels.Count || obj["channels"] is not JsonObject channels) throw Invalid();
        state.Next = (int)next;
        foreach (var (name, progress) in channels)
        {
            if (!Channels.Contains(name)) throw Invalid();
            state.Progress[name] = ChannelProgress.FromJson(progress);
        }
        return state;
    }

    public JsonObject ToJson()
    {
        var channels = new JsonObject();
        foreach (var (name, progress) in Progress) channels[name] = progress.ToJson();
        return new JsonObject { ["next"] = Next, ["channels"] = channels };
    }

    /// <summary>The token, at most 4096 characters (<c>agent_ad_dc_cursor_size_limit</c>).</summary>
    public Cursor ToCursor()
    {
        var token = CanonicalJson.Serialize(ToJson());
        if (token.Length > Cursor.MaxTokenCodePoints) throw new AgentException("agent_ad_dc_cursor_size_limit");
        return new Cursor(Strategy, token);
    }
}
