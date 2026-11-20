using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

/// <summary>An opaque position in a source stream. The server only compares cursors; the agent owns their meaning.</summary>
public sealed record Cursor(string Strategy, string Token)
{
    public const int MaxTokenCodePoints = 4096;
    public static readonly IReadOnlySet<string> Strategies = new HashSet<string> { "record_id", "bookmark", "file_offset", "snapshot" };

    public static Cursor Start(string strategy) => new(strategy, string.Empty);

    public JsonObject ToJson() => new() { ["strategy"] = Strategy, ["token"] = Token };

    public static Cursor FromJson(JsonNode? node)
    {
        if (node is JsonObject obj && JsonRead.HasExactly(obj, "strategy", "token")
            && JsonRead.TryString(obj["strategy"], out var strategy) && Strategies.Contains(strategy)
            && JsonRead.TryString(obj["token"], out var token) && JsonRead.CodePoints(token) <= MaxTokenCodePoints)
        {
            return new Cursor(strategy, token);
        }
        throw new ProtocolException(ErrorCodes.PacketInvalid);
    }
}
