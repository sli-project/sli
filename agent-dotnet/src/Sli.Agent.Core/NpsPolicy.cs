using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>The unchanged sli_agent.nps policy and opaque Accounting cursor contracts.</summary>
public sealed record NpsPolicy(string ModuleId, JsonObject Value)
{
    public const string Nps = "sli.vpn-nps";
    public const string Accounting = "sli.radius-accounting";
    public const int MaxPayloadBytes = 44 * 1024;
    public string SourceId => Value["source_instance_id"]!.GetValue<string>();
    public string Revision => Value["policy_revision"]!.GetValue<string>();
    public int BatchSize => Value["batch_size"]!.GetValue<int>();
    public string Family => ModuleId == Nps ? "nps" : "radius_accounting";
    public bool Active => !Value["paused"]!.GetValue<bool>() && Value["families"]![Family]!.GetValue<bool>();
    public string Text(string key) => Value[key]!.GetValue<string>();

    public static NpsPolicy Parse(string module, JsonObject input)
    {
        static AgentException Invalid() => new("agent_nps_config_invalid");
        try
        {
            var specific = module == Nps ? new[] { "source_name", "connect_address", "event_generation", "batch_size" }
                : new[] { "accounting_directory", "initial_cursor", "subscription_id", "source_timezone_id", "source_utc_offset_minutes", "batch_size" };
            if (module is not (Nps or Accounting) || input.Any(p => !specific.Concat(["source_instance_id", "policy_revision", "paused", "families"]).Contains(p.Key))) throw Invalid();
            var value = new JsonObject { ["policy_revision"] = "1", ["paused"] = false, ["batch_size"] = 32 };
            if (module == Nps) value["event_generation"] = "1";
            foreach (var p in input) value[p.Key] = p.Value?.DeepClone();
            var family = module == Nps ? "nps" : "radius_accounting";
            if (value.ContainsKey("families") && (value["families"] is not JsonObject f || f.Any(p => p.Key != family || !IsBool(p.Value)))) throw Invalid();
            value["families"] = new JsonObject { [family] = value["families"]?[family]?.DeepClone() ?? JsonValue.Create(true) };
            foreach (var name in specific.Concat(["source_instance_id", "policy_revision"]).Except(["batch_size", "initial_cursor", "source_utc_offset_minutes"]))
                if (!JsonRead.TryString(value[name], out var text) || string.IsNullOrWhiteSpace(text) || JsonRead.CodePoints(text) > 512) throw Invalid();
            if (!IsBool(value["paused"]) || !JsonRead.TryInteger(value["batch_size"], out var batch) || batch < 1 || batch > 128) throw Invalid();
            if (module == Nps)
            {
                if (JsonRead.CodePoints(value["event_generation"]!.GetValue<string>()) > 128) throw Invalid();
            }
            else
            {
                var cursor = RadiusCursor.Parse(value["initial_cursor"]);
                if (cursor.SourceId != value["source_instance_id"]!.GetValue<string>() || !JsonRead.TryInteger(value["source_utc_offset_minutes"], out var offset) || offset < -840 || offset > 840) throw Invalid();
            }
            return new(module, value);
        }
        catch (Exception e) when (e is AgentException or InvalidOperationException or JsonException) { throw Invalid(); }
    }
    internal static bool IsBool(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out _);
}

public sealed record RadiusCursor(string SourceId, string StreamId, string TransportBinding, string FileGeneration, long ByteOffset, string? LastRecordSha256)
{
    private static readonly Regex Identifier = new("\\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\\z", RegexOptions.CultureInvariant);
    internal static bool IsHash(string value) => Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant);
    public JsonObject ToJson() => new()
    {
        ["source_instance_id"] = SourceId, ["stream_id"] = StreamId, ["transport_binding"] = TransportBinding,
        ["file_generation"] = FileGeneration, ["byte_offset"] = ByteOffset, ["last_record_sha256"] = LastRecordSha256,
    };
    public static RadiusCursor Parse(JsonNode? node)
    {
        static AgentException Invalid() => new("agent_radius_cursor_invalid");
        if (node is not JsonObject value) throw Invalid();
        var fields = new[] { "source_instance_id", "stream_id", "transport_binding", "file_generation", "byte_offset", "last_record_sha256" };
        if (value.Count != fields.Length + (value.ContainsKey("exact_boundary_recovery") ? 1 : 0) || fields.Any(n => !value.ContainsKey(n))
            || value.ContainsKey("exact_boundary_recovery") && !NpsPolicy.IsBool(value["exact_boundary_recovery"])) throw Invalid();
        foreach (var key in fields.Take(4)) if (!JsonRead.TryString(value[key], out var s) || !Identifier.IsMatch(s)) throw Invalid();
        if (value["stream_id"]!.GetValue<string>() != "radius-accounting" || !JsonRead.TryInteger(value["byte_offset"], out var offset) || offset < 0 || offset > long.MaxValue
            || value["last_record_sha256"] is not null && (!JsonRead.TryString(value["last_record_sha256"], out var hash) || !IsHash(hash))) throw Invalid();
        return new(value["source_instance_id"]!.GetValue<string>(), value["stream_id"]!.GetValue<string>(), value["transport_binding"]!.GetValue<string>(),
            value["file_generation"]!.GetValue<string>(), (long)offset, value["last_record_sha256"]?.GetValue<string>());
    }
    internal static JsonObject Token(Cursor cursor, string strategy, string error)
    {
        if (cursor.Strategy != strategy) throw new AgentException(error);
        try { return JsonNode.Parse(cursor.Token) as JsonObject ?? throw new AgentException(error); }
        catch (JsonException) { throw new AgentException(error); }
    }
}
