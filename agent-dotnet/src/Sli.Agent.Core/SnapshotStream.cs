using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public sealed record SnapshotFamily(JsonNode Data, int Count);

/// <summary>Frozen source evidence survives restarts and queue backpressure. Only the queue advances the cursor.</summary>
public sealed class SnapshotStream
{
    public const int FragmentBytes = 32768;
    private readonly string _root;
    private readonly string _moduleId;
    private readonly IDurableFiles _files;
    // One runtime owns the queue/state directory. Retain its frozen capture so each fragment is O(fragment bytes).
    private JsonObject? _cached;
    private bool _loaded;
    private string CyclePath => Path.Combine(_root, "cycle.json");
    private string LastPath => Path.Combine(_root, "last_slot.json");

    public SnapshotStream(string root, string moduleId, IDurableFiles files)
    {
        if (moduleId is not (SnapshotPolicy.Ad or SnapshotPolicy.Gpo)) throw new AgentException("agent_snapshot_invalid");
        _root = Path.Combine(root, moduleId); _moduleId = moduleId; _files = files;
        files.EnsureDirectory(_root);
    }

    public JsonObject? Read()
    {
        if (_loaded) return _cached;
        try { if (_files.Length(CyclePath) > 128 * 1024 * 1024) throw new AgentException("agent_snapshot_state_invalid"); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        var raw = _files.ReadAll(CyclePath);
        if (raw is null) { _loaded = true; return null; }
        try
        {
            var state = JsonNode.Parse(raw)!.AsObject();
            var ready = state["ready"]!.GetValue<bool>();
            if (!JsonRead.HasExactly(state, ready ? ["cycle_id", "slot_start_utc", "policy", "ready", "families"] : ["cycle_id", "slot_start_utc", "policy", "ready"])
                || !Guid.TryParseExact(state["cycle_id"]!.GetValue<string>(), "D", out _)
                || !Iso8601.TryParseUtc(state["slot_start_utc"]!.GetValue<string>(), out _)) throw new AgentException("agent_snapshot_state_invalid");
            var policy = SnapshotPolicy.Parse(_moduleId, state["policy"]!.AsObject());
            if (!JsonNode.DeepEquals(policy.Config, state["policy"])) throw new AgentException("agent_snapshot_state_invalid");
            _cached = state; _loaded = true; return state;
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or NullReferenceException or FormatException)
        { throw new AgentException("agent_snapshot_state_invalid"); }
    }

    public JsonObject? Begin(SnapshotPolicy policy, DateTimeOffset now, Func<Guid>? newId = null)
    {
        var state = Read();
        if (state is not null) return state;
        var slot = policy.DueSlot(now);
        var last = _files.ReadAll(LastPath);
        if (last is not null && string.CompareOrdinal(JsonNode.Parse(last)!["slot"]!.GetValue<string>(), slot) >= 0) return null;
        state = new JsonObject { ["cycle_id"] = (newId ?? Guid.NewGuid)().ToString(), ["slot_start_utc"] = slot,
            ["policy"] = policy.Config.DeepClone(), ["ready"] = false };
        _files.WriteAtomic(CyclePath, CanonicalJson.ToBytes(state));
        _cached = state; _loaded = true;
        return state;
    }

    public void Freeze(JsonObject state, IReadOnlyDictionary<string, SnapshotFamily> families)
    {
        var policy = SnapshotPolicy.Parse(_moduleId, state["policy"]!.AsObject());
        if (!families.Keys.Order().SequenceEqual(policy.Families.Order())) throw new AgentException("agent_snapshot_invalid");
        var encoded = new JsonObject();
        long size = 0;
        var counts = new List<int>();
        foreach (var family in policy.Families)
        {
            var info = families[family];
            // Normalizers remove sensitive source attributes. A final recursive privacy gate precedes every disk write.
            var raw = CanonicalJson.ToBytes(SnapshotPrivacy.Mask(info.Data, _moduleId == SnapshotPolicy.Gpo));
            var limit = family == "computers_v6" ? 64 * 1024 * 1024 : policy.Number("max_bytes");
            if (info.Count < 0 || info.Count > policy.Number("max_objects") || raw.Length > limit) throw new AgentException("agent_snapshot_size_limit");
            size += family == "computers_v6" ? 0 : raw.Length; counts.Add(info.Count);
            encoded[family] = new JsonObject { ["data_b64"] = Convert.ToBase64String(raw), ["total_objects"] = info.Count,
                ["total_bytes"] = raw.Length, ["family_sha256"] = Convert.ToHexStringLower(SHA256.HashData(raw)) };
        }
        if (size > policy.Number("max_bytes") || (_moduleId == SnapshotPolicy.Gpo ? counts.Max() : counts.Sum()) > policy.Number("max_objects")) throw new AgentException("agent_snapshot_size_limit");
        var frozen = (JsonObject)state.DeepClone(); frozen["ready"] = true; frozen["families"] = encoded;
        var bytes = CanonicalJson.ToBytes(frozen);
        if (bytes.Length > policy.Number("buffer_bytes")) throw new AgentException("agent_snapshot_buffer_limit");
        var existing = Read();
        if (existing is null || !JsonNode.DeepEquals(existing["cycle_id"], state["cycle_id"]) || existing["ready"]!.GetValue<bool>() && !JsonNode.DeepEquals(existing, frozen))
            throw new AgentException("agent_snapshot_cycle_conflict");
        _files.WriteAtomic(CyclePath, bytes);
        _cached = frozen; _loaded = true;
    }

    public Sample? NextSample(CapturedPosition? captured)
    {
        var state = Read();
        if (state is null || !state["ready"]!.GetValue<bool>()) return null;
        var policy = SnapshotPolicy.Parse(_moduleId, state["policy"]!.AsObject());
        var before = captured?.CursorAfter ?? Cursor.Start("snapshot");
        var previous = ParseCursor(before);
        var family = policy.Families[0]; var index = 0;
        if (previous is not null && JsonNode.DeepEquals(previous["cycle_id"], state["cycle_id"]))
        {
            if (!JsonNode.DeepEquals(previous["cycle_families"], policy.Config["families"])) throw new AgentException("agent_snapshot_cursor_invalid");
            family = previous["family"]!.GetValue<string>(); index = previous["chunk_index"]!.GetValue<int>() + 1;
            if (index == previous["chunk_count"]!.GetValue<int>())
            {
                var next = Array.IndexOf(policy.Families, family) + 1;
                if (next == policy.Families.Length)
                {
                    _files.WriteAtomic(LastPath, CanonicalJson.ToBytes(new JsonObject { ["slot"] = state["slot_start_utc"]!.DeepClone() }));
                    _files.Delete(CyclePath); _cached = null; _loaded = true; return null;
                }
                family = policy.Families[next]; index = 0;
            }
        }
        else if (previous is not null && (previous["family"]!.GetValue<string>() != previous["cycle_families"]!.AsArray().Last()!.GetValue<string>()
            || previous["chunk_index"]!.GetValue<int>() != previous["chunk_count"]!.GetValue<int>() - 1)) throw new AgentException("agent_snapshot_cursor_invalid");
        var info = state["families"]![family]!;
        var size = info["total_bytes"]!.GetValue<int>();
        var count = Math.Max(1, (size + FragmentBytes - 1) / FragmentBytes);
        if (index >= count) throw new AgentException("agent_snapshot_state_invalid");
        var start = index * FragmentBytes; var end = Math.Min((index + 1) * FragmentBytes, size);
        // Base64 groups cover three bytes. Decode only the groups overlapping this fragment (Python next_sample).
        var encoded = info["data_b64"]!.GetValue<string>();
        var firstGroup = start / 3 * 4; var lastGroup = (end + 2) / 3 * 4;
        var raw = Convert.FromBase64String(encoded[firstGroup..lastGroup]);
        var fragment = raw.AsSpan(start % 3, end - start);
        var payload = new JsonObject { ["contract"] = _moduleId + ".chunk.v1", ["cycle_id"] = state["cycle_id"]!.DeepClone(),
            ["family"] = family, ["slot_start_utc"] = state["slot_start_utc"]!.DeepClone(), ["chunk_index"] = index, ["chunk_count"] = count,
            ["cycle_families"] = policy.Config["families"]!.DeepClone(), ["total_objects"] = info["total_objects"]!.DeepClone(),
            ["total_bytes"] = size, ["family_sha256"] = info["family_sha256"]!.DeepClone(),
            ["records"] = new JsonArray(new JsonObject { ["data_b64"] = Convert.ToBase64String(fragment) }) };
        foreach (var key in new[] { "domain_sid", "domain_dns", "scope" }) payload[key] = policy.Config[key]!.DeepClone();
        return new Sample(_moduleId, policy.SourceId, "snapshot", policy.SourceId, before, MakeCursor(payload), payload,
            PolicyRevision: policy.Revision, ContinuityState: "complete", LostCount: 0);
    }

    public static Cursor MakeCursor(JsonObject payload)
    {
        var token = new JsonObject();
        foreach (var key in new[] { "cycle_id", "family", "chunk_index", "chunk_count", "cycle_families" }) token[key] = payload[key]!.DeepClone();
        return new("snapshot", CanonicalJson.Serialize(token));
    }

    public static JsonObject? ParseCursor(Cursor cursor)
    {
        try
        {
            if (cursor.Strategy != "snapshot") throw new FormatException();
            if (cursor.Token == "") return null;
            var s = JsonNode.Parse(cursor.Token)!.AsObject();
            if (!JsonRead.HasExactly(s, "cycle_id", "family", "chunk_index", "chunk_count", "cycle_families") || CanonicalJson.Serialize(s) != cursor.Token
                || !Guid.TryParseExact(s["cycle_id"]!.GetValue<string>(), "D", out var id) || id.ToString() != s["cycle_id"]!.GetValue<string>()
                || s["cycle_families"] is not JsonArray fs || fs.Count is < 1 or > 6 || fs.Any(f => !JsonRead.TryString(f, out _))
                || fs.Select(f => f!.GetValue<string>()).Distinct().Count() != fs.Count || !fs.Any(f => JsonNode.DeepEquals(f, s["family"]))
                || !JsonRead.TryInteger(s["chunk_index"], out var index) || !JsonRead.TryInteger(s["chunk_count"], out var count) || index < 0 || index >= count || count > 2048) throw new FormatException();
            return s;
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or FormatException or NullReferenceException)
        { throw new AgentException("agent_snapshot_cursor_invalid"); }
    }
}
