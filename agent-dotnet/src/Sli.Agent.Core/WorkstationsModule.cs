using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public sealed record WorkstationPolicy(JsonObject Value, int BatchSize, int RateWindowSeconds)
{
    internal const int DefenderChannelIndex = 2;
    public static readonly string[] Channels = ["Security", "System", "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-Kernel-PnP/Configuration", "Microsoft-Windows-PowerShell/Operational"];
    public static readonly string[] Providers = ["Microsoft-Windows-Security-Auditing", "Service Control Manager", "Microsoft-Windows-Windows Defender",
        "Microsoft-Windows-TaskScheduler", "Microsoft-Windows-DriverFrameworks-UserMode", "Microsoft-Windows-Kernel-PnP", "Microsoft-Windows-PowerShell"];
    public static readonly int[][] ChannelEvents = [[1102,4624,4625,4634,4647,4688,4697,4698,4699,4700,4701,4702,4732,4733,4719,6416],
        [7036,7040,7045], [5001,5010,5012], [106,140,141,142], [2003,2100,2101], [400,410,420], [4104]];
    public static readonly IReadOnlyDictionary<string, int[]> FamilyEvents = new Dictionary<string, int[]>
    {
        ["logons"] = [4624,4625,4634,4647], ["processes"] = [4688], ["usb"] = [6416,2003,2100,2101,400,410,420],
        ["local_admins"] = [4732,4733], ["protection"] = [1102,7036,7040,4104,4697,4698,4699,4700,4701,4702,4719,7045,5001,5010,5012,106,140,141,142],
    };

    public bool FamilyEnabled(string name) => Value["families"]?[name]?.GetValue<bool>() ?? true;

    public bool ChannelEnabled(int index)
    {
        // The Defender packet carries the current protection state as well as log events.
        if (index == DefenderChannelIndex && FamilyEnabled("protection")) return true;
        return FamilyEvents.Any(family => family.Value.Any(id => ChannelEvents[index].Contains(id) && EventEnabled(id, family.Key)));
    }

    internal bool EventEnabled(int id, string family) => FamilyEnabled(family)
        && MatchesEventFilter(Value, id)
        && MatchesEventFilter(Value["family_filters"]?[family], id);

    private static bool MatchesEventFilter(JsonNode? filter, int id) =>
        (filter?["allow_event_ids"] is not JsonArray allow || allow.Any(item => item!.GetValue<int>() == id))
        && (filter?["deny_event_ids"] is not JsonArray deny || !deny.Any(item => item!.GetValue<int>() == id));

    public string Revision => Value["policy_revision"]?.GetValue<string>() ?? "1";

    public static WorkstationPolicy Parse(JsonObject value)
    {
        try
        {
            var allowed = new[] { "policy_revision", "allow_event_ids", "deny_event_ids", "allow_process_paths", "deny_process_paths", "rate_limits",
                "rate_window_seconds", "batch_size", "channel_generations", "families", "family_filters", "protected_services" };
            if (value.Any(item => !allowed.Contains(item.Key))) throw new InvalidOperationException();
            var config = (JsonObject)value.DeepClone();
            if (config.ContainsKey("protected_services") && (config["protected_services"] is not JsonArray services || services.Count > 64
                || services.Any(s => !JsonRead.TryString(s, out var text) || string.IsNullOrWhiteSpace(text) || text.Length > 256))) throw new InvalidOperationException();
            if (config.ContainsKey("policy_revision") && (!JsonRead.TryString(config["policy_revision"], out var revision) || string.IsNullOrWhiteSpace(revision) || revision.Length > 128)) throw new InvalidOperationException();
            var families = config["families"] as JsonObject ?? (config.ContainsKey("families") ? throw new InvalidOperationException() : new JsonObject());
            if (families.Any(item => !FamilyEvents.ContainsKey(item.Key) || item.Value is not JsonValue v || !v.TryGetValue<bool>(out _))) throw new InvalidOperationException();
            ValidateFilters(config);
            var filters = config["family_filters"] as JsonObject ?? (config.ContainsKey("family_filters") ? throw new InvalidOperationException() : new JsonObject());
            foreach (var pair in filters)
            {
                if (!FamilyEvents.TryGetValue(pair.Key, out var ids) || pair.Value is not JsonObject filter) throw new InvalidOperationException();
                var keys = pair.Key == "processes" ? new[] { "allow_event_ids", "deny_event_ids", "allow_process_paths", "deny_process_paths" } : ["allow_event_ids", "deny_event_ids"];
                if (filter.Any(item => !keys.Contains(item.Key))) throw new InvalidOperationException();
                ValidateFilters(filter);
                foreach (var name in new[] { "allow_event_ids", "deny_event_ids" })
                    if (filter[name] is JsonArray numbers && numbers.Any(item => !ids.Contains(item!.GetValue<int>()))) throw new InvalidOperationException();
            }
            int Number(string name, int fallback, int max)
            {
                if (!config.ContainsKey(name)) return fallback;
                if (!JsonRead.TryInteger(config[name], out var n) || n < 1 || n > max) throw new InvalidOperationException();
                return (int)n;
            }
            var generations = config["channel_generations"] as JsonObject ?? (config.ContainsKey("channel_generations") ? throw new InvalidOperationException() : new JsonObject());
            if (generations.Any(item => !Channels.Contains(item.Key) || !JsonRead.TryString(item.Value, out var g) || string.IsNullOrWhiteSpace(g) || g.Length > 128)) throw new InvalidOperationException();
            var rates = config["rate_limits"] as JsonObject ?? (config.ContainsKey("rate_limits") ? throw new InvalidOperationException() : new JsonObject());
            if (rates.Count > 32 || rates.Any(item => !int.TryParse(item.Key, NumberStyles.None, CultureInfo.InvariantCulture, out var id)
                || id.ToString(CultureInfo.InvariantCulture) != item.Key || !ChannelEvents.Any(ids => ids.Contains(id))
                || !JsonRead.TryInteger(item.Value, out var limit) || limit < 0 || limit > 1000000)) throw new InvalidOperationException();
            rates["4104"] = Math.Min(long.Parse(rates["4104"]?.ToJsonString() ?? "10", CultureInfo.InvariantCulture), 10L);
            if (!config.ContainsKey("rate_limits")) config["rate_limits"] = rates;
            return new(config, Number("batch_size", 32, 128), Number("rate_window_seconds", 60, 86400));
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or OverflowException)
        {
            throw new AgentException("agent_workstations_config_invalid");
        }
    }

    private static void ValidateFilters(JsonObject config)
    {
        foreach (var name in new[] { "allow_event_ids", "deny_event_ids" })
        {
            if (!config.ContainsKey(name) || name == "allow_event_ids" && config[name] is null) continue;
            if (config[name] is not JsonArray ids || ids.Count > 128 || ids.Any(item => !JsonRead.TryInteger(item, out var n) || n < 0 || n > 65535)) throw new InvalidOperationException();
        }
        foreach (var name in new[] { "allow_process_paths", "deny_process_paths" })
        {
            if (!config.ContainsKey(name)) continue;
            if (config[name] is not JsonArray patterns || patterns.Count > 64 || patterns.Any(item => !JsonRead.TryString(item, out var p) || string.IsNullOrWhiteSpace(p) || p.Length > 512)) throw new InvalidOperationException();
        }
    }
}

/// <summary>Port of sli_agent/workstations.py. Every cursor and rate count is committed inside the signed packet.</summary>
public sealed class WorkstationsModule(string hostId, WorkstationPolicy policy, IEventLogSource source, Func<JsonObject>? protectionReader = null)
{
    public const string ModuleId = "sli.workstations";
    public const string ModuleVersion = "1.1.0";
    public static readonly string[] ProtectedServices = ["SLIAgentNet", "SLI Agent .NET", "SLIAgent", "SLI Agent", "WinDefend", "Sense", "VSS", "wbengine",
        "Microsoft Defender Antivirus Service", "Windows Defender Antivirus Service", "Microsoft Defender for Endpoint Service",
        "Windows Defender Advanced Threat Protection Service", "Volume Shadow Copy", "Block Level Backup Engine Service",
        "Служба антивирусной программы Microsoft Defender", "Служба антивирусной программы Защитник Windows",
        "Теневое копирование тома", "Служба модуля архивации на уровне блоков"];
    private const int MaxPayloadBytes = 44 * 1024;
    private (DateTimeOffset At, JsonObject Value)? _protectionSnapshot;
    private static AgentException InvalidCursor() => new("agent_workstations_cursor_invalid");

    public CollectResult Collect(CapturedPosition? captured, DateTimeOffset now, string? channelOverride = null)
    {
        now = Iso8601.Truncate(now);
        var before = captured?.CursorAfter ?? Cursor.Start("bookmark");
        var state = new JsonObject { ["next"] = 0, ["channels"] = new JsonObject(), ["rate"] = new JsonObject { ["window"] = null, ["counts"] = new JsonObject() } };
        if (captured is not null)
        {
            try
            {
                if (captured.Generation != hostId || before.Strategy != "bookmark") throw InvalidCursor();
                state = JsonNode.Parse(before.Token)!.AsObject();
                if (!JsonRead.HasExactly(state, "next", "channels", "rate") || !JsonRead.TryInteger(state["next"], out var next) || next < 0 || next >= WorkstationPolicy.Channels.Length
                    || state["channels"] is not JsonObject saved || saved.Any(item => !WorkstationPolicy.Channels.Contains(item.Key))
                    || state["rate"] is not JsonObject rateState || !JsonRead.HasExactly(rateState, "window", "counts")
                    || rateState["window"] is not null && !JsonRead.TryInteger(rateState["window"], out _)
                    || rateState["counts"] is not JsonObject counts || counts.Count > 32 || counts.Any(item => !item.Key.All(char.IsAsciiDigit) || !JsonRead.TryInteger(item.Value, out var n) || n < 0)) throw InvalidCursor();
                foreach (var entry in saved)
                    if (entry.Value is not JsonObject p || !JsonRead.HasExactly(p, "record_id", "bookmark", "generation")
                        || p["record_id"] is not null && (!JsonRead.TryInteger(p["record_id"], out var n) || n < 0 || n > long.MaxValue)
                        || !JsonRead.TryString(p["bookmark"], out _) || !JsonRead.TryString(p["generation"], out _)) throw InvalidCursor();
            }
            catch (Exception exception) when (exception is System.Text.Json.JsonException or InvalidOperationException or NullReferenceException) { throw InvalidCursor(); }
        }
        if (!Enumerable.Range(0, WorkstationPolicy.Channels.Length).Any(policy.ChannelEnabled)) return new(null, null);
        var index = Enumerable.Range(0, WorkstationPolicy.Channels.Length).Select(offset => (state["next"]!.GetValue<int>() + offset) % WorkstationPolicy.Channels.Length).First(policy.ChannelEnabled);
        if (channelOverride is not null)
        {
            index = Array.IndexOf(WorkstationPolicy.Channels, channelOverride);
            if (index < 0 || !policy.ChannelEnabled(index)) throw new AgentException("agent_workstations_channel_invalid");
        }
        var channel = WorkstationPolicy.Channels[index];
        var generation = policy.Value["channel_generations"]?[channel]?.GetValue<string>() ?? hostId;
        var channels = state["channels"]!.AsObject();
        var progress = channels[channel]?.AsObject();
        var reset = progress is not null && progress["generation"]!.GetValue<string>() != generation;
        if (progress is null || reset) progress = new JsonObject { ["record_id"] = null, ["bookmark"] = "", ["generation"] = generation };
        var afterId = progress["record_id"]?.GetValue<long>();
        var previousId = afterId;
        var rate = state["rate"]!.AsObject();
        var window = now.ToUnixTimeSeconds() / policy.RateWindowSeconds;
        if (rate["window"] is null || window > rate["window"]!.GetValue<long>())
        {
            rate["window"] = window;
            rate["counts"] = new JsonObject();
        }
        var rates = policy.Value["rate_limits"] as JsonObject ?? new JsonObject();
        var countsNow = rate["counts"]!.AsObject();
        foreach (var name in countsNow.Select(item => item.Key).Where(name => !rates.ContainsKey(name)).ToArray()) countsNow.Remove(name);
        SourceBatch batch;
        string? error = null;
        try { batch = source.Read(channel, new ChannelProgress(afterId, progress["bookmark"]!.GetValue<string>(), generation), policy.BatchSize); }
        catch (EventLogReadException) { batch = new SourceBatch([]); error = "agent_workstations_read_failed"; }
        if (batch.Rows.Count > policy.BatchSize) throw new AgentException("agent_workstations_range_invalid");
        var records = new List<PacketRecord>();
        var dropped = new JsonObject();
        var filtered = 0;
        var full = false;
        foreach (var raw in batch.Rows)
        {
            var row = EventXml.Parse(raw.Xml, hostId, "localhost", channel);
            if (!JsonRead.TryInteger(row["record_id"], out var id) || id < 0 || id > long.MaxValue || previousId is not null && id <= previousId || string.IsNullOrEmpty(raw.Bookmark))
                throw new AgentException("agent_workstations_range_invalid");
            previousId = (long)id;
            var root = EventXml.ParseBounded(raw.Xml);
            if (EventXml.NativeChannel(root) != channel) throw new AgentException("agent_workstations_channel_invalid");
            var data = new Dictionary<string, string?>();
            System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            foreach (var field in root.Descendants(ns + "EventData").Elements(ns + "Data"))
                if (field.Attribute("Name")?.Value is { Length: > 0 } name && !data.TryAdd(name, field.Value)) throw new AgentException("agent_workstations_duplicate_event_field");
            var allowed = Allowed(row, data, index);
            var eventKey = row["event_id"]?.ToJsonString() ?? "None";
            var limited = allowed && rates[eventKey] is not null && (countsNow[eventKey]?.GetValue<long>() ?? 0) >= rates[eventKey]!.GetValue<long>();
            if (allowed && !limited)
            {
                row = BoundTamper(row, root);
                var record = new PacketRecord("event_xml", id, row);
                var candidate = new JsonArray(records.Append(record).Select(item => (JsonNode?)new JsonObject
                { ["format"] = item.Format, ["record_id"] = JsonRead.Integer(item.RecordId!.Value), ["payload"] = item.Payload.DeepClone() }).ToArray());
                if (CanonicalJson.ToBytes(candidate).Length > MaxPayloadBytes - 4096)
                {
                    if (records.Count == 0) throw new AgentException("agent_workstations_event_size_limit");
                    full = true;
                    break;
                }
                records.Add(record);
                if (rates[eventKey] is not null) countsNow[eventKey] = (countsNow[eventKey]?.GetValue<long>() ?? 0) + 1;
            }
            else if (limited) dropped[eventKey] = (dropped[eventKey]?.GetValue<long>() ?? 0) + 1;
            else filtered++;
            progress = new JsonObject { ["record_id"] = (long)id, ["bookmark"] = raw.Bookmark, ["generation"] = generation };
        }
        channels[channel] = progress.DeepClone();
        state["next"] = (index + 1) % WorkstationPolicy.Channels.Length;
        var lost = dropped.Sum(item => item.Value!.GetValue<long>());
        var context = new JsonObject
        {
            ["policy_revision"] = policy.Revision, ["filtered_count"] = filtered, ["dropped_count"] = lost, ["dropped_by_event_id"] = dropped,
            ["rate_window_seconds"] = policy.RateWindowSeconds, ["channel_reset"] = reset, ["read_error"] = error,
        };
        if (batch.BookmarkRecovered) context["bookmark_recovered"] = true;
        if (index == WorkstationPolicy.DefenderChannelIndex && policy.FamilyEnabled("protection"))
        {
            if (_protectionSnapshot is null || _protectionSnapshot.Value.At != now)
                _protectionSnapshot = (now, ProtectionSnapshot.Validate((protectionReader ?? ProtectionSnapshot.Unavailable)()));
            context["protection_state"] = _protectionSnapshot.Value.Value.DeepClone();
        }
        var payload = CollectionPacket.Make(hostId, channel, generation, new JsonObject { ["after_record_id"] = afterId, ["last_record_id"] = progress["record_id"]?.DeepClone() },
            records, "not_proven", new JsonObject { ["workstations"] = context }, now);
        if (CanonicalJson.ToBytes(payload).Length > MaxPayloadBytes) throw new AgentException("agent_workstations_event_size_limit");
        var token = CanonicalJson.Serialize(state);
        if (token.Length > 4096) throw new AgentException("agent_workstations_cursor_size_limit");
        var gap = reset || error is not null || batch.BookmarkRecovered;
        return new(new Sample(ModuleId, hostId, "workstations", hostId, before, new Cursor("bookmark", token), payload, ModuleVersion: ModuleVersion, PolicyRevision: policy.Revision,
            ContinuityState: gap || lost > 0 ? "gap" : filtered > 0 ? "filtered" : "not_proven", FilteredCount: filtered, LostCount: gap ? null : lost),
            error is null && (full || batch.Rows.Count == policy.BatchSize) ? channel : null);
    }

    private bool Allowed(JsonObject row, Dictionary<string, string?> data, int index)
    {
        if (!JsonRead.TryInteger(row["event_id"], out var id) || id < 0 || id > 65535 || !WorkstationPolicy.ChannelEvents[index].Contains((int)id)
            || !string.Equals(row["provider_name"]?.GetValue<string>(), id == 1102 ? "Microsoft-Windows-Eventlog" : WorkstationPolicy.Providers[index], StringComparison.OrdinalIgnoreCase)) return false;
        if (id == 7036 || id == 7040)
        {
            var names = ProtectedServices.Concat((policy.Value["protected_services"] as JsonArray ?? new JsonArray()).Select(s => s!.GetValue<string>()))
                .Select(s => s.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var service = data.GetValueOrDefault("ServiceName") ?? (id == 7040 ? data.GetValueOrDefault("param4") : null) ?? data.GetValueOrDefault("param1") ?? "";
            if (!names.Contains(service.Trim())) return false;
        }
        var family = WorkstationPolicy.FamilyEvents.First(item => item.Value.Contains((int)id)).Key;
        if (!policy.EventEnabled((int)id, family)) return false;
        if (id == 4688)
        {
            var path = (data.GetValueOrDefault("NewProcessName") ?? "").Replace('\\', '/').ToLowerInvariant();
            foreach (var filters in new[] { policy.Value, policy.Value["family_filters"]?[family] })
            {
                if (filters?["allow_process_paths"] is JsonArray paths && paths.Count > 0 && !paths.Any(p => Glob(path, p!.GetValue<string>()))
                    || filters?["deny_process_paths"] is JsonArray excluded && excluded.Any(p => Glob(path, p!.GetValue<string>()))) return false;
            }
        }
        return id != 4732 && id != 4733 || data.GetValueOrDefault("TargetSid") == "S-1-5-32-544";
    }

    internal static string BoundedUtf8(string text, int limit)
    {
        var result = new System.Text.StringBuilder();
        var bytes = 0;
        foreach (var rune in text.EnumerateRunes())
        {
            if (bytes + rune.Utf8SequenceLength > limit) break;
            bytes += rune.Utf8SequenceLength;
            result.Append(rune.ToString());
        }
        return result.ToString();
    }

    private JsonObject BoundTamper(JsonObject row, XElement root)
    {
        if (row["event_id"]!.GetValue<int>() is not (1102 or 7036 or 7040 or 4104)) return row;
        XNamespace ns = EventXml.Namespace;
        var changed = false;
        var maskedCount = 0;
        void Mark(string name = "ScriptBlockTextTruncated")
        {
            var parent = root.Element(ns + "EventData")!;
            var marker = parent.Elements(ns + "Data").FirstOrDefault(e => e.Attribute("Name")?.Value == name);
            if (marker is null) { marker = new XElement(ns + "Data", new XAttribute("Name", name)); parent.Add(marker); }
            marker.Value = "true";
        }
        foreach (var field in root.Descendants(ns + "EventData").Elements(ns + "Data").ToArray())
        {
            var script = field.Attribute("Name")?.Value == "ScriptBlockText";
            var bounded = BoundedUtf8(field.Value, script ? 8192 : 512);
            var truncated = bounded != field.Value;
            if (script && row["event_id"]!.GetValue<int>() == 4104)
            {
                var masked = ScriptSecrets.Mask(field.Value);
                bounded = masked.Text;
                maskedCount += masked.Count;
                truncated = masked.Truncated;
                if (bounded.StartsWith(ScriptSecrets.MaskFailed, StringComparison.Ordinal)) Mark("ScriptMaskingFailed");
            }
            if (bounded != field.Value) { field.Value = bounded; changed = true; }
            if (truncated)
            {
                Mark("CollectionFieldsTruncated");
                if (script) Mark();
            }
        }
        if (row["event_id"]!.GetValue<int>() == 4104)
        {
            row["secrets_masked"] = maskedCount;
            var parent = root.Element(ns + "EventData");
            if (parent is not null)
            {
                var marker = parent.Elements(ns + "Data").FirstOrDefault(e => e.Attribute("Name")?.Value == "SecretsMasked");
                if (marker is null && maskedCount > 0) { marker = new XElement(ns + "Data", new XAttribute("Name", "SecretsMasked")); parent.Add(marker); }
                if (marker is not null) { marker.Value = maskedCount.ToString(CultureInfo.InvariantCulture); changed = true; }
            }
        }
        if (!changed && CanonicalJson.ToBytes(row).Length <= MaxPayloadBytes - 8192) return row;
        while (true)
        {
            var result = EventXml.Parse(root.ToString(SaveOptions.DisableFormatting), hostId, "localhost", row["channel"]!.GetValue<string>());
            if (row["event_id"]!.GetValue<int>() == 4104) result["secrets_masked"] = maskedCount;
            if (CanonicalJson.ToBytes(result).Length <= MaxPayloadBytes - 8192) return result;
            var script = root.Descendants(ns + "Data").FirstOrDefault(e => e.Attribute("Name")?.Value == "ScriptBlockText");
            if (script is null || script.Value.Length == 0) throw new AgentException("agent_workstations_event_size_limit");
            script.Value = BoundedUtf8(script.Value, System.Text.Encoding.UTF8.GetByteCount(script.Value) / 2);
            Mark();
        }
    }

    private static bool Glob(string path, string pattern)
    {
        pattern = pattern.Replace('\\', '/').ToLowerInvariant();
        var regex = new System.Text.StringBuilder("\\A");
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '*') regex.Append(".*");
            else if (c == '?') regex.Append('.');
            else if (c == '[' && pattern.IndexOf(']', i + 1) is var end && end > i + 1)
            {
                var group = pattern[(i + 1)..end];
                regex.Append('[');
                if (group.StartsWith('!')) { regex.Append('^'); group = group[1..]; }
                else if (group.StartsWith('^')) regex.Append('\\');
                regex.Append(group.Replace("\\", "\\\\", StringComparison.Ordinal)).Append(']');
                i = end;
            }
            else regex.Append(Regex.Escape(c.ToString()));
        }
        regex.Append("\\z");
        try { return Regex.IsMatch(path, regex.ToString(), RegexOptions.Singleline | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)); }
        catch (ArgumentException) { return false; }
    }
}
