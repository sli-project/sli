using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Server.Compatibility;

namespace Sli.Server.Storage.Direct;

// The importer projects an admitted native packet into bounded short fields.
// Packet identity is transient input to the database's provenance gate.
internal sealed record ShortEventRow(long EventId, DateTime Time, int Kind, string Layer,
    string? Actor, string? Target, string? Source, string Computer, long DomainId,
    string Method, string Outcome, IReadOnlyDictionary<string, string?> Fields, Guid? PacketId = null, int? PacketOrdinal = null)
{
    internal static ShortEventRow? Create(long eventId, long domainId, JsonObject row, Direct4624Projection projection, long? serverId = null)
    {
        var catalog = EventStorageMeaning.Current;
        var meaning = catalog.Find(projection);
        if (meaning is null || meaning.Layer == "not_collected") return null;
        int limit = catalog.Common.MaxLength;
        var data = new Dictionary<string, string>(projection.Data, StringComparer.Ordinal);
        // This identity comes from System/Security, never from host EventData.
        data.Remove("$user_id");
        if (row["user_id"] is JsonValue user && user.TryGetValue<string>(out var userId)) data["$user_id"] = userId;
        string? machine = null;
        // UserData wraps named values in a provider namespace; the old generic
        // parser exposes only its top-level wrapper. Keep only named leaves.
        if (row["xml"] is JsonValue xml && xml.TryGetValue<string>(out var native)) {
            var root = EventXml.ParseBounded(native);
            machine = Bound(root.Element(XName.Get("System", EventXml.Namespace))?.Element(XName.Get("Computer", EventXml.Namespace))?.Value, limit);
            foreach (var leaf in root.Elements(XName.Get("UserData", EventXml.Namespace))
                .Descendants().Where(e => !e.HasElements))
                data.TryAdd(leaf.Name.LocalName, leaf.Value);
        }
        var rights = meaning.ReplicationRights.Where(g => ContainsGuid(data.GetValueOrDefault("Properties"), g)).ToArray();
        if (meaning.ReplicationRights.Length > 0 && rights.Length == 0) return null;
        string computer = Bound(row["computer_name"]?.GetValue<string>(), limit)
            ?? throw new InvalidDataException("short_event_computer_missing");
        data["$computer"] = computer;
        data["$channel"] = projection.Channel;
        if (rights.Length > 0) data["$replication_rights"] = string.Join(',', rights);
        if (meaning.Fields.Any(f => f.Sources.Any(s => s.StartsWith("$task_", StringComparison.Ordinal))))
            TaskFields(data);
        string? Pick(IEnumerable<string> keys, int length) => keys.Select(k => Bound(data.GetValueOrDefault(k), length))
            .FirstOrDefault(value => value is not null);
        string? Account(string[] keys, string[] domainKeys)
        {
            string? account = Pick(keys, limit);
            if (account is null || account.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) || account.Contains('\\')) return account;
            string? domain = Pick(domainKeys, limit);
            return Bound(domain is null ? account : domain + "\\" + account, limit);
        }
        // JSON encodes the dimensions without delimiter collisions from host
        // strings. Null is distinct from zero; failure subcodes and encryption
        // are kept separately for the future daily-summary grouping key.
        string Dimensions(string[] keys, bool keywords = false)
        {
            var values = new Dictionary<string, string?>();
            foreach (string key in keys)
                if (Bound(data.GetValueOrDefault(key), 64) is { } value) values[key] = value;
            if (keywords && Bound(projection.Keywords, 64) is { } flags) values["keywords"] = flags;
            return JsonSerializer.Serialize(values);
        }
        var fields = meaning.Fields.ToDictionary(f => f.Name, f => Pick(f.Sources, f.MaxLength), StringComparer.Ordinal);
        // Keep the admitted source identity with the short row. Readers must not
        // infer a provider from a numeric event kind or a server from host text.
        var method = JsonNode.Parse(Dimensions(catalog.Common.MethodFields))!.AsObject();
        method["$server_id"] = serverId;
        method["$channel"] = projection.Channel;
        method["$provider"] = projection.Provider;
        method["$machine_name"] = machine;
        // A destination computer is an entity of 4648/4769 too. Daily groups
        // discard fields, so keep its admitted identity among the dimensions.
        var destination = projection.Entities.FirstOrDefault(e => e.Type=="asset" && e.Role=="target");
        if(destination is not null && destination.NaturalKey.EnumerateRunes().Count()<=limit)
            method["$target_server"] = destination.NaturalKey;
        // Principal names must survive even when the display identity is a SID.
        // Keep conflicting client addresses too: choosing one would change a
        // password detector's decision. These are bounded dimensions, not XML.
        method["$principals"] = JsonSerializer.SerializeToNode(new[] {
            "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "TargetSid",
            "TargetUserSid", "TargetUserName", "TargetDomainName", "IpAddress",
            "ClientAddress", "SourceNetworkAddress", "Workstation", "WorkstationName"
        }.Where(data.ContainsKey).ToDictionary(k => k, k => Bound(data[k], limit)));
        return new ShortEventRow(eventId, DirectEventTime.Utc(row["time_created"]!.GetValue<string>()), projection.EventKind,
            meaning.Layer, Account(meaning.ActorFields ?? catalog.Common.ActorFields,
                meaning.ActorDomainFields ?? catalog.Common.ActorDomainFields),
            Account(meaning.TargetFields ?? catalog.Common.TargetFields, meaning.TargetDomainFields ?? catalog.Common.TargetDomainFields),
            Pick(catalog.Common.SourceFields, limit), computer, domainId,
            method.ToJsonString(), Dimensions(catalog.Common.OutcomeFields, keywords: true), fields);
    }

    private static bool ContainsGuid(string? properties, string guid)
    {
        if (properties is null) return false;
        int offset = 0;
        while ((offset = properties.IndexOf(guid, offset, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            int end = offset + guid.Length;
            if ((offset == 0 || !IsGuidCharacter(properties[offset - 1])) &&
                (end == properties.Length || !IsGuidCharacter(properties[end]))) return true;
            offset = end;
        }
        return false;
    }

    private static bool IsGuidCharacter(char c) => char.IsAsciiHexDigit(c) || c == '-';

    private static string? Bound(string? value, int length)
    {
        if (value is null) return null;
        value = PythonText.Strip(value);
        if (value is "" or "-" or "—") return null;
        // PostgreSQL text cannot contain NUL. Unicode runes prevent cutting a
        // surrogate pair; host text stays data and is never interpreted here.
        string result = string.Concat(value.EnumerateRunes().Where(r => r.Value != 0).Take(length).Select(r => r.ToString()));
        return result.Length == 0 ? null : result;
    }

    private static void TaskFields(Dictionary<string, string> data)
    {
        foreach (string key in new[] { "$task_command", "$task_arguments", "$task_user" }) data.Remove(key);
        string? task = data.GetValueOrDefault("TaskContentNew") ?? data.GetValueOrDefault("TaskContent");
        if (string.IsNullOrWhiteSpace(task)) return;
        XElement root;
        try { root = EventXml.ParseBounded(task); }
        catch (EventXmlException) { throw new InvalidDataException("short_event_task_xml_invalid"); }
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        if (root.Name != ns + "Task") throw new InvalidDataException("short_event_task_xml_invalid");
        var actions = root.Element(ns + "Actions");
        // The compact format has one field per task property; preserve all Exec
        // actions within its field bound, rather than selecting an arbitrary one.
        string Join(string name) => string.Join("; ", actions?.Elements(ns + "Exec").Elements(ns + name).Select(e => e.Value) ?? []);
        data["$task_command"] = Join("Command");
        data["$task_arguments"] = Join("Arguments");
        var principals = root.Element(ns + "Principals")?.Elements(ns + "Principal").ToArray() ?? [];
        string? context = (string?)actions?.Attribute("Context");
        var principal = context is null ? principals.SingleOrDefault() : principals.SingleOrDefault(p => (string?)p.Attribute("id") == context);
        data["$task_user"] = principal?.Element(ns + "UserId")?.Value ?? principal?.Element(ns + "GroupId")?.Value ?? "";
    }
}
