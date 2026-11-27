using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Core;

namespace Sli.Server.Semantic;

internal sealed record SigmaEvent(int Id, string Channel, string Computer, DateTimeOffset At, JsonObject Fields, HashSet<string> Unavailable)
{
    internal static SigmaEvent Map(string xml)
    {
        try { return MapCore(xml); }
        catch (Exception e) when (e is FormatException or OverflowException or System.Xml.XmlException or EventXmlException)
        { throw new InvalidDataException("sigma_event_mapping_invalid"); }
    }
    private static SigmaEvent MapCore(string xml)
    {
        var root = EventXml.ParseBounded(xml); XNamespace ns = EventXml.Namespace;
        XElement? One(XElement parent, string name, bool required = true) { var nodes = parent.Elements(ns + name).ToArray(); if (nodes.Length > 1 || required && nodes.Length == 0) throw new InvalidDataException("sigma_event_structure_invalid"); return nodes.FirstOrDefault(); }
        string Text(XElement? node) => node is not null && !node.HasElements && node.Attribute(XName.Get("nil", "http://www.w3.org/2001/XMLSchema-instance")) is null ? node.Value : throw new InvalidDataException("sigma_event_structure_invalid");
        var system = One(root, "System")!; string channel = Text(One(system, "Channel")), provider = One(system, "Provider")?.Attribute("Name")?.Value ?? "";
        int id = int.Parse(Text(One(system, "EventID")), CultureInfo.InvariantCulture), version = int.Parse(Text(One(system, "Version")), CultureInfo.InvariantCulture);
        int[] versions = (channel, provider, id) switch
        {
            ("Security", "Microsoft-Windows-Eventlog", 1102) => [0],
            ("Security", "Microsoft-Windows-Security-Auditing", 4624 or 4688) => [0, 1, 2],
            ("Security", "Microsoft-Windows-Security-Auditing", 4698 or 4702) => [0, 1],
            ("Security", "Microsoft-Windows-Security-Auditing", 4768 or 4769) => [0, 2],
            ("Security", "Microsoft-Windows-Security-Auditing", 4625 or 4697 or 4719 or 4720 or 4732 or 4776 or 4781) => [0],
            ("System", "Service Control Manager", 7045 or 7036 or 7040) => [0],
            ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104) => [1], _ => []
        };
        if (!versions.Contains(version)) throw new InvalidDataException("sigma_event_schema_unsupported");
        string? guid = One(system, "Provider")?.Attribute("Guid")?.Value;
        if (guid is not null)
        {
            string expected = provider switch { "Microsoft-Windows-Security-Auditing" => "54849625-5478-4994-a5ba-3e3b0328c30d", "Microsoft-Windows-Eventlog" => "fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148", "Service Control Manager" => "555908d1-a6d7-4695-8e1e-26931d2012f4", _ => "a0c1853b-5c40-4b15-8766-3cf1c58f985a" };
            if (!Guid.TryParse(guid, out var parsed) || parsed.ToString() != expected) throw new InvalidDataException("sigma_event_provider_invalid"); guid = parsed.ToString();
        }
        string computer = Text(One(system, "Computer")), stamp = One(system, "TimeCreated")!.Attribute("SystemTime")?.Value ?? "";
        if (string.IsNullOrWhiteSpace(computer) || !Regex.IsMatch(stamp, @"\A[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}(\.[0-9]{1,9})?Z\z")) throw new InvalidDataException("sigma_event_header_invalid");
        ulong record = ulong.Parse(Text(One(system, "EventRecordID")), CultureInfo.InvariantCulture); if (record == 0) throw new InvalidDataException("sigma_event_header_invalid");
        var fields = new JsonObject(); var unavailable = new HashSet<string>(); var data = One(root, "EventData", false); var user = One(root, "UserData", false);
        if (data is not null && user is not null) throw new InvalidDataException("sigma_event_payload_ambiguous");
        var entries = new List<(string Name, string Value)>();
        if (user is not null)
        {
            XNamespace log = "http://manifests.microsoft.com/win/2004/08/windows/eventlog";
            if (id != 1102 || user.Elements().Count() != 1 || user.Elements().Single().Name != log + "LogFileCleared") throw new InvalidDataException("sigma_event_userdata_unsupported");
            foreach (var leaf in user.Elements().Single().Elements()) { if (leaf.Name.Namespace != log) throw new InvalidDataException("sigma_event_userdata_unsupported"); entries.Add((leaf.Name.LocalName, Text(leaf))); }
        }
        else if (data is not null)
        {
            if (data.Elements().Any(x => x.Name != ns + "Data" && x.Name != ns + "Binary")) throw new InvalidDataException("sigma_event_structure_invalid");
            var values = data.Elements(ns + "Data").ToArray(); var names = values.Select(x => x.Attribute("Name")?.Value).ToArray();
            if (names.Any(x => x is not null) && names.Any(x => x is null)) throw new InvalidDataException("sigma_event_payload_ambiguous");
            if (values.Length > 0 && names.All(x => x is null)) { if (channel != "System" || provider != "Service Control Manager" || id != 7045 || version != 0 || values.Length != 5) throw new InvalidDataException("sigma_event_positional_unsupported"); names = ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"]; fields["Data"] = new JsonArray(values.Select(x => JsonValue.Create(Text(x))).ToArray()); }
            entries.AddRange(values.Select((x, index) => (names[index]!, Text(x))));
        }
        var seen = new HashSet<string>(); HashSet<string> reserved = ["eventid", "provider_name", "provider_guid", "channel", "computer", "version", "eventrecordid", "timecreated", "processid", "threadid", "data", "message", "message_text", "renderedmessage", "rendered_message"];
        foreach (var entry in entries) { if (string.IsNullOrWhiteSpace(entry.Name) || entry.Name.Trim() != entry.Name || !seen.Add(entry.Name)) throw new InvalidDataException("sigma_event_payload_ambiguous"); if (!reserved.Contains(entry.Name.ToLowerInvariant()) || id == 4688 && entry.Name == "ProcessId") fields[entry.Name] = entry.Value; }
        if (id == 4688)
        {
            string[] unsupported = ["OriginalFileName", "Description", "Product", "Company", "FileVersion", "Hashes", "CurrentDirectory", "ParentCommandLine", "ParentUser", "ProcessGuid", "ParentProcessGuid"];
            foreach (string name in unsupported.Concat(["Image", "ParentImage", "User", "UserSid", "LogonId", "LogonIdNumeric", "IntegrityLevel", "ParentProcessId", "CreatorProcessId", "NativeProcessId"])) fields.Remove(name);
            unavailable.UnionWith(unsupported);
            bool Present(string key) => fields.Text(key) is { Length: > 0 } value && value.Trim().Length > 0 && value != "-";
            void Alias(string dest, string native) { if (Present(native)) fields[dest] = fields[native].Copy(); else unavailable.Add(dest); }
            ulong? Hex(string? value, int bits) => value is not null && Regex.IsMatch(value, @"\A0[xX][0-9a-fA-F]{1,16}\z") && ulong.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong n) && (bits == 64 || n <= uint.MaxValue) ? n : null;
            Alias("Image", "NewProcessName"); string? creator = fields.Text("ProcessId"); fields.Remove("ProcessId"); if (creator is not null) fields["CreatorProcessId"] = creator;
            foreach (var (dest, value) in new[] { ("ProcessId", fields.Text("NewProcessId")), ("ParentProcessId", creator) }) { if (Hex(value, 32) is { } number) fields[dest] = number; else unavailable.Add(dest); }
            if (version < 1) { fields.Remove("CommandLine"); unavailable.Add("CommandLine"); } else if (!Present("CommandLine")) unavailable.Add("CommandLine");
            if (version < 2) unavailable.UnionWith(["ParentImage", "IntegrityLevel"]);
            else { Alias("ParentImage", "ParentProcessName"); var levels = new Dictionary<string, string> { ["S-1-16-0"] = "Untrusted", ["S-1-16-4096"] = "Low", ["S-1-16-8192"] = "Medium", ["S-1-16-8448"] = "MediumPlus", ["S-1-16-12288"] = "High", ["S-1-16-16384"] = "System", ["S-1-16-20480"] = "ProtectedProcess" }; if (levels.TryGetValue(fields.Text("MandatoryLabel") ?? "", out string? level)) fields["IntegrityLevel"] = level; else unavailable.Add("IntegrityLevel"); }
            bool nullTarget = fields.Text("TargetUserSid") is null or "" or "-" or "S-1-0-0" && new[] { "TargetUserName", "TargetDomainName", "TargetLogonId" }.All(x => fields.Text(x) is null or "" or "-" or "0x0"); string prefix = version == 2 && !nullTarget ? "Target" : "Subject";
            string? sid = fields.Text(prefix + "UserSid");
            if (sid is null || !Regex.IsMatch(sid, @"\AS-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}\z") || sid == "S-1-0-0") unavailable.UnionWith(["User", "UserSid", "LogonId", "LogonIdNumeric"]);
            else { Alias("UserSid", prefix + "UserSid"); if (Present(prefix + "UserName") && Present(prefix + "DomainName")) fields["User"] = fields.Text(prefix + "DomainName") + "\\" + fields.Text(prefix + "UserName"); else unavailable.Add("User"); if (Hex(fields.Text(prefix + "LogonId"), 64) is { } number) { Alias("LogonId", prefix + "LogonId"); fields["LogonIdNumeric"] = number; } else unavailable.UnionWith(["LogonId", "LogonIdNumeric"]); }
        }
        fields["EventID"] = id; fields["Version"] = version; fields["Provider_Name"] = provider; fields["Channel"] = channel; fields["Computer"] = computer; fields["EventRecordID"] = record; fields["TimeCreated"] = stamp; if (guid is not null) fields["Provider_Guid"] = guid;
        if (id == 4104 && One(system, "Security", false)?.Attribute("UserID")?.Value is { } userId)
            fields["UserID"] = userId;
        var execution = One(system, "Execution", false); if (execution is not null) foreach (var (native, name) in new[] { ("ProcessID", id == 4688 ? "NativeProcessId" : "ProcessId"), ("ThreadID", "ThreadId") }) if (execution.Attribute(native) is { } value) fields[name] = uint.Parse(value.Value, CultureInfo.InvariantCulture);
        return new(id, channel, computer, SemanticQuery.Time(stamp, "UTC", "sigma_event_header_invalid"), fields, unavailable);
    }
}
