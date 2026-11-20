using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.SourcePacks.Examples;

internal readonly record struct LinuxAuthEntitySemantics(bool TargetIsGroup, bool ServiceNameIsEntity, bool TargetServerIsEntity);

internal static class LinuxAuthPack
{
    // Frozen source: server/source_packs/examples/linux_auth.py. This example is
    // deliberately outside OperationsCatalog and the bundled product normalizers.
    private static readonly string[] Months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".Split(' ');
    private static readonly Regex Line = new(@"\A(?<mon>[A-Z][a-z]{2}) +(?<day>\d{1,2}) (?<hms>\d{2}:\d{2}:\d{2}) (?<host>[A-Za-z0-9._-]{1,253}) (?<program>[A-Za-z0-9_.-]{1,64})(?:\[(?<pid>\d{1,10})\])?: (?<msg>.*)\z", RegexOptions.CultureInvariant);
    private static readonly Regex Accepted = new(@"\AAccepted (?<method>password|publickey) for (?<user>\S{1,64}) from (?<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}", RegexOptions.CultureInvariant);
    private static readonly Regex Failed = new(@"\AFailed (?<method>password|publickey) for (?:invalid user )?(?<user>\S{1,64}) from (?<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}", RegexOptions.CultureInvariant);
    private static readonly Regex Sudo = new(@"\A\s*(?<user>\S{1,64}) : (?:.*?; )?COMMAND=(?<command>.+)\z", RegexOptions.CultureInvariant);
    private static readonly Regex Session = new(@"\Apam_unix\(sshd:session\): session (?<state>opened|closed) for user (?<user>[^\s(]{1,64})", RegexOptions.CultureInvariant);

    private static JsonObject Document(string name)
    {
        using var stream = typeof(LinuxAuthPack).Assembly.GetManifestResourceStream("Sli.Server.SourcePacks.Examples." + name)
            ?? throw new InvalidOperationException("example_linux_auth_contract_missing");
        return JsonNode.Parse(stream)!.AsObject();
    }

    internal static JsonObject Manifest() => Document("linux_auth.json");
    internal static JsonObject Catalog() => Document("linux_auth_event_catalog.json");

    // Syslog carries neither year nor timezone. The caller supplies them;
    // unsupported messages and impossible dates are skipped without inference.
    internal static JsonObject? ParseLine(string? line, int year, TimeZoneInfo? timezone = null)
    {
        var match = Line.Match((line ?? "").TrimEnd('\r', '\n'));
        if (!match.Success) return null;
        int month = Array.IndexOf(Months, match.Groups["mon"].Value) + 1;
        if (month == 0) return null;
        string program = match.Groups["program"].Value, message = match.Groups["msg"].Value;
        int id;
        Match found;
        if (program == "sshd" && (found = Accepted.Match(message)).Success) id = 100;
        else if (program == "sshd" && (found = Failed.Match(message)).Success) id = 101;
        else if (program == "sudo" && (found = Sudo.Match(message)).Success) id = 110;
        else if (program == "sshd" && (found = Session.Match(message)).Success) id = found.Groups["state"].Value == "opened" ? 120 : 121;
        else return null;

        DateTimeOffset time;
        try
        {
            var hms = match.Groups["hms"].Value.Split(':');
            var local = new DateTime(year, month, int.Parse(match.Groups["day"].Value, CultureInfo.InvariantCulture),
                int.Parse(hms[0], CultureInfo.InvariantCulture), int.Parse(hms[1], CultureInfo.InvariantCulture), int.Parse(hms[2], CultureInfo.InvariantCulture), DateTimeKind.Unspecified);
            var zone = timezone ?? TimeZoneInfo.Utc;
            // Python's default fold=0 chooses the earlier occurrence on a clock rollback.
            var offset = zone.IsAmbiguousTime(local) ? zone.GetAmbiguousTimeOffsets(local).Max() : zone.GetUtcOffset(local);
            time = new DateTimeOffset(local, offset).ToUniversalTime();
        }
        catch (ArgumentException) { return null; }

        return new JsonObject
        {
            ["event_id"] = id, ["host"] = match.Groups["host"].Value, ["program"] = program,
            ["pid"] = match.Groups["pid"].Success ? match.Groups["pid"].Value : null,
            ["user"] = found.Groups["user"].Value,
            ["source_ip"] = id is 100 or 101 ? found.Groups["ip"].Value : null,
            ["auth_method"] = id is 100 or 101 ? found.Groups["method"].Value : null,
            // Match Python's 512 Unicode code point bound, including non-BMP commands.
            ["command"] = id == 110 ? string.Concat(found.Groups["command"].Value.Trim().EnumerateRunes().Take(512).Select(r => r.ToString())) : null,
            ["time"] = time,
        };
    }

    internal static JsonObject EventFacts(JsonObject row, JsonObject? eventData = null)
    {
        if (!int.TryParse(row["event_id"]?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int id)
            || id is not (100 or 101 or 110 or 120 or 121)) return new JsonObject();
        var data = eventData ?? row;
        return new JsonObject
        {
            ["process_name"] = data["program"]?.DeepClone(), ["process_id"] = data["pid"]?.DeepClone(),
            ["target_server_name"] = data["host"]?.DeepClone(), ["service_name"] = null,
            ["task_name"] = null, ["task_action"] = null, ["task_author"] = null, ["run_as"] = null,
            ["logon_type"] = data["auth_method"]?.DeepClone(),
            ["result_code"] = id == 100 ? "success" : id == 101 ? "failure" : null,
            ["object_name"] = data["command"]?.DeepClone(), ["share_name"] = null, ["message_sample"] = null,
        };
    }

    internal static LinuxAuthEntitySemantics EntitySemantics(string? channel, int eventId) => default;

    internal static string? EventLabel(int eventId, string? lang)
    {
        bool english = string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase);
        return eventId switch
        {
            100 => english ? "sshd: login accepted" : "sshd: вход принят",
            101 => english ? "sshd: login failed" : "sshd: вход отклонён",
            110 => english ? "sudo: command run" : "sudo: выполнена команда",
            120 => english ? "Session opened" : "Сессия открыта",
            121 => english ? "Session closed" : "Сессия закрыта",
            _ => null,
        };
    }

    // The example supplies no finding rules, search families or state transitions.
    internal static JsonObject FindingRules() => new();
    internal static int[] EventIdsForSearchFamily(string family) => [];
    internal static object? StateSemantics(string? channel, int eventId) => null;
}
