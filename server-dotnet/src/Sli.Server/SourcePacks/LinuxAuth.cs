using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.SourcePacks;

// server/source_packs/examples/linux_auth.py: the reference file source and its facts handler.
public static class LinuxAuth
{
    public const string CollectorEntry = "server.source_packs.examples.linux_auth:auth_log_collector";
    public const string NormalizerEntry = "server.source_packs.examples.linux_auth:normalizer_namespace";
    public const string NormalizerId = "example-linux-auth-v1";
    private static readonly Regex Line = new(@"\A(?<mon>[A-Z][a-z]{2}) +(?<day>\d{1,2}) (?<hms>\d{2}:\d{2}:\d{2}) (?<host>[A-Za-z0-9._-]{1,253}) (?<program>[A-Za-z0-9_.-]{1,64})(?:\[(?<pid>\d{1,10})\])?: (?<msg>.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex Accepted = new(@"\AAccepted (?<method>password|publickey) for (?<user>\S{1,64}) from (?<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}", RegexOptions.CultureInvariant);
    private static readonly Regex Failed = new(@"\AFailed (?<method>password|publickey) for (?:invalid user )?(?<user>\S{1,64}) from (?<ip>[0-9a-fA-F:.]{2,45}) port \d{1,5}", RegexOptions.CultureInvariant);
    private static readonly Regex Sudo = new(@"\A\s*(?<user>\S{1,64}) : (?:.*?; )?COMMAND=(?<command>.+)$", RegexOptions.CultureInvariant);
    private static readonly Regex Session = new(@"\Apam_unix\(sshd:session\): session (?<state>opened|closed) for user (?<user>[^\s(]{1,64})", RegexOptions.CultureInvariant);
    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    public static JsonObject? ParseLine(string line, int year, string? timezone = null)
    {
        var match = Line.Match(line.TrimEnd('\r', '\n'));
        int month = Array.IndexOf(Months, match.Groups["mon"].Value) + 1;
        if (!match.Success || month == 0) return null;
        string program = match.Groups["program"].Value, message = match.Groups["msg"].Value;
        Match found;
        int id;
        if (program == "sshd" && (found = Accepted.Match(message)).Success) id = 100;
        else if (program == "sshd" && (found = Failed.Match(message)).Success) id = 101;
        else if (program == "sudo" && (found = Sudo.Match(message)).Success) id = 110;
        else if (program == "sshd" && (found = Session.Match(message)).Success) id = found.Groups["state"].Value == "opened" ? 120 : 121;
        else return null;
        DateTime local;
        try
        {
            int[] hms = match.Groups["hms"].Value.Split(':').Select(s => int.Parse(s, CultureInfo.InvariantCulture)).ToArray();
            local = new DateTime(year, month, int.Parse(match.Groups["day"].Value, CultureInfo.InvariantCulture), hms[0], hms[1], hms[2], DateTimeKind.Unspecified);
        }
        catch (ArgumentOutOfRangeException) { return null; }
        var zone = string.IsNullOrEmpty(timezone) || timezone.Equals("UTC", StringComparison.OrdinalIgnoreCase)
            ? TimeZoneInfo.Utc : TimeZoneInfo.FindSystemTimeZoneById(timezone);
        // Python's default fold=0 selects the earlier occurrence at an autumn transition.
        var offset = zone.IsAmbiguousTime(local) ? zone.GetAmbiguousTimeOffsets(local).Max() : zone.GetUtcOffset(local);
        string? command = id == 110 ? string.Concat(found.Groups["command"].Value.Trim().EnumerateRunes().Take(512).Select(r => r.ToString())) : null;
        return new JsonObject
        {
            ["event_id"] = id, ["host"] = match.Groups["host"].Value, ["program"] = program,
            ["pid"] = match.Groups["pid"].Success ? match.Groups["pid"].Value : null,
            ["user"] = found.Groups["user"].Value, ["source_ip"] = id is 100 or 101 ? found.Groups["ip"].Value : null,
            ["auth_method"] = id is 100 or 101 ? found.Groups["method"].Value : null, ["command"] = command,
            ["time"] = new DateTimeOffset(local, offset).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
        };
    }

    public static JsonObject EventFacts(JsonObject row, JsonObject? eventData = null)
    {
        if (!int.TryParse(row["event_id"]?.ToString(), out int id) || id is not (100 or 101 or 110 or 120 or 121)) return new();
        var data = eventData ?? row;
        return new JsonObject
        {
            ["process_name"] = data["program"]?.DeepClone(), ["process_id"] = data["pid"]?.DeepClone(),
            ["target_server_name"] = data["host"]?.DeepClone(), ["service_name"] = null,
            ["task_name"] = null, ["task_action"] = null, ["task_author"] = null, ["run_as"] = null,
            ["logon_type"] = data["auth_method"]?.DeepClone(), ["result_code"] = id == 100 ? "success" : id == 101 ? "failure" : null,
            ["object_name"] = data["command"]?.DeepClone(), ["share_name"] = null, ["message_sample"] = null
        };
    }
}
