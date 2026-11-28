using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Workstations;

internal sealed record StationObservation(long? Id, string? SummaryKey, int Code, string Channel, string Provider,
    DateTimeOffset First, DateTimeOffset Last, long Count)
{
    internal string? Path { get; init; }
    internal string? Name { get; init; }
    internal string? Account { get; init; }
    internal string? LogonType { get; init; }
    internal string? DeviceId { get; init; }
    internal string? DeviceClass { get; init; }
    internal string? GroupSid { get; init; }
    internal string? TargetDomain { get; init; }
}

internal sealed record StationFact(string Fact, string Severity, string? Object, DateTimeOffset First, DateTimeOffset Last, long Count);
internal sealed record StationProgram(string Name, string Path, bool Writable, DateTimeOffset First, DateTimeOffset Last, long Count, string[] Users);
internal sealed record StationLogon(string? Account, string? Type, DateTimeOffset Last, long Count, long Failures);
internal sealed record StationDevice(string? Class, string? Name, DateTimeOffset First, DateTimeOffset Last);

internal sealed class WorkstationActivity(StationFact[] notable, StationProgram[] programs, StationLogon[] logons, StationDevice[] devices,
    Dictionary<(long?, string?), int> importance)
{
    private const string AuditProvider = "Microsoft-Windows-Security-Auditing";
    private const int High = 3, Medium = 2, Low = 1;
    private static readonly StringComparer Names = StringComparer.OrdinalIgnoreCase;
    internal static readonly TimeSpan ProgramHistory = TimeSpan.FromDays(7);
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(10);
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    internal StationFact[] Notable => notable;
    internal StationProgram[] Programs => programs;
    internal StationLogon[] Logons => logons;
    internal StationDevice[] Devices => devices;
    internal int Priority(long? id, string? summaryKey) => importance.GetValueOrDefault((id, summaryKey));
    internal string? Importance(long? id, string? summaryKey) => Severity(Priority(id, summaryKey));
    internal static string? Severity(int priority) => priority switch { High => "high", Medium => "medium", Low => "low", _ => null };
    internal JsonNode ToJson() => JsonSerializer.SerializeToNode(new { Notable, Programs, Logons, Devices }, Json)!;

    internal static WorkstationActivity Rank(IEnumerable<StationObservation> observations, DateTimeOffset from, DateTimeOffset to, string host)
    {
        var ordered = observations.Where(row => row.Last < to).OrderBy(row => row.First).ThenBy(row => row.Id).ToArray();
        var current = ordered.Where(row => row.First >= from).ToArray();
        var facts = new Dictionary<(string Fact, int Priority, string? Key), StationFact>();
        var importance = new Dictionary<(long?, string?), int>();
        void Flag(StationObservation row, string fact, int priority, string? value, string? key = null)
        {
            var identity = (fact, priority, (key ?? value)?.ToUpperInvariant());
            if (facts.TryGetValue(identity, out var old))
                facts[identity] = old with { First = row.First < old.First ? row.First : old.First,
                    Last = row.Last > old.Last ? row.Last : old.Last, Count = old.Count + row.Count };
            else
                facts.Add(identity, new(fact, Severity(priority)!, value, row.First, row.Last, row.Count));
            var source = (row.Id, row.SummaryKey);
            importance[source] = Math.Max(importance.GetValueOrDefault(source), priority);
        }

        var lastProgramStart = new Dictionary<string, DateTimeOffset>(Names);
        DateTimeOffset? firstProcess = null;
        foreach (var row in ordered.Where(row => IsSecurity(row, 4688) && row.Path is not null))
        {
            firstProcess ??= row.First;
            string path = ProgramKey(row.Path!);
            if (row.First >= from)
            {
                if (UserWritable(path)) Flag(row, "writable_program", High, row.Path, path);
                else if (row.First - firstProcess.Value >= ProgramHistory &&
                    (!lastProgramStart.TryGetValue(path, out var previous) || row.First - previous > ProgramHistory))
                    Flag(row, "new_program", Medium, row.Path, path);
            }
            lastProgramStart[path] = row.Last;
        }

        var devicesSeen = new HashSet<string>(Names);
        foreach (var row in ordered.Where(row => IsSecurity(row, 6416) && row.DeviceId is not null))
            if (devicesSeen.Add(row.DeviceId!) && row.First >= from && UsbStorage(row))
                Flag(row, "new_usb_storage", Medium, row.Name ?? row.DeviceId, row.DeviceId);

        foreach (var row in current)
        {
            if (row is { Code: 7045, Channel: "System", Provider: "Service Control Manager", Path: not null })
            {
                string binary = ServiceBinary(row.Path);
                bool trustedLocation = SystemDirectory(binary);
                Flag(row, trustedLocation ? "service_installed" : "service_outside_system", trustedLocation ? Low : High,
                    row.Name, (row.Name ?? "") + "\n" + binary);
            }
            else if (IsSecurity(row, 4732) && row.GroupSid == "S-1-5-32-544")
                Flag(row, "local_admin_added", High, row.Name);
            else if (IsSecurity(row, 4719))
                Flag(row, "audit_policy_changed", High, host);
            else if (row is { Code: 1102, Channel: "Security", Provider: "Microsoft-Windows-Eventlog" })
                Flag(row, "security_log_cleared", High, host);
            else if (IsSecurity(row, 4624) && row.LogonType == "10")
                Flag(row, "remote_logon", Medium, row.Account);
            else if (IsSecurity(row, 4720) && (Names.Equals(row.TargetDomain, host) || Names.Equals(row.TargetDomain, host.Split('.')[0])))
                Flag(row, "local_account_created", Low, row.Account);
        }

        foreach (var account in current.Where(row => IsSecurity(row, 4625) && row.Account is not null && row.Id is not null)
                     .GroupBy(row => row.Account!, Names))
        {
            var failures = account.ToArray();
            int left = 0, markedThrough = -1;
            for (int right = 0; right < failures.Length; right++)
            {
                while (failures[right].First - failures[left].First > FailureWindow) left++;
                if (right - left + 1 < 10) continue;
                for (int i = Math.Max(left, markedThrough + 1); i <= right; i++)
                    Flag(failures[i], "logon_failure_burst", Medium, failures[i].Account);
                markedThrough = right;
            }
        }

        var programs = current.Where(row => IsSecurity(row, 4688) && row.Path is not null)
            .GroupBy(row => ProgramKey(row.Path!), Names).Select(group =>
            {
                var first = group.First();
                return new StationProgram(group.Key.Split('\\')[^1], first.Path!, UserWritable(group.Key),
                    first.First, group.Max(row => row.Last), group.Sum(row => row.Count),
                    group.Select(row => row.Account).OfType<string>().Distinct(Names).Order(Names).ToArray());
            })
            .OrderByDescending(row => row.Writable).ThenByDescending(row => row.First).ThenBy(row => row.Path, Names).ToArray();
        var logons = current.Where(row => IsSecurity(row, 4625)
                || IsSecurity(row, 4624) && row.LogonType is "2" or "10" or "11" or "12")
            .GroupBy(row => (row.Account?.ToUpperInvariant(), row.LogonType))
            .Select(group => new StationLogon(group.First().Account, group.Key.LogonType, group.Max(row => row.Last),
                group.Sum(row => row.Count), group.Where(row => row.Code == 4625).Sum(row => row.Count)))
            .OrderByDescending(row => row.Last).ThenBy(row => row.Account, Names).ThenBy(row => row.Type, StringComparer.Ordinal).ToArray();
        var devices = current.Where(row => IsSecurity(row, 6416) && (row.DeviceId is not null || row.Name is not null))
            .GroupBy(row => row.DeviceId ?? row.DeviceClass + "\n" + row.Name, Names)
            .Select(group => new StationDevice(group.Last().DeviceClass, group.Last().Name ?? group.Last().DeviceId,
                group.First().First, group.Max(row => row.Last)))
            .OrderByDescending(row => row.Last).ThenBy(row => row.Name, Names).ToArray();
        var ranked = facts.OrderByDescending(entry => entry.Key.Priority).ThenByDescending(entry => entry.Value.Last)
            .ThenBy(entry => entry.Key.Fact, StringComparer.Ordinal).ThenBy(entry => entry.Key.Key, StringComparer.Ordinal)
            .Select(entry => entry.Value).ToArray();
        return new(ranked, programs, logons, devices, importance);
    }

    private static bool IsSecurity(StationObservation row, int code) =>
        row.Code == code && row.Channel == "Security" && row.Provider == AuditProvider;

    private static bool UsbStorage(StationObservation row) =>
        row.DeviceId!.StartsWith("USBSTOR\\", StringComparison.OrdinalIgnoreCase)
        || row.DeviceId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) && Names.Equals(row.DeviceClass, "DiskDrive");

    private static string ProgramKey(string path) => path.Replace('/', '\\');

    private static string ServiceBinary(string input)
    {
        string command = ProgramKey(input.Trim());
        if (command.StartsWith('"') && command.IndexOf('"', 1) is > 0 and var close) return command[1..close];
        // Unquoted service paths can contain spaces. Stop at the first binary
        // extension followed by whitespace or end of input.
        for (int i = 0; i + 4 <= command.Length; i++)
            if ((i + 4 == command.Length || char.IsWhiteSpace(command[i + 4])) &&
                (command.AsSpan(i, 4).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                 command.AsSpan(i, 4).Equals(".sys", StringComparison.OrdinalIgnoreCase)))
                return command[..(i + 4)];
        return command;
    }

    private static string[] Directories(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        if (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\')
            path = path[3..];
        else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = "Windows" + path[11..];
        else if (!path.StartsWith('%')) return [];

        var parts = new List<string>();
        foreach (string part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..")
            {
                if (parts.Count == 0) return [];
                parts.RemoveAt(parts.Count - 1);
            }
            else parts.Add(part.TrimEnd(' ', '.'));
        }
        return parts.Count >= 2 ? parts.Take(parts.Count - 1).ToArray() : [];
    }

    private static bool SystemDirectory(string path) => Directories(path).FirstOrDefault()?.ToUpperInvariant() is
        "WINDOWS" or "PROGRAM FILES" or "PROGRAM FILES (X86)" or "%WINDIR%" or "%SYSTEMROOT%"
        or "%PROGRAMFILES%" or "%PROGRAMFILES(X86)%" or "%PROGRAMW6432%";

    private static bool UserWritable(string path)
    {
        var parts = Directories(path).Select(part => part.ToUpperInvariant()).ToArray();
        return parts.FirstOrDefault() is "TEMP" or "%TEMP%" or "%TMP%" or "%APPDATA%" or "%LOCALAPPDATA%"
            || parts is ["WINDOWS" or "%WINDIR%" or "%SYSTEMROOT%", "TEMP", ..]
            || parts is ["USERS", _, "DOWNLOADS" or "DESKTOP" or "APPDATA" or "TEMP", ..]
            || parts is ["%USERPROFILE%", "DOWNLOADS" or "DESKTOP" or "APPDATA" or "TEMP", ..];
    }
}
