using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sli.Server.Operations;

public sealed record WindowsEventLogRequest(
    string Backend, string PythonExecutable, string PythonScript, string PowershellScript,
    string ComputerName, string SourceName, int Hours, int MaxEventsPerChannel,
    int ChannelTimeoutSeconds, string OutputRoot, string[] Channels, string CollectionMode, bool CollectMessage)
{
    public IReadOnlyDictionary<string, int> ChannelLimits { get; init; } = new Dictionary<string, int>();
    public IReadOnlyDictionary<string, int> ChannelTimeouts { get; init; } = new Dictionary<string, int>();
    public string? StartTimeUtc { get; init; }
    public IReadOnlyDictionary<string, string> ChannelStartTimes { get; init; } = new Dictionary<string, string>();
    public IReadOnlyDictionary<string, long> ChannelAfterRecordIds { get; init; } = new Dictionary<string, long>();
    public IReadOnlyDictionary<string, string> ChannelCursorGenerations { get; init; } = new Dictionary<string, string>();
    public int[] EventIds { get; init; } = [];
    public string? EndTimeUtc { get; init; }
    public bool SourceContinuityCanary { get; init; }
    public bool NpsContinuous { get; init; }
    public string AdSourceCredentialMode { get; init; } = "process";
}

public sealed record AdContextRequest(
    string PowershellExecutable, string OutputPath, string RunId, string DirectoryServer,
    string SearchBase, string Domain, string[] Sections)
{
    public string? CollectionProfile { get; init; }
    public string[] PrivilegedGroups { get; init; } = [];
    public string[] VpnGroups { get; init; } = [];
    public int InactiveDays { get; init; } = 180;
    public string Mode { get; init; } = "full";
    public int MaxRecords { get; init; } = 2000;
    public int MaxBundleBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxDirectoryAccounts { get; init; } = 2000;
    public int? MaxDirectoryUsers { get; init; }
    public int? MaxDirectoryComputers { get; init; }
    public int MaxDirectoryGroups { get; init; } = 10000;
    public int MaxDirectoryMemberships { get; init; } = 35000;
    public int MaxVpnMembers { get; init; } = 500;
    public int MaxGpos { get; init; } = 72;
    public string[] TechnicalServers { get; init; } = [];
    public int TechnicalInventoryTimeoutSeconds { get; init; } = 20;
}

// Source: server/source_packs/adapters.py. These functions build argv only;
// executors retain process ownership. No shell interpolation or dynamic loading.
public static class SourceAdapterCommands
{
    static void Add(List<string> command, string name, object value)
    { command.Add(name); command.Add(Convert.ToString(value, CultureInfo.InvariantCulture)!); }
    public static string AdapterIdForBackend(string backend) => backend switch
    {
        "python" => "windows-eventlog-pywin32",
        "powershell" => "windows-eventlog-powershell",
        _ => throw new ArgumentException($"unsupported Windows Event Log backend: {backend}")
    };

    public static List<string> WindowsEventLog(WindowsEventLogRequest r)
    {
        if (r.AdSourceCredentialMode is not ("process" or "dpapi_current_user")) throw new ArgumentException("ad_source_credential_mode_invalid");
        if (r.AdSourceCredentialMode == "dpapi_current_user" && r.Backend is not ("python" or "auto")) throw new ArgumentException("ad_source_backend_unsupported");
        List<string> command;
        if (r.Backend == "python")
        {
            command = [r.PythonExecutable, r.PythonScript];
            Add(command, "--computer-name", r.ComputerName); Add(command, "--source-name", r.SourceName);
            Add(command, "--hours", r.Hours); Add(command, "--max-events-per-channel", r.MaxEventsPerChannel);
            Add(command, "--channel-timeout-seconds", r.ChannelTimeoutSeconds); Add(command, "--output-root", r.OutputRoot);
            Add(command, "--channels", string.Join(',', r.Channels)); Add(command, "--collection-mode", r.CollectionMode);
            Add(command, "--collect-message", r.CollectMessage ? "true" : "false");
            if (r.AdSourceCredentialMode != "process") Add(command, "--ad-source-credential-mode", r.AdSourceCredentialMode);
            if (r.ChannelLimits.Count > 0) Add(command, "--channel-limits-json", JsonSerializer.Serialize(r.ChannelLimits));
            if (r.ChannelTimeouts.Count > 0) Add(command, "--channel-timeouts-json", JsonSerializer.Serialize(r.ChannelTimeouts));
            if (!string.IsNullOrEmpty(r.StartTimeUtc)) Add(command, "--start-time-utc", r.StartTimeUtc);
            if (r.EventIds.Length > 0) Add(command, "--event-ids-json", JsonSerializer.Serialize(r.EventIds));
            if (!string.IsNullOrEmpty(r.EndTimeUtc)) Add(command, "--end-time-utc", r.EndTimeUtc);
            if (r.SourceContinuityCanary) command.Add("--source-continuity-canary");
            if (r.NpsContinuous) command.Add("--nps-continuous");
            if (r.ChannelStartTimes.Count > 0) Add(command, "--channel-start-times-json", JsonSerializer.Serialize(r.ChannelStartTimes));
            if (r.ChannelAfterRecordIds.Count > 0) Add(command, "--channel-after-record-ids-json", JsonSerializer.Serialize(r.ChannelAfterRecordIds));
            if (r.ChannelCursorGenerations.Count > 0) Add(command, "--channel-cursor-generations-json", JsonSerializer.Serialize(r.ChannelCursorGenerations));
            return command;
        }
        if (r.EventIds.Length > 0 || !string.IsNullOrEmpty(r.EndTimeUtc) || r.SourceContinuityCanary || r.NpsContinuous)
            throw new ArgumentException("bounded Windows Event Log selection requires the python backend");
        _ = AdapterIdForBackend(r.Backend);
        command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r.PowershellScript];
        Add(command, "-ComputerName", r.ComputerName); Add(command, "-SourceName", r.SourceName);
        Add(command, "-Hours", r.Hours); Add(command, "-MaxEventsPerChannel", r.MaxEventsPerChannel);
        Add(command, "-ChannelTimeoutSeconds", r.ChannelTimeoutSeconds); Add(command, "-OutputRoot", r.OutputRoot);
        command.Add(r.CollectMessage ? "-CollectMessage:$true" : "-CollectMessage:$false");
        Add(command, "-RequestedCollectionMode", r.CollectionMode);
        if (r.Channels.Length > 0) Add(command, "-Channels", string.Join(',', r.Channels));
        if (r.ChannelLimits.Count > 0) Add(command, "-ChannelMaxEventsJson", JsonSerializer.Serialize(r.ChannelLimits));
        if (r.ChannelTimeouts.Count > 0) Add(command, "-ChannelTimeoutSecondsJson", JsonSerializer.Serialize(r.ChannelTimeouts));
        if (!string.IsNullOrEmpty(r.StartTimeUtc)) Add(command, "-StartTimeUtc", r.StartTimeUtc);
        if (r.ChannelStartTimes.Count > 0) Add(command, "-ChannelStartTimesJson", JsonSerializer.Serialize(r.ChannelStartTimes));
        if (r.ChannelAfterRecordIds.Count > 0) Add(command, "-ChannelAfterRecordIdsJson", JsonSerializer.Serialize(r.ChannelAfterRecordIds));
        return command;
    }

    static readonly Dictionary<string, string> ContextProfiles = new(StringComparer.Ordinal)
    {
        ["privileged_membership"] = "privileged_membership_v1", ["directory_accounts"] = "directory_security_v1",
        ["directory_group_graph"] = "directory_group_graph_v1", ["directory_exact_logon"] = "directory_exact_logon_v1",
        ["vpn_membership"] = "vpn_security_v1", ["gpo_governance"] = "gpo_governance_v4",
        ["domain_posture"] = "domain_posture_v1", ["domain_health"] = "domain_health_v1"
    };
    static string[] Clean(IEnumerable<string> values) => values.Select(v => v.Trim()).Where(v => v.Length > 0).ToArray();
    static void Require(bool condition, string message) { if (!condition) throw new ArgumentException(message); }
    // Same component-wise link resolution used by the bundled plugin validators.
    static string Resolve(string path)
    {
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var next = new DirectoryInfo(Path.Combine(current, part));
            current = next.LinkTarget is null ? next.FullName : next.ResolveLinkTarget(true)!.FullName;
        }
        return current;
    }

    // repositoryRoot is the installed repository root, never a pack-supplied script path.
    public static List<string> AdContext(AdContextRequest r, string repositoryRoot)
    {
        string executable = r.PowershellExecutable.Trim();
        Require(Path.IsPathFullyQualified(executable) && Path.GetFileName(executable).ToLowerInvariant() is "powershell.exe" or "pwsh" or "pwsh.exe",
            "AD Context requires an absolute allowlisted PowerShell executable path");
        Require(!string.IsNullOrWhiteSpace(r.RunId) && !string.IsNullOrWhiteSpace(r.DirectoryServer) && !string.IsNullOrWhiteSpace(r.SearchBase) && !string.IsNullOrWhiteSpace(r.Domain),
            "AD Context run_id, directory_server, search_base and domain are required");
        // Retain the frozen collector wire-contract validation; no process deadline is introduced here.
        Require(r.MaxRecords is >= 1 and <= 50000, "AD Context max_records is out of bounds");
        Require(r.MaxBundleBytes is >= 1024 and <= 25 * 1024 * 1024, "AD Context max_bundle_bytes is out of bounds");
        Require(r.Mode is "full" or "targeted" or "reconcile", "unsupported AD Context collection mode");
        string[] sections = Clean(r.Sections).Distinct(StringComparer.Ordinal).ToArray();
        Require(sections.Length > 0 && sections.All(ContextProfiles.ContainsKey), "AD Context contains an unsupported collection section");
        bool unified = r.CollectionProfile == "ad_snapshot_base_v1";
        if (unified) Require(sections.SequenceEqual(new[] { "directory_accounts", "directory_group_graph", "directory_exact_logon" }), "ad_snapshot_base_v1 requires the exact bounded section set");
        else
        {
            Require(r.CollectionProfile is null, "unsupported explicit AD Context collection profile");
            Require(sections.Length == 1, "AD Context execution requires exactly one bounded section");
        }
        string[] groups = Clean(r.PrivilegedGroups), vpnGroups = Clean(r.VpnGroups);
        if (sections.Contains("privileged_membership"))
            Require(groups.Length is >= 1 and <= 10 && groups.All(g => Regex.IsMatch(g, @"\AS-1-(?:[0-9]+-){1,14}[0-9]+\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)), "AD Context requires one to ten exact privileged group SIDs");
        else Require(groups.Length == 0, "privileged groups require the privileged_membership section");
        if (sections.Contains("vpn_membership"))
            Require(vpnGroups.Length is >= 1 and <= 10 && vpnGroups.All(g => Regex.IsMatch(g, @"\A[^,\x00-\x1f]{1,128}\z", RegexOptions.CultureInvariant)), "AD Context requires one to ten exact bounded VPN group references");
        else Require(vpnGroups.Length == 0, "VPN groups require the vpn_membership section");
        Require(r.InactiveDays is >= 1 and <= 3650, "AD Context inactive_days is out of bounds");
        int users = r.MaxDirectoryUsers ?? r.MaxDirectoryAccounts / 2;
        int computers = r.MaxDirectoryComputers ?? r.MaxDirectoryAccounts - users;
        if (sections.Contains("directory_accounts")) Require(users >= 1 && computers >= 1 && (long)users + computers <= r.MaxRecords, "AD Context independent directory limits exceed max_records");
        string[] servers = Clean(r.TechnicalServers).Distinct(StringComparer.Ordinal).ToArray();
        Require(servers.Length <= 50 && servers.All(s => Regex.IsMatch(s, @"\A[A-Za-z0-9][A-Za-z0-9.-]{0,252}\z", RegexOptions.CultureInvariant)), "AD Context technical server inventory is out of bounds");
        Require(servers.Length == 0 || sections.SequenceEqual(new[] { "directory_accounts" }), "technical server inventory requires the directory_accounts section");
        Require(r.TechnicalInventoryTimeoutSeconds is >= 5 and <= 60, "technical inventory timeout must be between 5 and 60 seconds");
        List<int> limits = [];
        if (sections.Contains("directory_accounts")) limits.Add(r.MaxDirectoryAccounts);
        if (sections.Contains("directory_group_graph")) limits.AddRange([r.MaxDirectoryGroups, r.MaxDirectoryMemberships]);
        if (sections.Contains("directory_exact_logon")) limits.Add(users);
        if (sections.Contains("vpn_membership")) limits.Add(r.MaxVpnMembers);
        if (sections.Contains("gpo_governance")) limits.Add(r.MaxGpos);
        Require(limits.All(v => v >= 1 && v <= r.MaxRecords), "AD Context section limit is out of bounds or exceeds max_records");
        Require(!sections.Contains("gpo_governance") || r.MaxGpos <= 72, "GPO governance exceeds the proven 72-policy contract");
        bool privileged = sections.SequenceEqual(new[] { "privileged_membership" });
        string root = Resolve(repositoryRoot);
        string script = Resolve(Path.Combine(root, "scripts", "ad_context", privileged ? "Export-AdContextBundle.ps1" : "Export-AdAuditContextBundle.ps1"));
        string relative = Path.GetRelativePath(root, script);
        Require(!Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal), "AD Context collector path escapes the repository");
        List<string> command = [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script];
        Add(command, "-OutputPath", r.OutputPath); Add(command, "-RunId", r.RunId); Add(command, "-DirectoryServer", r.DirectoryServer);
        Add(command, "-SearchBase", r.SearchBase); Add(command, "-Domain", r.Domain); Add(command, "-Sections", string.Join(',', sections));
        Add(command, "-CollectionProfile", unified ? "ad_snapshot_base_v1" : ContextProfiles[sections[0]]);
        Add(command, "-Mode", r.Mode); Add(command, "-PrivilegedGroups", string.Join(',', groups));
        Add(command, "-MaxRecords", r.MaxRecords); Add(command, "-MaxBundleBytes", r.MaxBundleBytes);
        if (!privileged)
        {
            Add(command, "-VpnGroups", string.Join(',', vpnGroups)); Add(command, "-InactiveDays", r.InactiveDays);
            Add(command, "-MaxDirectoryAccounts", r.MaxDirectoryAccounts); Add(command, "-MaxDirectoryUsers", users);
            Add(command, "-MaxDirectoryComputers", computers); Add(command, "-MaxDirectoryGroups", r.MaxDirectoryGroups);
            Add(command, "-MaxDirectoryMemberships", r.MaxDirectoryMemberships); Add(command, "-MaxVpnMembers", r.MaxVpnMembers);
            Add(command, "-MaxGpos", r.MaxGpos); Add(command, "-TechnicalServers", string.Join(',', servers));
            Add(command, "-TechnicalInventoryTimeoutSeconds", r.TechnicalInventoryTimeoutSeconds);
        }
        return command;
    }
}
