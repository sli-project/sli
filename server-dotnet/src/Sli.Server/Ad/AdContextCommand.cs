using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Server.Ad;

public record AdContextRequest
{
    public string PowershellExecutable { get; init; } = "";
    public string OutputPath { get; init; } = "";
    public string RunId { get; init; } = "";
    public string DirectoryServer { get; init; } = "";
    public string Domain { get; init; } = "";
    public string SearchBase { get; init; } = "";
    public string[] Sections { get; init; } = [];
    public string[] PrivilegedGroups { get; init; } = [];
    public string[] VpnGroups { get; init; } = [];
    public string Mode { get; init; } = "full";
    public int InactiveDays { get; init; } = 180;
    public int MaxRecords { get; init; } = 2000;
    public int MaxBundleBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxDirectoryAccounts { get; init; } = 2000;
    public int? MaxDirectoryUsers { get; init; }
    public int? MaxDirectoryComputers { get; init; }
    public int MaxVpnMembers { get; init; } = 500;
    public int MaxGpos { get; init; } = 72;
}

// Builds argv only. The executable and repository script never come from bundle data.
public static class AdContextCommand
{
    internal static readonly IReadOnlyDictionary<string, string> Profiles = new Dictionary<string, string>
    {
        ["privileged_membership"] = "privileged_membership_v1", ["directory_accounts"] = "directory_security_v1",
        ["vpn_membership"] = "vpn_security_v1", ["gpo_governance"] = "gpo_governance_v4",
        ["domain_posture"] = "domain_posture_v1", ["domain_health"] = "domain_health_v1"
    };
    internal static bool Sid(string value) => Regex.IsMatch(value, @"\AS-1-(?:\d+-){1,14}\d+\z", RegexOptions.IgnoreCase);
    internal static void Require(bool valid, string message) { if (!valid) throw new ArgumentException(message); }
    internal static (int Users, int Computers) DirectoryLimits(AdContextRequest r)
    {
        int users = r.MaxDirectoryUsers ?? r.MaxDirectoryAccounts / 2;
        return (users, r.MaxDirectoryComputers ?? r.MaxDirectoryAccounts - users);
    }
    internal static void CheckSectionLimits(AdContextRequest r, string section, bool canary)
    {
        int? limit = section switch { "directory_accounts" => r.MaxDirectoryAccounts, "vpn_membership" => r.MaxVpnMembers, "gpo_governance" => r.MaxGpos, _ => null };
        Require(limit is null || limit >= 1 && limit <= r.MaxRecords, "section limits must be positive and not exceed max_records");
        if (section == "directory_accounts")
        {
            var (users, computers) = DirectoryLimits(r);
            Require(users >= 1 && computers >= 1 && (long)users + computers <= (canary ? Math.Min(r.MaxRecords, r.MaxDirectoryAccounts) : r.MaxRecords), "independent directory limits exceed the approved total limit");
        }
        Require(section != "gpo_governance" || r.MaxGpos <= 72, "GPO governance exceeds the proven 72-policy contract");
    }
    public static string[] Build(AdContextRequest r, string repositoryRoot)
    {
        string executable = r.PowershellExecutable.Trim();
        Require(Path.IsPathFullyQualified(executable) && new[] { "powershell.exe", "pwsh", "pwsh.exe" }.Contains(Path.GetFileName(executable), StringComparer.OrdinalIgnoreCase), "AD Context requires an absolute allowlisted PowerShell executable path");
        Require(new[] { r.RunId, r.DirectoryServer, r.SearchBase, r.Domain }.All(s => !string.IsNullOrWhiteSpace(s)), "AD Context run_id, directory_server, search_base and domain are required");
        Require(r.MaxRecords is >= 1 and <= 50000, "AD Context max_records is out of bounds");
        Require(r.MaxBundleBytes is >= 1024 and <= 25 * 1024 * 1024, "AD Context max_bundle_bytes is out of bounds");
        Require(r.Mode is "full" or "targeted" or "reconcile", "unsupported AD Context collection mode");
        string[] sections = r.Sections.Select(s => s.Trim()).Where(s => s.Length > 0).Distinct().ToArray();
        Require(sections.Length > 0 && sections.All(Profiles.ContainsKey), "unsupported AD Context collection section");
        Require(sections.Length == 1, "AD Context execution requires exactly one bounded section");
        string section = sections[0];
        string[] groups = r.PrivilegedGroups.Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
        string[] vpn = r.VpnGroups.Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
        Require(section == "privileged_membership" ? groups.Length is >= 1 and <= 10 && groups.All(Sid) : groups.Length == 0, "AD Context requires one to ten exact privileged group SIDs in privileged_membership");
        Require(section == "vpn_membership" ? vpn.Length is >= 1 and <= 10 && vpn.All(s => Regex.IsMatch(s, @"\A[^,\x00-\x1f]{1,128}\z")) : vpn.Length == 0, "AD Context requires one to ten exact bounded VPN group references in vpn_membership");
        Require(r.InactiveDays is >= 1 and <= 3650, "AD Context inactive_days is out of bounds");
        CheckSectionLimits(r, section, false);
        string script = Path.GetFullPath(Path.Combine(repositoryRoot, "scripts", "ad_context", section == "privileged_membership" ? "Export-AdContextBundle.ps1" : "Export-AdAuditContextBundle.ps1"));
        var command = new List<string> { executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script };
        void Add(string key, object value) { command.Add("-" + key); command.Add(Convert.ToString(value, CultureInfo.InvariantCulture)!); }
        Add("OutputPath", r.OutputPath); Add("RunId", r.RunId); Add("DirectoryServer", r.DirectoryServer); Add("SearchBase", r.SearchBase); Add("Domain", r.Domain);
        Add("Sections", section); Add("CollectionProfile", Profiles[section]); Add("Mode", r.Mode); Add("PrivilegedGroups", string.Join(',', groups));
        Add("MaxRecords", r.MaxRecords); Add("MaxBundleBytes", r.MaxBundleBytes);
        if (section != "privileged_membership")
        {
            var (users, computers) = DirectoryLimits(r);
            Add("VpnGroups", string.Join(',', vpn)); Add("InactiveDays", r.InactiveDays); Add("MaxDirectoryAccounts", r.MaxDirectoryAccounts);
            Add("MaxDirectoryUsers", users); Add("MaxDirectoryComputers", computers); Add("MaxDirectoryGroups", 10000); Add("MaxDirectoryMemberships", 35000);
            Add("MaxVpnMembers", r.MaxVpnMembers); Add("MaxGpos", r.MaxGpos); Add("TechnicalServers", ""); Add("TechnicalInventoryTimeoutSeconds", 20);
        }
        return command.ToArray();
    }
}
