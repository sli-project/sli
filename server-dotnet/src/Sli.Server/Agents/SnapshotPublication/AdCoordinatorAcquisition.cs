using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Ad;
using Sli.Server.Hosting;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Agents.SnapshotPublication;

// The same repository-owned, read-only collectors as the native Python role.
internal sealed class AdCoordinatorAcquisition(string root, Func<string, string?> get,
    Func<string, JsonObject, CancellationToken, Task> progress,
    Func<string, CancellationToken, Task>? validateEndpoint = null)
{
    internal static readonly string[] Families = ["ad_context_base", "ad_privileged_membership", "ad_vpn_membership", "ad_domain_posture", "ad_domain_health", "ad_gpo_governance"];
    internal static readonly string[] BaseSections = ["directory_accounts", "directory_group_graph", "directory_exact_logon"];
    static readonly string[] Blocking = ["directory_accounts_truncated", "directory_accounts_failed", "directory_group_graph_truncated", "directory_group_memberships_truncated", "directory_group_links_unresolved", "directory_group_graph_failed", "exact_last_logon_users_truncated", "exact_last_logon_dc_coverage_partial", "directory_exact_logon_failed"];
    internal static void QualifyBase(JsonObject bundle)
    {
        void Require(bool ok) { if (!ok) throw new WorkerFailure("base_qualification", "base_source_not_complete"); }
        var sections = bundle["sections"]!.AsArray().OfType<JsonObject>().ToArray();
        Require(sections.Length == 3 && sections.Select(s => s.Text("name")).ToHashSet().SetEquals(BaseSections));
        var quality = bundle["records"]!.AsArray().Where(r => r!.Text("record_type") == "data_quality" && BaseSections.Contains(r.Text("section"))).ToArray();
        foreach (var r in quality) {
            string code = r!.Text("code")!;
            Require(code == "password_expiry_partial" || !Blocking.Contains(code) && Regex.IsMatch(code, @"\Atechnical_inventory_[a-z0-9][a-z0-9.-]{0,252}_(?:timeout|failed)\z"));
        }
        foreach (var s in sections) {
            bool password = quality.Any(r => r!.Text("section") == "directory_accounts" && r.Text("code") == "password_expiry_partial");
            Require(s.Text("name") == "directory_accounts" && s.Text("status") == "partial"
                ? s.Text("error_code") == "collection_incomplete" && password
                : s.Text("status") == "complete" && s["error_code"] is null && (s.Text("name") != "directory_accounts" || !password));
        }
    }
    string Required(string name) => get(name)?.Trim() is { Length: > 0 } value ? value : throw new WorkerFailure("configuration", "ad_snapshot_coordinator_configuration_missing");
    string Server => get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER")?.Trim() is { Length: > 0 } value ? value : Required("ADLOG_COLLECTION_PREFLIGHT_SERVER");
    string Scope(string name, bool sid)
    {
        var values = Required(name).Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).Distinct().ToArray();
        if (values.Length is < 1 or > 10 || values.Any(s => sid ? !Regex.IsMatch(s, @"\AS-1-(?:\d+-){1,14}\d+\z", RegexOptions.IgnoreCase) : s.Length > 128 || s.Any(char.IsControl)))
            throw new WorkerFailure("configuration", "ad_snapshot_scope_invalid");
        return string.Join(',', values);
    }
    int Bound(string name, int fallback)
    {
        if (!int.TryParse(get(name) ?? fallback.ToString(CultureInfo.InvariantCulture), out int n) || n is < 1 or > 50000)
            throw new WorkerFailure("configuration", "ad_snapshot_record_bound_invalid");
        return n;
    }
    internal ProcessStartInfo Command(string family, string directory)
    {
        string executable = get("ADLOG_AD_CONTEXT_POWERSHELL")?.Trim() is { Length: > 0 } value ? value : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32/WindowsPowerShell/v1.0/powershell.exe");
        if (!Path.IsPathFullyQualified(executable) || !new[] { "powershell.exe", "pwsh.exe", "pwsh" }.Contains(Path.GetFileName(executable), StringComparer.OrdinalIgnoreCase))
            throw new WorkerFailure("configuration", "ad_source_process_command_invalid");
        var start = new ProcessStartInfo(executable) { WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        void Add(params string[] args) { foreach (string arg in args) start.ArgumentList.Add(arg); }
        Add("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File");
        string output = Path.Combine(directory, "output.json");
        if (family == "computers_v6") {
            Add(Path.Combine(root, "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"), "-OutputPath", output, "-Server", Server,
                "-SearchBase", Required("ADLOG_AD_CONTEXT_SEARCH_BASE"), "-CollectAdSite", "-CollectExactLastLogon", "-CoordinatorBaseInputPath", Path.Combine(directory, "base.json"));
            return start;
        }
        int users = Bound("ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_USERS", 40000), computers = Bound("ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_COMPUTERS", 10000);
        if (users + computers > 50000) throw new WorkerFailure("configuration", "ad_snapshot_record_bound_invalid");
        string privileged = Scope("ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS", true), vpn = Scope("ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES", false);
        var (profile, section) = family switch {
            "ad_context_base" => ("ad_snapshot_base_v1", string.Join(',', BaseSections)),
            "ad_privileged_membership" => ("privileged_membership_v1", "privileged_membership"),
            "ad_vpn_membership" => ("vpn_security_v1", "vpn_membership"),
            "ad_domain_posture" => ("domain_posture_v1", "domain_posture"),
            "ad_domain_health" => ("domain_health_v1", "domain_health"),
            "ad_gpo_governance" => ("gpo_governance_v4", "gpo_governance"),
            _ => throw new WorkerFailure("configuration", "unsupported_ad_snapshot_family")
        };
        Add(Path.Combine(root, "scripts/ad_context/" + (family == "ad_privileged_membership" ? "Export-AdContextBundle.ps1" : "Export-AdAuditContextBundle.ps1")),
            "-OutputPath", output, "-RunId", Guid.NewGuid().ToString("D"), "-DirectoryServer", Server, "-SearchBase", Required("ADLOG_AD_CONTEXT_SEARCH_BASE"),
            "-Domain", Required("ADLOG_AD_CONTEXT_DOMAIN"), "-Sections", section, "-CollectionProfile", profile, "-Mode", "reconcile", "-PrivilegedGroups", family == "ad_privileged_membership" ? privileged : "",
            "-MaxRecords", "50000", "-MaxBundleBytes", "26214400");
        if (family != "ad_privileged_membership") Add("-VpnGroups", family == "ad_vpn_membership" ? vpn : "", "-InactiveDays", "180", "-MaxDirectoryAccounts", "50000",
            "-MaxDirectoryUsers", users.ToString(CultureInfo.InvariantCulture), "-MaxDirectoryComputers", computers.ToString(CultureInfo.InvariantCulture), "-MaxDirectoryGroups", "10000", "-MaxDirectoryMemberships", "35000",
            "-MaxVpnMembers", Bound("ADLOG_AD_SNAPSHOT_MAX_VPN_MEMBERS", 5000).ToString(CultureInfo.InvariantCulture), "-MaxGpos", Bound("ADLOG_AD_SNAPSHOT_MAX_GPOS", 72).ToString(CultureInfo.InvariantCulture), "-ProgressPath", Path.Combine(directory, "p.json"));
        return start;
    }
    internal static JsonObject ComputerBase(JsonObject bundle)
    {
        var rows = new JsonArray();
        var mapping = new Dictionary<string, string> { ["Name"]="display_name", ["OperatingSystem"]="operating_system", ["ServicePrincipalName"]="service_principal_names", ["DNSHostName"]="dns_host_name", ["OperatingSystemVersion"]="operating_system_version", ["OperatingSystemServicePack"]="operating_system_service_pack", ["Enabled"]="enabled", ["CanonicalName"]="canonical_name", ["DistinguishedName"]="distinguished_name", ["PasswordLastSet"]="password_last_set_utc", ["whenCreated"]="created_utc", ["whenChanged"]="when_changed_utc", ["Description"]="description", ["Location"]="location", ["ManagedBy"]="managed_by", ["userAccountControl"]="user_account_control", ["TrustedForDelegation"]="trusted_for_delegation", ["TrustedToAuthForDelegation"]="trusted_to_auth_for_delegation" };
        foreach (var r in bundle["records"]!.AsArray().Where(r => r!.Text("section") == "directory_accounts" && r!["identity"]?.Text("kind") == "ad_computer")) {
            var attrs = r!["attributes"]!; var row = new JsonObject();
            foreach (var (key, attr) in mapping) row[key] = attrs[attr]?.DeepClone();
            row["ObjectGUID"] = r["identity"]!["object_guid"]!.DeepClone(); row["SID"] = r["identity"]!["object_sid"]?.DeepClone();
            row["lastLogonTimestamp"] = attrs["last_logon_utc"] is null ? null : JsonValue.Create(DateTimeOffset.Parse(attrs.Text("last_logon_utc")!, CultureInfo.InvariantCulture).UtcDateTime.ToFileTimeUtc());
            rows.Add(row);
        }
        string json = Sli.Agent.Protocol.CanonicalJson.Serialize(rows, false);
        return Obj(new { schema_version = "sli.ad-computer-base/1.0", object_count = rows.Count, objects_sha256 = AdJobPlugin.Digest(rows), objects_json = json });
    }
    internal static JsonObject SafeProgress(JsonObject raw)
    {
        var safe = new JsonObject();
        if (raw.Text("phase") is {} phase && new[] { "starting", "base_users_start", "base_users_end", "base_computers_start", "base_computers_end", "raw_serialization_start", "raw_serialization_end", "accounts_start", "accounts_end", "group_graph_start", "group_graph_end", "exact_logon_start", "exact_logon_queries", "exact_logon_queried", "exact_logon_end", "final_serialization_start", "final_serialization_end", "completed" }.Contains(phase)) {
            safe["collector_phase"] = phase;
            foreach (string key in new[] { "elapsed_sec", "user_count", "computer_count", "record_count", "exact_queries_completed", "dc_count" })
                if (raw[key] is JsonValue v && v.TryGetValue<int>(out int count) && count is >= 0 and <= 10000000) safe[key] = count;
        }
        return safe;
    }
    internal async Task<JsonObject> CollectAsync(string family, JsonObject? baseBundle, CancellationToken ct)
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-ad-snapshot-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try {
            if (family == "computers_v6") await File.WriteAllTextAsync(Path.Combine(directory, "base.json"), ComputerBase(baseBundle!).ToJsonString(), ct);
            var start = Command(family, directory);
            // Never silently switch a separately configured source identity to the service identity.
            string mode = get("ADLOG_AD_SOURCE_CREDENTIAL_MODE") ?? "process";
            if (mode is not ("process" or "dpapi_current_user")) throw new WorkerFailure("acquisition", "ad_source_credential_mode_invalid");
            AdCoordinatorIdentity? identity = null;
            if (mode == "dpapi_current_user") {
                if (!OperatingSystem.IsWindows() || validateEndpoint is null) throw new WorkerFailure("acquisition", "ad_source_endpoint_invalid");
                await validateEndpoint(Server, ct);
                var config = new Sli.Server.Storage.Lifecycle.LifecycleConfiguration(root, get);
                identity = AdCoordinatorIdentity.Start(start, config.DataRoot(root));
            }
            using var identityLifetime = identity;
            using var process = identity?.Process ?? Process.Start(start) ?? throw new WorkerFailure("acquisition", "collector_start_failed");
            if (identity is null) process.StandardInput.Close();
            static async Task Drain(StreamReader stream, CancellationToken token) { char[] chars = new char[4096]; while (await stream.ReadAsync(chars, token) > 0) { } }
            var stdout = identity is null ? Drain(process.StandardOutput, ct) : Task.CompletedTask;
            var stderr = identity is null ? Drain(process.StandardError, ct) : Task.CompletedTask;
            var exited = process.WaitForExitAsync(ct);
            try {
                while (!exited.IsCompleted) {
                    var details = new JsonObject { ["family"] = family, ["collector_pid"] = process.Id };
                    string path = Path.Combine(directory, "p.json");
                    try { if (File.Exists(path) && new FileInfo(path).Length <= 4096) foreach (var (key, value) in SafeProgress(JsonNode.Parse(await File.ReadAllTextAsync(path, ct))!.AsObject())) details[key] = value?.DeepClone(); }
                    catch (Exception e) when (e is IOException or System.Text.Json.JsonException or InvalidOperationException) { }
                    await progress("collecting", details, ct);
                    using var tick = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(30), tick.Token)); await tick.CancelAsync();
                }
                await exited; await Task.WhenAll(stdout, stderr);
            } finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
            string output = Path.Combine(directory, "output.json");
            if (!File.Exists(output) || new FileInfo(output).Length is <= 0 or > 67108864) throw new WorkerFailure("acquisition", "collector_bundle_missing_or_invalid");
            var result = JsonNode.Parse(await File.ReadAllTextAsync(output, ct))!.AsObject();
            if (process.ExitCode != 0 && result["sections"] is not JsonArray { Count: > 0 } && result["metadata"]?.Text("collection_status") != "partial") throw new WorkerFailure("acquisition", "collector_failed");
            return result;
        } finally { Directory.Delete(directory, true); }
    }
}
