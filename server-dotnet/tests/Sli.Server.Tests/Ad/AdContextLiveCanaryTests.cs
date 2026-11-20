using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdContextLiveCanaryTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-512";
    static readonly string Root = Path.Combine(Path.GetTempPath(), "sli-ad-canary-tests");
    static readonly AdContextLiveCanary Canary = new(Root);
    static AdContextCanaryRequest Request(string section = "privileged_membership") => new()
    {
        DirectoryServer = "dc1.example.test", Domain = "example.test", SearchBase = "DC=example,DC=test",
        Sections = [section], PrivilegedGroups = section == "privileged_membership" ? [Sid] : [],
        VpnGroups = section == "vpn_membership" ? [Sid] : [], ExpectedAccount = "EXAMPLE\\svc_sli_read",
        NotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"), NotAfterUtc = DateTimeOffset.UtcNow.AddMinutes(30).ToString("O")
    };
    static AdContextRequest Adapter(string section = "privileged_membership") => Request(section) with
    {
        PowershellExecutable = OperatingSystem.IsWindows() ? @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" : "/usr/bin/pwsh",
        OutputPath = "bundle.json", RunId = "00000000-0000-4000-8000-000000000046"
    };
    static string Value(string[] command, string key) => command[Array.IndexOf(command, "-" + key) + 1];
    static (string, string) NoExternalChecks() => throw new Xunit.Sdk.XunitException("must reject before Windows, account, PowerShell or AD checks");

    [Fact] public void Approval_hash_matches_python_canonical_request()
    {
        var scope = Canary.Validate(Request("vpn_membership") with { NotBeforeUtc = "2026-11-09T00:00:00Z", NotAfterUtc = "2026-11-09T00:30:00Z" });
        scope["output_root"] = "/canary"; // Platform-independent Python hashlib/json reference.
        Assert.Equal("eadc715504c76284d9be976f88e76390f255e832838a5e388a1fc6971dcf71cb", AdContextLiveCanary.ApprovalRequestSha256(scope));
        foreach (var (key, value) in scope.ToArray())
        {
            var changed = scope.DeepClone().AsObject();
            changed[key] = value is JsonArray ? new JsonArray("changed") : JsonValue.Create("changed");
            Assert.NotEqual(AdContextLiveCanary.ApprovalRequestSha256(scope), AdContextLiveCanary.ApprovalRequestSha256(changed));
        }
    }

    [Fact] public async Task Validate_only_has_no_external_or_storage_side_effects()
    {
        var result = await Canary.RunAsync(Request(), NoExternalChecks, TestContext.Current.CancellationToken);
        Assert.Equal("validated_only", result["status"]!.ToString());
        foreach (string flag in new[] { "live_ad_contacted", "database_imported", "scheduler_changed", "runtime_restarted", "html_generated", "approval_hash_verified", "credentials_accepted", "gpo_changed" }) Assert.False(result[flag]!.GetValue<bool>());
        Assert.Matches("^[0-9a-f]{64}$", result["approval_request_sha256"]!.ToString());
    }
    [Fact] public async Task Command_validate_only_returns_real_pinned_scope_without_creating_output()
    {
        string project = Path.Combine(Path.GetTempPath(), "sli-ad-command-" + Guid.NewGuid().ToString("N"));
        var r = Request("vpn_membership");
        string[] args = ["--project-root", project, "--directory-server", r.DirectoryServer, "--domain", r.Domain, "--search-base", r.SearchBase,
            "--expected-account", r.ExpectedAccount, "--not-before-utc", r.NotBeforeUtc, "--not-after-utc", r.NotAfterUtc,
            "--section", "vpn_membership", "--vpn-group-sid", Sid, "--validate-only"];
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(0, await AdContextLiveCanaryCommand.RunAsync(args, output, error, TestContext.Current.CancellationToken));
        Assert.Equal("", error.ToString());
        var result = JsonNode.Parse(output.ToString())!;
        Assert.Equal("validated_only", result["status"]!.ToString());
        Assert.Equal("vpn_security_v1", result["approved_scope"]!["collection_profile"]!.ToString());
        Assert.False(Directory.Exists(project));
        Assert.Equal(1, await AdContextLiveCanaryCommand.RunAsync(args.Append("--execute").ToArray(), output, error, TestContext.Current.CancellationToken));
        Assert.Contains("mutually exclusive", error.ToString());
    }
    [Theory]
    [InlineData("group", "exact privileged group SIDs")]
    [InlineData("timeout", "timeout_seconds")]
    [InlineData("records", "max_records")]
    [InlineData("server", "directory_server")]
    [InlineData("window", "two hours")]
    public void Parameters_fail_closed(string field, string message)
    {
        var r = Request(); r = field switch {
            "group" => r with { PrivilegedGroups = ["Domain Admins"] }, "timeout" => r with { TimeoutSeconds = 301 },
            "records" => r with { MaxRecords = 5001 }, "server" => r with { DirectoryServer = "dc1; whoami" },
            _ => r with { NotAfterUtc = DateTimeOffset.UtcNow.AddHours(3).ToString("O") }
        };
        Assert.Contains(message, Assert.Throws<ArgumentException>(() => Canary.Validate(r)).Message);
    }
    [Theory] [InlineData("privileged_membership", "group_sids")] [InlineData("vpn_membership", "vpn_group_sids")]
    public void Canary_allows_fifty_distinct_group_SIDs_but_rejects_fifty_one(string section, string key)
    {
        var groups = Enumerable.Range(1000, 50).Select(n => $"S-1-5-21-100000001-200000002-300000003-{n}").ToArray();
        var r = Request(section);
        r = section == "privileged_membership" ? r with { PrivilegedGroups = groups } : r with { VpnGroups = groups };
        Assert.Equal(50, Canary.Validate(r)[key]!.AsArray().Count);
        var extra = groups.Append("S-1-5-21-100000001-200000002-300000003-2000").ToArray();
        Assert.Throws<ArgumentException>(() => Canary.Validate(section == "privileged_membership" ? r with { PrivilegedGroups = extra } : r with { VpnGroups = extra }));
    }
    [Fact] public void Full_directory_bundle_and_independent_population_budgets_match_exporter()
    {
        var r = Request("directory_accounts") with { MaxRecords = 5000, MaxDirectoryAccounts = 5000, MaxDirectoryUsers = 3600, MaxDirectoryComputers = 1400, MaxBundleBytes = 25 * 1024 * 1024 };
        var scope = Canary.Validate(r);
        Assert.Equal(25 * 1024 * 1024, scope["max_bundle_bytes"]!.GetValue<int>());
        Assert.Equal(3600, scope["max_directory_users"]!.GetValue<int>()); Assert.Equal(1400, scope["max_directory_computers"]!.GetValue<int>());
        Assert.Contains("max_bundle_bytes", Assert.Throws<ArgumentException>(() => Canary.Validate(r with { MaxBundleBytes = r.MaxBundleBytes + 1 })).Message);
        Assert.Throws<ArgumentException>(() => Canary.Validate(r with { MaxDirectoryComputers = 1401 }));
    }
    [Theory]
    [InlineData("privileged_membership", "privileged_membership_v1", "targeted", "0.5.0")]
    [InlineData("directory_accounts", "directory_security_v1", "full", "0.10.0")]
    [InlineData("vpn_membership", "vpn_security_v1", "targeted", "0.10.0")]
    [InlineData("gpo_governance", "gpo_governance_v4", "full", "0.10.0")]
    [InlineData("domain_posture", "domain_posture_v1", "full", "0.10.0")]
    [InlineData("domain_health", "domain_health_v1", "full", "0.10.0")]
    public async Task Validate_only_pins_exact_section_profile_mode_and_pack(string section, string profile, string mode, string version)
    {
        var r = Request(section); var result = await Canary.RunAsync(r, NoExternalChecks, TestContext.Current.CancellationToken); var scope = result["approved_scope"]!;
        Assert.Equal("validated_only", result["status"]!.ToString()); Assert.False(result["live_ad_contacted"]!.GetValue<bool>());
        Assert.Equal(section, scope["sections"]![0]!.ToString()); Assert.Equal(profile, scope["collection_profile"]!.ToString());
        Assert.Equal(mode, scope["collection_mode"]!.ToString()); Assert.Equal(version, scope["source_pack_version"]!.ToString());
        if (section == "vpn_membership") Assert.Equal(Sid, scope["vpn_group_sids"]![0]!.ToString());
        Assert.NotEqual(result["approval_request_sha256"]!.ToString(), AdContextLiveCanary.ApprovalRequestSha256(Canary.Validate(r with { MaxGpos = 71 })));
    }
    [Fact] public void Supplemental_requests_reject_names_oversized_sections_and_multiple_sections()
    {
        Assert.Contains("exact VPN group SIDs", Assert.Throws<ArgumentException>(() => Canary.Validate(Request("vpn_membership") with { VpnGroups = ["VPNl2tp"] })).Message);
        Assert.Contains("section limits", Assert.Throws<ArgumentException>(() => Canary.Validate(Request("gpo_governance") with { MaxRecords = 100, MaxGpos = 101 })).Message);
        Assert.Contains("exactly one section", Assert.Throws<ArgumentException>(() => Canary.Validate(Request("directory_accounts") with { Sections = ["directory_accounts", "gpo_governance"] })).Message);
        var r = Request("gpo_governance") with { MaxRecords = 100, MaxGpos = 72, TimeoutSeconds = 300 };
        Assert.Equal(72, Canary.Validate(r)["max_gpos"]!.GetValue<int>());
        Assert.Contains("72-policy", Assert.Throws<ArgumentException>(() => Canary.Validate(r with { MaxGpos = 73 })).Message);
    }
    [Fact] public async Task Execution_requires_confirmation_then_exact_owner_hash_then_active_window()
    {
        var r = Request() with { Execute = true };
        Assert.Contains(AdContextLiveCanary.Confirmation, (await Assert.ThrowsAsync<ArgumentException>(() => Canary.RunAsync(r, NoExternalChecks, TestContext.Current.CancellationToken))).Message);
        r = r with { Confirmation = AdContextLiveCanary.Confirmation };
        Assert.Contains("owner-approved SHA-256", (await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Canary.RunAsync(r, NoExternalChecks, TestContext.Current.CancellationToken))).Message);
        var approved = r with { ApprovedRequestSha256 = AdContextLiveCanary.ApprovalRequestSha256(Canary.Validate(r)) };
        Assert.Contains("owner-approved SHA-256", (await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Canary.RunAsync(approved with { MaxGpos = 71 }, NoExternalChecks, TestContext.Current.CancellationToken))).Message);
        foreach (int minutes in new[] { -120, 60 })
        {
            var outside = r with { NotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(minutes).ToString("O"), NotAfterUtc = DateTimeOffset.UtcNow.AddMinutes(minutes + 30).ToString("O") };
            outside = outside with { ApprovedRequestSha256 = AdContextLiveCanary.ApprovalRequestSha256(Canary.Validate(outside)) };
            Assert.Contains("window is not active", (await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Canary.RunAsync(outside, NoExternalChecks, TestContext.Current.CancellationToken))).Message);
        }
    }
    [Fact] public async Task Existing_lock_blocks_collector_and_is_preserved()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-ad-canary-" + Guid.NewGuid().ToString("N"));
        var canary = new AdContextLiveCanary(root);
        Directory.CreateDirectory(canary.DefaultOutputRoot);
        string path = Path.Combine(canary.DefaultOutputRoot, "ADCTX-LIVE-CANARY-1.lock");
        try
        {
            await File.WriteAllTextAsync(path, "busy", TestContext.Current.CancellationToken);
            var r = Request() with { Execute = true, Confirmation = AdContextLiveCanary.Confirmation };
            r = r with { ApprovedRequestSha256 = AdContextLiveCanary.ApprovalRequestSha256(canary.Validate(r)) };
            Assert.Contains("lock already exists", (await Assert.ThrowsAsync<InvalidOperationException>(() => canary.RunAsync(r, () => (r.ExpectedAccount, "must-not-execute"), TestContext.Current.CancellationToken))).Message);
            Assert.Equal("busy", await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
            Assert.Single(Directory.GetFiles(canary.DefaultOutputRoot));
        }
        finally { Directory.Delete(root, true); }
    }
    [Fact] public void Adapter_pins_executable_server_scope_and_budgets()
    {
        var r = Adapter() with { Mode = "targeted", MaxRecords = 101, MaxBundleBytes = 65536 };
        string[] command = AdContextCommand.Build(r, Root);
        Assert.True(Path.IsPathFullyQualified(command[0])); Assert.Equal(r.DirectoryServer, Value(command, "DirectoryServer"));
        Assert.Equal("101", Value(command, "MaxRecords")); Assert.Equal("65536", Value(command, "MaxBundleBytes"));
        Assert.Equal("privileged_membership_v1", Value(command, "CollectionProfile")); Assert.Equal("Export-AdContextBundle.ps1", Path.GetFileName(Value(command, "File")));
        Assert.Contains("absolute allowlisted", Assert.Throws<ArgumentException>(() => AdContextCommand.Build(r with { PowershellExecutable = "powershell.exe" }, Root)).Message);
        Assert.Throws<ArgumentException>(() => AdContextCommand.Build(r with { PowershellExecutable = Path.Combine(Path.GetTempPath(), "arbitrary.exe") }, Root));
    }
    [Theory] [InlineData("vpn_membership", "vpn_security_v1")] [InlineData("domain_posture", "domain_posture_v1")] [InlineData("domain_health", "domain_health_v1")]
    public void Supplemental_adapter_pins_repository_script_and_section_profile(string section, string profile)
    {
        var r = Adapter(section) with { VpnGroups = section == "vpn_membership" ? ["VPNl2tp"] : [], MaxRecords = 5000, MaxBundleBytes = 4 * 1024 * 1024 };
        string[] command = AdContextCommand.Build(r, Root);
        Assert.Equal(Path.Combine(Root, "scripts", "ad_context", "Export-AdAuditContextBundle.ps1"), Value(command, "File"));
        Assert.Equal(section, Value(command, "Sections")); Assert.Equal(profile, Value(command, "CollectionProfile"));
        Assert.Equal("180", Value(command, "InactiveDays")); Assert.Equal("2000", Value(command, "MaxDirectoryAccounts"));
        Assert.Equal("500", Value(command, "MaxVpnMembers")); Assert.Equal("72", Value(command, "MaxGpos"));
        if (section == "vpn_membership") Assert.Equal("VPNl2tp", Value(command, "VpnGroups"));
    }
    [Fact] public void Supplemental_adapter_rejects_unbounded_references_sections_and_budgets()
    {
        Assert.Contains("exactly one bounded section", Assert.Throws<ArgumentException>(() => AdContextCommand.Build(Adapter("directory_accounts") with { Sections = ["directory_accounts", "gpo_governance"], MaxRecords = 5000 }, Root)).Message);
        Assert.Contains("exact bounded VPN group", Assert.Throws<ArgumentException>(() => AdContextCommand.Build(Adapter("vpn_membership") with { VpnGroups = ["VPN,Other"] }, Root)).Message);
        Assert.Contains("section limits", Assert.Throws<ArgumentException>(() => AdContextCommand.Build(Adapter("gpo_governance") with { MaxRecords = 100, MaxGpos = 101 }, Root)).Message);
        Assert.Contains("72-policy", Assert.Throws<ArgumentException>(() => AdContextCommand.Build(Adapter("gpo_governance") with { MaxRecords = 200, MaxGpos = 73 }, Root)).Message);
    }
    [Fact] public void Adapter_uses_independent_user_and_computer_ceilings()
    {
        var command = AdContextCommand.Build(Adapter("directory_accounts") with { MaxRecords = 5000, MaxDirectoryUsers = 3600, MaxDirectoryComputers = 1400 }, Root);
        Assert.Equal("3600", Value(command, "MaxDirectoryUsers")); Assert.Equal("1400", Value(command, "MaxDirectoryComputers"));
    }
    static JsonObject Bundle() => JsonNode.Parse("""
        {"schema_version":"ad-context-bundle/v1","source_pack_id":"sli.windows.ad-context","source_pack_version":"0.5.0",
         "run_id":"00000000-0000-4000-8000-000000000046","mode":"targeted","observed_at_utc":"2026-11-09T00:00:00Z",
         "domain":{"sid":"S-1-5-21-100000001-200000002-300000003","dns_name":"example.test"},
         "scope":{"search_base":"DC=example,DC=test","privileged_group_sids":["S-1-5-21-100000001-200000002-300000003-512"],"collection_profile":"privileged_membership_v1"},
         "sections":[{"name":"privileged_membership","status":"complete","record_count":1,"duration_ms":12}],
         "records":[{"record_type":"entity","record_key":"group-1","section":"privileged_membership","observed_at_utc":"2026-11-09T00:00:00Z",
           "identity":{"kind":"ad_group","domain_sid":"S-1-5-21-100000001-200000002-300000003","object_guid":"00000000-0000-4000-8000-000000000001","object_sid":"S-1-5-21-100000001-200000002-300000003-512"},"attributes":{}}]}
        """)!.AsObject();
    [Fact] public void Summary_distinguishes_transport_and_normalized_hashes()
    {
        var bundle = Bundle(); var scope = Canary.Validate(Request());
        var bytes = Encoding.UTF8.GetBytes(bundle.ToJsonString());
        var first = AdContextLiveCanary.SummarizeBundle(bytes, scope, bundle["run_id"]!.ToString());
        var second = AdContextLiveCanary.SummarizeBundle(Encoding.UTF8.GetBytes(bundle.ToJsonString(new JsonSerializerOptions { WriteIndented = true })), scope, bundle["run_id"]!.ToString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), first["transport_file_sha256"]!.ToString());
        Assert.Matches("^[0-9a-f]{64}$", first["normalized_content_sha256"]!.ToString()); Assert.False(first.ContainsKey("bundle_sha256"));
        Assert.Equal(first["normalized_content_sha256"]!.ToString(), second["normalized_content_sha256"]!.ToString());
        Assert.NotEqual(first["transport_file_sha256"]!.ToString(), second["transport_file_sha256"]!.ToString());
        Assert.Equal(1, first["record_counts"]!["entity"]!.GetValue<int>()); Assert.Equal(1, first["entity_kind_counts"]!["ad_group"]!.GetValue<int>());
        Assert.Equal(12, first["collector_duration_ms"]!.GetValue<long>());
    }
    [Theory]
    [InlineData("run_id")] [InlineData("domain")] [InlineData("search_base")] [InlineData("source_pack_version")]
    [InlineData("collection_mode")] [InlineData("collection_profile")] [InlineData("group_sids")]
    [InlineData("vpn_group_sids")] [InlineData("sections")] [InlineData("max_records")] [InlineData("max_bundle_bytes")]
    public void Summary_rejects_output_outside_approved_scope(string field)
    {
        var bundle = Bundle(); var scope = Canary.Validate(Request()); string runId = bundle["run_id"]!.ToString();
        if (field == "run_id") runId = "00000000-0000-4000-8000-000000000099";
        else scope[field] = field switch {
            "group_sids" or "vpn_group_sids" => new JsonArray("S-1-5-21-100000001-200000002-300000003-999"),
            "sections" => new JsonArray("gpo_governance"), "max_records" => JsonValue.Create(0), "max_bundle_bytes" => JsonValue.Create(1),
            _ => JsonValue.Create("changed")
        };
        Assert.Throws<ArgumentException>(() => AdContextLiveCanary.SummarizeBundle(Encoding.UTF8.GetBytes(bundle.ToJsonString()), scope, runId));
    }
    [Theory] [InlineData("partial")] [InlineData("failed")] [InlineData("missing")] [InlineData("skipped")]
    public void Incomplete_or_missing_approved_section_is_rejected(string status)
    {
        var scope = Canary.Validate(Request("gpo_governance"));
        var statuses = status == "missing" ? new JsonObject() : new JsonObject { ["gpo_governance"] = status };
        Assert.Contains("gpo_governance=" + status, Assert.Throws<InvalidOperationException>(() => AdContextLiveCanary.RequireCompleteSections(new JsonObject { ["section_statuses"] = statuses }, scope)).Message);
    }
    [Fact] public void Only_complete_approved_section_is_accepted() => AdContextLiveCanary.RequireCompleteSections(
        new JsonObject { ["section_statuses"] = new JsonObject { ["gpo_governance"] = "complete" } }, Canary.Validate(Request("gpo_governance")));

    static string RepositoryScript(string relative)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string path = Path.Combine(directory.FullName, relative);
            if (File.Exists(path)) return File.ReadAllText(path);
        }
        throw new FileNotFoundException("repository-owned AD Context script not found", relative);
    }
    [Fact] public void Shared_wrapper_preserves_explicit_consent_and_resolves_root_before_changing_location()
    {
        string source = RepositoryScript("scripts/maintenance/Run-SLI-AdContext-LiveCanary-v1.ps1");
        foreach (string value in new[] { "[switch]$ValidateOnly", "[switch]$Execute", "$ApprovedRequestSha256", "$NotBeforeUtc", "$NotAfterUtc", "[ValidateRange(1, 72)][int]$MaxGpos = 72" }) Assert.Contains(value, source);
        Assert.True(source.IndexOf("GetFullPath($ProjectRoot)", StringComparison.Ordinal) < source.IndexOf("Set-Location -LiteralPath $ProjectRoot", StringComparison.Ordinal));
        Assert.DoesNotContain(AdContextLiveCanary.Confirmation, source);
    }
    [Fact] public void Shared_privileged_collector_bounds_queries_on_the_directory_server()
    {
        string source = RepositoryScript("scripts/ad_context/Export-AdContextBundle.ps1");
        Assert.DoesNotContain("Get-ADGroupMember -Server", source);
        Assert.Contains("-ResultSetSize $queryLimit", source);
        Assert.Contains("member query exceeded the approved record budget", source);
    }
    [Fact] public void Shared_supplemental_collector_preserves_query_budgets_GPO_identity_and_population_integrity()
    {
        string source = RepositoryScript("scripts/ad_context/Export-AdAuditContextBundle.ps1");
        foreach (string forbidden in new[] { "$rawXml = Get-GPOReport", "Get-GPO -All", "link_count = 0", "links = @()" }) Assert.DoesNotContain(forbidden, source);
        foreach (string required in new[] {
            "$MaxDirectoryAccounts", "$MaxVpnMembers", "$MaxGpos", "LDAPFilter \"(objectClass=groupPolicyContainer)\"", "-Properties Name, ObjectGUID", "-ResultSetSize $gpoQueryLimit",
            "GPO inventory exceeded the approved section budget", "Invoke-SLIBoundedGpoReportRead", "Invoke-SLIBoundedGpoPermissionRead",
            "$gpoDirectoryObjectGuid = [guid]$gpo.ObjectGUID", "$gpoPolicyGuid = [guid]([string]$gpo.Name)", "Invoke-SLIBoundedGpoReportRead -Guid $gpoPolicyGuid",
            "Invoke-SLIBoundedGpoPermissionRead -Guid $gpoPolicyGuid", "Get-StableRecordKey -DomainSid $domainSid -ObjectGuid $gpoDirectoryObjectGuid",
            "gpo_governance_total_time_ceiling_exceeded", "Get-ADComputer -Server $DirectoryServer", "-ResultSetSize ($computerLimit + 1)",
            "$computersTruncated = (-not $isBaseProfile) -and $computers.Count -gt $computerLimit",
            "if (-not $isBaseProfile) { $computers = @($computers | Select-Object -First $computerLimit) }",
            "if ($baseComputers.Count -gt $computerLimit) { throw \"ad_snapshot_base_v1_computer_record_bound_exceeded\" }",
            "if ($baseUsers.Count -gt $userLimit) { throw \"ad_snapshot_base_v1_user_record_bound_exceeded\" }", "-Code \"directory_accounts_truncated\"",
            "dns_host_name", "operating_system", "operating_system_version"
        }) Assert.Contains(required, source);
    }
}
