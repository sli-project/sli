using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Legacy;
using static Sli.Server.Ad.AdJson;
using static Sli.Server.Ad.AdContextCommand;

namespace Sli.Server.Ad;

public sealed record AdContextCanaryRequest : AdContextRequest
{
    public string ExpectedAccount { get; init; } = "";
    public int TimeoutSeconds { get; init; } = 120;
    public string NotBeforeUtc { get; init; } = "";
    public string NotAfterUtc { get; init; } = "";
    public string? OutputRoot { get; init; }
    public bool Execute { get; init; }
    public string Confirmation { get; init; } = "";
    public string ApprovedRequestSha256 { get; init; } = "";
}

// Read-only acquisition: no database, scheduler, restart or report dependencies.
public sealed class AdContextLiveCanary(string repositoryRoot)
{
    public const string Confirmation = "ADCTX-LIVE-CANARY-READ-ONLY";
    public string DefaultOutputRoot => Path.GetFullPath(Path.Combine(repositoryRoot, "artifacts", "ad_context_live_canary"));
    static string Utc(DateTimeOffset value) => value.UtcDateTime.ToString(value.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'+00:00'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'", CultureInfo.InvariantCulture);
    public JsonObject Validate(AdContextCanaryRequest r)
    {
        Require(Regex.IsMatch(r.DirectoryServer, @"\A[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\z"), "directory_server must be one hostname, FQDN or IP address");
        Require(Regex.IsMatch(r.Domain, @"\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z"), "domain must be a DNS domain name");
        Require(r.SearchBase.StartsWith("DC=", StringComparison.OrdinalIgnoreCase) && !r.SearchBase.Any(c => c is '\r' or '\n'), "search_base must be one bounded directory DN");
        string[] sections = (r.Sections.Length == 0 ? ["privileged_membership"] : r.Sections).Distinct().ToArray();
        Require(sections.All(Profiles.ContainsKey), "provide only supported AD Context sections");
        Require(sections.Length == 1, "live canary requires exactly one section per approved execution");
        string section = sections[0];
        string[] groups = r.PrivilegedGroups.Select(s => s.ToUpperInvariant()).Distinct().ToArray();
        string[] vpn = r.VpnGroups.Select(s => s.ToUpperInvariant()).Distinct().ToArray();
        Require(section == "privileged_membership" ? groups.Length is >= 1 and <= 50 && groups.All(Sid) : groups.Length == 0, "provide between one and fifty exact privileged group SIDs for privileged_membership");
        Require(section == "vpn_membership" ? vpn.Length is >= 1 and <= 50 && vpn.All(Sid) : vpn.Length == 0, "provide between one and fifty exact VPN group SIDs for vpn_membership");
        Require(r.TimeoutSeconds is >= 5 and <= 300, "timeout_seconds must be between 5 and 300");
        Require(r.MaxRecords is >= 1 and <= 5000, "max_records must be between 1 and 5000 for the live canary");
        Require(r.MaxBundleBytes is >= 1024 and <= 25 * 1024 * 1024, "max_bundle_bytes must be between 1024 and 26214400");
        CheckSectionLimits(r, section, true);
        Require(!string.IsNullOrWhiteSpace(r.ExpectedAccount) && !r.ExpectedAccount.Any(c => c is '\r' or '\n'), "expected_account must be one Windows account name; credentials are never accepted");
        var timestamps = new JsonObject { ["not_before_utc"] = r.NotBeforeUtc, ["not_after_utc"] = r.NotAfterUtc };
        var before = timestamps.Time("not_before_utc"); var after = timestamps.Time("not_after_utc");
        Require(before < after, "not_before_utc must be earlier than not_after_utc");
        Require(after - before <= TimeSpan.FromHours(2), "the approved execution window cannot exceed two hours");
        string output = Path.GetFullPath(r.OutputRoot ?? DefaultOutputRoot);
        string relative = Path.GetRelativePath(DefaultOutputRoot, output);
        Require(!Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal), "output_root must stay under artifacts/ad_context_live_canary");
        var (users, computers) = DirectoryLimits(r);
        return Obj(new {
            directory_server = r.DirectoryServer, domain = r.Domain.ToLowerInvariant(), search_base = r.SearchBase,
            sections, collection_mode = section is "privileged_membership" or "vpn_membership" ? "targeted" : "full",
            collection_profile = Profiles[section], source_pack_version = section == "privileged_membership" ? "0.5.0" : "0.10.0",
            group_sids = groups, vpn_group_sids = vpn, expected_account = r.ExpectedAccount, timeout_seconds = r.TimeoutSeconds,
            max_records = r.MaxRecords, max_bundle_bytes = r.MaxBundleBytes, max_directory_accounts = r.MaxDirectoryAccounts,
            max_directory_users = users, max_directory_computers = computers, max_vpn_members = r.MaxVpnMembers, max_gpos = r.MaxGpos,
            not_before_utc = Utc(before), not_after_utc = Utc(after), powershell_runtime = "windows-powershell-5.1-system32", output_root = output
        });
    }
    public static string ApprovalRequestSha256(JsonObject scope) => AdJobPlugin.Digest(scope);
    public static void RequireCompleteSections(JsonObject measurements, JsonObject scope)
    {
        string[] incomplete = scope["sections"]!.AsArray().Select(s => s!.ToString())
            .Select(s => (Name: s, Status: measurements["section_statuses"]?[s]?.ToString() ?? "missing"))
            .Where(s => s.Status != "complete").Select(s => s.Name + "=" + s.Status).ToArray();
        if (incomplete.Length > 0) throw new InvalidOperationException("AD Context collector did not complete the approved section: " + string.Join(", ", incomplete));
    }
    public static JsonObject SummarizeBundle(byte[] bytes, JsonObject expected, string runId)
    {
        var bundle = AdContextBundle.Normalize(JsonNode.Parse(bytes)!.AsObject());
        void Same(string actual, string wanted, string label, bool ignoreCase = false) => Require(string.Equals(actual, wanted, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), "collector returned an unexpected " + label);
        Same(bundle.Text("run_id")!, runId, "run_id"); Same(bundle["domain"]!.Text("dns_name")!, expected.Text("domain")!, "domain", true);
        Same(bundle["scope"]!.Text("search_base")!, expected.Text("search_base")!, "search_base", true);
        foreach (var (key, field) in new[] { ("source_pack_version", "source_pack_version"), ("mode", "collection_mode") }) Same(bundle.Text(key)!, expected.Text(field)!, field);
        Same(bundle["scope"]!.Text("collection_profile") ?? "", expected.Text("collection_profile") ?? "", "collection_profile");
        foreach (var (key, field) in new[] { ("privileged_group_sids", "group_sids"), ("vpn_group_sids", "vpn_group_sids") })
            Require(bundle["scope"]![key]!.AsArray().Select(s => s!.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(expected[field]!.AsArray().Select(s => s!.ToString())), "collector group SID scope differs from the approved scope");
        var sections = bundle["sections"]!.AsArray(); var records = bundle["records"]!.AsArray();
        Require(sections.Select(s => s!.Text("name")!).SequenceEqual(expected["sections"]!.AsArray().Select(s => s!.ToString())), "collector sections differ from the approved scope");
        Require(records.Count <= expected.Int("max_records") && bytes.Length <= expected.Int("max_bundle_bytes"), "collector output exceeded the approved budget");
        return new JsonObject {
            ["run_id"] = runId, ["observed_at_utc"] = bundle["observed_at_utc"]!.DeepClone(),
            ["section_status"] = sections.Count == 1 ? sections[0]!["status"]!.DeepClone() : null,
            ["section_statuses"] = new JsonObject(sections.Select(s => KeyValuePair.Create<string, JsonNode?>(s!.Text("name")!, s!["status"]!.DeepClone()))),
            ["collector_duration_ms"] = sections.Select(s => s!.Int("duration_ms")).DefaultIfEmpty().Max(),
            ["record_counts"] = new JsonObject(new[] { "entity", "relation", "data_quality" }.Select(k => KeyValuePair.Create<string, JsonNode?>(k, JsonValue.Create(records.Count(r => r!.Text("record_type") == k))))),
            ["entity_kind_counts"] = new JsonObject(records.Where(r => r!.Text("record_type") == "entity").GroupBy(r => r!["identity"]!.Text("kind")!).Select(g => KeyValuePair.Create<string, JsonNode?>(g.Key, JsonValue.Create(g.Count())))),
            ["bundle_bytes"] = bytes.Length, ["transport_file_sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            ["normalized_content_sha256"] = bundle["bundle_sha256"]!.DeepClone()
        };
    }
    public Task<JsonObject> RunAsync(AdContextCanaryRequest request, CancellationToken ct = default) => RunAsync(request, WindowsPreflight, ct);
    internal async Task<JsonObject> RunAsync(AdContextCanaryRequest request, Func<(string Account, string Executable)> preflight, CancellationToken ct = default)
    {
        var settings = new LegacySettings(new ConfigurationBuilder().Build());
        if (settings.Disabled) throw new InvalidOperationException(LegacySettings.DisabledMessage);
        var scope = Validate(request); string hash = ApprovalRequestSha256(scope);
        var result = Obj(new { package_type = "ADCTX-LIVE-CANARY-1", generated_at_utc = Utc(DateTimeOffset.UtcNow), mode = request.Execute ? "execute" : "validate_only",
            approved_scope = scope, approval_request_sha256 = hash, output_root = scope.Text("output_root"), database_imported = false, scheduler_changed = false,
            runtime_restarted = false, gpo_changed = false, html_generated = false, credentials_accepted = false, live_ad_contacted = false, approval_hash_verified = false });
        if (!request.Execute) { result["status"] = "validated_only"; return result; }
        Require(request.Confirmation == Confirmation, "execute requires --confirmation " + Confirmation);
        if (!string.Equals(request.ApprovedRequestSha256.Trim(), hash, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("execute requires the owner-approved SHA-256 of this exact request");
        var now = DateTimeOffset.UtcNow;
        if (now < scope.Time("not_before_utc") || now > scope.Time("not_after_utc")) throw new UnauthorizedAccessException("the approved live-canary execution window is not active");
        var runtime = preflight();
        if (!runtime.Account.Equals(request.ExpectedAccount, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("current Windows account differs from expected_account");
        string output = scope.Text("output_root")!;
        Directory.CreateDirectory(output);
        string lockPath = Path.Combine(output, "ADCTX-LIVE-CANARY-1.lock");
        FileStream lease;
        try { lease = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
        catch (IOException) when (File.Exists(lockPath)) { throw new InvalidOperationException("canary lock already exists"); }
        await using (lease)
        {
            string runId = Guid.NewGuid().ToString("D"), bundlePath = Path.Combine(output, "ad_context_live_canary_" + runId + ".json");
            try
            {
                await lease.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"pid={Environment.ProcessId} started={Utc(now)}\n"), ct);
                await lease.FlushAsync(ct);
                string[] command = Build(request with { PowershellExecutable = runtime.Executable, RunId = runId, OutputPath = bundlePath,
                    Sections = scope["sections"]!.AsArray().Select(s => s!.ToString()).ToArray(), Mode = scope.Text("collection_mode")! }, repositoryRoot);
                var start = new ProcessStartInfo(command[0]) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = Path.GetFullPath(repositoryRoot) };
                foreach (string arg in command.Skip(1)) start.ArgumentList.Add(arg);
                using var process = Process.Start(start) ?? throw new InvalidOperationException("AD Context collector did not start");
                result["live_ad_contacted"] = true; result["approval_hash_verified"] = true;
                // Q500: cancellation is explicit; there is no deadline for a live collector.
                using var cancel = ct.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } });
                var stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, ct);
                var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, ct);
                var exit = process.WaitForExitAsync(ct);
                while (!exit.IsCompleted)
                {
                    await lease.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"heartbeat={Utc(DateTimeOffset.UtcNow)} pid={process.Id}\n"), ct);
                    await lease.FlushAsync(ct);
                    await Task.WhenAny(exit, Task.Delay(TimeSpan.FromSeconds(5), ct));
                }
                await Task.WhenAll(exit, stdout, stderr);
                if (process.ExitCode != 0) throw new InvalidOperationException("AD Context collector failed with exit code " + process.ExitCode);
                var measurements = SummarizeBundle(await File.ReadAllBytesAsync(bundlePath, ct), scope, runId);
                RequireCompleteSections(measurements, scope);
                result["measurements"] = measurements; result["status"] = "accepted";
                return result;
            }
            finally { lease.Close(); File.Delete(lockPath); }
        }
    }
    static (string Account, string Executable) WindowsPreflight()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("live AD canary execution is supported only on the Windows SLI host");
        using var identity = WindowsIdentity.GetCurrent();
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(executable)) throw new InvalidOperationException("trusted system Windows PowerShell was not found");
        return (identity.Name, executable);
    }
}
