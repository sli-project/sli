using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AdCoordinatorTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    const string Sid = "S-1-5-21-100000001-200000002-300000003";
    internal static JsonObject Bundle(string family) {
        string section = family switch { "ad_privileged_membership" => "privileged_membership", "ad_vpn_membership" => "vpn_membership", "ad_domain_posture" => "domain_posture", "ad_domain_health" => "domain_health", _ => "directory_accounts" };
        var sections = new JsonArray();
        foreach (string name in family == "ad_context_base" ? AdCoordinatorAcquisition.BaseSections : new[] { section })
            sections.Add(new JsonObject { ["name"] = name, ["status"] = name is "privileged_membership" or "vpn_membership" ? "skipped" : "complete", ["record_count"] = 0L, ["duration_ms"] = 1L, ["error_code"] = null });
        return new() { ["schema_version"] = "ad-context-bundle/v1", ["source_pack_id"] = "sli.windows.ad-context", ["source_pack_version"] = "0.9.0", ["run_id"] = Guid.NewGuid().ToString("D"), ["mode"] = "reconcile", ["domain"] = new JsonObject { ["sid"] = Sid, ["dns_name"] = "example.test" }, ["scope"] = new JsonObject { ["search_base"] = "DC=example,DC=test", ["collection_profile"] = family == "ad_context_base" ? "ad_snapshot_base_v1" : family == "ad_vpn_membership" ? "vpn_security_v1" : section + "_v1", ["privileged_group_sids"] = new JsonArray(), ["vpn_group_sids"] = new JsonArray() }, ["observed_at_utc"] = "2026-11-08T12:00:00Z", ["sections"] = sections, ["records"] = new JsonArray() };
    }
    static JsonObject Computers() {
        var reference = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/tests/Sli.Server.Tests/Ad/snapshot-reference.json")))!;
        var computer = (JsonObject)reference["families"]!["computers_v6"]!.DeepClone();
        computer["objects"] = new JsonArray(); var m = computer["metadata"]!;
        m["domain"] = "example.test"; m["query_dc"] = "dc.example.test"; m["search_base"] = "DC=example,DC=test";
        m["object_count"] = 0; m["collection_status"] = "partial"; m["started_at"] = "2026-11-08T11:10:00Z"; m["completed_at"] = "2026-11-08T12:01:00Z";
        return computer;
    }
    static JsonObject Gpo() {
        var vector = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "server-dotnet/tests/Sli.Server.Tests/Agents/gpo-publication-source-vector.json")))!;
        var families = vector["families"]!;
        string text = families.ToJsonString().Replace(families["gpo_v2"]!["domain"]!["sid"]!.GetValue<string>(), Sid)
            .Replace("directory.invalid", "example.test").Replace("DC=directory,DC=invalid", "DC=example,DC=test").Replace("2026-10-08", "2026-11-08");
        families = JsonNode.Parse(text)!; var bundle = families["ad_gpo_governance"]!.AsObject();
        bundle["gpo_v2_snapshot"] = families["gpo_v2"]!.DeepClone(); return bundle;
    }
    [Theory]
    [InlineData("2026-11-08T10:59:59Z", "2026-11-07T23:00:00Z")]
    [InlineData("2026-11-08T11:00:00Z", "2026-11-08T11:00:00Z")]
    [InlineData("2026-11-08T22:59:59Z", "2026-11-08T11:00:00Z")]
    [InlineData("2026-11-08T23:00:00Z", "2026-11-08T23:00:00Z")]
    public void Calendar_matches_actual_reference_not_stale_docstring(string now, string due) => Assert.Equal(DateTimeOffset.Parse(due), AdCoordinatorLoop.Slot(DateTimeOffset.Parse(now)));
    [Fact]
    public async Task Loop_retries_errors_at_next_calendar_slot_and_once_reports_failure() {
        var now = DateTimeOffset.Parse("2026-11-08T10:56:30Z"); int calls = 0; var phases = new List<string>();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var loop = new AdCoordinatorLoop(() => now, (slot, _) => { Assert.Equal(calls++ == 0 ? 23 : 11, slot.Hour); if (calls == 2) stop.Cancel(); throw new InvalidOperationException("synthetic"); }, (p, _, _) => { phases.Add(p); return Task.CompletedTask; }, (wait, _) => { Assert.InRange(wait.TotalSeconds, 1, 300); now += wait; return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(false, false, stop.Token)); Assert.Equal(2, calls); Assert.Contains("initial_delay", phases); Assert.Contains("waiting_for_calendar_slot", phases);
        loop = new(() => now, (_, _) => throw new InvalidOperationException(), (_, _, _) => Task.CompletedTask, (_, _) => throw new Exception("once must not delay"));
        Assert.Equal(1, await loop.RunAsync(true, false, Ct));
    }
    [Fact]
    public void Base_qualification_allows_only_reference_partial_reasons() {
        var bundle = Bundle("ad_context_base"); AdCoordinatorAcquisition.QualifyBase(bundle);
        bundle["sections"]![0]!["status"] = "partial"; bundle["sections"]![0]!["error_code"] = "collection_incomplete";
        Assert.ThrowsAny<InvalidOperationException>(() => AdCoordinatorAcquisition.QualifyBase(bundle));
        bundle["records"]!.AsArray().Add(new JsonObject { ["record_type"] = "data_quality", ["section"] = "directory_accounts", ["code"] = "password_expiry_partial" });
        AdCoordinatorAcquisition.QualifyBase(bundle);
        bundle["records"]![0]!["code"] = "directory_accounts_truncated";
        Assert.ThrowsAny<InvalidOperationException>(() => AdCoordinatorAcquisition.QualifyBase(bundle));
        bundle["records"]![0]!["code"] = "unrecognized";
        Assert.ThrowsAny<InvalidOperationException>(() => AdCoordinatorAcquisition.QualifyBase(bundle));
    }
    [Fact]
    public void Collector_uses_fixed_scripts_and_progress_never_exposes_host_text() {
        var settings = new Dictionary<string, string?> { ["ADLOG_AD_CONTEXT_POWERSHELL"] = OperatingSystem.IsWindows() ? "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" : "/usr/bin/pwsh", ["ADLOG_AD_CONTEXT_DOMAIN"] = "example.test", ["ADLOG_AD_CONTEXT_DIRECTORY_SERVER"] = "dc.example.test", ["ADLOG_AD_CONTEXT_SEARCH_BASE"] = "DC=example,DC=test", ["ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS"] = Sid + "-512", ["ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES"] = "fixture-group" };
        var acquisition = new AdCoordinatorAcquisition(PostCollectionPostgres.Repository(), settings.GetValueOrDefault, (_, _, _) => Task.CompletedTask);
        foreach (string family in AdCoordinatorAcquisition.Families.Concat(["computers_v6"])) {
            var command = acquisition.Command(family, Path.GetTempPath());
            Assert.False(command.UseShellExecute); Assert.True(command.CreateNoWindow); Assert.Contains("-File", command.ArgumentList);
            if (family == "computers_v6") Assert.Contains("-CoordinatorBaseInputPath", command.ArgumentList);
        }
        var safe = AdCoordinatorAcquisition.SafeProgress(new() { ["phase"] = "exact_logon_queries", ["exact_queries_completed"] = 9, ["user_count"] = -1, ["error"] = "fixture-private", ["password"] = "fixture-secret" });
        Assert.Equal(2, safe.Count); Assert.Equal(9, safe["exact_queries_completed"]!.GetValue<int>());
        Assert.Empty(AdCoordinatorAcquisition.SafeProgress(new() { ["phase"] = "fixture-private" }));
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Real_import_manifest_projection_replay_and_tamper_detection_use_exact_sources(bool gpo) {
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        // The fixture has the canonical tables; install the existing v2 schedule header.
        await PostCollectionPostgres.Sql(db, """
            create function fixture_schedule() returns trigger language plpgsql as $$begin new.scheduled_local_at:=new.slot_start_utc at time zone 'Asia/Novosibirsk';return new;end$$;
            create trigger fixture_schedule before insert on ad_snapshot_manifests for each row execute function fixture_schedule();
            update domains set domain_sid='S-1-5-21-100000001-200000002-300000003',fqdn='example.test' where id=7;
            """, Ct);
        var calls = new List<string>(); var phases = new List<string>(); int retained = 0;
        Task<JsonObject> Collect(string family, JsonObject? basis, CancellationToken _) { calls.Add(family); if (family == "computers_v6") Assert.NotNull(basis); return Task.FromResult(family == "computers_v6" ? Computers() : family == "ad_gpo_governance" ? Gpo() : Bundle(family)); }
        var cycle = new AdCoordinatorCycle(db, "EXAMPLE.TEST", gpo, Collect, (p, _, _) => { phases.Add(p); return Task.CompletedTask; }, (_, _) => { retained++; return Task.FromResult(new JsonObject { ["status"] = "executed" }); });
        var slot = DateTimeOffset.Parse("2026-11-08T11:00:00Z"); var result = await cycle.RunAsync(slot, Ct);
        var expected = new[] { "ad_context_base", "computers_v6", "ad_privileged_membership", "ad_vpn_membership", "ad_domain_posture", "ad_domain_health" }.Concat(gpo ? new[] { "ad_gpo_governance" } : []).ToArray();
        Assert.Equal("published", result["status"]!.ToString()); Assert.Equal(expected, calls);
        Assert.Equal(gpo ? 4 : 3, result["projection_results"]!.AsObject().Count); Assert.Contains("projecting", phases); Assert.Equal(1, retained);
        var replay = await cycle.RunAsync(slot, Ct); Assert.Equal("replayed_existing", replay["status"]!.ToString()); Assert.Equal(expected.Length, calls.Count); Assert.Equal(2, retained);
        Assert.Equal(result["manifest_sha256"]!.ToString(), replay["manifest_sha256"]!.ToString());
        await PostCollectionPostgres.Sql(db, "update computers_v6_source_snapshots set payload_sha256=decode(repeat('00',32),'hex')", Ct);
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => cycle.RunAsync(slot, Ct)); Assert.Equal(expected.Length, calls.Count); Assert.Equal(2, retained);
        Assert.DoesNotContain("ERROR:", await pg.DiagnosticsAsync(Ct));
    }
    [Fact]
    public async Task Cutover_gates_do_not_open_source_or_database_credentials() {
        string? legacy = Environment.GetEnvironmentVariable("SLI_LEGACY_COLLECTION_DISABLED"), pilot = Environment.GetEnvironmentVariable("SLI_CORE_JOB_AD_GPO_PILOT");
        try {
            Environment.SetEnvironmentVariable("SLI_LEGACY_COLLECTION_DISABLED", "0"); Environment.SetEnvironmentVariable("SLI_CORE_JOB_AD_GPO_PILOT", "1");
            Assert.Equal(0, await AdCoordinatorCommand.RunAsync(["--once"]));
            Environment.SetEnvironmentVariable("SLI_LEGACY_COLLECTION_DISABLED", "1"); Assert.Equal(1, await AdCoordinatorCommand.RunAsync(["--once"]));
        } finally { Environment.SetEnvironmentVariable("SLI_LEGACY_COLLECTION_DISABLED", legacy); Environment.SetEnvironmentVariable("SLI_CORE_JOB_AD_GPO_PILOT", pilot); }
    }
    [Fact]
    public void Native_identity_rejects_an_unprotected_store_before_decryption() {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.Combine(Path.GetTempPath(), "sli-ad-identity-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "runtime/ad-source-credentials"));
        try {
            var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32/WindowsPowerShell/v1.0/powershell.exe"));
            Assert.ThrowsAny<InvalidOperationException>(() => AdCoordinatorIdentity.Start(start, root));
            Assert.Equal("\"a\\\"b\\\\\"", AdCoordinatorIdentity.Quote("a\"b\\"));
        } finally { Directory.Delete(root, true); }
    }
}
