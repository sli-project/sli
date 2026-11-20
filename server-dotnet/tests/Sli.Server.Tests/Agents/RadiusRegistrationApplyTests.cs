using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Behavioral vectors from tests/sources/test_stage9_radius_registration_apply.py.
public sealed class RadiusRegistrationApplyTests : IDisposable
{
    const string Source = "nps.example.test", Subscription = "vpn-radius-session-observations-nps-v1";
    readonly string temporary = Path.Combine(Path.GetTempPath(), "sli-radius-registration-" + Guid.NewGuid().ToString("N"));
    static JsonObject Json(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    static string RepositoryRoot
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "config", "postgres_migrations", "058_radius_accounting_transaction_foundation.sql"))) directory = directory.Parent;
            return directory?.FullName ?? throw new InvalidOperationException("repository fixture missing");
        }
    }
    static JsonObject Postgres() => Json(new { status = "passed", action = "apply", migration = new { version = 58 },
        production_database_changed = true, source_instance_created = false, runtime_enabled = false });
    static JsonObject Acl() => Json(new { status = "accepted", classification = "protected_acl_exact", contract_id = "sli.radius-acquisition-evidence-root.v2",
        node_count = 4, acl_entry_count = 12, activation_enabled = false, raw_path_persisted = false, readback_sha256 = new string('d', 64) });
    static JsonObject Cursor() => Json(new { status = "completed", read_only = true, cursor_updated = false, source_instance_created = false,
        worker_activated = false, source_instance_id = Source, stream_id = "radius-accounting", transport_binding = "windows-rpc-smb-readonly-tail-v1",
        cursor_bootstrap = new { cursor_epoch = "00000000-0000-4000-8000-000000000043", file_generation = "gen-8ba902d1827e23272db2644bb703a1e2",
            byte_offset = 10134781, last_record_sha256 = new string('a', 64) } });
    static JsonObject Attestation()
    {
        var value = Json(new { status = "passed", action = "finalize_applied_readback", evidence_kind = "production_current_state_attestation",
            postcondition = new { marker = true, worker_role = true, evidence_insert = true, evidence_delete = false, cursor_update = true,
                tables = new[] { "acquisition_source_instances", "acquisition_stream_cursors", "acquisition_consumer_subscriptions", "core_evidence_manifests",
                    "radius_accounting_session_observations", "acquisition_delivery_outbox", "radius_accounting_class_cache" }.Order(StringComparer.Ordinal).ToArray() },
            production_migration_applied = true, production_database_changed = false, source_instance_created = false, runtime_enabled = false, radius_source_contacted = false });
        value["migration"] = RadiusRegistrationApply.CurrentMigration(RepositoryRoot);
        return value;
    }
    static JsonObject Legacy() => Json(new {
        legacy_source_instance_id = "radius." + Source, legacy_subscription_id = "vpn-radius-session-observations-v1",
        cursor = new object?[] { "radius-accounting", "windows-rpc-smb-readonly-tail-v1", "00000000-0000-4000-8000-000000000058", "gen-legacy-registration", 28, new string('a', 64), null, null, 28 },
        cursor_revision = 28, source_contract_matches = true, subscription_contract_matches = true, cursor_contract_matches = true,
        source_disabled = true, subscription_disabled = true, runtime_state_rows = 0 });
    static JsonObject Rows(int count = 0) => Json(new { migration_58 = true, source_count = count, cursor_count = count, subscription_count = count });
    static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<InvalidOperationException>(action).Message);
    static RadiusRegistrationBootstrap Validate(JsonObject? postgres, JsonObject? cursor = null, JsonObject? acl = null, JsonObject? attestation = null) =>
        RadiusRegistrationApply.ValidatePrerequisites(RepositoryRoot, Source, postgres, cursor ?? Cursor(), acl ?? Acl(), attestation);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PrerequisitesYieldExactBootstrapWithoutActivation(bool currentAttestation)
    {
        var bootstrap = Validate(currentAttestation ? null : Postgres(), attestation: currentAttestation ? Attestation() : null);
        Assert.Equal(Guid.Parse("00000000-0000-4000-8000-000000000043"), bootstrap.CursorEpoch);
        Assert.Equal(10134781, bootstrap.ByteOffset);
        Assert.Equal("gen-8ba902d1827e23272db2644bb703a1e2", bootstrap.FileGeneration);
        Assert.Equal(new string('a', 64), bootstrap.LastRecordSha256);
    }

    [Theory]
    [InlineData("classification", "broad_acl")]
    [InlineData("contract_id", "sli.radius-acquisition-evidence-root.v1")]
    public void RejectsUnacceptedAndV1Acl(string field, string value)
    {
        var acl = Acl(); acl[field] = value;
        Error("protected_root_evidence_invalid", () => Validate(Postgres(), acl: acl));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RejectsAlreadyUpdatedCursorAndHistoricalPlaceholder(bool historical)
    {
        var cursor = Cursor();
        if (historical) cursor["source_instance_id"] = "radius.radius01.example.test";
        else cursor["cursor_updated"] = true;
        Error("cursor_bootstrap_evidence_invalid", () => Validate(Postgres(), cursor));
    }

    [Fact]
    public void RejectsMissingOrInconsistentMigrationAuthority()
    {
        Error("production_058_evidence_invalid", () => RadiusRegistrationApply.ValidatePostgresAuthority(RepositoryRoot, null, null));
        var legacy = Postgres();
        legacy["migration"]!["forward_sha256"] = new string('c', 64);
        legacy["migration"]!["rollback_sha256"] = new string('b', 64);
        Error("production_058_evidence_hash_mismatch", () => RadiusRegistrationApply.ValidatePostgresAuthority(RepositoryRoot, legacy, Attestation()));
        legacy["migration"] = RadiusRegistrationApply.CurrentMigration(RepositoryRoot);
        RadiusRegistrationApply.ValidatePostgresAuthority(RepositoryRoot, legacy, Attestation());
    }

    [Theory]
    [InlineData("forward_sha256")]
    [InlineData("rollback_sha256")]
    [InlineData("version")]
    public void RejectsTamperedCurrentAttestation(string field)
    {
        var attestation = Attestation();
        attestation["migration"]![field] = field == "version" ? JsonValue.Create(57) : JsonValue.Create(new string('0', 64));
        Error("production_058_attestation_invalid", () => RadiusRegistrationApply.ValidatePostgresAuthority(RepositoryRoot, null, attestation));
    }

    [Fact]
    public void LegacyRemediationAcceptsOnlyExactDisabledEmptyState()
    {
        var candidate = Legacy();
        Assert.True(JsonNode.DeepEquals(candidate, RadiusRegistrationApply.RequireSafeLegacyRemediation(candidate, Source, Subscription)));
    }

    [Theory]
    [InlineData("legacy_source_instance_id", "radius.unexpected.example.test", "legacy_remediation_source_identity_unexpected")]
    [InlineData("legacy_subscription_id", "vpn-radius-session-observations-unexpected-v1", "legacy_remediation_subscription_identity_unexpected")]
    public void LegacyRemediationRejectsNoncanonicalIdentity(string field, string value, string code)
    {
        var candidate = Legacy(); candidate[field] = value;
        Error(code, () => RadiusRegistrationApply.RequireSafeLegacyRemediation(candidate, Source, Subscription));
    }

    [Theory]
    [InlineData("runtime_state_rows", "legacy_remediation_runtime_state_present")]
    [InlineData("source_contract_matches", "legacy_remediation_source_contract_mismatch")]
    [InlineData("subscription_contract_matches", "legacy_remediation_subscription_contract_mismatch")]
    [InlineData("cursor_contract_matches", "legacy_remediation_cursor_contract_mismatch")]
    [InlineData("source_disabled", "legacy_remediation_source_not_disabled")]
    [InlineData("subscription_disabled", "legacy_remediation_subscription_not_disabled")]
    public void LegacyRemediationRejectsUnsafeState(string field, string code)
    {
        var candidate = Legacy(); candidate[field] = field == "runtime_state_rows" ? JsonValue.Create(1) : JsonValue.Create(false);
        Error(code, () => RadiusRegistrationApply.RequireSafeLegacyRemediation(candidate, Source, Subscription));
    }

    [Fact]
    public void LoadsProtectedEnvironmentWhenPostgresValuesLackCollectionIdentity()
    {
        var environment = new Dictionary<string, string?> { ["ADLOG_PG_ADMIN_USER"] = "fixture-admin", ["ADLOG_PG_ADMIN_PASSWORD"] = "fixture-only", ["ADLOG_PG_DSN"] = "fixture-dsn" };
        string? Get(string key) => environment.GetValueOrDefault(key);
        int calls = 0;
        void Load() { calls++; environment["ADLOG_COLLECTION_PRINCIPAL"] = "fixture@example.test"; environment["ADLOG_COLLECTION_PRINCIPAL_SID"] = "S-1-5-21-100000001-200000002-300000003-1101"; }
        RadiusRegistrationApply.LoadEnvironmentIfMissing(Get, Load);
        Assert.Equal(1, calls);
        RadiusRegistrationApply.LoadEnvironmentIfMissing(Get, Load);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void TrustedPowerShellDoesNotDependOnChildPath()
    {
        string executable = Path.Combine(temporary, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(executable)!); File.WriteAllText(executable, "");
        string? Environment(string key) => key == "SystemRoot" ? temporary : key == "PATH" ? "" : null;
        Assert.Equal(Path.GetFullPath(executable), RadiusRegistrationApply.TrustedWindowsPowerShell(Environment));
        File.Delete(executable);
        Error("trusted_windows_powershell_not_found", () => RadiusRegistrationApply.TrustedWindowsPowerShell(Environment));
    }

    JsonObject? Evidence(string path, bool optional) => Path.GetFileName(path) switch {
        RadiusRegistrationApply.PostgresApply => Postgres(), RadiusRegistrationApply.CursorBootstrap or "configured-cursor.json" => Cursor(),
        RadiusRegistrationApply.AclReadback => Acl(), RadiusRegistrationApply.PostgresAttestation when optional => null,
        _ => throw new InvalidOperationException("unexpected fixture path") };

    [Fact]
    public void FreshPrerequisitesAreIsolatedFromHistoricalEvidence()
    {
        string fresh = Path.Combine(temporary, "artifacts", "restore"); Directory.CreateDirectory(fresh);
        var seen = new List<string>();
        JsonObject? Read(string path, bool optional) { seen.Add(path); return Evidence(path, optional); }
        var plan = RadiusRegistrationApply.Plan(temporary, Source, Acl, () => Rows(), new Dictionary<string, string?>(), fresh, Read);
        Assert.Equal("ready", plan.Result["status"]!.GetValue<string>());
        Assert.False(plan.Result["registration_already_exact_candidate"]!.GetValue<bool>());
        Assert.Equal(5, seen.Count);
        Assert.All(seen, path => Assert.Equal(fresh, Path.GetDirectoryName(path)));
        Assert.Equal(new[] { RadiusRegistrationApply.AclReadback, RadiusRegistrationApply.CursorBootstrap, RadiusRegistrationApply.PostgresApply, RadiusRegistrationApply.PostgresAttestation }.Order(), seen.Select(Path.GetFileName).Distinct().Order());
        Assert.Equal(10134781, plan.Bootstrap.ByteOffset);
        Assert.Equal("disabled", plan.Result["desired_activation"]!.GetValue<string>());
        foreach (string field in new[] { "source_contacted", "worker_activated", "runtime_enabled" }) Assert.False(plan.Result[field]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("")]
    [InlineData("artifacts")]
    [InlineData("artifacts/../outside")]
    [InlineData("artifacts/missing")]
    public void RejectsPrerequisitesOutsideArtifactsBeforeAnyRead(string relative)
    {
        Directory.CreateDirectory(Path.Combine(temporary, "artifacts"));
        Error("prerequisites_directory_invalid", () => RadiusRegistrationApply.Plan(temporary, Source, Acl, () => Rows(),
            new Dictionary<string, string?>(), Path.Combine(temporary, relative), (_, _) => throw new Exception("read before path admission")));
    }

    [Fact]
    public void ConfiguredCursorPathPreservesExistingInstallation()
    {
        string configured = Path.Combine(temporary, "configured-cursor.json"); var seen = new List<string>();
        JsonObject? Read(string path, bool optional) { seen.Add(path); return Evidence(path, optional); }
        var plan = RadiusRegistrationApply.Plan(temporary, Source, Acl, () => Rows(1),
            new Dictionary<string, string?> { ["ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH"] = configured }, readEvidence: Read);
        Assert.True(plan.Result["registration_already_exact_candidate"]!.GetValue<bool>());
        Assert.Contains(configured, seen);
        Assert.DoesNotContain(seen, path => Path.GetFileName(path) == RadiusRegistrationApply.CursorBootstrap);
    }

    [Fact]
    public void PlanConsumesCurrentAttestationWhenHistoricalApplyIsMissing()
    {
        JsonObject? Read(string path, bool optional) => Path.GetFileName(path) switch {
            RadiusRegistrationApply.PostgresApply when optional => null,
            RadiusRegistrationApply.PostgresAttestation when optional => Attestation(),
            _ => Evidence(path, optional) };
        var plan = RadiusRegistrationApply.Plan(RepositoryRoot, Source, Acl, () => Rows(), new Dictionary<string, string?>(), readEvidence: Read);
        Assert.Equal("ready", plan.Result["status"]!.GetValue<string>());
        Assert.Equal(10134781, plan.Bootstrap.ByteOffset);
    }

    [Theory]
    [InlineData("acl", "protected_root_acl_changed")]
    [InlineData("migration", "migration_58_missing")]
    [InlineData("partial", "partial_registration_state_detected")]
    public void PlanRejectsDriftAndPartialRegistration(string change, string code)
    {
        JsonObject ReadAcl() { var acl = Acl(); if (change == "acl") acl["readback_sha256"] = "changed"; return acl; }
        JsonObject Inspect() { var rows = Rows(); if (change == "migration") rows["migration_58"] = false; if (change == "partial") rows["cursor_count"] = 1; return rows; }
        Error(code, () => RadiusRegistrationApply.Plan(temporary, Source, ReadAcl, Inspect, new Dictionary<string, string?>(), readEvidence: Evidence));
    }

    [Fact]
    public void PlanReadsRealPrerequisiteFilesAndRejectsMalformedEvidence()
    {
        string fresh = Path.Combine(temporary, "artifacts", "restore"); Directory.CreateDirectory(fresh);
        foreach (string name in new[] { RadiusRegistrationApply.PostgresApply, RadiusRegistrationApply.CursorBootstrap, RadiusRegistrationApply.AclReadback })
            File.WriteAllText(Path.Combine(fresh, name), Evidence(name, false)!.ToJsonString());
        var plan = RadiusRegistrationApply.Plan(temporary, Source, Acl, () => Rows(), new Dictionary<string, string?>(), fresh);
        Assert.Equal("ready", plan.Result["status"]!.GetValue<string>());
        File.WriteAllText(Path.Combine(fresh, RadiusRegistrationApply.AclReadback), "[]");
        Error("prerequisite_object_required:" + RadiusRegistrationApply.AclReadback,
            () => RadiusRegistrationApply.Plan(temporary, Source, Acl, () => Rows(), new Dictionary<string, string?>(), fresh));
    }

    public void Dispose()
    {
        string resolved = Path.GetFullPath(temporary), tempRoot = Path.GetFullPath(Path.GetTempPath());
        Assert.StartsWith(tempRoot, resolved, StringComparison.OrdinalIgnoreCase);
        if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
    }
}
