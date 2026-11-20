using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_stage9_radius_manual_worker.py.
public sealed class RadiusManualWorkerTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "radius-manual-" + Guid.NewGuid().ToString("N"));
    private RadiusManualWorker Worker => new(root, "nps.example.test", "radius-accounting-session-v1");
    public RadiusManualWorkerTests()
    {
        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null && !File.Exists(Path.Combine(repository.FullName, "config", "postgres_migrations", "060_radius_identity_resolver_owner.sql")))
            repository = repository.Parent;
        Assert.NotNull(repository);
        string target = Path.Combine(root, "config", "postgres_migrations");
        Directory.CreateDirectory(target);
        foreach (string name in new[] { "059_radius_identity_spine_resolver", "060_radius_identity_resolver_owner" })
            foreach (string suffix in new[] { ".sql", ".rollback.sql" })
                File.Copy(Path.Combine(repository.FullName, "config", "postgres_migrations", name + suffix), Path.Combine(target, name + suffix));
    }
    public void Dispose() => Directory.Delete(root, true);
    private static JsonObject Disposable() => JsonNode.Parse("""
        {"status":"passed","production_database_changed":false,"radius_source_contacted":false,"runtime_enabled":false,
         "acceptance":{"success_final_state":"disabled","failure_final_state":"disabled","success_ephemeral_login_dropped":true,
                       "failure_ephemeral_login_dropped":true,"cursor_unchanged":true}}
        """)!.AsObject();
    private static JsonObject Identity() => JsonNode.Parse("""
        {"status":"passed","action":"apply","migration":{"version":59},"production_database_changed":true,"runtime_enabled":false}
        """)!.AsObject();
    private static JsonObject Registration() => JsonNode.Parse("""
        {"status":"passed","action":"disabled_registration","source_instance_id":"nps.example.test",
         "subscription_id":"radius-accounting-session-v1","desired_activation":"disabled","cursor_revision":0,
         "worker_activated":false,"runtime_enabled":false}
        """)!.AsObject();
    private static JsonObject Acl() => JsonNode.Parse("""
        {"status":"accepted","classification":"protected_acl_exact","contract_id":"sli.radius-acquisition-evidence-root.v2",
         "node_count":4,"acl_entry_count":12,"activation_enabled":false,"raw_path_persisted":false}
        """)!.AsObject();
    private JsonObject Attestation()
    {
        var value = JsonNode.Parse("""
        {"status":"passed","action":"finalize_applied_readback","evidence_kind":"production_current_state_attestation",
         "covers_migrations":[59,60],"migrations":{
           "59":{"version":59},"60":{"version":60}},
         "postcondition":{"marker":true,"resolver_owner":"adlog_radius_identity_resolver","resolver_owner_restricted_nologin":true,
                          "domains_column_select":true,"aliases_column_select":true,"resolver_owner_schema_create":false,
                          "worker_identity_select":false,"public_execute":false,"missing_identity_result":null},
         "production_migration_applied":true,"production_database_changed":false,"radius_source_contacted":false,"runtime_enabled":false}
        """)!.AsObject();
        // The Python fixture hashes the checked-out migration bytes too (LF/CRLF may differ).
        foreach (var (version, name) in new[] { ("59", "059_radius_identity_spine_resolver"), ("60", "060_radius_identity_resolver_owner") })
            foreach (var (field, suffix) in new[] { ("forward_sha256", ".sql"), ("rollback_sha256", ".rollback.sql") })
                value["migrations"]![version]![field] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(
                    Path.Combine(root, "config", "postgres_migrations", name + suffix))));
        return value;
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ExactLegacyAndCurrentAuthorityChainsAreAccepted(bool legacy, bool current)
    {
        var identity = legacy ? Identity() : null;
        var attestation = current ? Attestation() : null;
        if (legacy && current) identity!["migration"] = attestation!["migrations"]!["59"]!.DeepClone();
        Worker.ValidatePrerequisiteEvidence(Disposable(), identity, Registration(), Acl(), attestation);
    }

    [Fact]
    public void MissingIdentityAuthorityIsRejected() => Assert.Equal("identity_resolver_evidence_invalid",
        Assert.Throws<InvalidOperationException>(() => Worker.ValidatePrerequisiteEvidence(Disposable(), null, Registration(), Acl())).Message);

    [Theory]
    [InlineData("disposable", "acceptance.failure_final_state", "\"manual_enabled\"", "manual_disposable_acceptance_invalid")]
    [InlineData("disposable", "acceptance.failure_ephemeral_login_dropped", "false", "manual_disposable_acceptance_invalid")]
    [InlineData("disposable", "acceptance.cursor_unchanged", "false", "manual_disposable_acceptance_invalid")]
    [InlineData("disposable", "runtime_enabled", "0", "manual_disposable_acceptance_invalid")]
    [InlineData("identity", "migration.version", "60", "identity_resolver_apply_evidence_invalid")]
    [InlineData("registration", "cursor_revision", "1", "disabled_registration_evidence_invalid")]
    [InlineData("registration", "source_instance_id", "\"other.example.test\"", "disabled_registration_evidence_invalid")]
    [InlineData("registration", "subscription_id", "\"other\"", "disabled_registration_evidence_invalid")]
    [InlineData("registration", "desired_activation", "\"manual_enabled\"", "disabled_registration_evidence_invalid")]
    [InlineData("registration", "worker_activated", "true", "disabled_registration_evidence_invalid")]
    [InlineData("acl", "contract_id", "\"sli.radius-acquisition-evidence-root.v1\"", "protected_root_evidence_invalid")]
    [InlineData("acl", "activation_enabled", "true", "protected_root_evidence_invalid")]
    public void InvalidPrerequisitesKeepTheirSourceErrorCodes(string evidence, string field, string replacement, string error)
    {
        var values = new Dictionary<string, JsonObject> { ["disposable"] = Disposable(), ["identity"] = Identity(), ["registration"] = Registration(), ["acl"] = Acl() };
        Replace(values[evidence], field, JsonNode.Parse(replacement));
        Assert.Equal(error, Assert.Throws<InvalidOperationException>(() => Worker.ValidatePrerequisiteEvidence(
            values["disposable"], values["identity"], values["registration"], values["acl"])).Message);
    }

    [Theory]
    [InlineData("59", "forward_sha256", "\"0000000000000000000000000000000000000000000000000000000000000000\"")]
    [InlineData("59", "rollback_sha256", "\"0000000000000000000000000000000000000000000000000000000000000000\"")]
    [InlineData("60", "forward_sha256", "\"0000000000000000000000000000000000000000000000000000000000000000\"")]
    [InlineData("60", "rollback_sha256", "\"0000000000000000000000000000000000000000000000000000000000000000\"")]
    [InlineData("59", "version", "58")]
    [InlineData("60", "version", "61")]
    public void TamperedCurrentAttestationIsRejected(string migration, string field, string replacement)
    {
        var attestation = Attestation();
        attestation["migrations"]![migration]![field] = JsonNode.Parse(replacement);
        Assert.Equal("identity_resolver_attestation_invalid", Assert.Throws<InvalidOperationException>(() =>
            Worker.ValidatePrerequisiteEvidence(Disposable(), null, Registration(), Acl(), attestation)).Message);
    }

    [Theory]
    [InlineData("resolver_owner_restricted_nologin", false)]
    [InlineData("domains_column_select", false)]
    [InlineData("aliases_column_select", false)]
    [InlineData("resolver_owner_schema_create", true)]
    [InlineData("worker_identity_select", true)]
    [InlineData("public_execute", true)]
    public void AttestationMustProveLeastPrivilege(string field, bool value)
    {
        var attestation = Attestation(); attestation["postcondition"]![field] = value;
        Assert.Equal("identity_resolver_attestation_invalid", Assert.Throws<InvalidOperationException>(() =>
            Worker.ValidatePrerequisiteEvidence(Disposable(), null, Registration(), Acl(), attestation)).Message);
    }

    [Theory]
    [InlineData("forward_sha256")]
    [InlineData("rollback_sha256")]
    public void LegacyHashesMustMatchCurrentAuthority(string field)
    {
        var attestation = Attestation(); var identity = Identity();
        identity["migration"] = attestation["migrations"]!["59"]!.DeepClone();
        identity["migration"]![field] = new string('0', 64);
        Assert.Equal("identity_resolver_evidence_hash_mismatch", Assert.Throws<InvalidOperationException>(() =>
            Worker.ValidatePrerequisiteEvidence(Disposable(), identity, Registration(), Acl(), attestation)).Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SharedPreflightUsesConfiguredRegistrationAndFinal060Authority(bool configured)
    {
        string evidence = Path.Combine(root, "artifacts", "stage9", "evidence"); Directory.CreateDirectory(evidence);
        File.WriteAllText(Path.Combine(evidence, "radius-manual-control-disposable-pg18.json"), Disposable().ToJsonString());
        File.WriteAllText(Path.Combine(evidence, "radius-identity-owner60-production-attestation.json"), Attestation().ToJsonString());
        File.WriteAllText(Path.Combine(evidence, "radius-evidence-root-acl-readback.json"), Acl().ToJsonString());
        string registration = configured ? Path.Combine(root, "registration-evidence.json")
            : Path.Combine(evidence, "radius-accounting-disabled-registration-radius01-production.json");
        File.WriteAllText(registration, Registration().ToJsonString());
        string before = File.ReadAllText(registration);
        // No legacy identity file, and no default registration file in the override case.
        Worker.ReadAndValidatePrerequisites(_ => configured ? "  " + registration + "  " : "  ");
        Assert.Equal(before, File.ReadAllText(registration));
    }

    [Theory]
    [InlineData("ADLOG_COLLECTION_PRINCIPAL")]
    [InlineData("ADLOG_COLLECTION_PRINCIPAL_SID")]
    public void DatabaseCredentialsDoNotSuppressProtectedIdentityLoading(string missing)
    {
        var environment = new Dictionary<string, string?> {
            ["ADLOG_PG_ADMIN_USER"] = "test-admin", ["ADLOG_PG_ADMIN_PASSWORD"] = "test-admin-password",
            ["ADLOG_PG_DSN"] = "test-admin-dsn", ["ADLOG_COLLECTION_PRINCIPAL"] = "example.test\\collector",
            ["ADLOG_COLLECTION_PRINCIPAL_SID"] = "S-1-5-21-100000001-200000002-300000003-1001" };
        environment.Remove(missing); int loads = 0;
        RadiusManualWorker.LoadEnvironment(key => environment.GetValueOrDefault(key), () => { loads++; environment[missing] = "configured"; });
        Assert.Equal(1, loads);
        RadiusManualWorker.LoadEnvironment(key => environment.GetValueOrDefault(key), () => loads++);
        Assert.Equal(1, loads);
    }

    [Fact]
    public void ChildEnvironmentContainsOnlyTheWorkerDatabaseSecret()
    {
        var parent = new Dictionary<string, string> { ["ADLOG_PG_ADMIN_PASSWORD"] = "test-admin-password", ["ADLOG_PG_DSN"] = "test-admin-dsn",
            ["ADLOG_OTHER_TOKEN"] = "test-token", ["adlog_other_secret"] = "test-secret", ["SAFE_VALUE"] = "kept",
            ["ADLOG_COLLECTION_PRINCIPAL"] = "example.test\\collector", ["SLI_PLUGIN_PG_DSN"] = "old-dsn" };
        var child = RadiusManualWorker.ChildEnvironment(parent, "test-worker-dsn");
        Assert.Equal("test-worker-dsn", child["SLI_PLUGIN_PG_DSN"]); Assert.Equal("kept", child["SAFE_VALUE"]);
        Assert.Equal("example.test\\collector", child["ADLOG_COLLECTION_PRINCIPAL"]);
        foreach (string name in new[] { "ADLOG_PG_ADMIN_PASSWORD", "ADLOG_PG_DSN", "ADLOG_OTHER_TOKEN", "adlog_other_secret" }) Assert.False(child.ContainsKey(name));
        Assert.Equal("test-admin-dsn", parent["ADLOG_PG_DSN"]);
    }

    [Fact]
    public void ExecutionCreatesMissingEvidenceParentsAndRefusesOverwrite()
    {
        string output = Path.Combine(root, "artifacts", "stage9", "evidence", "run.json");
        Assert.Equal(0, Worker.ExecuteWithEvidence(output, RadiusManualWorker.Confirmation,
            () => new() { ["status"] = "passed", ["source_contacted"] = true, ["continuous_runtime_enabled"] = false, ["autostart_enabled"] = false }));
        Assert.Equal("passed", JsonNode.Parse(File.ReadAllText(output))!["status"]!.GetValue<string>());
        Assert.Throws<IOException>(() => Worker.ExecuteWithEvidence(output, RadiusManualWorker.Confirmation, () => throw new Exception()));
    }

    [Fact]
    public void FailureEvidenceDoesNotDiscloseExceptionMessage()
    {
        string output = Path.Combine(root, "artifacts", "stage9", "evidence", "failure.json");
        Assert.Equal(1, Worker.ExecuteWithEvidence(output, RadiusManualWorker.Confirmation, () => throw new InvalidOperationException("test-secret")));
        string text = File.ReadAllText(output); Assert.DoesNotContain("test-secret", text);
        Assert.False(JsonNode.Parse(text)!["continuous_runtime_enabled"]!.GetValue<bool>());
    }

    [Fact]
    public void ConfirmationAndArtifactBoundaryAreCheckedBeforeExecution()
    {
        int calls = 0; JsonObject Execute() { calls++; return new() { ["status"] = "passed" }; }
        Assert.Throws<UnauthorizedAccessException>(() => Worker.ExecuteWithEvidence(Path.Combine(root, "artifacts", "run.json"), "wrong", Execute));
        Assert.Throws<ArgumentException>(() => Worker.ExecuteWithEvidence(Path.Combine(root, "artifacts", "..", "run.json"), RadiusManualWorker.Confirmation, Execute));
        Assert.Equal(0, calls);
    }

    private static void Replace(JsonObject value, string field, JsonNode? replacement)
    {
        string[] path = field.Split('.'); JsonNode current = value;
        foreach (string part in path[..^1]) current = current[part]!;
        current[path[^1]] = replacement;
    }
}
