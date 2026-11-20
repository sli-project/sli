using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Ingress;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

// Control-plane helpers from scripts/maintenance/stage9_radius_manual_worker.py.
// The caller supplies the trusted installation root and validated registration identity.
// Reading prerequisites never opens PostgreSQL or the accounting source.
public sealed class RadiusManualWorker(string root, string sourceInstanceId, string subscriptionId)
{
    public const string Confirmation = "RUN-STAGE9-RADIUS-MANUAL-ONCE";
    private string Evidence(string name) => Path.Combine(root, "artifacts", "stage9", "evidence", name);
    private static InvalidOperationException Error(string code) => new(code);
    private static bool Is(JsonObject obj, string key, string value) => JsonNode.DeepEquals(obj[key], JsonValue.Create(value));
    private static bool Flag(JsonObject obj, string key, bool value) => obj[key]?.GetValueKind() == (value ? JsonValueKind.True : JsonValueKind.False);
    private static bool Number(JsonObject obj, string key, int value) => PythonMetadataEquality.Equal(obj[key], JsonValue.Create(value));

    private static JsonObject Read(string path)
    {
        JsonNode? value;
        try { value = JsonNode.Parse(File.ReadAllText(path)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        { throw Error("prerequisite_invalid:" + Path.GetFileName(path)); }
        return value as JsonObject ?? throw Error("prerequisite_object_required:" + Path.GetFileName(path));
    }
    private static JsonObject? ReadOptional(string path) => File.Exists(path) ? Read(path) : null;

    // Both planning and contract self-check use this same evidence-loading path.
    public void ReadAndValidatePrerequisites(Func<string, string?> environment)
    {
        string registration = PythonText.Strip(environment("ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH") ?? "");
        ValidatePrerequisiteEvidence(
            Read(Evidence("radius-manual-control-disposable-pg18.json")),
            ReadOptional(Evidence("radius-identity-resolver59-production-apply.json")),
            Read(registration.Length == 0 ? Evidence("radius-accounting-disabled-registration-radius01-production.json") : registration),
            Read(Evidence("radius-evidence-root-acl-readback.json")),
            ReadOptional(Evidence("radius-identity-owner60-production-attestation.json")));
    }

    private JsonObject AttestationMigrations()
    {
        JsonObject Migration(int version, string name)
        {
            string Hash(string suffix) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(
                Path.Combine(root, "config", "postgres_migrations", $"{version:000}_{name}{suffix}.sql"))));
            return new() { ["version"] = version, ["forward_sha256"] = Hash(""), ["rollback_sha256"] = Hash(".rollback") };
        }
        return new() { ["59"] = Migration(59, "radius_identity_spine_resolver"), ["60"] = Migration(60, "radius_identity_resolver_owner") };
    }

    public void ValidatePrerequisiteEvidence(JsonObject disposable, JsonObject? identityApply, JsonObject registration,
        JsonObject acl, JsonObject? identityAttestation = null)
    {
        var acceptance = disposable["acceptance"] as JsonObject ?? new();
        if (!(Is(disposable, "status", "passed") && Flag(disposable, "production_database_changed", false)
            && Flag(disposable, "radius_source_contacted", false) && Flag(disposable, "runtime_enabled", false)
            && Is(acceptance, "success_final_state", "disabled") && Is(acceptance, "failure_final_state", "disabled")
            && Flag(acceptance, "success_ephemeral_login_dropped", true) && Flag(acceptance, "failure_ephemeral_login_dropped", true)
            && Flag(acceptance, "cursor_unchanged", true))) throw Error("manual_disposable_acceptance_invalid");

        if (identityApply is null && identityAttestation is null) throw Error("identity_resolver_evidence_invalid");
        if (identityApply is not null && !(Is(identityApply, "status", "passed") && Is(identityApply, "action", "apply")
            && Number(identityApply["migration"] as JsonObject ?? new(), "version", 59)
            && Flag(identityApply, "production_database_changed", true) && Flag(identityApply, "runtime_enabled", false)))
            throw Error("identity_resolver_apply_evidence_invalid");
        if (identityAttestation is not null)
        {
            var postcondition = new JsonObject
            {
                ["marker"] = true, ["resolver_owner"] = "adlog_radius_identity_resolver",
                ["resolver_owner_restricted_nologin"] = true, ["domains_column_select"] = true, ["aliases_column_select"] = true,
                ["resolver_owner_schema_create"] = false, ["worker_identity_select"] = false,
                ["public_execute"] = false, ["missing_identity_result"] = null
            };
            if (!(Is(identityAttestation, "status", "passed") && Is(identityAttestation, "action", "finalize_applied_readback")
                && Is(identityAttestation, "evidence_kind", "production_current_state_attestation")
                && PythonMetadataEquality.Equal(identityAttestation["covers_migrations"], new JsonArray(59, 60))
                && PythonMetadataEquality.Equal(identityAttestation["migrations"], AttestationMigrations())
                && PythonMetadataEquality.Equal(identityAttestation["postcondition"], postcondition)
                && Flag(identityAttestation, "production_migration_applied", true) && Flag(identityAttestation, "production_database_changed", false)
                && Flag(identityAttestation, "radius_source_contacted", false) && Flag(identityAttestation, "runtime_enabled", false)))
                throw Error("identity_resolver_attestation_invalid");
            if (identityApply is not null)
            {
                var legacy = identityApply["migration"] as JsonObject;
                var current = identityAttestation["migrations"]?["59"];
                if (new[] { "forward_sha256", "rollback_sha256" }.Any(key => !PythonMetadataEquality.Equal(legacy?[key], current?[key])))
                    throw Error("identity_resolver_evidence_hash_mismatch");
            }
        }

        if (!(Is(registration, "status", "passed") && Is(registration, "action", "disabled_registration")
            && Is(registration, "source_instance_id", sourceInstanceId) && Is(registration, "subscription_id", subscriptionId)
            && Is(registration, "desired_activation", "disabled") && Number(registration, "cursor_revision", 0)
            && Flag(registration, "worker_activated", false) && Flag(registration, "runtime_enabled", false)))
            throw Error("disabled_registration_evidence_invalid");
        if (!(Is(acl, "status", "accepted") && Is(acl, "classification", "protected_acl_exact")
            && Is(acl, "contract_id", "sli.radius-acquisition-evidence-root.v2") && Number(acl, "node_count", 4)
            && Number(acl, "acl_entry_count", 12) && Flag(acl, "activation_enabled", false) && Flag(acl, "raw_path_persisted", false)))
            throw Error("protected_root_evidence_invalid");
    }

    // Protected supervisor loading remains caller-owned; PG credentials alone are insufficient.
    public static void LoadEnvironment(Func<string, string?> environment, Action loadSupervisorEnvironment)
    {
        bool Has(string key) => PythonText.Strip(environment(key) ?? "").Length > 0;
        if (!(Has("ADLOG_PG_ADMIN_USER") && !string.IsNullOrEmpty(environment("ADLOG_PG_ADMIN_PASSWORD"))
            && Has("ADLOG_PG_DSN") && Has("ADLOG_COLLECTION_PRINCIPAL") && Has("ADLOG_COLLECTION_PRINCIPAL_SID")))
            loadSupervisorEnvironment();
    }

    // The caller derives workerDsn using the ephemeral lease, never an administrator login.
    public static Dictionary<string, string> ChildEnvironment(IReadOnlyDictionary<string, string> parent, string workerDsn)
    {
        var child = new Dictionary<string, string>(parent, StringComparer.Ordinal);
        foreach (string name in child.Keys.ToArray())
        {
            string upper = name.ToUpperInvariant();
            if (upper.StartsWith("ADLOG_", StringComparison.Ordinal)
                && new[] { "PASSWORD", "SECRET", "TOKEN", "DSN" }.Any(upper.Contains)) child.Remove(name);
        }
        child["SLI_PLUGIN_PG_DSN"] = workerDsn;
        return child;
    }

    public int ExecuteWithEvidence(string output, string confirmation, Func<JsonObject> execute)
    {
        if (confirmation != Confirmation) throw new UnauthorizedAccessException("manual_worker_confirmation_required");
        string path = Resolve(output), artifacts = Resolve(Path.Combine(root, "artifacts"));
        string relative = Path.GetRelativePath(artifacts, path);
        if (relative == "." || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || Path.IsPathRooted(relative)) throw new ArgumentException("output must stay under artifacts");
        if (File.Exists(path)) throw new IOException("manual worker evidence already exists");
        JsonObject result;
        try { result = execute(); }
        catch (Exception e)
        {
            result = new() { ["status"] = "failed", ["action"] = "bounded_manual_worker",
                ["generated_at_utc"] = DateTimeOffset.UtcNow.ToString("O"), ["error_type"] = e.GetType().Name,
                ["error_code"] = "", ["source_instance_id"] = sourceInstanceId, ["subscription_id"] = subscriptionId,
                ["continuous_runtime_enabled"] = false, ["autostart_enabled"] = false, ["raw_record_persisted_in_report"] = false };
        }
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
        using var writer = new StreamWriter(stream);
        writer.WriteLine(result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return Is(result, "status", "passed") ? 0 : 1;
    }

    private static string Resolve(string path)
    {
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var next = new DirectoryInfo(Path.Combine(current, part));
            current = next.LinkTarget is null ? next.FullName : next.ResolveLinkTarget(true)!.FullName;
        }
        return current;
    }
}
