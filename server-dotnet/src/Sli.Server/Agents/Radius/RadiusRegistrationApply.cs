using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Agents.Radius;

public sealed record RadiusRegistrationBootstrap(Guid CursorEpoch, string FileGeneration, long ByteOffset, string LastRecordSha256);
public sealed record RadiusRegistrationPlan(JsonObject Result, RadiusRegistrationBootstrap Bootstrap);

// Admission and read-only planning from scripts/maintenance/stage9_radius_registration_apply.py.
// Live ACL and database inspection are supplied by the host; this code never activates a worker.
public static class RadiusRegistrationApply
{
    public const string PostgresApply = "radius-accounting-postgres58-production-apply.json";
    public const string PostgresAttestation = "radius-accounting-postgres58-production-attestation.json";
    public const string CursorBootstrap = "radius-accounting-cursor-bootstrap-radius01.json";
    public const string AclReadback = "radius-evidence-root-acl-readback.json";
    public const string AclContract = "sli.radius-acquisition-evidence-root.v2";
    const string Stream = "radius-accounting", Transport = "windows-rpc-smb-readonly-tail-v1";
    static readonly string[] Tables = ["acquisition_consumer_subscriptions", "acquisition_delivery_outbox",
        "acquisition_source_instances", "acquisition_stream_cursors", "core_evidence_manifests",
        "radius_accounting_class_cache", "radius_accounting_session_observations"];
    static InvalidOperationException Bad(string code) => new(code);
    static JsonNode? Get(JsonNode? node, string key) => node is JsonObject obj ? obj[key] : null;
    static string Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
    static bool Is(JsonNode? node, string key, string value) => Text(Get(node, key)) == value;
    static bool Bool(JsonNode? node, string key, bool value) => Get(node, key) is JsonValue v && v.TryGetValue<bool>(out var b) && b == value;
    static bool Number(JsonNode? node, string key, long value) => Get(node, key) is JsonValue v && v.GetValueKind() == JsonValueKind.Number &&
        decimal.TryParse(v.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var n) && n == value;
    static bool Integer(JsonNode? node, out long n) => long.TryParse(node?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out n);
    static bool Token(JsonNode? node) => Regex.IsMatch(Text(node), @"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z", RegexOptions.CultureInvariant);
    static bool Hash(JsonNode? node) => Regex.IsMatch(Text(node), @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    public static JsonObject CurrentMigration(string root)
    {
        string directory = Path.Combine(root, "config", "postgres_migrations");
        string Digest(string suffix) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "058_radius_accounting_transaction_foundation" + suffix))));
        return new JsonObject { ["version"] = 58, ["forward_sha256"] = Digest(".sql"), ["rollback_sha256"] = Digest(".rollback.sql") };
    }

    public static void ValidatePostgresAuthority(string root, JsonObject? apply, JsonObject? attestation)
    {
        if (apply is null && attestation is null) throw Bad("production_058_evidence_invalid");
        if (apply is not null && !(Is(apply, "status", "passed") && Is(apply, "action", "apply") &&
            Number(apply["migration"], "version", 58) && Bool(apply, "production_database_changed", true) &&
            Bool(apply, "source_instance_created", false) && Bool(apply, "runtime_enabled", false)))
            throw Bad("production_058_evidence_invalid");
        if (attestation is not null)
        {
            var postcondition = new JsonObject { ["marker"] = true, ["worker_role"] = true, ["evidence_insert"] = true,
                ["evidence_delete"] = false, ["cursor_update"] = true, ["tables"] = new JsonArray(Tables.Select(t => (JsonNode?)JsonValue.Create(t)).ToArray()) };
            if (!(Is(attestation, "status", "passed") && Is(attestation, "action", "finalize_applied_readback") &&
                Is(attestation, "evidence_kind", "production_current_state_attestation") &&
                JsonNode.DeepEquals(attestation["migration"], CurrentMigration(root)) && JsonNode.DeepEquals(attestation["postcondition"], postcondition) &&
                Bool(attestation, "production_migration_applied", true) && Bool(attestation, "production_database_changed", false) &&
                Bool(attestation, "source_instance_created", false) && Bool(attestation, "runtime_enabled", false) && Bool(attestation, "radius_source_contacted", false)))
                throw Bad("production_058_attestation_invalid");
        }
        if (apply is not null && attestation is not null && new[] { "forward_sha256", "rollback_sha256" }.Any(key =>
            !JsonNode.DeepEquals(Get(apply["migration"], key), Get(attestation["migration"], key))))
            throw Bad("production_058_evidence_hash_mismatch");
    }

    public static RadiusRegistrationBootstrap ValidatePrerequisites(string root, string sourceInstanceId,
        JsonObject? apply, JsonObject cursor, JsonObject acl, JsonObject? attestation = null)
    {
        ValidatePostgresAuthority(root, apply, attestation);
        if (!(Is(acl, "status", "accepted") && Is(acl, "classification", "protected_acl_exact") && Is(acl, "contract_id", AclContract) &&
            Number(acl, "node_count", 4) && Number(acl, "acl_entry_count", 12) && Bool(acl, "activation_enabled", false) && Bool(acl, "raw_path_persisted", false)))
            throw Bad("protected_root_evidence_invalid");
        if (!(Is(cursor, "status", "completed") && Bool(cursor, "read_only", true) && Bool(cursor, "cursor_updated", false) &&
            Bool(cursor, "source_instance_created", false) && Bool(cursor, "worker_activated", false) && Is(cursor, "source_instance_id", sourceInstanceId) &&
            Is(cursor, "stream_id", Stream) && Is(cursor, "transport_binding", Transport)))
            throw Bad("cursor_bootstrap_evidence_invalid");
        var bootstrap = cursor["cursor_bootstrap"];
        if (!Guid.TryParse(Text(Get(bootstrap, "cursor_epoch")), out var epoch) ||
            Get(bootstrap, "file_generation") is null || Get(bootstrap, "last_record_sha256") is null || !Integer(Get(bootstrap, "byte_offset"), out long offset))
            throw Bad("cursor_bootstrap_values_invalid");
        return new(epoch, Get(bootstrap, "file_generation")!.ToString(), offset, Get(bootstrap, "last_record_sha256")!.ToString());
    }

    public static void LoadEnvironmentIfMissing(Func<string, string?> environment, Action loadSupervisorEnvironment)
    {
        if (new[] { "ADLOG_PG_ADMIN_USER", "ADLOG_PG_DSN", "ADLOG_COLLECTION_PRINCIPAL", "ADLOG_COLLECTION_PRINCIPAL_SID" }
            .Any(key => string.IsNullOrWhiteSpace(environment(key))) || string.IsNullOrEmpty(environment("ADLOG_PG_ADMIN_PASSWORD")))
            loadSupervisorEnvironment();
    }

    public static string TrustedWindowsPowerShell(Func<string, string?> environment)
    {
        string path = Path.GetFullPath(Path.Combine(environment("SystemRoot") ?? @"C:\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"));
        if (!File.Exists(path)) throw Bad("trusted_windows_powershell_not_found");
        return path;
    }

    public static JsonObject RequireSafeLegacyRemediation(JsonObject candidate, string sourceInstanceId, string subscriptionId)
    {
        string label = sourceInstanceId.Split('.')[0], marker = "-" + label + "-";
        int index = subscriptionId.IndexOf(marker, StringComparison.Ordinal);
        if (label.Length == 0 || index < 0 || subscriptionId.IndexOf(marker, index + marker.Length, StringComparison.Ordinal) >= 0)
            throw Bad("legacy_remediation_contract_identity_invalid");
        string legacySubscription = subscriptionId[..index] + "-" + subscriptionId[(index + marker.Length)..];
        if (!Is(candidate, "legacy_source_instance_id", "radius." + sourceInstanceId)) throw Bad("legacy_remediation_source_identity_unexpected");
        if (!Is(candidate, "legacy_subscription_id", legacySubscription)) throw Bad("legacy_remediation_subscription_identity_unexpected");
        foreach (var (field, code) in new[] {
            ("source_contract_matches", "source_contract_mismatch"), ("subscription_contract_matches", "subscription_contract_mismatch"),
            ("cursor_contract_matches", "cursor_contract_mismatch"), ("source_disabled", "source_not_disabled"), ("subscription_disabled", "subscription_not_disabled") })
            if (!Bool(candidate, field, true)) throw Bad("legacy_remediation_" + code);
        if (!Integer(candidate["runtime_state_rows"], out long rows) || rows != 0) throw Bad("legacy_remediation_runtime_state_present");
        if (candidate["cursor"] is not JsonArray c || c.Count != 9 || Text(c[0]) != Stream || Text(c[1]) != Transport ||
            !Guid.TryParse(Text(c[2]), out _) || !Token(c[3]) || !Integer(c[4], out long offset) || offset < 0 ||
            !Integer(c[8], out long revision) || revision < 0 || (c[5] is not null && !Hash(c[5])) ||
            (c[6] is not null && !Token(c[6])) || (c[7] is not null && !Hash(c[7])))
            throw Bad("legacy_remediation_cursor_values_invalid");
        return (JsonObject)candidate.DeepClone();
    }

    static string ResolveDirectory(string path)
    {
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            var next = new DirectoryInfo(Path.Combine(current, part));
            current = next.LinkTarget is null ? next.FullName : next.ResolveLinkTarget(true)!.FullName;
        }
        return current;
    }

    static JsonObject? ReadEvidence(string path, bool optional)
    {
        if (optional && !File.Exists(path)) return null;
        try
        {
            var node = JsonNode.Parse(File.ReadAllText(path));
            return node as JsonObject ?? throw Bad("prerequisite_object_required:" + Path.GetFileName(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        { throw Bad("invalid prerequisite:" + Path.GetFileName(path)); }
    }

    public static RadiusRegistrationPlan Plan(string root, string sourceInstanceId, Func<JsonObject> liveAclReadback,
        Func<JsonObject> inspectRows, IReadOnlyDictionary<string, string?> environment, string? prerequisitesDirectory = null,
        Func<string, bool, JsonObject?>? readEvidence = null)
    {
        string directory = Path.Combine(root, "artifacts", "stage9", "evidence");
        string cursorPath = environment.GetValueOrDefault("ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH")?.Trim() ?? "";
        if (cursorPath.Length == 0) cursorPath = Path.Combine(directory, CursorBootstrap);
        if (prerequisitesDirectory is not null)
        {
            string resolved = ResolveDirectory(prerequisitesDirectory), artifacts = ResolveDirectory(Path.Combine(root, "artifacts"));
            string relative = Path.GetRelativePath(artifacts, resolved);
            if (!Directory.Exists(resolved) || relative == "." || relative == ".." || Path.IsPathRooted(relative) || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw Bad("prerequisites_directory_invalid");
            directory = resolved;
            cursorPath = Path.Combine(directory, Path.GetFileName(cursorPath));
        }
        var read = readEvidence ?? ReadEvidence;
        string aclPath = Path.Combine(directory, AclReadback);
        var bootstrap = ValidatePrerequisites(root, sourceInstanceId, read(Path.Combine(directory, PostgresApply), true),
            read(cursorPath, false)!, read(aclPath, false)!, read(Path.Combine(directory, PostgresAttestation), true));
        var liveAcl = liveAclReadback();
        if (!JsonNode.DeepEquals(liveAcl["readback_sha256"], read(aclPath, false)!["readback_sha256"])) throw Bad("protected_root_acl_changed");
        var rows = inspectRows();
        if (!Bool(rows, "migration_58", true)) throw Bad("migration_58_missing");
        bool empty = new[] { "source_count", "cursor_count", "subscription_count" }.All(key => Number(rows, key, 0));
        bool exact = new[] { "source_count", "cursor_count", "subscription_count" }.All(key => Number(rows, key, 1));
        if (!empty && !exact) throw Bad("partial_registration_state_detected");
        return new(new JsonObject { ["status"] = "ready", ["action"] = "plan", ["registration_already_exact_candidate"] = exact,
            ["migration_58"] = true, ["protected_root"] = "accepted", ["cursor_bootstrap"] = "accepted", ["desired_activation"] = "disabled",
            ["source_contacted"] = false, ["worker_activated"] = false, ["runtime_enabled"] = false, ["required_confirmation"] = "REGISTER-STAGE9-RADIUS-DISABLED" }, bootstrap);
    }
}
