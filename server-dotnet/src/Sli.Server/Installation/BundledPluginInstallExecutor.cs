using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Compatibility;

namespace Sli.Server.InstallationSetup;

// Exact bundled registration only. Like the Python executor, this is not a mutation API
// and does not contact sources, control processes, or activate runtime.
public sealed class BundledPluginInstallExecutor(IInstallationDatabase database)
{
    static string Text(JsonNode? node) => InstallationPackages.Text(node);
    static bool IsBool(JsonNode? node, bool expected) => node is JsonValue value
        && value.TryGetValue<bool>(out var actual) && actual == expected;
    static bool Integer(JsonNode? node, out long number)
    {
        number = 0;
        if (node is not JsonValue value) return false;
        if (value.TryGetValue<long>(out number)) return true;
        if (!value.TryGetValue<int>(out var small)) return false;
        number = small; return true;
    }

    public async Task<JsonObject> ExecuteAsync(JsonObject plan, string confirmation, string operationUid,
        string actorKind, string actorKey, IReadOnlySet<string> actorCapabilities, CancellationToken ct)
    {
        if (!actorCapabilities.Any(c => c == "plugins.manage")) throw new InstallationException("plugins_manage_required", 403);
        if (plan["confirmation"] is not JsonValue token || !token.TryGetValue<string>(out var expectedConfirmation)
            || confirmation != expectedConfirmation)
            throw new InstallationException("plugin_lifecycle_confirmation_invalid");
        if (Text(plan["requested_action"]) != "install" || Text(plan["plugin_id"]) != "sli.remote-access"
            || plan["effects"] is not JsonObject effects || effects.Count != 1 || Text(effects["package_lifecycle"]) != "registered"
            || !IsBool(plan["preconditions_met"], true) || !IsBool(plan["preserve_immutable_evidence"], true)
            || !IsBool(plan["production_read_path_cutover"], false) || !IsBool(plan["destructive_purge"], false))
            throw new InstallationException("plugin_bundled_install_plan_invalid");
        string hash = Text(plan["plan_sha256"]);
        if (hash.Length != 64 || !hash.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            throw new InstallationException("plugin_bundled_install_plan_hash_invalid");
        if (!Integer(plan["expected_revision"], out long revision))
            throw new InstallationException("plugin_bundled_install_revision_invalid");
        // Python UUID accepts dashed, compact, braced and urn:uuid forms.
        string uuidText = (operationUid ?? "").Replace("urn:", "", StringComparison.Ordinal)
            .Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        if (!Guid.TryParseExact(uuidText, "N", out var uid))
            throw new InstallationException("plugin_bundled_install_operation_uid_invalid");
        string kind = PythonText.Strip(actorKind ?? ""), key = PythonText.Strip(actorKey ?? "");
        if (kind is not ("session" or "api_key" or "windows" or "system" or "local_operator")
            || key.Length == 0 || key.EnumerateRunes().Count() > 200)
            throw new InstallationException("plugin_bundled_install_actor_invalid");

        string cleanUid = uid.ToString();
        var rows = await database.WriteAsync(s => s.QueryAsync("""
            select operation_id,committed_revision,package_lifecycle,desired_activation
            from execute_bundled_plugin_install_v1(@p0::uuid,@p1,@p2::bigint,@p3,@p4,@p5,@p6)
            """, ct, cleanUid, "sli.remote-access", revision, hash, confirmation, kind, key), ct);
        var row = rows.FirstOrDefault() as JsonObject;
        if (!Integer(row?["operation_id"], out long operationId) || operationId < 1
            || !Integer(row?["committed_revision"], out long committedRevision) || revision == long.MaxValue || committedRevision != revision + 1
            || Text(row?["package_lifecycle"]) != "registered" || Text(row?["desired_activation"]) != "disabled")
            throw new InstallationException("plugin_bundled_install_result_invalid");
        return new JsonObject
        {
            ["status"] = "registered", ["plugin_id"] = "sli.remote-access", ["operation_uid"] = cleanUid,
            ["operation_id"] = operationId, ["committed_revision"] = committedRevision,
            ["package_lifecycle"] = "registered", ["desired_activation"] = "disabled",
            ["process_started_or_stopped"] = false, ["source_contacted"] = false,
            ["runtime_enabled"] = false, ["autostart_enabled"] = false, ["production_read_path_cutover"] = false
        };
    }
}
