using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Compatibility;

namespace Sli.Server.InstallationSetup;

// Parity with server/sli/sources/plugin_runtime_activation_executor.py.
// Only durable state and audit are changed by the existing PostgreSQL function.
public sealed class PluginRuntimeActivationExecutor(IInstallationDatabase database)
{
    public async Task<JsonObject> ExecuteAsync(JsonObject plan, string confirmation, string operationUid,
        string actorKind, string actorKey, IReadOnlySet<string> actorCapabilities, CancellationToken ct)
    {
        if (!actorCapabilities.Any(c => c == "plugins.manage"))
            throw new InstallationException("plugins_manage_required", 403);
        string action = Text(plan["requested_action"]), digest = Text(plan["plan_sha256"]);
        long? revision = Integer(plan["expected_revision"]);
        string expected = $"PLUGIN-{action.ToUpperInvariant()}-SLI-REMOTE-ACCESS-R{revision?.ToString(CultureInfo.InvariantCulture)}-{digest[..Math.Min(12, digest.Length)].ToUpperInvariant()}";
        if (action is not ("enable" or "drain" or "disable") || Text(plan["plugin_id"]) != "sli.remote-access"
            || revision is null || digest.Length != 64 || digest.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            || confirmation != expected || !Flag(plan["preserve_immutable_evidence"], true)
            || !Flag(plan["production_read_path_cutover"], false) || !Flag(plan["destructive_purge"], false))
            throw new InstallationException("plugin_runtime_transition_plan_invalid");

        // Python UUID accepts the hex, canonical, braced and urn forms.
        string uidText = operationUid.Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal)
            .Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        if (!Guid.TryParseExact(uidText, "N", out var uid))
            throw new InstallationException("plugin_runtime_operation_uid_invalid");
        string kind = PythonText.Strip(actorKind), key = PythonText.Strip(actorKey);
        if (kind is not ("session" or "api_key" or "windows" or "system" or "local_operator")
            || key.Length == 0 || key.EnumerateRunes().Count() > 200)
            throw new InstallationException("plugin_runtime_actor_invalid");

        var rows = await database.WriteAsync(s => s.QueryAsync("""
            select operation_id,committed_revision,desired_activation,
                   component_runtime,queue_state
            from execute_plugin_runtime_transition_v1(
              @p0::uuid,@p1,@p2::bigint,@p3,@p4,@p5,@p6
            )
            """, ct, uid.ToString(), action, revision.Value, digest, confirmation, kind, key), ct);
        var row = rows.FirstOrDefault() as JsonObject;
        long operationId = ResultInteger(row?["operation_id"]), committed = ResultInteger(row?["committed_revision"]);
        if (operationId < 1 || revision == long.MaxValue || committed != revision.Value + 1)
            throw new InstallationException("plugin_runtime_transition_result_invalid");
        return new JsonObject {
            ["status"] = "succeeded", ["plugin_id"] = "sli.remote-access", ["requested_action"] = action,
            ["operation_uid"] = uid.ToString(), ["operation_id"] = operationId, ["committed_revision"] = committed,
            ["desired_activation"] = row?["desired_activation"]?.DeepClone(),
            ["component_runtime"] = row?["component_runtime"]?.DeepClone(), ["queue_state"] = row?["queue_state"]?.DeepClone(),
            ["source_contacted"] = false, ["process_started_or_stopped"] = false, ["production_read_path_cutover"] = false };
    }

    static string Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : "";
    static bool Flag(JsonNode? node, bool expected) => node is JsonValue value && value.TryGetValue<bool>(out bool flag) && flag == expected;
    static long? Integer(JsonNode? node) => node is JsonValue value && value.TryGetValue<long>(out long number) ? number
        : node is JsonValue small && small.TryGetValue<int>(out int integer) ? integer : null;
    static long ResultInteger(JsonNode? node) => Integer(node) ?? (long.TryParse(Text(node), NumberStyles.Integer, CultureInfo.InvariantCulture, out long number) ? number : 0);
}
