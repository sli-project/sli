using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Access.Administration;

internal static class AssignmentAudit
{
    internal static async Task AppendAsync(NpgsqlTransaction transaction, AssignmentActor? actor, AssignmentValues values,
        long assignmentId, bool package, string? address, CancellationToken ct)
    {
        string action = package ? "package_assignment_created" : "report_assignment_created";
        string target = package ? "package" : "report";
        var details = new { assignment_id = assignmentId, effect = values.Effect,
            valid_until = values.ValidUntil is { } until ? Stamp(until) : null };
        await AppendEventAsync(transaction, actor, action, values.SubjectType, (long)values.SubjectId, target, values.Key,
            values.Reason, details, address, ct);
    }

    // The caller owns the transaction. Always persist and fetch the legacy row before the optional bridge.
    internal static async Task AppendEventAsync(NpgsqlTransaction transaction, AssignmentActor? actor, string action,
        string? subjectType, long? subjectId, string? target, string? targetKey, string? reason, object details,
        string? address, CancellationToken ct, string outcome = "ok", bool? writeEnabled = null)
    {
        string actorType = actor?.Type is { Length: > 0 } type ? type : "local";
        action = string.Concat(action.EnumerateRunes().Take(120).Select(r => r.ToString()));
        outcome = string.Concat(outcome.EnumerateRunes().Take(40).Select(r => r.ToString()));
        long id;
        DateTime created;
        await using (var command = new NpgsqlCommand("""
            insert into access_audit_v4(actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,details_json,remote_address)
            values(@actor,@actor_id,@action,@subject,@subject_id,@target,@key,@reason,@outcome,@details::jsonb,@address)
            returning id,created_at
            """, transaction.Connection, transaction))
        {
            command.Parameters.AddWithValue("actor", actorType);
            command.Parameters.AddWithValue("actor_id", NpgsqlDbType.Bigint, (object?)actor?.Id ?? DBNull.Value);
            command.Parameters.AddWithValue("action", action);
            command.Parameters.AddWithValue("subject", NpgsqlDbType.Text, (object?)subjectType ?? DBNull.Value);
            command.Parameters.AddWithValue("subject_id", NpgsqlDbType.Bigint, (object?)subjectId ?? DBNull.Value);
            command.Parameters.AddWithValue("target", NpgsqlDbType.Text, (object?)target ?? DBNull.Value);
            command.Parameters.AddWithValue("key", NpgsqlDbType.Text, (object?)targetKey ?? DBNull.Value);
            command.Parameters.AddWithValue("reason", NpgsqlDbType.Text, (object?)reason ?? DBNull.Value);
            command.Parameters.AddWithValue("outcome", outcome);
            command.Parameters.AddWithValue("details", JsonSerializer.Serialize(details));
            command.Parameters.AddWithValue("address", NpgsqlDbType.Text, (object?)address ?? DBNull.Value);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw AssignmentValidation.Error("administrative_activity_access_audit_id_invalid");
            id = reader.GetInt64(0);
            created = reader.GetDateTime(1);
        }
        if (!AdministrativeActivityProducer.SupportsAccess(action)) return;
        var activity = AdministrativeActivityProducer.ProjectAccess(id, created, actorType, actor?.Id, action,
            subjectType, subjectId, target, targetKey, outcome, address);
        await AdministrativeActivityProducer.MirrorAsync(transaction, activity, "access_audit_v4", id,
            writeEnabled ?? RuntimeWriteEnabled(), ct);
    }

    internal static bool RuntimeWriteEnabled()
    {
        ValidateDisabledContract();
        return false; // The frozen contract requires explicit reviewed activation.
    }

    internal static void ValidateDisabledContract()
    {
        using var stream = typeof(AssignmentAudit).Assembly.GetManifestResourceStream("Sli.Server.Auth.Lifecycle.Security.administrative-activity-v1.json")
            ?? throw AssignmentValidation.Error("administrative_activity_contract_unreadable");
        JsonObject contract;
        try { contract = JsonNode.Parse(stream)!.AsObject(); }
        catch (JsonException) { throw AssignmentValidation.Error("administrative_activity_contract_unreadable"); }
        var expected = JsonNode.Parse("""
            {"schema_version":1,"contract_id":"sli.administrative-activity.v1","required_migration":66,
             "runtime_write_enabled":false,"runtime_read_enabled":false,"source_contact_allowed":false,
             "maximum_detail_bytes":8192,"details_shape":"flat_scalar_object_only"}
            """)!.AsObject();
        foreach (var item in expected)
            if (!JsonNode.DeepEquals(contract[item.Key], item.Value)) throw AssignmentValidation.Error("administrative_activity_contract_" + item.Key + "_invalid");
        if (contract.ContainsKey("status") || contract.ContainsKey("production_migration_applied")) throw AssignmentValidation.Error("administrative_activity_contract_production_claim_present");
        if (contract["categories"] is not JsonArray categories || categories.Count == 0 || contract["outcomes"] is not JsonArray outcomes || outcomes.Count == 0)
            throw AssignmentValidation.Error("administrative_activity_contract_values_missing");
        if (!categories.Any(v => v?.GetValue<string>() == "access_management")) throw AssignmentValidation.Error("administrative_activity_category_invalid");
        if (!outcomes.Any(v => v?.GetValue<string>() == "succeeded")) throw AssignmentValidation.Error("administrative_activity_outcome_invalid");
        var reader = JsonNode.Parse("""
            {"required_migration":72,"capability":"administrative.activity.view","access_package":"access_admin",
             "endpoint":"/api/v1/operations/administrative-activity","database_function":"read_administrative_activity_v1",
             "pagination":"reverse_activity_id_keyset","default_limit":50,"maximum_limit":200,"direct_table_select":false}
            """);
        if (!JsonNode.DeepEquals(contract["prepared_reader"], reader)) throw AssignmentValidation.Error("administrative_activity_contract_prepared_reader_invalid");
        var auth = JsonNode.Parse("""
            {"source_table":"auth_audit","source_actions":["login","logout","initial_owner_claimed","user_created","user_updated","user_password_reset","api_key_issued","api_key_revoked"],"atomic_cursor_bridge":true,"runtime_enabled":false,"raw_username_or_key_prefix_copied":false}
            """);
        if (!JsonNode.DeepEquals(contract["prepared_producers"]?["auth_audit"], auth)) throw AssignmentValidation.Error("administrative_activity_contract_auth_producer_invalid");
        var access = JsonNode.Parse("""
            {"source_table":"access_audit_v4","source_actions":["report_assignment_created","package_assignment_created","vpn_session_evidence_grant_created","report_access_requested","report_access_request_rejected","report_access_request_approved","report_published","report_draft_created","report_version_promoted","report_retired","report_visibility_changed"],"excluded_actions":["report_preference_updated"],"atomic_cursor_bridge":true,"runtime_enabled":false,"raw_reason_or_details_copied":false}
            """);
        if (!JsonNode.DeepEquals(contract["prepared_producers"]?["access_audit_v4"], access)) throw AssignmentValidation.Error("administrative_activity_contract_access_producer_invalid");
    }

    internal static string Stamp(DateTimeOffset time)
    {
        string stamp = time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (time.Ticks % TimeSpan.TicksPerSecond != 0) stamp += "." + time.ToString("ffffff", CultureInfo.InvariantCulture);
        return stamp + time.ToString("zzz", CultureInfo.InvariantCulture);
    }

    internal static JsonElement Row(string json)
    {
        var row = JsonNode.Parse(json)!.AsObject();
        foreach (string key in new[] { "created_at", "valid_from", "valid_until" })
            if (row[key] is JsonValue value && value.TryGetValue<string>(out var stamp)) row[key] = Stamp(DateTimeOffset.Parse(stamp, CultureInfo.InvariantCulture));
        return JsonSerializer.SerializeToElement(row);
    }
}
