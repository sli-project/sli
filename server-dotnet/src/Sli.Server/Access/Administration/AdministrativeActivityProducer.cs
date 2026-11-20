using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Reporting;

namespace Sli.Server.Access.Administration;

internal sealed record AdministrativeActivity(Guid EventUid, DateTime OccurredAt, string ActorKind, string ActorKey,
    string Category, string ActionKey, string? TargetKind, string? TargetKey, string Outcome, string? ReasonCode,
    JsonObject Details, string? RemoteAddress);

// Safe projections of the existing audit rows; raw details and reasons stay in the legacy audit only.
internal static class AdministrativeActivityProducer
{
    private static readonly IReadOnlyDictionary<string, (string Category, string Action, string Target)> AccessActions =
        new Dictionary<string, (string, string, string)>(StringComparer.Ordinal)
        {
            ["report_key_capabilities_created"] = ("access_management", "access.report_key.capabilities_created", "ad_domain"),
            ["report_api_key_issued"] = ("access_management", "access.report_key.issued", "api_key"),
            ["report_assignment_created"] = ("access_management", "access.report.assignment_created", "report"),
            ["package_assignment_created"] = ("access_management", "access.package.assignment_created", "package"),
            ["vpn_session_evidence_grant_created"] = ("access_management", "access.vpn.session_evidence_grant_created", "capability"),
            ["report_access_requested"] = ("access_management", "access.report.requested", "report"),
            ["report_access_request_rejected"] = ("access_management", "access.report.request_rejected", "report"),
            ["report_access_request_approved"] = ("access_management", "access.report.request_approved", "report"),
            ["report_published"] = ("report_publication", "report.published", "report"),
            ["report_draft_created"] = ("report_publication", "report.draft_created", "report"),
            ["report_version_promoted"] = ("report_publication", "report.version_promoted", "report"),
            ["report_retired"] = ("report_publication", "report.retired", "report"),
            ["report_visibility_changed"] = ("report_publication", "report.visibility_changed", "report"),
            ["platform_setting_update"] = ("source_configuration", "platform.setting.updated", "platform_setting"),
            ["setup_domain_add"] = ("source_configuration", "setup.domain.added", "ad_domain"),
            ["setup_domain_update"] = ("source_configuration", "setup.domain.updated", "ad_domain"),
            ["setup_dc_add"] = ("source_configuration", "setup.domain_controller.added", "domain_controller"),
            ["setup_dc_update"] = ("source_configuration", "setup.domain_controller.updated", "domain_controller")
        };

    internal static bool SupportsAccess(string action) => AccessActions.ContainsKey(AssignmentValidation.Strip(action));

    internal static AdministrativeActivity ProjectAccess(long id, DateTime created, string actorType, long? actorId,
        string action, string? subjectType, long? subjectId, string? targetType, string? targetKey, string outcome, string? address)
    {
        if (id < 1) throw AssignmentValidation.Error("administrative_activity_access_audit_id_invalid");
        if (!AccessActions.TryGetValue(AssignmentValidation.Strip(action), out var mapping))
            throw AssignmentValidation.Error("administrative_activity_access_action_not_allowlisted");
        string actorKind = AssignmentValidation.Strip(actorType).ToLowerInvariant() switch
        {
            "session" => "session", "api_key" => "api_key", "windows" => "windows", "plugin" => "plugin",
            "anonymous" or "system" => "system", "local" or "local_operator" => "local_operator",
            _ => throw AssignmentValidation.Error("administrative_activity_access_actor_not_allowlisted")
        };
        string mappedOutcome = AssignmentValidation.Strip(outcome).ToLowerInvariant() switch
        {
            "ok" => "succeeded", "failed" => "failed", "throttled" or "denied" => "denied",
            _ => throw AssignmentValidation.Error("administrative_activity_access_outcome_not_allowlisted")
        };
        string cleanKey = AssignmentValidation.Strip(targetKey ?? "");
        if (AssignmentValidation.Strip(targetType ?? "").ToLowerInvariant() != mapping.Target || cleanKey.Length == 0)
            throw AssignmentValidation.Error("administrative_activity_access_target_invalid");
        var details = new JsonObject { ["legacy_access_audit_id"] = id };
        if (subjectType is not null)
        {
            string subject = AssignmentValidation.Strip(subjectType).ToLowerInvariant();
            if (subject is not ("user" or "group") || subjectId is null or < 1)
                throw AssignmentValidation.Error("administrative_activity_access_subject_invalid");
            details["subject_type"] = subject;
            details["subject_id"] = subjectId;
        }
        string actorKey = actorKind + ":" + (actorId?.ToString(CultureInfo.InvariantCulture) ?? "anonymous");
        if (actorKey.EnumerateRunes().Count() > 200) throw AssignmentValidation.Error("administrative_activity_actor_key_invalid");
        string projectedKey = mapping.Target + ":" + cleanKey;
        if (projectedKey.EnumerateRunes().Count() > 240) throw AssignmentValidation.Error("administrative_activity_target_key_invalid");
        return new(AuthAudit.Uuid5("sli:access_audit_v4:" + id.ToString(CultureInfo.InvariantCulture)), created,
            actorKind, actorKey, mapping.Category, mapping.Action, mapping.Target, projectedKey, mappedOutcome, null, details, address);
    }

    internal const string AppendSql = """
        select activity_id,encode(record_hash,'hex') as record_hash from append_administrative_activity_v1(
        @p0::uuid,@p1::timestamptz,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10::jsonb,@p11::inet,@p12::uuid)
        """;

    internal static object?[] Arguments(AdministrativeActivity activity) =>
        [activity.EventUid, activity.OccurredAt, activity.ActorKind, activity.ActorKey, activity.Category,
         activity.ActionKey, activity.TargetKind, activity.TargetKey, activity.Outcome, activity.ReasonCode,
         activity.Details.ToJsonString(), activity.RemoteAddress, null];

    internal static JsonObject Result(string source, long id, long? activityId = null)
    {
        var result = new JsonObject { ["status"] = activityId.HasValue ? "written" : "disabled", ["source"] = source,
            ["source_row_id"] = id, ["journal_written"] = activityId.HasValue };
        if (activityId.HasValue) result["activity_id"] = activityId.Value;
        return result;
    }

    internal static void ValidateResult(long id, string hash)
    {
        if (id < 1 || hash.Length != 64 || hash.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidOperationException("administrative_activity_write_result_invalid");
    }

    internal static async Task<JsonObject> MirrorAsync(NpgsqlTransaction transaction, AdministrativeActivity activity,
        string source, long id, bool enabled, CancellationToken ct)
    {
        if (!enabled) return Result(source, id);
        await using var command = new NpgsqlCommand(AppendSql, transaction.Connection, transaction);
        var values = Arguments(activity);
        for (int i = 0; i < values.Length; i++)
            command.Parameters.Add(values[i] is { } value ? new NpgsqlParameter("p" + i, value)
                : new NpgsqlParameter("p" + i, NpgsqlDbType.Text) { Value = DBNull.Value });
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("administrative_activity_write_result_invalid");
        long activityId = reader.GetInt64(0);
        ValidateResult(activityId, reader.GetString(1));
        return Result(source, id, activityId);
    }

    internal static async Task MirrorAsync(IReportSession session, AdministrativeActivity activity, bool enabled, CancellationToken ct)
    {
        if (!enabled) return;
        var row = (await session.QueryAsync(AppendSql, Arguments(activity), ct)).FirstOrDefault();
        long.TryParse(row?["activity_id"]?.ToString(), out long id);
        ValidateResult(id, row?["record_hash"]?.ToString() ?? "");
    }
}
