using System.Numerics;
using System.Text;
using System.Text.Json;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access.Requests;

public sealed partial class AccessRequestService(IPostgresConnectionFactory connections, IAccessRequestEvaluator evaluator,
    IAccessRequestAudit audit, IReportAssignmentWriter assignments) : IAccessRequestService
{
    public async Task<JsonElement> CreateAsync(JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct)
    {
        long userId = RequestJson.SessionId(actor);
        string key = RequestJson.Strip(RequestJson.Text(payload, "report_key"));
        string reason = RequestJson.Strip(RequestJson.Text(payload, "business_reason"));
        if (key.Length == 0 || reason.EnumerateRunes().Count() is < 10 or > 2000) throw new AccessRequestException("invalid_access_request");
        var access = await evaluator.EvaluateAsync(actor, ct);
        var report = access.Reports.FirstOrDefault(r => r.Text("report_key") == key);
        if (report.ValueKind == JsonValueKind.Undefined || !RequestJson.True(report, "discoverable")) throw new AccessRequestException("report_not_found");
        if (RequestJson.True(report, "allowed")) throw new AccessRequestException("report_already_accessible");
        if (!RequestJson.True(report, "requestable") || report.Text("access_state") == "request_unavailable") throw new AccessRequestException("report_request_unavailable", 403);
        var profile = report.Get("request_profile");
        var kinds = RequestJson.Strings(profile.Get("scope_kinds"), ["all"]).Where(s => s.Length > 0).ToHashSet();
        var scope = RequestJson.NormalizeScope(payload.Get("scope"), kinds);
        var now = DateTimeOffset.UtcNow;
        var until = AssignmentValidation.Timestamp(payload.Get("valid_until"), "invalid_request_valid_until");
        var duration = profile.Get("max_duration_days");
        int days = (int)BigInteger.Clamp(AuthJsonBody.Truthy(duration) ? AssignmentValidation.Integer(duration) : 90, 1, 365);
        if (until is null || until <= now || until > now.AddDays(days)) throw new AccessRequestException("invalid_request_valid_until");
        var fields = RequestJson.Sorted(profile.Get("field_categories"), []);
        var actions = RequestJson.Sorted(profile.Get("allowed_actions"), ["view"]).Append("view").Distinct().Order(StringComparer.Ordinal).ToArray();
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var insert = new NpgsqlCommand("""
            with inserted as (
                insert into report_access_requests_v4(requester_user_id,report_key,report_version,dataset_version,
                    requested_scope_json,requested_valid_until,business_reason,requested_field_categories,requested_actions,status)
                values(@user,@key,@report_version,@dataset_version,@scope::jsonb,@until,@reason,@fields,@actions,'submitted')
                on conflict(requester_user_id,report_key,requested_scope_json) where status in ('submitted','reviewing') do nothing
                returning *
            ) select to_jsonb(inserted) from inserted
            """, connection, transaction);
        insert.Parameters.AddWithValue("user", userId); insert.Parameters.AddWithValue("key", key);
        insert.Parameters.AddWithValue("report_version", report.Get("version").GetInt32());
        insert.Parameters.AddWithValue("dataset_version", report.Get("dataset_version").GetInt32());
        insert.Parameters.AddWithValue("scope", scope.GetRawText()); insert.Parameters.AddWithValue("until", until.Value);
        insert.Parameters.AddWithValue("reason", reason); insert.Parameters.AddWithValue("fields", fields); insert.Parameters.AddWithValue("actions", actions);
        if (await insert.ExecuteScalarAsync(ct) is not string json) throw new AccessRequestException("active_request_already_exists", 409);
        var item = RequestJson.Row(json);
        await audit.AppendAsync(transaction, new(RequestJson.Actor(actor), "report_access_requested", userId, key, reason,
            new { request_id = item.Get("id").GetInt64(), report_version = report.Get("version").GetInt32(),
                dataset_version = report.Get("dataset_version").GetInt32(), scope, valid_until = RequestJson.Iso(until.Value),
                field_categories = fields, allowed_actions = actions }, remoteAddress), ct);
        await transaction.CommitAsync(ct);
        return item;
    }

    public async Task<JsonElement> ListAsync(Principal actor, bool includeAll, BigInteger limit, CancellationToken ct)
    {
        long userId = RequestJson.SessionId(actor);
        var access = await evaluator.EvaluateAsync(actor, ct);
        bool canReview = access.Capabilities.Capabilities.Contains("access.manage");
        if (includeAll && !canReview) throw new AccessRequestException("access_manage_required", 403);
        int cleanLimit = (int)BigInteger.Clamp(limit, 1, 250);
        await using var connection = await connections.OpenAsync(ct);
        string filter = includeAll ? "" : "where request.requester_user_id=@user";
        await using var read = new NpgsqlCommand("""
            select to_jsonb(r) from (
                select request.*,users.username,coalesce(report.name,request.report_key) as report_name
                from report_access_requests_v4 request join auth_users users on users.id=request.requester_user_id
                left join lateral(select name from report_registry_v4 where report_key=request.report_key and version=request.report_version) report on true
            """ + "\n" + filter + "\n" + """
                order by case request.status when 'submitted' then 0 when 'reviewing' then 1 else 2 end,
                    request.created_at desc,request.id desc limit @limit
            ) r
            """, connection);
        read.Parameters.AddWithValue("user", userId); read.Parameters.AddWithValue("limit", cleanLimit);
        var items = new List<JsonElement>();
        await using var reader = await read.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) items.Add(RequestJson.Row(reader.GetString(0)));
        return JsonSerializer.SerializeToElement(new { api_version = "v4", items, limit = cleanLimit, review_allowed = canReview });
    }
}
