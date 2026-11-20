using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;

namespace Sli.Server.Access.Requests;

public sealed partial class AccessRequestService
{
    public async Task<JsonElement> DecideAsync(BigInteger requestId, JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct)
    {
        long actorId = RequestJson.SessionId(actor);
        var actorAccess = await evaluator.EvaluateAsync(actor, ct);
        if (!new[] { "access.manage", "reports.assign" }.All(actorAccess.Capabilities.Capabilities.Contains))
            throw new AccessRequestException("access_request_review_required", 403);
        string decision = RequestJson.Strip(RequestJson.Text(payload, "decision")).ToLowerInvariant();
        string reason = RequestJson.Strip(RequestJson.Text(payload, "decision_reason"));
        if (decision is not ("approve" or "reject") || reason.EnumerateRunes().Count() < 5) throw new AccessRequestException("invalid_access_request_decision");
        if (requestId < long.MinValue || requestId > long.MaxValue) throw new AccessRequestException("access_request_not_pending");
        long id = (long)requestId;
        JsonElement request, requestedScope = default, grantedScope = default;
        string[] requestedFields = [], requestedActions = [], grantedFields = [], grantedActions = [];
        DateTimeOffset requestedUntil = default, grantedUntil = default;
        bool limited = false;
        // Preserve source's first commit, including validation rollback before
        // its CAS claim becomes durable. This is not a universal all-in-one TX.
        await using (var connection = await connections.OpenAsync(ct))
        await using (var transaction = await connection.BeginTransactionAsync(ct))
        {
            await using var claim = new NpgsqlCommand("""
                with claimed as (
                    update report_access_requests_v4 set status='reviewing',decided_by=@actor,updated_at=now()
                    where id=@id and status='submitted' returning *
                ) select to_jsonb(claimed) from claimed
                """, connection, transaction);
            claim.Parameters.AddWithValue("actor", actorId); claim.Parameters.AddWithValue("id", id);
            if (await claim.ExecuteScalarAsync(ct) is not string json) throw new AccessRequestException("access_request_not_pending");
            request = RequestJson.Row(json);
            if (decision == "approve")
            {
                requestedScope = request.Get("requested_scope_json");
                grantedScope = RequestJson.NormalizeScope(payload.TryGetProperty("scope", out var rawScope) ? rawScope : requestedScope,
                    new HashSet<string> { "all", "server", "domain", "channel" });
                requestedFields = request.Get("requested_field_categories").Strings().Order(StringComparer.Ordinal).ToArray();
                grantedFields = RequestJson.Sorted(payload.Get("field_categories"), requestedFields);
                requestedActions = request.Get("requested_actions").Strings().Order(StringComparer.Ordinal).ToArray();
                grantedActions = RequestJson.Sorted(payload.Get("allowed_actions"), requestedActions);
                requestedUntil = DateTimeOffset.Parse(request.Text("requested_valid_until"), CultureInfo.InvariantCulture);
                var until = AssignmentValidation.Timestamp(payload.TryGetProperty("valid_until", out var rawUntil) ? rawUntil : request.Get("requested_valid_until"), "invalid_request_valid_until");
                if (!RequestJson.Subset(grantedScope, requestedScope) || !grantedFields.ToHashSet().IsSubsetOf(requestedFields)
                    || !grantedActions.ToHashSet().IsSubsetOf(requestedActions) || !grantedActions.Contains("view") || until is null || until > requestedUntil
                    // GAP046: approved native fail-closed delta. Never pass an
                    // empty request selection to T9's source default-all writer.
                    || grantedFields.Length == 0) throw new AccessRequestException("decision_may_not_expand_request");
                grantedUntil = until.Value;
                limited = !JsonElement.DeepEquals(grantedScope, requestedScope) || !grantedFields.ToHashSet().SetEquals(requestedFields)
                    || !grantedActions.ToHashSet().SetEquals(requestedActions) || grantedUntil != requestedUntil;
            }
            await transaction.CommitAsync(ct);
        }
        // The source synchronous handler continues accepted work after client
        // disconnect. Once the claim commits, client cancellation must not cut
        // off its writer, compensation or final audit. Provider timeouts remain.
        var durable = CancellationToken.None;
        long userId = request.Get("requester_user_id").GetInt64();
        string key = request.Text("report_key");
        if (decision == "reject")
        {
            await using var connection = await connections.OpenAsync(durable);
            await using var transaction = await connection.BeginTransactionAsync(durable);
            await using var update = new NpgsqlCommand("""
                with updated as (
                    update report_access_requests_v4 set status='rejected',decision_reason=@reason,decided_at=now(),updated_at=now()
                    where id=@id and status='reviewing' returning *
                ) select to_jsonb(updated) from updated
                """, connection, transaction);
            update.Parameters.AddWithValue("reason", reason); update.Parameters.AddWithValue("id", id);
            var result = await update.ExecuteScalarAsync(durable) is string json ? RequestJson.Row(json) : RequestJson.Empty;
            await audit.AppendAsync(transaction, new(RequestJson.Actor(actor), "report_access_request_rejected", userId, key, reason, new { request_id = id }, remoteAddress), durable);
            await transaction.CommitAsync(durable);
            return result;
        }
        ReportAssignmentResult assignment;
        try
        {
            // GAP045: public request/granted scopes retain source string IDs;
            // only the internal persisted assignment gets validated numeric IDs.
            var assignmentScope = AssignmentScope(grantedScope);
            var command = JsonSerializer.SerializeToElement(new { subject_type = "user", subject_id = userId, report_key = key,
                effect = "allow", scope = assignmentScope, field_categories = grantedFields, allowed_actions = grantedActions,
                valid_until = RequestJson.Iso(grantedUntil), source_type = "temporary",
                business_reason = "Заявка #" + id.ToString(CultureInfo.InvariantCulture) + ": " + request.Text("business_reason"),
                approved_by = string.IsNullOrEmpty(actor.Username) ? actorId.ToString(CultureInfo.InvariantCulture) : actor.Username });
            assignment = await assignments.CreateAsync(new(command), RequestJson.Actor(actor), remoteAddress, durable);
        }
        catch
        {
            // Source compensation is another committed transaction and applies
            // only to assignment-call failure, not later preview/final failures.
            await using var connection = await connections.OpenAsync(durable);
            await using var restore = new NpgsqlCommand("update report_access_requests_v4 set status='submitted',decided_by=null,updated_at=now() where id=@id and status='reviewing'", connection);
            restore.Parameters.AddWithValue("id", id); await restore.ExecuteNonQueryAsync(durable);
            throw;
        }
        var actual = await evaluator.PreviewReportAsync(userId, key, durable);
        string status = limited || !RequestJson.True(actual, "allowed") ? "approved_limited" : "approved";
        await using (var connection = await connections.OpenAsync(durable))
        await using (var transaction = await connection.BeginTransactionAsync(durable))
        {
            await using var update = new NpgsqlCommand("""
                with updated as (
                    update report_access_requests_v4 set status=@status,decision_reason=@reason,assignment_id=@assignment,
                        granted_scope_json=@scope::jsonb,granted_valid_until=@until,granted_field_categories=@fields,granted_actions=@actions,
                        decided_at=now(),updated_at=now() where id=@id and status='reviewing' returning *
                ) select to_jsonb(updated) from updated
                """, connection, transaction);
            update.Parameters.AddWithValue("status", status); update.Parameters.AddWithValue("reason", reason);
            update.Parameters.AddWithValue("assignment", assignment.Item.Get("id").GetInt64()); update.Parameters.AddWithValue("scope", grantedScope.GetRawText());
            update.Parameters.AddWithValue("until", grantedUntil); update.Parameters.AddWithValue("fields", grantedFields); update.Parameters.AddWithValue("actions", grantedActions); update.Parameters.AddWithValue("id", id);
            var result = await update.ExecuteScalarAsync(durable) is string json ? RequestJson.Row(json) : RequestJson.Empty;
            await audit.AppendAsync(transaction, new(RequestJson.Actor(actor), "report_access_request_approved", userId, key, reason,
                new { request_id = id, assignment_id = assignment.Item.Get("id").GetInt64(),
                    requested = new { scope = requestedScope, valid_until = RequestJson.Iso(requestedUntil), field_categories = requestedFields, allowed_actions = requestedActions },
                    granted = new { scope = grantedScope, valid_until = RequestJson.Iso(grantedUntil), field_categories = grantedFields, allowed_actions = grantedActions },
                    effective_allowed = RequestJson.True(actual, "allowed") }, remoteAddress), durable);
            await transaction.CommitAsync(durable);
            var response = JsonNode.Parse(result.GetRawText())!.AsObject(); response["effective_report"] = JsonNode.Parse(actual.GetRawText());
            return JsonSerializer.SerializeToElement(response);
        }
    }

    private static JsonElement AssignmentScope(JsonElement wire)
    {
        string kind = wire.Text("kind");
        if (kind is not ("domain" or "server")) return wire;
        var ids = wire.Get("ids").Items().Select(AssignmentValidation.Integer).ToArray();
        if (ids.Any(n => n < 1 || n > long.MaxValue)) throw new AccessRequestException("report_scope_target_not_found");
        return JsonSerializer.SerializeToElement(new { kind, ids = ids.Select(n => (long)n).Distinct().Order().ToArray() });
    }
}
