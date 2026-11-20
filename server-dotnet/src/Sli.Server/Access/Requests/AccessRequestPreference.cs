using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Access.Requests;

public sealed partial class AccessRequestService
{
    public async Task<JsonElement> SetPreferenceAsync(string reportKey, JsonElement payload, Principal actor, string? remoteAddress, CancellationToken ct)
    {
        long userId = RequestJson.SessionId(actor);
        string key = RequestJson.Strip(reportKey);
        bool hasPinned = payload.TryGetProperty("pinned", out var pinnedValue), hasFocus = payload.TryGetProperty("focus_metric_keys", out var focus);
        if (key.Length == 0 || !hasPinned && !hasFocus || hasPinned && pinnedValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new AccessRequestException("invalid_report_preference");
        if (hasFocus && (focus.ValueKind != JsonValueKind.Array || focus.GetArrayLength() > 24
            || focus.Items().Any(v => v.ValueKind != JsonValueKind.String || !Regex.IsMatch(v.GetString()!, @"\A[a-z0-9][a-z0-9_.-]{1,79}\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking))
            || focus.Items().Select(v => v.GetString()).Distinct().Count() != focus.GetArrayLength())) throw new AccessRequestException("invalid_report_preference");
        var access = await evaluator.EvaluateAsync(actor, ct);
        var report = access.Reports.FirstOrDefault(r => r.Text("report_key") == key);
        if (report.ValueKind == JsonValueKind.Undefined || !RequestJson.True(report, "allowed")) throw new AccessRequestException("report_access_denied", 403);
        var optional = report.Get("dashboard_metrics").Items().Where(m => m.Text("kind") == "optional" && AuthJsonBody.Truthy(m.Get("key")))
            .Select(m => RequestJson.Text(m, "key")).ToHashSet();
        string[] focusKeys = hasFocus ? focus.Items().Select(v => v.GetString()!).ToArray() : [];
        if (hasFocus && !focusKeys.ToHashSet().IsSubsetOf(optional)) throw new AccessRequestException("invalid_report_preference");
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        bool pinned = false;
        JsonObject view = new();
        await using (var current = new NpgsqlCommand("select pinned,view_json from user_report_preferences where user_id=@user and report_key=@key", connection, transaction))
        {
            current.Parameters.AddWithValue("user", userId); current.Parameters.AddWithValue("key", key);
            await using var reader = await current.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                pinned = reader.GetBoolean(0);
                using var json = JsonDocument.Parse(reader.GetString(1));
                try { var parsed = json.RootElement.Object(); if (parsed.ValueKind == JsonValueKind.Object) view = JsonNode.Parse(parsed.GetRawText())!.AsObject(); }
                catch (JsonException) { }
            }
        }
        if (hasPinned) pinned = pinnedValue.GetBoolean();
        if (hasFocus) view["focus_metric_keys"] = JsonSerializer.SerializeToNode(focusKeys);
        await using var write = new NpgsqlCommand("""
            with changed as (
                insert into user_report_preferences(user_id,report_key,pinned,view_json,updated_at) values(@user,@key,@pinned,@view::jsonb,now())
                on conflict(user_id,report_key) do update set pinned=excluded.pinned,view_json=excluded.view_json,updated_at=now()
                returning user_id,report_key,pinned,view_json,updated_at
            ) select to_jsonb(changed) from changed
            """, connection, transaction);
        write.Parameters.AddWithValue("user", userId); write.Parameters.AddWithValue("key", key); write.Parameters.AddWithValue("pinned", pinned);
        write.Parameters.AddWithValue("view", view.ToJsonString());
        var item = RequestJson.Row((string)(await write.ExecuteScalarAsync(ct))!);
        var details = new Dictionary<string, object> { ["pinned"] = pinned };
        if (hasFocus) details["focus_metric_keys"] = focusKeys;
        await audit.AppendAsync(transaction, new(RequestJson.Actor(actor), "report_preference_updated", userId, key, null, details, remoteAddress), ct);
        await transaction.CommitAsync(ct);
        return item;
    }
}
