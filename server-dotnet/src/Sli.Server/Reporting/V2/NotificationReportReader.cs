using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
namespace Sli.Server.Reporting.V2;

// Reads only persisted allowlisted metadata. No transport, secret resolution or producer runs here.
public sealed class NotificationReportReader(IPostgresConnectionFactory connections) : IReportV2Reader
{
    public static string Timestamp(string iso)
    {
        var stamp = DateTimeOffset.Parse(iso, CultureInfo.InvariantCulture, DateTimeStyles.None);
        string local = stamp.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
        return Sli.Server.Investigations.InvestigationList.FormatSessionTimestamp(local, (int)stamp.Offset.TotalSeconds);
    }
    private static void NormalizeTimestamp(JsonObject row, string key)
    { if (row[key] is JsonValue value && value.TryGetValue<string>(out string? iso)) row[key] = Timestamp(iso); }
    public string OwnerId => "sli.core";
    public bool Handles(string reportKey) => reportKey is "notifications.channels" or "notifications.deliveries";
    public async Task<JsonObject> QueryAsync(ReportQueryContext context, CancellationToken ct)
    {
        string? cursor = context.Paging.Cursor;
        bool channels = context.Definition.Key == "notifications.channels";
        if (channels && cursor is not (null or "smtp" or "telegram") || !channels && cursor is not null && !Guid.TryParse(cursor, out _)) throw new ReportRequestException("invalid_cursor");
        // Both declarations require global scope. Verify it again at the storage boundary.
        if (context.Scope.Mode != "all") throw new ReportRequestException("report_scope_not_executable", 403);
        try
        {
            await using var connection = await connections.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var limits = new NpgsqlCommand("set transaction read only", connection, transaction) { CommandTimeout = 0 }) await limits.ExecuteNonQueryAsync(ct);
            var items = new JsonArray(); long count = 0; bool more;
            if (channels)
            {
                string sql = "select row_to_json(c)::text from (select " + NotificationAdministrationRepository.ChannelFields
                    + " from (" + NotificationAdministrationRepository.ChannelStatus + ") status order by kind) c";
                await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 0 };
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    count++; var row = JsonNode.Parse(reader.GetString(0))!.AsObject();
                    NormalizeTimestamp(row, "updated_at");
                    if (cursor is null || string.CompareOrdinal(row.Text("kind"), cursor) > 0) items.Add(row);
                }
                more = items.Count > context.Paging.Limit;
            }
            else
            {
                await using var command = new NpgsqlCommand("""
                    select row_to_json(c)::text from (
                      select j.id,j.subscription_id,j.object_id,j.channel,j.state,j.attempts,j.result_code,j.created_at,j.updated_at,
                             j.delivery_reason,j.delay_minutes,j.object_kind,r.period_from,r.period_to,r.quality
                      from (select id,subscription_id,object_id,channel,state,attempts,result_code,created_at,updated_at,
                                   delivery_reason,delay_minutes,object_kind from notification_outbox
                            where (@before::uuid is null or id<@before) order by id desc limit @limit) j
                      left join report_schedule_runs r on j.object_kind='report_schedule' and r.id=j.object_id
                      order by j.id desc
                    ) c
                    """, connection, transaction) { CommandTimeout = 0 };
                command.Parameters.AddWithValue("before", NpgsqlDbType.Uuid, cursor is null ? DBNull.Value : Guid.Parse(cursor));
                command.Parameters.AddWithValue("limit", context.Paging.Limit + 1);
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    var row = JsonNode.Parse(reader.GetString(0))!.AsObject();
                    if (row.Text("object_kind") != "report_schedule" || row["period_from"] is null)
                        foreach (string key in new[] { "period_from", "period_to", "quality" }) row.Remove(key);
                    foreach (string key in new[] { "created_at", "updated_at", "period_from", "period_to" }) NormalizeTimestamp(row, key);
                    row.Remove("object_kind"); items.Add(row);
                }
                more = items.Count > context.Paging.Limit;
            }
            while (items.Count > context.Paging.Limit) items.RemoveAt(items.Count - 1);
            var result = ReportResult.Create(context.Definition.Key, channels ? count > 0 ? "ok" : "empty" : items.Count > 0 ? "ok" : "empty", items);
            result["has_more"] = more;
            result["next_cursor"] = more ? items[^1]![channels ? "kind" : "id"]!.DeepClone() : null;
            if (channels) result["filtered_count"] = count;
            await transaction.CommitAsync(ct);
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (ReportRequestException) { throw; }
        catch (Exception) { return ReportResult.Create(context.Definition.Key, "error"); }
    }
}
