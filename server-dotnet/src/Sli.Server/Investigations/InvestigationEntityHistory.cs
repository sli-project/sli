using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
using Sli.Server.Reports.SecurityCandidates;

namespace Sli.Server.Investigations;

public interface IInvestigationEntityHistory
{
    Task<long[]> CandidatesAsync(InvestigationWorkspaceInput input, AccessDecision access, string report, CancellationToken ct);
    Task<IReadOnlyList<JsonObject>> MetadataAsync(InvestigationWorkspaceInput input, long[] ids, CancellationToken ct);
}

internal sealed class InvestigationEntityHistory(IPostgresConnectionFactory connections, SecurityCandidateOwner candidates, IConfiguration? config = null) : IInvestigationEntityHistory
{
    public async Task<long[]> CandidatesAsync(InvestigationWorkspaceInput input, AccessDecision access, string report, CancellationToken ct)
    {
        if (input.From is not null && input.To is not null)
        {
            var result = await candidates.ReadAsync(input.Entity!.Value, DateTimeOffset.Parse(input.From, CultureInfo.InvariantCulture),
                DateTimeOffset.Parse(input.To, CultureInfo.InvariantCulture), 101, access, ct);
            return result.State == "available" ? result.Ids.ToArray() : [];
        }
        if (input.Entity > int.MaxValue) return [];
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await ReadOnly(db, tx, ct);
        string sql = EntityShortSql.Cte("@boundary","@entity",daily:false) + """
            select event.id as event_db_id,event.time_created_utc from short_events event
            join servers server on server.id=event.server_id and server.domain_id=event.domain_id
            where event.id>0
            """;
        sql += Range(input) + " order by event.time_created_utc desc,event.id desc limit 101";
        var rows = await InvestigationLinksRepository.Rows(db, tx, sql, c => { c.CommandTimeout = 0; Parameters(c, input); c.Parameters.AddWithValue("boundary",EventReadService.ShortBoundary(config).UtcDateTime); }, ct);
        await tx.CommitAsync(ct); return rows.Select(r => r["event_db_id"]!.GetValue<long>()).ToArray();
    }
    public async Task<IReadOnlyList<JsonObject>> MetadataAsync(InvestigationWorkspaceInput input, long[] ids, CancellationToken ct)
    {
        if (ids.Length == 0) return [];
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct); await ReadOnly(db, tx, ct);
        bool security = input.From is not null && input.To is not null;
        string sql = (security ? "with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+") " : EntityShortSql.Cte("@boundary","@entity",daily:false)) + """
            select event.id as event_db_id,event.event_id,event.time_created_utc,server.hostname as server,
                event.channel,event.provider_name,event.method#>>'{$principals,SubjectUserName}' as subject_user_name,
                event.method#>>'{$principals,TargetUserName}' as target_user_name
            from short_events event join servers server on server.id=event.server_id and server.domain_id=event.domain_id
            where event.id=any(@ids)
            """;
        if (!security) sql += Range(input);
        sql += " order by event.time_created_utc desc,event.id desc limit @limit";
        var rows = await InvestigationLinksRepository.Rows(db, tx, sql, c => { c.CommandTimeout = 0; Parameters(c, input); c.Parameters.AddWithValue("ids", ids); c.Parameters.AddWithValue("limit", ids.Length); c.Parameters.AddWithValue("boundary",EventReadService.ShortBoundary(config).UtcDateTime); }, ct);
        await tx.CommitAsync(ct); return rows;
    }
    static string Range(InvestigationWorkspaceInput i) => (i.From is null ? "" : " and event.time_created_utc>=@start") + (i.To is null ? "" : " and event.time_created_utc<@end");
    static void Parameters(NpgsqlCommand c, InvestigationWorkspaceInput i)
    {
        c.Parameters.AddWithValue("entity", checked((int)i.Entity!.Value));
        if (i.From is not null) c.Parameters.AddWithValue("start", NpgsqlDbType.TimestampTz, DateTimeOffset.Parse(i.From, CultureInfo.InvariantCulture).UtcDateTime);
        if (i.To is not null) c.Parameters.AddWithValue("end", NpgsqlDbType.TimestampTz, DateTimeOffset.Parse(i.To, CultureInfo.InvariantCulture).UtcDateTime);
    }
    static Task ReadOnly(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct) => InvestigationLinksRepository.Execute(db, tx, "set transaction read only", c => c.CommandTimeout = 0, ct);
}
