using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public sealed class AdReportStore(IPostgresConnectionFactory connections,IEventReadService details,IConfiguration? config=null, ILogger<AdReportStore>? logger=null) : IAdReportStore
{
    internal const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
    internal const string PowerProvider = "Microsoft-Windows-PowerShell";
    internal const string PowerChannel = "Microsoft-Windows-PowerShell/Operational";
    internal static int[] EventIds(string kind) => kind switch
    {
        "account" => AdHistory.Map("_AD_ACCOUNT_CHANGE_KIND_BY_EVENT_ID").Select(p => int.Parse(p.Key)).Order().ToArray(),
        "membership" => AdHistory.Map("_GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID").Select(p => int.Parse(p.Key)).Order().ToArray(),
        "powershell" => [4103, 4104], _ => AdHistory.Ids("SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS")
    };
    internal static int[] DiscoveryEventIds(string kind) => kind == "security"
        ? EventIds(kind).Concat(new[] { 4697, 4698, 4699, 4700, 4701, 4702, 7045 }).Distinct().Order().ToArray()
        : EventIds(kind);
    internal static string SecurityPresenceSql => PresenceSql("security",null);
    private static string PresenceSql(string kind,IConfiguration? config) =>
        "select exists(select 1 " + AdColdFactsSql.Joins(config,authentication:kind=="security") + "\n" + """
            where event.domain_id=$1 and server.role='domain_controller' and event.event_id=any($2)
            and ((event.event_id=7045 and channel.value='System' and provider.value='Service Control Manager')
            or (event.event_id<>7045 and channel.value=$3
            and ((event.event_id=1102 and provider.value='Microsoft-Windows-Eventlog')
            or (event.event_id<>1102 and provider.value=$4))))) as present
            """;
    public async Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        return (await AdJson.ReadAsync(db, "select id from domains where id>$1 order by id limit 256", ct, after)).Select(r => r.Int("id")).ToArray();
    }
    public async Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        return await Presence(db,kind,domain,ct,config:config);
    }
    internal static async Task<bool> Presence(NpgsqlConnection db, string kind, long domain, CancellationToken ct,int[]? selected=null,IConfiguration? config=null)
    {
        if (kind == "powershell") {
            var present = await AdJson.ReadAsync(db,"with short_events as (" + EventReadService.ShortSource("$4") + ") " + """
                select exists(select 1 from short_events e
                join servers s on s.id=e.server_id and s.domain_id=e.domain_id and s.role='domain_controller'
                where e.domain_id=$1 and e.event_id in (4103,4104) and e.channel=$2 and e.provider_name=$3) as present
                """, ct,domain,PowerChannel,PowerProvider,EventReadService.ShortBoundary(config));
            return present[0]["present"]!.GetValue<bool>();
        }
        string sql = PresenceSql(kind,config);
        var rows = await AdJson.ReadAsync(db,sql,ct,domain,selected??DiscoveryEventIds(kind),"Security",SecurityProvider);
        return rows[0]["present"]!.GetValue<bool>();
    }
    public async Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var readOnly = new NpgsqlCommand("set transaction read only", db, tx)) await readOnly.ExecuteNonQueryAsync(ct);
        if (request.Kind == "security")
        {
            var result = await AdSecurity.ReadAsync(db, request, ct, details,config,logger);
            await tx.CommitAsync(ct); return result;
        }
        var p = request.Period!;
        if (request.Kind == "powershell") {
            var rows = await AdJson.ReadAsync(db,AdHistorySql.ShortPowerShellRows,ct,request.Domain,PowerChannel,PowerProvider,
                p.Start.UtcDateTime,p.End.UtcDateTime,request.Limit+1,EventReadService.ShortBoundary(config),sensitive);
            if (rows.Count > request.Limit) throw new AdInputException("dc_powershell_activity_input_bound_exceeded");
            bool present = await Presence(db,request.Kind,request.Domain,ct,config:config);
            var report = AdHistory.Compose(request.Kind,request.Domain,p,rows.Where(r => r["day"] is null).ToArray(),present,sensitive);
            report["daily_summaries"] = AdJson.Array(rows.Where(r => r["day"] is not null)
                .GroupBy(r => (Day:r.Text("day"),Computer:r.Text("domain_controller"),Actor:r.Text("actor")))
                .Select(g => new { day=g.Key.Day,computer=g.Key.Computer,user=g.Key.Actor,event_count=g.Sum(r => r.Int("event_count")) }));
            if (rows.Count > 0) report["state"] = "available";
            await tx.CommitAsync(ct); return report;
        }
        string sql = AdHistorySql.ChangeRows(request.Kind,config);
        object?[] args = [request.Domain, EventIds(request.Kind), "Security", SecurityProvider, p.Start.UtcDateTime, p.End.UtcDateTime, request.Limit + 1];
        var events = await AdJson.ReadAsync(db, sql, ct, args);
        if (events.Select(e => e.Int("event_db_id")).Distinct().Count() > request.Limit) throw new AdInputException(AdHistory.Prefix(request.Kind) + "_input_bound_exceeded");
        bool history = await Presence(db, request.Kind, request.Domain, ct,config:config);
        var payload = AdHistory.Compose(request.Kind, request.Domain, p, events, history, sensitive);
        await tx.CommitAsync(ct); return payload;
    }
}

