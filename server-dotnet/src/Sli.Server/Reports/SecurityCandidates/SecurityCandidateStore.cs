using System.Data;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
namespace Sli.Server.Reports.SecurityCandidates;
internal sealed class SecurityCandidateStore(IPostgresConnectionFactory connections,IConfiguration? config=null):ISecurityCandidateStore
{
    private static readonly int[] SourceEventIds=[1102,4624,4625,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4740,4754,4755,4756,4757,4758,4764,4767,4771,4776,4781];
    public static IReadOnlyList<int> EventIds=>Array.AsReadOnly(SourceEventIds);
    internal static string CandidateSql => EntityShortSql.Cte("@boundary","@entity",daily:false) + """
        select e.id as event_db_id from short_events e
        join servers server on server.id=e.server_id and server.domain_id=e.domain_id
        where e.id>0 and e.domain_id=@domain and server.role='domain_controller'
          and e.event_id=any(@event_ids) and e.channel='Security'
          and ((e.event_id=1102 and e.provider_name='Microsoft-Windows-Eventlog')
            or (e.event_id<>1102 and e.provider_name='Microsoft-Windows-Security-Auditing'))
          and e.time_created_utc>=@start and e.time_created_utc<@end
        order by e.time_created_utc desc,e.id desc limit @count
        """;
    public async Task<EntityResource?> EntityAsync(long id,CancellationToken ct)
    {
        if(id<=0)throw new ArgumentOutOfRangeException(nameof(id));
        if(id>int.MaxValue)return null;
        await using var db=await connections.OpenAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var bound=new NpgsqlCommand("set local statement_timeout='3000ms'",db,tx)){await bound.ExecuteNonQueryAsync(ct);}
        EntityResource? result;
        await using(var cmd=new NpgsqlCommand("select entity.id,entity_type.value,entity.domain_id,entity.server_id from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id where entity.id=resolve_entity_identity_v2(@id) limit 1",db,tx){CommandTimeout=3}) {
            cmd.Parameters.AddWithValue("id",checked((int)id));await using var r=await cmd.ExecuteReaderAsync(ct);
            result=await r.ReadAsync(ct)?new(r.GetInt64(0),r.IsDBNull(2)?null:r.GetInt64(2),r.IsDBNull(3)?null:r.GetInt64(3)):null;
        }
        await tx.CommitAsync(ct);return result;
    }
    public async Task<IReadOnlyList<long>> CandidatesAsync(long id,long domain,DateTimeOffset start,DateTimeOffset end,int count,CancellationToken ct)
    {
        if(id<=0 || id>int.MaxValue || domain<=0 || count is <2 or >501 || start>=end || end-start>TimeSpan.FromDays(31))throw new ArgumentOutOfRangeException(nameof(id));
        await using var db=await connections.OpenAsync(ct);
        await using var tx=await db.BeginTransactionAsync(IsolationLevel.RepeatableRead,ct);
        await using(var mode=new NpgsqlCommand("set transaction read only",db,tx)){await mode.ExecuteNonQueryAsync(ct);}
        await using var cmd=new NpgsqlCommand(CandidateSql,db,tx);
        cmd.Parameters.AddWithValue("boundary",EventReadService.ShortBoundary(config).UtcDateTime);
        cmd.Parameters.AddWithValue("entity",checked((int)id));cmd.Parameters.AddWithValue("domain",domain);
        cmd.Parameters.AddWithValue("event_ids",NpgsqlDbType.Array|NpgsqlDbType.Integer,SourceEventIds);
        cmd.Parameters.AddWithValue("start",start.UtcDateTime);cmd.Parameters.AddWithValue("end",end.UtcDateTime);cmd.Parameters.AddWithValue("count",count);
        var rows=new List<long>();await using(var r=await cmd.ExecuteReaderAsync(ct)){while(await r.ReadAsync(ct))rows.Add(r.GetInt64(0));}
        await tx.CommitAsync(ct);return rows;
    }
}
internal static class SecurityCandidateRegistration
{
    public static IServiceCollection AddSecurityCandidates(this IServiceCollection services)
    {services.TryAddScoped<ISecurityCandidateStore,SecurityCandidateStore>();services.TryAddScoped<SecurityCandidateOwner>();return services;}
}
