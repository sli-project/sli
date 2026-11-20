using System.Numerics;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
namespace Sli.Server.Investigations;
public interface IInvestigationEventRepository
{
    Task<IReadOnlyList<AccessResource>> EventResourcesAsync(BigInteger eventId,CancellationToken ct);
    Task<InvestigationEventResult> AddAsync(InvestigationIdentity identity,InvestigationEventInput input,string actor,CancellationToken ct);
    Task RemoveAsync(InvestigationIdentity identity,BigInteger eventId,string actor,CancellationToken ct);
}
public sealed class InvestigationEventRepository(IPostgresConnectionFactory connections):IInvestigationEventRepository
{
    public async Task<IReadOnlyList<AccessResource>> EventResourcesAsync(BigInteger eventId,CancellationToken ct)
    {
        if(eventId<=0)throw new InvestigationException("event_not_found",$"Event {eventId} was not found",404);
        await using var db=await connections.OpenAsync(ct);
        await using var cmd=new NpgsqlCommand("select core.server_id,server.domain_id,channel.value from storage_v2_event_identity_allocations core join servers server on server.id=core.server_id join storage_v2_channel channel on channel.id=core.channel_id where core.id=@event",db);
        cmd.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,eventId);
        await using var r=await cmd.ExecuteReaderAsync(ct);
        if(!await r.ReadAsync(ct))throw new InvestigationException("event_not_found",$"Event {eventId} was not found",404);
        var result=new List<AccessResource>();if(!r.IsDBNull(0))result.Add(new("server",r.GetInt64(0)));if(!r.IsDBNull(1))result.Add(new("domain",r.GetInt64(1)));if(!r.IsDBNull(2) && r.GetString(2).Length>0)result.Add(new("channel",Value:r.GetString(2)));
        if(result.Count==0)throw new InvestigationException("unavailable","Event resource context is unavailable",503);
        return result;
    }
    public async Task<InvestigationEventResult> AddAsync(InvestigationIdentity identity,InvestigationEventInput input,string actor,CancellationToken ct)
    {await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);return await InvestigationEventMutation.AddAsync(new SqlTx(db,tx),identity,input,actor,ct);}
    public async Task RemoveAsync(InvestigationIdentity identity,BigInteger eventId,string actor,CancellationToken ct)
    {await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);await InvestigationEventMutation.RemoveAsync(new SqlTx(db,tx),identity,eventId,actor,ct);}
    internal sealed class SqlTx(NpgsqlConnection db,NpgsqlTransaction tx):IInvestigationEventTransaction
    {
        public async Task LockAsync(CancellationToken ct)
        {
            await using(var isolation=new NpgsqlCommand("show transaction_isolation",db,tx))
                if((string?)await isolation.ExecuteScalarAsync(ct)!="read committed")throw new InvestigationException("evidence_write_requires_read_committed","Investigation evidence writes require READ COMMITTED isolation");
            await using var cmd=new NpgsqlCommand("lock table investigation_events in row exclusive mode",db,tx);await cmd.ExecuteNonQueryAsync(ct);
        }
        public async Task<long> ReadCaseAsync(InvestigationIdentity identity,CancellationToken ct)
        {
            long id;
            await using(var cmd=new NpgsqlCommand($"select id,public_id,title,status,owner,created_by,created_at,updated_at,closed_at from investigations where {identity.Column}=@identity",db,tx)) {
                if(identity.Id is {} n)cmd.Parameters.AddWithValue("identity",NpgsqlDbType.Numeric,n);else cmd.Parameters.AddWithValue("identity",NpgsqlDbType.Uuid,identity.PublicId!.Value);
                await using var reader=await cmd.ExecuteReaderAsync(ct);if(!await reader.ReadAsync(ct))throw new InvestigationException("not_found",$"Investigation {identity.Display} was not found",404);id=reader.GetInt64(0);
            }
            foreach(string sql in new[]{"select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id order by added_at desc limit 500","select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id order by added_at desc,evidence_kind,reference_id limit 500","select id,body,created_by,created_at from investigation_notes where investigation_id=@id order by created_at desc limit 100"}) {
                await using var cmd=new NpgsqlCommand(sql,db,tx);cmd.Parameters.AddWithValue("id",id);await using var r=await cmd.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct)){}
            }
            return id;
        }
        public async Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct)
        {await using var cmd=new NpgsqlCommand("select exists(select 1 from storage_v2_event_identity_allocations where id=@event)",db,tx);cmd.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,id);return await cmd.ExecuteScalarAsync(ct) is true;}
        public async Task<InvestigationEventRow?> InsertAsync(long id,BigInteger ev,string relation,string actor,CancellationToken ct)
        {
            await using var cmd=new NpgsqlCommand("insert into investigation_events(investigation_id,event_db_id,relation_status,added_by) values(@id,@event,@relation,@actor) on conflict(investigation_id,event_db_id) do nothing returning event_db_id,relation_status,added_by,to_char(added_at,'YYYY-MM-DD HH24:MI:SS.US'),extract(timezone from added_at)::integer",db,tx);
            Parameters(cmd,id,ev);cmd.Parameters.AddWithValue("relation",relation);cmd.Parameters.AddWithValue("actor",actor);return await Row(cmd,ct);
        }
        public async Task<InvestigationEventRow?> ReadExistingAsync(long id,BigInteger ev,CancellationToken ct)
        {await using var cmd=new NpgsqlCommand("select event_db_id,relation_status,added_by,to_char(added_at,'YYYY-MM-DD HH24:MI:SS.US'),extract(timezone from added_at)::integer from investigation_events where investigation_id=@id and event_db_id=@event",db,tx);Parameters(cmd,id,ev);return await Row(cmd,ct);}
        private static async Task<InvestigationEventRow?> Row(NpgsqlCommand cmd,CancellationToken ct)
        {await using var r=await cmd.ExecuteReaderAsync(ct);return !await r.ReadAsync(ct)?null:new(r.GetInt64(0),r.GetString(1),r.GetString(2),InvestigationList.FormatSessionTimestamp(r.GetString(3),r.GetInt32(4)));}
        public async Task<bool> DeleteAsync(long id,BigInteger ev,CancellationToken ct)
        {await using var cmd=new NpgsqlCommand("delete from investigation_events where investigation_id=@id and event_db_id=@event returning event_db_id",db,tx);Parameters(cmd,id,ev);return await cmd.ExecuteScalarAsync(ct) is not null;}
        public async Task UpdateAndAuditAsync(long id,BigInteger ev,string? relation,string actor,CancellationToken ct)
        {
            await using(var cmd=new NpgsqlCommand("update investigations set updated_at=now() where id=@id",db,tx)){cmd.Parameters.AddWithValue("id",id);await cmd.ExecuteNonQueryAsync(ct);}
            string sql=relation is null?"insert into investigation_audit(investigation_id,action,actor,payload) values(@id,'event_unlinked',@actor,jsonb_build_object('event_db_id',@event::bigint))":"insert into investigation_audit(investigation_id,action,actor,payload) values(@id,'event_linked',@actor,jsonb_build_object('event_db_id',@event::bigint,'relation_status',@relation::text))";
            await using var audit=new NpgsqlCommand(sql,db,tx);Parameters(audit,id,ev);audit.Parameters.AddWithValue("actor",actor);if(relation is not null)audit.Parameters.AddWithValue("relation",relation);await audit.ExecuteNonQueryAsync(ct);
        }
        private static void Parameters(NpgsqlCommand cmd,long id,BigInteger ev){cmd.Parameters.AddWithValue("id",id);cmd.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,ev);}
        public Task CommitAsync(CancellationToken ct)=>tx.CommitAsync(ct);
    }
}
