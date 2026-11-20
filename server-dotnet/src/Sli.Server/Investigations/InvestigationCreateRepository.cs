using System.Numerics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
namespace Sli.Server.Investigations;
public interface IInvestigationCreateRepository {Task<JsonObject> CreateAsync(InvestigationCreateInput input,string actor,CancellationToken ct);}
public sealed class InvestigationCreateRepository(IPostgresConnectionFactory connections):IInvestigationCreateRepository
{
    public async Task<JsonObject> CreateAsync(InvestigationCreateInput input,string actor,CancellationToken ct)
    {await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);return await InvestigationCreate.ExecuteAsync(new SqlTx(db,tx),input,actor,ct);}
    internal sealed class SqlTx(NpgsqlConnection db,NpgsqlTransaction tx):IInvestigationCreateTransaction
    {
        public async Task LockAsync(CancellationToken ct)
        {
            await using(var check=new NpgsqlCommand("show transaction_isolation",db,tx))
                if((string?)await check.ExecuteScalarAsync(ct)!="read committed")throw new InvestigationException("evidence_write_requires_read_committed","Investigation evidence writes require READ COMMITTED isolation");
            await using var cmd=new NpgsqlCommand("lock table investigation_events in row exclusive mode",db,tx);await cmd.ExecuteNonQueryAsync(ct);
        }
        public async Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct)
        {await using var cmd=new NpgsqlCommand("select exists(select 1 from storage_v2_event_identity_allocations where id=@event)",db,tx);cmd.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,id);return await cmd.ExecuteScalarAsync(ct) is true;}
        public async Task<long> InsertAsync(Guid publicId,string title,string? owner,string actor,CancellationToken ct)
        {
            await using var cmd=new NpgsqlCommand("insert into investigations(public_id,title,owner,created_by) values(@public,@title,@owner,@actor) returning id",db,tx);
            cmd.Parameters.AddWithValue("public",publicId);cmd.Parameters.AddWithValue("title",title);cmd.Parameters.AddWithValue("owner",NpgsqlDbType.Text,(object?)owner??DBNull.Value);cmd.Parameters.AddWithValue("actor",actor);
            return (long)(await cmd.ExecuteScalarAsync(ct)??throw new InvalidOperationException("case_insert_missing"));
        }
        public async Task CreatedAuditAsync(long id,string actor,CancellationToken ct)
        {await using var cmd=new NpgsqlCommand("insert into investigation_audit(investigation_id,action,actor) values(@id,'created',@actor)",db,tx);cmd.Parameters.AddWithValue("id",id);cmd.Parameters.AddWithValue("actor",actor);await cmd.ExecuteNonQueryAsync(ct);}
        public async Task LinkEventAsync(long id,BigInteger eventId,string actor,CancellationToken ct)
        {
            await using(var cmd=new NpgsqlCommand("insert into investigation_events(investigation_id,event_db_id,relation_status,added_by) values(@id,@event,'confirmed',@actor)",db,tx)){cmd.Parameters.AddWithValue("id",id);cmd.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,eventId);cmd.Parameters.AddWithValue("actor",actor);await cmd.ExecuteNonQueryAsync(ct);}
            await using var audit=new NpgsqlCommand("insert into investigation_audit(investigation_id,action,actor,payload) values(@id,'event_linked',@actor,jsonb_build_object('event_db_id',@event::bigint,'relation_status','confirmed'))",db,tx);
            audit.Parameters.AddWithValue("id",id);audit.Parameters.AddWithValue("event",NpgsqlDbType.Numeric,eventId);audit.Parameters.AddWithValue("actor",actor);await audit.ExecuteNonQueryAsync(ct);
        }
        public async Task<JsonObject> ReadAsync(long id,CancellationToken ct)
        {
            JsonObject row;
            await using(var cmd=new NpgsqlCommand("select row_to_json(c)::text from (select id,public_id,title,status,owner,created_by,created_at,updated_at,closed_at from investigations where id=@id) c",db,tx)) {
                cmd.Parameters.AddWithValue("id",id);var raw=(string?)await cmd.ExecuteScalarAsync(ct);row=JsonNode.Parse(raw??throw new InvalidOperationException("case_read_missing"))!.AsObject();
            }
            foreach(var (name,sql) in new[]{("events","select event_db_id,relation_status,added_by,added_at from investigation_events where investigation_id=@id order by added_at desc limit 500"),("evidence_refs","select evidence_kind,source_domain_id,reference_id,relation_status,added_by,added_at from investigation_evidence_refs where investigation_id=@id order by added_at desc,evidence_kind,reference_id limit 500"),("notes","select id,body,created_by,created_at from investigation_notes where investigation_id=@id order by created_at desc limit 100")}) {
                var rows=new JsonArray();await using var cmd=new NpgsqlCommand("select row_to_json(t)::text from ("+sql+") t",db,tx);cmd.Parameters.AddWithValue("id",id);
                await using var reader=await cmd.ExecuteReaderAsync(ct);while(await reader.ReadAsync(ct))rows.Add(JsonNode.Parse(reader.GetString(0)));row[name]=rows;
            }
            return row;
        }
        public Task CommitAsync(CancellationToken ct)=>tx.CommitAsync(ct);
    }
}
