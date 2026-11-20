using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Storage.Backfill;

// Uses existing migrations 009/010 and the same worker role as direct publication.
// Connections/transactions are owned here; the source, manifest and heartbeat use
// separate transactions so long IO cannot silently abandon an active lease.
internal sealed partial class StorageV2Postgres(NpgsqlDataSource worker)
{
    internal static async Task<T> RetryAsync<T>(Func<Task<T>> operation,Func<TimeSpan,Task> delay,CancellationToken ct)
    {
        int attempt=0;
        while(true) {
            ct.ThrowIfCancellationRequested();
            try{return await operation();}
            catch(PostgresException e)when(e.SqlState=="55P03") {await delay(TimeSpan.FromSeconds(Math.Min(.1*Math.Pow(2,attempt++),1)));}
        }
    }
    async Task<T> Run<T>(Func<NpgsqlConnection,NpgsqlTransaction,Task<T>> operation,CancellationToken ct)=>await RetryAsync(async()=>{
        await using var db=await worker.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await Execute(db,tx,"set local role adlog_storage_worker",ct);
        var role=await Query(db,tx,"select current_user as name",ct);
        if(role.Single()["name"]!.ToString()!="adlog_storage_worker")throw new InvalidOperationException("storage_v2_worker_role_required");
        var result=await operation(db,tx);await tx.CommitAsync(ct);return result;
    },duration=>Task.Delay(duration,ct),ct);
    internal static NpgsqlCommand Command(NpgsqlConnection db,NpgsqlTransaction tx,string sql,params (string Name,object? Value)[] values)
    {
        var command=new NpgsqlCommand(sql,db,tx){CommandTimeout=0};
        foreach(var (name,value) in values) {
            if(value is JsonNode json)command.Parameters.AddWithValue(name,NpgsqlDbType.Jsonb,json.ToJsonString());
            else if(value is null)command.Parameters.AddWithValue(name,NpgsqlDbType.Text,DBNull.Value);
            else command.Parameters.AddWithValue(name,value);
        }
        return command;
    }
    internal static async Task<List<JsonObject>> Query(NpgsqlConnection db,NpgsqlTransaction tx,string sql,CancellationToken ct,params (string Name,object? Value)[] values)
    {
        await using var command=Command(db,tx,sql,values);await using var reader=await command.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();
        while(await reader.ReadAsync(ct)) {
            var row=new JsonObject();for(int i=0;i<reader.FieldCount;i++)row[reader.GetName(i)]=reader.IsDBNull(i)?null:reader.GetValue(i) switch {
                byte[] bytes=>JsonValue.Create("\\x"+Convert.ToHexStringLower(bytes)),DateTime date=>JsonValue.Create(DirectEntityModel.Timestamp(date)),
                _=>System.Text.Json.JsonSerializer.SerializeToNode(reader.GetValue(i))};rows.Add(row);
        }
        return rows;
    }
    static async Task<int> Execute(NpgsqlConnection db,NpgsqlTransaction tx,string sql,CancellationToken ct,params (string Name,object? Value)[] values)
    {await using var command=Command(db,tx,sql,values);return await command.ExecuteNonQueryAsync(ct);}
    static JsonObject One(List<JsonObject> rows)=>rows.Count==1?rows[0]:throw new StorageV2LeaseLostException();
    static StorageV2Checkpoint Checkpoint(JsonObject row)=>new(row["worker_name"]!.ToString(),(long?)row["high_watermark_event_id"],(long)row["last_verified_event_id"]!,
        (int)row["chunk_size"]!,row["state"]!.ToString(),row["lease_token"] is {} token?Guid.Parse(token.ToString()):null,row["lease_until"] is {} until?DirectEventTime.Utc(until.ToString()):null);
    static StorageV2Outbox Outbox(JsonObject row)=>new((long)row["id"]!,Guid.Parse(row["batch_id"]!.ToString()),(long)row["first_event_id"]!,
        (long)row["last_event_id"]!,(int)row["event_count"]!,row["event_ids"]!.AsArray().Select(x=>(long)x!).ToArray(),Convert.FromHexString(row["identity_sha256"]!.ToString().Replace("\\x","",StringComparison.Ordinal)),
        row["state"]!.ToString(),(int)row["attempt_count"]!,DirectEventTime.Utc(row["available_at"]!.ToString()),row["lease_token"] is {} token?Guid.Parse(token.ToString()):null,
        row["lease_until"] is {} until?DirectEventTime.Utc(until.ToString()):null);
    public Task<StorageV2Checkpoint> AcquireAsync(string name,Guid token,int seconds,CancellationToken ct)=>Run(async(db,tx)=>{
        await Execute(db,tx,"insert into storage_v2_backfill_checkpoints(worker_name) values(@worker) on conflict(worker_name) do nothing",ct,("worker",name));
        return Checkpoint(One(await Query(db,tx,"""
            update storage_v2_backfill_checkpoints set state='running',lease_token=@token,lease_until=now()+(@seconds*interval '1 second'),last_error=null,updated_at=now()
            where worker_name=@worker and (lease_until is null or lease_until<=now() or lease_token=@token) returning *
            """,ct,("token",token),("seconds",seconds),("worker",name))));
    },ct);
    public Task<bool> RenewCheckpointAsync(string name,Guid token,int seconds,CancellationToken ct)=>Run(async(db,tx)=>
        (await Query(db,tx,"update storage_v2_backfill_checkpoints set lease_until=now()+(@seconds*interval '1 second'),updated_at=now() where worker_name=@worker and lease_token=@token and state='running' returning worker_name",ct,("worker",name),("token",token),("seconds",seconds))).Count==1,ct);
    public Task<StorageV2Checkpoint> WatermarkAsync(string name,Guid token,long max,CancellationToken ct)=>Run(async(db,tx)=>Checkpoint(One(await Query(db,tx,
        "update storage_v2_backfill_checkpoints set high_watermark_event_id=coalesce(high_watermark_event_id,@max),updated_at=now() where worker_name=@worker and lease_token=@token returning *",ct,("worker",name),("token",token),("max",max)))),ct);
    public Task<StorageV2Checkpoint> FinishAsync(string name,Guid token,string? error,CancellationToken ct)=>Run(async(db,tx)=>Checkpoint(One(await Query(db,tx,
        "update storage_v2_backfill_checkpoints set state=@state,lease_token=null,lease_until=null,last_error=@error,updated_at=now() where worker_name=@worker and lease_token=@token returning *",ct,
        ("worker",name),("token",token),("state",error is null?"completed":"failed"),("error",error is null?null:error[..Math.Min(2000,error.Length)])))),ct);
    public Task<StorageV2Outbox> EnqueueAsync(StorageV2Outbox item,CancellationToken ct)
    {
        StorageV2Outbox.Validate(item.First,item.Last,item.Count,item.EventIds);
        return Run(async(db,tx)=>{
            var row=Outbox(One(await Query(db,tx,"""
                insert into storage_v2_outbox(batch_id,first_event_id,last_event_id,event_count,event_ids,identity_sha256)
                values(@batch,@first,@last,@count,@ids,@hash) on conflict(batch_id) do update set batch_id=excluded.batch_id returning *
                """,ct,("batch",item.BatchId),("first",item.First),("last",item.Last),("count",item.Count),("ids",item.EventIds),("hash",item.IdentityHash))));
            if(!row.EventIds.SequenceEqual(item.EventIds)||!row.IdentityHash.AsSpan().SequenceEqual(item.IdentityHash))throw new InvalidDataException("outbox_identity_hash_mismatch");return row;
        },ct);
    }
    internal const string ClaimSql="""
        with candidate as (
            select id from storage_v2_outbox where (state in ('pending','failed') and available_at<=now())
                or (state='leased' and (lease_until is null or lease_until<=now()))
            order by id for update skip locked limit 1
        ) update storage_v2_outbox o set state='leased',attempt_count=attempt_count+1,lease_token=@token,
            lease_until=now()+(@seconds*interval '1 second') from candidate where o.id=candidate.id returning o.*
        """;
    public Task<StorageV2Outbox?> ClaimAsync(Guid token,int seconds,CancellationToken ct)=>Run(async(db,tx)=>{
        var rows=await Query(db,tx,ClaimSql,ct,("token",token),("seconds",seconds));return rows.Count==0?null:Outbox(One(rows));
    },ct);
    public Task<bool> RenewOutboxAsync(long id,Guid token,int seconds,CancellationToken ct)=>Run(async(db,tx)=>(await Query(db,tx,
        "update storage_v2_outbox set lease_until=now()+(@seconds*interval '1 second') where id=@id and lease_token=@token and state='leased' returning id",ct,("id",id),("token",token),("seconds",seconds))).Count==1,ct);
    public async Task FinishOutboxAsync(long id,Guid token,string? error,int retry,CancellationToken ct)=>_ = await Run(async(db,tx)=>One(await Query(db,tx,error is null?"""
        update storage_v2_outbox set state='completed',completed_at=now(),lease_token=null,lease_until=null,last_error=null
        where id=@id and (lease_token=@token or state='completed') returning id
        """:"""
        update storage_v2_outbox set state='failed',available_at=now()+(@retry*interval '1 second'),lease_token=null,lease_until=null,last_error=@error
        where id=@id and lease_token=@token returning id
        """,ct,("id",id),("token",token),("retry",retry),("error",error is null?null:error[..Math.Min(error.Length,2000)]))),ct);
    internal static async Task ResolveDictionaryAsync(string kind,IReadOnlyList<string> requested,Dictionary<(string,string),int> cache,
        Func<string,string[],Task<List<JsonObject>>> query)
    {
        string table=DictionaryTable(kind);
        var values=requested.Distinct().Where(value=>!cache.ContainsKey((kind,value))).Order(StringComparer.Ordinal).ToArray();
        if(values.Length==0)return;
        foreach(var row in await query($"select id,value from {table} where value=any(@values)",values))cache[(kind,row["value"]!.ToString())]=(int)row["id"]!;
        var missing=values.Where(value=>!cache.ContainsKey((kind,value))).ToArray();
        if(missing.Length==0)return;
        await query($"insert into {table}(value) select value from unnest(@values) w(value) order by value collate \"C\" on conflict(value) do nothing",missing);
        foreach(var row in await query($"select id,value from {table} where value=any(@values)",missing))cache[(kind,row["value"]!.ToString())]=(int)row["id"]!;
        if(values.Any(value=>!cache.ContainsKey((kind,value))))throw new InvalidOperationException("storage_v2_dictionary_unresolved");
    }
    internal static string DictionaryTable(string kind)=>kind switch{
        "provider"=>"storage_v2_provider","channel"=>"storage_v2_channel","computer"=>"storage_v2_computer","keywords"=>"storage_v2_keywords",
        "domain"=>"storage_v2_domain_name","role"=>"storage_v2_role","extracted_from"=>"storage_v2_extracted_from","entity_type"=>"storage_v2_entity_type",
        _=>throw new InvalidDataException("storage_v2_dictionary_kind_invalid")};
}
