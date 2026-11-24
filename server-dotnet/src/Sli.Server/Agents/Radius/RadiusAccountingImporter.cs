using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Radius;

// Supplied by the trusted server configuration, never by a packet.
public sealed record RadiusImportBinding(string EvidenceRoot,string SourceName)
{
    internal RadiusAccountingMode? AccountingMode { get; init; }
}
public sealed record RadiusAcquisitionReceipt(string Status,long CursorRevisionBefore,long CursorRevisionAfter,
    int EvidenceRows,int ObservationRows,int OutboxRows,int ClassCacheRows,bool RotationFromEof);
public sealed class RadiusImportPending(string code) : Exception(code) { public string Code { get; }=code; }

// Dedicated accounting worker path, caller owns transaction and commits inbox with sink.
public static class RadiusAccountingImporter
{
    private const string Module="sli.radius-accounting";
    private const string Runtime="sli.radius-accounting-runtime.v1";
    private static string Text(JsonNode? n)=>JsonRead.TryString(n,out var s)?s:throw new InvalidDataException();
    private static string Hash(string s)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    private static async Task<int> Sql(NpgsqlConnection db,NpgsqlTransaction tx,string sql,CancellationToken ct,params (string Key,object? Value,NpgsqlDbType Type)[] values)
    {
        await using var cmd=new NpgsqlCommand(sql,db,tx);foreach(var (key,value,type) in values) cmd.Parameters.AddWithValue(key,type,value ?? DBNull.Value);return await cmd.ExecuteNonQueryAsync(ct);
    }
    public static string WorkerConnectionString(string workerDsn)
    {
        if(string.IsNullOrWhiteSpace(workerDsn)) throw new ArgumentException("agent_nps_worker_not_configured");
        return new NpgsqlConnectionStringBuilder(workerDsn) {
            Timeout=5,CommandTimeout=30,Pooling=false,Multiplexing=false,
            Options="-c statement_timeout=30000 -c lock_timeout=2000"
        }.ConnectionString;
    }
    public static async Task<int> RunOnceFromDsnAsync(string workerDsn,RadiusImportBinding binding,int limit,CancellationToken ct)
        => await RunFromDsnAsync(workerDsn,binding,limit,true,ct);
    // The common post-collection host retains its source lock while this dedicated
    // worker identity imports accounting. Never reuse the host/web DB identity.
    public static async Task<int> RunUnderPostCollectionLockAsync(NpgsqlConnection host,string workerDsn,RadiusImportBinding binding,int limit,CancellationToken ct)
    {
        await using var proof=new NpgsqlCommand("""
            select exists(select 1 from pg_locks where locktype='advisory' and pid=pg_backend_pid() and granted
                and classid::bigint=((hashtext('ad_log_reports_runtime_post_collection_process')::bigint>>32)&4294967295)
                and objid::bigint=(hashtext('ad_log_reports_runtime_post_collection_process')::bigint&4294967295) and objsubid=1)
            """,host);
        if(await proof.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("agent_import_lock_unavailable");
        return await RunFromDsnAsync(workerDsn,binding,limit,false,ct);
    }
    private static async Task<int> RunFromDsnAsync(string workerDsn,RadiusImportBinding binding,int limit,bool takeLock,CancellationToken ct)
    {
        try {
            await using var db=new NpgsqlConnection(WorkerConnectionString(workerDsn));await db.OpenAsync(ct);
            await using(var cmd=new NpgsqlCommand("set role adlog_nps_agent_import_worker",db)) await cmd.ExecuteNonQueryAsync(ct);
            if(takeLock) await using(var lockCommand=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))
                if(await lockCommand.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("agent_import_lock_unavailable");
            try {
                using var admission=AgentAssignmentPluginAdmission.Enter("sli.remote-access",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
                return await RunOnceAsync(db,binding,limit,ct);
            }
            finally {
                if(takeLock) {await using var unlock=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db);
                await unlock.ExecuteScalarAsync(CancellationToken.None);}
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { throw new InvalidOperationException("agent_radius_import_failed"); }
    }
    // The caller supplies a dedicated SLI_NPS_AGENT_WORKER_DSN session already set
    // to the source worker role. Never fall back to a web/admin connection.
    public static async Task<int> RunOnceAsync(NpgsqlConnection db,RadiusImportBinding binding,int limit,CancellationToken ct)
    {
        try { await using var tx=await db.BeginTransactionAsync(ct);int imported=await ConsumeAsync(db,tx,binding,limit,ct);await tx.CommitAsync(ct);return imported; }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { throw new InvalidOperationException("agent_radius_import_failed"); }
    }
    public static async Task<int> ConsumeAsync(NpgsqlConnection db,NpgsqlTransaction tx,RadiusImportBinding binding,int limit,CancellationToken ct)
    {
        if(limit is <1 or >128) throw new ArgumentOutOfRangeException(nameof(limit));
        if(!Path.IsPathFullyQualified(binding.EvidenceRoot) || string.IsNullOrWhiteSpace(binding.SourceName)) throw new ArgumentException("radius_binding_invalid");
        await using(var role=new NpgsqlCommand("select current_role",db,tx)) if((string?)await role.ExecuteScalarAsync(ct)!="adlog_nps_agent_import_worker") throw new InvalidOperationException("agent_nps_worker_role_unavailable");
        var rows=new List<(Guid Id,JsonObject Envelope,JsonObject Packet,JsonArray Rows)>();
        await using(var cmd=new NpgsqlCommand("""
            select packet_id,envelope::text,packet::text,event_rows::text from sli_agent_packet_inbox i
            where imported_at is null and module_disabled_at is null and envelope->>'module_id'='sli.radius-accounting'
              and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
            order by received_at,packet_id limit @limit for update skip locked
            """,db,tx)) { cmd.Parameters.AddWithValue("limit",limit);await using var reader=await cmd.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) rows.Add((reader.GetGuid(0),JsonNode.Parse(reader.GetString(1))!.AsObject(),JsonNode.Parse(reader.GetString(2))!.AsObject(),JsonNode.Parse(reader.GetString(3))!.AsArray())); }
        foreach(var row in rows) {
            await ImportAsync(db,tx,binding,row.Id,row.Envelope,row.Packet,row.Rows,ct);
            await Sql(db,tx,"update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet",ct,("packet",row.Id,NpgsqlDbType.Uuid));
        }
        return rows.Count;
    }
    internal static async Task ImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,RadiusImportBinding binding,Guid packetId,JsonObject envelopeJson,JsonObject packet,JsonArray rows,CancellationToken ct)
    {
        var envelope=Envelope.Parse(envelopeJson);Guid agent=Guid.Parse(envelope.AgentId);
        if(envelope.ModuleId!=Module || Guid.Parse(envelope.PacketId)!=packetId || rows.Count!=0) throw new RadiusImportPending("agent_packet_attestation_invalid");
        await using(var schema=new NpgsqlCommand("select to_regprocedure('public.lock_nps_import_agent_v304(uuid)') is not null",db,tx))
            if(await schema.ExecuteScalarAsync(ct) is not true) throw new RadiusImportPending("agent_import_schema_304_required");
        JsonArray assignments;
        await using(var cmd=new NpgsqlCommand("select status,assigned_modules::text from public.lock_nps_import_agent_v304(@id)",db,tx)) {
            cmd.Parameters.AddWithValue("id",agent);await using var r=await cmd.ExecuteReaderAsync(ct);
            if(!await r.ReadAsync(ct) || r.GetString(0)!="active") throw new RadiusImportPending("agent_disabled");assignments=JsonNode.Parse(r.GetString(1))!.AsArray();
        }
        var assignment=AgentPolicyAssignments.FindCurrent(assignments,Module) ?? throw new RadiusImportPending("agent_module_not_assigned");
        NpsPolicy policy;try { policy=NpsPolicy.Parse(Module,assignment["config"] as JsonObject ?? new JsonObject()); } catch(AgentException) { throw new RadiusImportPending("agent_module_not_assigned"); }
        if(envelope.SourceInstanceId!=policy.SourceId) throw new RadiusImportPending("agent_source_binding_changed");
        await using(var cmd=new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx)) {
            cmd.Parameters.AddWithValue("packet",packetId);cmd.Parameters.AddWithValue("agent",agent);cmd.Parameters.AddWithValue("module",Module);await using var r=await cmd.ExecuteReaderAsync(ct);
            if(!await r.ReadAsync(ct) || !PythonMetadataEquality.Equal(JsonNode.Parse(r.GetString(0)),envelopeJson) || r.GetString(1)!=Packets.Digest(envelopeJson) || envelope.PayloadSha256!=Packets.Digest(packet)) throw new RadiusImportPending("agent_packet_attestation_invalid");
        }
        await Sql(db,tx,"select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",ct);
        if(binding.AccountingMode is { } mode)
        {
            if(!mode.Matches(policy) || !await mode.RegisteredAsync(db,tx,true,ct))
                throw new RadiusImportPending("agent_source_binding_changed");
        }
        else
        {
            await using var cmd=new NpgsqlCommand("select installed,enabled from read_plugin_states_v1() where plugin_id='sli.remote-access'",db,tx);
            await using var r=await cmd.ExecuteReaderAsync(ct);
            if(!await r.ReadAsync(ct) || !r.GetBoolean(0) || !r.GetBoolean(1))
                throw new RadiusImportPending("agent_plugin_disabled");
        }
        CollectionPacket.Validate(packet);
        var header=packet["header"]!.AsObject();var bounds=header["cursor"]!.AsObject();var records=packet["records"]!.AsArray();
        if(records.Any(x=>Text(x!["format"])!="accounting_line")) throw new RadiusImportPending("agent_packet_attestation_invalid");
        await Sql(db,tx,"set local lock_timeout='5s'; set local statement_timeout='30s'; set local role adlog_radius_accounting_worker",ct);
        try {
            string subscription=policy.Text("subscription_id");RadiusCursor current;Guid epoch;long revision;
            await using(var cmd=new NpgsqlCommand("""
                select c.source_instance_id,c.stream_id,c.transport_binding,c.cursor_epoch,c.file_generation,c.byte_offset,c.last_record_sha256,c.revision,
                       s.desired_activation,sub.desired_activation
                from acquisition_consumer_subscriptions sub join acquisition_stream_cursors c
                  on c.source_instance_id=sub.source_instance_id and c.stream_id=sub.stream_id and c.transport_binding=sub.transport_binding
                join acquisition_source_instances s on s.source_instance_id=c.source_instance_id where sub.subscription_id=@subscription
                """,db,tx)) { cmd.Parameters.AddWithValue("subscription",subscription);await using var r=await cmd.ExecuteReaderAsync(ct);
                if(!await r.ReadAsync(ct)) throw new RadiusImportPending("subscription_not_found");
                if(r.GetString(8)!="manual_enabled" || r.GetString(9)!="manual_enabled") throw new RadiusImportPending("subscription_not_manually_enabled");
                current=new RadiusCursor(r.GetString(0),r.GetString(1),r.GetString(2),r.GetString(4),r.GetInt64(5),r.IsDBNull(6)?null:r.GetString(6));epoch=r.GetGuid(3);revision=r.GetInt64(7);
            }
            var initial=RadiusCursor.Parse(policy.Value["initial_cursor"]);
            if(current.SourceId!=initial.SourceId || current.StreamId!=initial.StreamId || current.TransportBinding!=initial.TransportBinding) throw new RadiusImportPending("agent_source_binding_changed");
            if(!PythonMetadataEquality.Equal(bounds["before"],current.ToJson())) throw new RadiusImportPending("agent_radius_cursor_conflict");
            string generation=Text(header["generation"]);long start=bounds["start_offset"]!.GetValue<long>(),end=bounds["end_offset"]!.GetValue<long>();bool rotation=generation!=current.FileGeneration;
            if(Text(header["source"])!=current.SourceId || Text(header["channel"])!=current.StreamId || start!=(rotation?0:current.ByteOffset) || end<start || rotation && packet["continuity"]!["previous_generation_eof"]!.GetValue<bool>()!=true) throw new RadiusImportPending("collection_packet_radius_mismatch");
            string[] lines=records.Select(x=>Text(x!["payload"])).ToArray();var context=packet["context"]!.AsObject();
            if(lines.Length==0) {
                if(context["empty_progress_v1"] is null) return;
                var proof=context["empty_progress_v1"]!.AsObject();long skipped=proof["skipped_bytes"]!.GetValue<long>(),physical=proof["physical_lines"]!.GetValue<long>();
                var after=RadiusCursor.Parse(JsonNode.Parse(envelope.CursorAfter.Token));
                if(after.SourceId!=current.SourceId || after.StreamId!=current.StreamId || after.TransportBinding!=current.TransportBinding || after.LastRecordSha256!=current.LastRecordSha256 || after.FileGeneration!=generation || after.ByteOffset!=end) throw new RadiusImportPending("empty_progress_invalid");
                if(skipped<0 || skipped>4*1024*1024 || physical<0 || physical>128 || physical>skipped || (skipped!=0)!=(physical!=0) || end-start!=skipped || skipped==0 && !rotation) throw new RadiusImportPending("empty_progress_invalid");
                await LockAndAdvance(db,tx,subscription,current,epoch,revision,generation,end,current.LastRecordSha256,rotation,ct);return;
            }
            await CommitRecordsWithReceiptAsync(db,tx,binding,subscription,current,epoch,revision,generation,start,end,rotation,lines,
                Text(context["source_timezone_id"]),context["source_utc_offset_minutes"]!.GetValue<int>(),AgentAdDcUtc.Parse(Text(header["observed_at_utc"])),ct,
                RadiusCursor.Parse(JsonNode.Parse(envelope.CursorAfter.Token)));
        }
        finally { await Sql(db,tx,"set local role adlog_nps_agent_import_worker",CancellationToken.None); }
    }
    // Shared transaction writer for attested agent packets and identity-scoped local acquisition.
    internal static async Task<int> CommitRecordsAsync(NpgsqlConnection db,NpgsqlTransaction tx,RadiusImportBinding binding,string subscription,
        RadiusCursor current,Guid epoch,long revision,string generation,long start,long end,bool rotation,string[] lines,
        string timezone,int offset,DateTimeOffset observed,CancellationToken ct)
        => (await CommitRecordsWithReceiptAsync(db,tx,binding,subscription,current,epoch,revision,generation,start,end,rotation,lines,timezone,offset,observed,ct)).ObservationRows;
    private static async Task<RadiusAcquisitionReceipt> CommitRecordsWithReceiptAsync(NpgsqlConnection db,NpgsqlTransaction tx,RadiusImportBinding binding,string subscription,
        RadiusCursor current,Guid epoch,long revision,string generation,long start,long end,bool rotation,string[] lines,
        string timezone,int offset,DateTimeOffset observed,CancellationToken ct,RadiusCursor? next=null)
    {
            var cache=new Dictionary<string,(string Principal,DateTimeOffset Expires)>(StringComparer.Ordinal);
            await using(var cmd=new NpgsqlCommand("select class_scope_sha256,exact_principal_key,expires_at_utc from radius_accounting_class_cache where source_instance_id=@source and expires_at_utc>now() order by class_scope_sha256",db,tx)) { cmd.Parameters.AddWithValue("source",current.SourceId);await using var r=await cmd.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct)) cache.Add(r.GetString(0),(r.GetString(1),new DateTimeOffset(r.GetDateTime(2),TimeSpan.Zero))); }
            string organization=binding.SourceName.Contains('.') ? binding.SourceName[(binding.SourceName.IndexOf('.')+1)..] : "";
            var plan=await RadiusPlanner.ProjectAsync(lines,current.SourceId,timezone,offset,observed,cache,dn=>RadiusIdentity.ResolveAsync(db,tx,dn,organization,ct));
            var evidence=RadiusEvidenceStore.PublishBatch(binding.EvidenceRoot,current,epoch,generation,plan,lines);
            next ??=current with { FileGeneration=generation,ByteOffset=end,LastRecordSha256=evidence[^1].Hash };
            ValidateBatch(current,next,rotation,plan,evidence);
            if(next.FileGeneration!=generation || next.ByteOffset!=end || next.LastRecordSha256!=evidence[^1].Hash) throw new RadiusImportPending("collection_packet_radius_mismatch");
            await LockAndCheck(db,tx,subscription,current,epoch,revision,ct);
            foreach(var (item,index) in evidence.Select((e,i)=>(e,i))) await Sql(db,tx,"""
                insert into core_evidence_manifests(evidence_uid,source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,cursor_start_byte_offset,batch_record_ordinal,canonical_record_sha256,object_reference,object_sha256,object_size_bytes,verified_at_utc)
                values(@id,@source,@stream,@binding,@epoch,@generation,@offset,@ordinal,@hash,@reference,@hash,@size,@verified)
                """,ct,("id",item.Id,NpgsqlDbType.Uuid),("source",current.SourceId,NpgsqlDbType.Text),("stream",current.StreamId,NpgsqlDbType.Text),("binding",current.TransportBinding,NpgsqlDbType.Text),("epoch",epoch,NpgsqlDbType.Uuid),("generation",generation,NpgsqlDbType.Text),("offset",start,NpgsqlDbType.Bigint),("ordinal",index,NpgsqlDbType.Integer),("hash",item.Hash,NpgsqlDbType.Text),("reference",item.Reference,NpgsqlDbType.Text),("size",checked((int)item.Size),NpgsqlDbType.Integer),("verified",item.VerifiedAt.UtcDateTime,NpgsqlDbType.TimestampTz));
            var byHash=evidence.GroupBy(x=>x.Hash).ToDictionary(x=>x.Key,x=>new Queue<RadiusEvidence>(x),StringComparer.Ordinal);
            foreach(var item in plan.Observations) {
                var ev=byHash[item.RecordHash].Dequeue();Guid observationId=RadiusEvidenceStore.Uuid5(ev.Id,"sli.radius-accounting-session-observation.v1");
                var provenance=new JsonObject { ["adapter_contract_id"]="radius-accounting-database-compatible-v1",["postgres_contract_id"]="sli.radius-accounting-postgres.v1",["runtime_contract_id"]=Runtime,["source_instance_id"]=current.SourceId,["canonical_record_sha256"]=item.RecordHash };
                await Sql(db,tx,"""
                    insert into radius_accounting_session_observations(observation_id,evidence_uid,lifecycle_event,session_identity_key,exact_principal_key,identity_state,observed_at_utc,timestamp_basis,timestamp_state,session_confirmed_by_accounting,producer_contract_id,resource_groups,row_sensitivity,field_categories,evidence_access_requirement,label_policy_version,provenance_json)
                    values(@id,@evidence,@lifecycle,@session,@principal,@identity,@observed,'record_date_time_plus_observed_source_timezone','ready',true,'radius-accounting-database-compatible-v1',array['vpn.sessions'],'restricted',array['identity','authentication','network'],'vpn.session.evidence.read','sli.access-labels.v1',@provenance)
                    """,ct,("id",observationId,NpgsqlDbType.Uuid),("evidence",ev.Id,NpgsqlDbType.Uuid),("lifecycle",item.Lifecycle,NpgsqlDbType.Text),("session",item.SessionIdentityKey,NpgsqlDbType.Text),("principal",item.Principal,NpgsqlDbType.Text),("identity",item.Principal is null?"unresolved":"exact",NpgsqlDbType.Text),("observed",item.ObservedAt.UtcDateTime,NpgsqlDbType.TimestampTz),("provenance",CanonicalJson.Serialize(provenance),NpgsqlDbType.Jsonb));
                string key=Hash($"{subscription}\0{observationId:D}\0{Runtime}");
                await Sql(db,tx,"insert into acquisition_delivery_outbox(subscription_id,evidence_uid,observation_id,idempotency_key) values(@subscription,@evidence,@observation,@key)",ct,("subscription",subscription,NpgsqlDbType.Text),("evidence",ev.Id,NpgsqlDbType.Uuid),("observation",observationId,NpgsqlDbType.Uuid),("key",key,NpgsqlDbType.Text));
            }
            await Sql(db,tx,"delete from radius_accounting_class_cache where source_instance_id=@source and expires_at_utc<=now()",ct,("source",current.SourceId,NpgsqlDbType.Text));
            foreach(var (key,entry) in plan.Cache) await Sql(db,tx,"""
                insert into radius_accounting_class_cache(source_instance_id,class_scope_sha256,exact_principal_key,expires_at_utc) values(@source,@key,@principal,@expires)
                on conflict(source_instance_id,class_scope_sha256) do update set exact_principal_key=excluded.exact_principal_key,expires_at_utc=excluded.expires_at_utc,updated_at=now()
                """,ct,("source",current.SourceId,NpgsqlDbType.Text),("key",key,NpgsqlDbType.Text),("principal",entry.Principal,NpgsqlDbType.Text),("expires",entry.Expires.UtcDateTime,NpgsqlDbType.TimestampTz));
            await Advance(db,tx,current,epoch,revision,generation,end,evidence[^1].Hash,rotation,ct);
        return new("committed",revision,revision+1,evidence.Count,plan.Observations.Count,plan.Observations.Count,plan.Cache.Count,rotation);
    }
    // Local acquisition uses the same evidence, cache, outbox and CAS write path as admitted agent packets.
    // An empty wire packet is not proof of physical progress and must not open a transaction.
    public static async Task<RadiusAcquisitionReceipt> ImportAcquisitionPacketAsync(NpgsqlConnection db,JsonObject packet,
        RadiusCursor current,Guid epoch,long revision,string subscription,RadiusImportBinding binding,CancellationToken ct)
    {
        CollectionPacket.Validate(packet);
        var header=packet["header"]!.AsObject();var bounds=header["cursor"]!.AsObject();var records=packet["records"]!.AsArray();
        if(!PythonMetadataEquality.Equal(bounds["before"],current.ToJson()) || Text(header["source"])!=current.SourceId
            || Text(header["channel"])!=current.StreamId || records.Any(r=>Text(r!["format"])!="accounting_line"))
            throw new RadiusImportPending("collection_packet_radius_mismatch");
        if(records.Count==0) return new("no_new_complete_records",revision,revision,0,0,0,0,false);
        string generation=Text(header["generation"]);long start=bounds["start_offset"]!.GetValue<long>(),end=bounds["end_offset"]!.GetValue<long>();
        bool rotation=generation!=current.FileGeneration;
        if(start!=(rotation?0:current.ByteOffset) || end<start || rotation && packet["continuity"]!["previous_generation_eof"]?.GetValue<bool>()!=true)
            throw new RadiusImportPending("collection_packet_radius_mismatch");
        await using var tx=await db.BeginTransactionAsync(ct);
        await Sql(db,tx,"set local role adlog_radius_accounting_worker",ct);
        var result=await ImportRecordsAsync(db,tx,binding,packet,current,epoch,revision,subscription,ct);
        await tx.CommitAsync(ct);return result;
    }
    private static async Task<RadiusAcquisitionReceipt> ImportRecordsAsync(NpgsqlConnection db,NpgsqlTransaction tx,RadiusImportBinding binding,
        JsonObject packet,RadiusCursor current,Guid epoch,long revision,string subscription,CancellationToken ct)
    {
        var header=packet["header"]!.AsObject();var context=packet["context"]!.AsObject();
        string generation=Text(header["generation"]);long end=header["cursor"]!["end_offset"]!.GetValue<long>();bool rotation=generation!=current.FileGeneration;
        string[] lines=packet["records"]!.AsArray().Select(r=>Text(r!["payload"])).ToArray();
        long start=header["cursor"]!["start_offset"]!.GetValue<long>();
        return await CommitRecordsWithReceiptAsync(db,tx,binding,subscription,current,epoch,revision,generation,start,end,rotation,lines,
            Text(context["source_timezone_id"]),context["source_utc_offset_minutes"]!.GetValue<int>(),AgentAdDcUtc.Parse(Text(header["observed_at_utc"])),ct);
    }
    // Source: accounting_postgres.py::_validate_batch. Validate before any DB sink
    // writes; publication can leave immutable orphan objects for an idempotent retry.
    internal static void ValidateBatch(RadiusCursor current,RadiusCursor next,bool rotationFromEof,RadiusPlan plan,IReadOnlyList<RadiusEvidence> evidence)
    {
        if(next.SourceId!=current.SourceId || next.StreamId!=current.StreamId || next.TransportBinding!=current.TransportBinding) throw new RadiusImportPending("cursor_owner_changed_in_batch");
        bool rotation=next.FileGeneration!=current.FileGeneration;
        if(rotationFromEof!=rotation) throw new RadiusImportPending("rotation_claim_mismatch");
        if(!rotation && next.ByteOffset<current.ByteOffset) throw new RadiusImportPending("cursor_offset_regressed");
        if(evidence.Count==0) throw new RadiusImportPending("evidence_batch_size_invalid");
        if(evidence.Count!=plan.EvidenceHashes.Count) throw new RadiusImportPending("evidence_count_mismatch");
        var seen=new HashSet<Guid>();
        for(int i=0;i<evidence.Count;i++) {
            var item=evidence[i];
            if(!seen.Add(item.Id)) throw new RadiusImportPending("evidence_uid_duplicate");
            if(!Regex.IsMatch(item.Hash,@"\A[0-9a-f]{64}\z") || item.Hash!=plan.EvidenceHashes[i]) throw new RadiusImportPending("evidence_hash_mismatch");
            if(!Regex.IsMatch(item.Reference,@"\Aevidence:[A-Za-z0-9_.:-]{1,500}\z")) throw new RadiusImportPending("evidence_reference_invalid");
            if(item.Size is <1 or >65536) throw new RadiusImportPending("evidence_object_size_invalid");
        }
    }
    private static async Task LockAndCheck(NpgsqlConnection db,NpgsqlTransaction tx,string subscription,RadiusCursor current,Guid epoch,long revision,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("""
            select c.cursor_epoch,c.file_generation,c.byte_offset,c.last_record_sha256,c.revision,s.desired_activation,sub.desired_activation
            from acquisition_consumer_subscriptions sub join acquisition_stream_cursors c on c.source_instance_id=sub.source_instance_id and c.stream_id=sub.stream_id and c.transport_binding=sub.transport_binding
            join acquisition_source_instances s on s.source_instance_id=c.source_instance_id
            where sub.subscription_id=@subscription and c.source_instance_id=@source and c.stream_id=@stream and c.transport_binding=@binding for update of c
            """,db,tx);
        cmd.Parameters.AddWithValue("subscription",subscription);cmd.Parameters.AddWithValue("source",current.SourceId);cmd.Parameters.AddWithValue("stream",current.StreamId);cmd.Parameters.AddWithValue("binding",current.TransportBinding);
        await using var r=await cmd.ExecuteReaderAsync(ct);
        if(!await r.ReadAsync(ct) || r.GetGuid(0)!=epoch || r.GetString(1)!=current.FileGeneration || r.GetInt64(2)!=current.ByteOffset || (r.IsDBNull(3)?null:r.GetString(3))!=current.LastRecordSha256 || r.GetInt64(4)!=revision || r.GetString(5)!="manual_enabled" || r.GetString(6)!="manual_enabled") throw new RadiusImportPending("agent_radius_cursor_conflict");
    }
    internal static async Task LockAndAdvance(NpgsqlConnection db,NpgsqlTransaction tx,string subscription,RadiusCursor current,Guid epoch,long revision,string generation,long end,string? last,bool rotation,CancellationToken ct)
    { await LockAndCheck(db,tx,subscription,current,epoch,revision,ct);await Advance(db,tx,current,epoch,revision,generation,end,last,rotation,ct); }
    private static async Task Advance(NpgsqlConnection db,NpgsqlTransaction tx,RadiusCursor current,Guid epoch,long revision,string generation,long end,string? last,bool rotation,CancellationToken ct)
    {
        int count=await Sql(db,tx,"""
            update acquisition_stream_cursors set file_generation=@generation,byte_offset=@end,last_record_sha256=@last,
                previous_file_generation=case when @rotation then @oldgen else previous_file_generation end,
                previous_generation_last_record_sha256=case when @rotation then @oldhash else previous_generation_last_record_sha256 end,revision=revision+1,updated_at=now()
            where source_instance_id=@source and stream_id=@stream and transport_binding=@binding and cursor_epoch=@epoch and revision=@revision
                and file_generation=@oldgen and byte_offset=@oldoffset and last_record_sha256 is not distinct from @oldhash
            """,ct,("generation",generation,NpgsqlDbType.Text),("end",end,NpgsqlDbType.Bigint),("last",last,NpgsqlDbType.Text),("rotation",rotation,NpgsqlDbType.Boolean),("oldgen",current.FileGeneration,NpgsqlDbType.Text),("oldhash",current.LastRecordSha256,NpgsqlDbType.Text),("source",current.SourceId,NpgsqlDbType.Text),("stream",current.StreamId,NpgsqlDbType.Text),("binding",current.TransportBinding,NpgsqlDbType.Text),("epoch",epoch,NpgsqlDbType.Uuid),("revision",revision,NpgsqlDbType.Bigint),("oldoffset",current.ByteOffset,NpgsqlDbType.Bigint));
        if(count!=1) throw new RadiusImportPending("cursor_compare_and_swap_failed");
    }
}
