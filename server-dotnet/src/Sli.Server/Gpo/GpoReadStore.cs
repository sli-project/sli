using System.Text.Json;
using System.Text.Json.Nodes;
using System.Runtime.CompilerServices;
using Npgsql;
using NpgsqlTypes;
using Sli.Gpo.SnapshotModel;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal sealed class GpoReadStore(IPostgresConnectionFactory connections,IConfiguration config) : IGpoReadStore, IGpoSnapshotReadStore
{
    public async Task<JsonObject> PairAsync(long[]? domains,CancellationToken ct)
    {
        await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using(var limits=new NpgsqlCommand("set transaction read only",db,tx) { CommandTimeout = 0 }) await limits.ExecuteNonQueryAsync(ct);
        await using var cmd=new NpgsqlCommand("""
            with newest as (
                select domain_id from gpo_report_v2_source_snapshots
                where (@domains::bigint[] is null or domain_id=any(@domains)) and import_status='completed'
                  and schema_version='sli.ad-gpo.snapshot/1.0'
                order by source_completed_at_utc desc, source_run_id desc limit 1
            )
            select snapshot.payload_json,snapshot.payload_sha256,snapshot.domain_id,snapshot.source_run_id,snapshot.source_observed_at_utc
            from gpo_report_v2_source_snapshots snapshot
            join newest on newest.domain_id=snapshot.domain_id
            where snapshot.import_status='completed' and snapshot.schema_version='sli.ad-gpo.snapshot/1.0'
            order by snapshot.source_completed_at_utc desc, snapshot.source_run_id desc limit 2
            """,db,tx) { CommandTimeout = 0 };BindDomains(cmd,domains);var snapshots=new List<JsonObject>();long? domain=null,previousDomain=null;
        string? snapshotId = null, observedAt = null;
        await using(var reader=await cmd.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct))
        {
            if (snapshots.Count == 0)
            {
                domain = reader.GetInt64(2);
                snapshotId = reader.GetGuid(3).ToString("D");
                observedAt = Iso(reader.GetFieldValue<DateTimeOffset>(4));
            }
            else previousDomain = reader.GetInt64(2);
            snapshots.Add(ValidateSnapshot(reader.GetString(0),reader.IsDBNull(1)?null:(byte[])reader.GetValue(1)));
        }
        await tx.CommitAsync(ct);return new JsonObject { ["state"]=snapshots.Count==0?"not_collected":snapshots.Count==1?"partial":"available",["current"]=snapshots.FirstOrDefault(),["previous"]=snapshots.Skip(1).FirstOrDefault(),["domain_id"]=domain,["previous_domain_id"]=previousDomain,["snapshot_id"]=snapshotId,["observed_at_utc"]=observedAt };
    }
    internal static JsonObject ValidateSnapshot(string json,byte[]? hash)
    {
        try
        {
            using var document=JsonDocument.Parse(json);GpoSnapshotValidator.Validate(document.RootElement);
            if(hash is not null&&!GpoSnapshotDocument.CanonicalSha256(document.RootElement).AsSpan().SequenceEqual(hash)) throw new GpoSourceException();
            return JsonNode.Parse(json)!.AsObject();
        }
        catch(Exception e) when(e is JsonException or InvalidDataException or ArgumentException or InvalidOperationException) { throw new GpoSourceException(); }
    }
    internal static void BindDomains(NpgsqlCommand cmd,long[]? domains)=>cmd.Parameters.AddWithValue("domains",NpgsqlDbType.Array|NpgsqlDbType.Bigint,domains is null?DBNull.Value:domains);

    public async Task<GpoPolicySnapshot?> ExactSnapshotAsync(long domain, Guid snapshot, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            select source_observed_at_utc, payload_json, payload_sha256
            from gpo_report_v2_source_snapshots
            where domain_id = @domain and source_run_id = @snapshot and import_status = 'completed'
              and collection_status <> 'failed'
              and schema_version = 'sli.ad-gpo.snapshot/1.0'
              and payload_json->>'collection_status' = collection_status
              and jsonb_array_length(payload_json->'settings') = setting_count
            """, db) { CommandTimeout = 0 };
        cmd.Parameters.AddWithValue("domain", domain);
        cmd.Parameters.AddWithValue("snapshot", snapshot);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        if (reader.IsDBNull(2)) throw new GpoSourceException();
        return new(snapshot, reader.GetFieldValue<DateTimeOffset>(0), ValidateSnapshot(reader.GetString(1), reader.GetFieldValue<byte[]>(2)));
    }

    public async IAsyncEnumerable<GpoPolicySnapshot> PolicySnapshotsAsync(long domain, string policyId,
        (Guid Before, Guid After)? comparison, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            select source_run_id, source_observed_at_utc,
                case when @runs is not null then payload_json else jsonb_build_object(
                    'gpos', jsonb_build_array((
                        select jsonb_build_object('id', policy->'id', 'computer', policy->'computer', 'user', policy->'user')
                        from jsonb_array_elements(payload_json->'gpos') as policy
                        where policy->>'id' = @policy_id
                    )),
                    'settings', coalesce((
                        select jsonb_agg(setting order by ordinal)
                        from jsonb_array_elements(payload_json->'settings') with ordinality as entries(setting, ordinal)
                        where setting->>'gpo_id' = @policy_id
                    ), '[]'::jsonb)
                ) end,
                case when @runs is not null then payload_sha256 end
            from gpo_report_v2_source_snapshots
            where domain_id = @domain and import_status = 'completed' and collection_status <> 'failed'
              and schema_version = 'sli.ad-gpo.snapshot/1.0'
              and (@runs is null or source_run_id = any(@runs))
              and payload_json->>'collection_status' = collection_status
              and jsonb_array_length(payload_json->'settings') = setting_count
              and payload_json @> @policy
            order by source_observed_at_utc desc, snapshot_id desc
            """, db) { CommandTimeout = 0 };
        cmd.Parameters.AddWithValue("domain", domain);
        cmd.Parameters.AddWithValue("policy_id", policyId);
        cmd.Parameters.AddWithValue("runs", NpgsqlDbType.Array | NpgsqlDbType.Uuid,
            comparison is { } pair ? new[] { pair.Before, pair.After } : DBNull.Value);
        cmd.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, JsonSerializer.Serialize(new
        {
            gpos = new[] { new { id = policyId, source_states = new { report = new { status = "observed" } } } },
        }));

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var payload = comparison is null ? JsonNode.Parse(reader.GetString(2))!.AsObject()
                : ValidateSnapshot(reader.GetString(2), reader.GetFieldValue<byte[]>(3));
            yield return new(reader.GetGuid(0), reader.GetFieldValue<DateTimeOffset>(1), payload);
        }
    }

    public async Task<JsonObject> GraphAsync(JsonObject snapshot,long[]? domains,CancellationToken ct)
    {
        if(domains is {Length:0}) throw new UnauthorizedAccessException("gpo_domain_scope_required");
        var absent=new JsonObject { ["state"]="not_collected",["entities"]=new JsonArray(),["relations"]=new JsonArray() };
        if(snapshot["domain"].Text("sid").Length==0||snapshot["domain"].Text("dns_name").Length==0||snapshot.Text("observed_at").Length==0) return absent;
        await using var db=await connections.OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using(var limits=new NpgsqlCommand("set transaction read only",db,tx) { CommandTimeout = 0 }) await limits.ExecuteNonQueryAsync(ct);
        JsonObject? source;
        await using(var cmd=new NpgsqlCommand("""
            select jsonb_build_object('run_id',run.run_id::text,'domain_id',run.domain_id,'observed_at_utc',run.observed_at_utc,
              'section_status',section.status,'record_count',section.record_count,'scope_json',run.scope_json,'source_pack_version',run.source_pack_version)
            from ad_context_runs run join domains domain on domain.id=run.domain_id
            join ad_context_sections section on section.run_id=run.run_id
            where run.status='completed' and run.mode in ('full','reconcile') and section.section_name='directory_group_graph'
              and domain.domain_sid=@sid and lower(domain.fqdn)=lower(@dns) and run.observed_at_utc<=@observed
              and (@domains::bigint[] is null or run.domain_id=any(@domains))
            order by run.observed_at_utc desc,run.created_at desc,run.run_id desc limit 1
            """,db,tx) { CommandTimeout = 0 })
        {
            BindDomains(cmd,domains);cmd.Parameters.AddWithValue("sid",snapshot["domain"].Text("sid"));cmd.Parameters.AddWithValue("dns",snapshot["domain"].Text("dns_name"));cmd.Parameters.AddWithValue("observed",Stamp(snapshot.Text("observed_at")));
            source=await cmd.ExecuteScalarAsync(ct) is string json?JsonNode.Parse(json)!.AsObject():null;
        }
        if(source is null) return absent;source["observed_at_utc"]=Iso(Stamp(source.Text("observed_at_utc")));
        var entities=await Read("""
            select distinct version.attributes_json from ad_context_evidence evidence join ad_context_entity_versions version
              on version.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
              and version.source_section=evidence.locator_json->>'section' and version.valid_from_utc<=evidence.observed_at_utc
              and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
            join entities_v2 entity on entity.id=version.entity_id and entity.domain_id=@domain
            where evidence.source_run_id=@run and evidence.evidence_type='entity_observation'
              and evidence.locator_json->>'section' in ('directory_accounts','directory_group_graph')
            order by version.attributes_json limit 20001
            """);
        var relations=await Read("""
            select distinct version.attributes_json from ad_context_evidence evidence join ad_context_relation_versions version
              on version.relation_key=evidence.locator_json->>'record_key' and version.domain_id=@domain
              and version.source_section='directory_group_graph' and version.valid_from_utc<=evidence.observed_at_utc
              and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
            where evidence.source_run_id=@run and evidence.evidence_type='relation_observation'
              and evidence.locator_json->>'section'='directory_group_graph'
            order by version.attributes_json limit 50001
            """);
        bool truncated=entities.Count>20000||relations.Count>50000,missing=source.Number("record_count")>entities.Count(e=>e.Text("section")=="directory_group_graph")+relations.Count;
        await tx.CommitAsync(ct);
        return new JsonObject { ["state"]=source.Text("section_status")=="complete"&&!truncated&&!missing?"ok":"partial",["entities"]=Array(entities.Take(20000)),["relations"]=Array(relations.Take(50000)),["computers_collected"]=source["scope_json"].True("computer_membership_collected"),["source"]=source,["truncated"]=truncated,["missing_records"]=missing };
        async Task<List<JsonObject>> Read(string sql)
        {
            await using var cmd=new NpgsqlCommand(sql,db,tx) { CommandTimeout = 0 };cmd.Parameters.AddWithValue("domain",source.Number("domain_id"));cmd.Parameters.AddWithValue("run",Guid.Parse(source.Text("run_id")));await using var reader=await cmd.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();while(await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());return rows;
        }
    }
    public Task<JsonObject> HistoryAsync(long[]? domains,DateTimeOffset from,DateTimeOffset to,string query,CancellationToken ct)
        => ReadHistoryAsync(domains,from,to,query,null,null,ct);

    public Task<JsonObject> PolicyHistoryAsync(long[] domains,DateTimeOffset from,DateTimeOffset to,string policyId,string guid,CancellationToken ct)
        => ReadHistoryAsync(domains,from,to,"",policyId,guid,ct);

    async Task<JsonObject> ReadHistoryAsync(long[]? domains,DateTimeOffset from,DateTimeOffset to,string query,string? policyId,string? guid,CancellationToken ct)
    {
        var unavailable=new JsonObject { ["state"]="unavailable",["items"]=new JsonArray(),["coverage"]=new JsonObject { ["state"]="unavailable" },["truncated"]=false };
        if(domains is {Length:0}) return unavailable;
        try
        {
            var confirmations=new List<JsonObject>();int days;
            await using(var db=await connections.OpenAsync(ct))
            {
                await using var tx=await db.BeginTransactionAsync(ct);await using(var limits=new NpgsqlCommand("set transaction read only",db,tx) { CommandTimeout = 0 }) await limits.ExecuteNonQueryAsync(ct);
                await using(var setting=new NpgsqlCommand("select value from platform_settings where key='ad.snapshot_history_days'",db,tx) { CommandTimeout = 0 })
                {
                    string raw=(string?)await setting.ExecuteScalarAsync(ct)??config["Sli:Gpo:SnapshotHistoryDays"]??Environment.GetEnvironmentVariable("SLI_AD_SNAPSHOT_HISTORY_DAYS")??"365";
                    if(!int.TryParse(raw,out days)||days is <7 or >3650) throw new InvalidDataException();
                }
                if(domains is null)
                {
                    await using var select=new NpgsqlCommand("select distinct domain_id from ad_snapshot_history_confirmations",db,tx) { CommandTimeout = 0 };await using var reader=await select.ExecuteReaderAsync(ct);var ids=new List<long>();while(await reader.ReadAsync(ct)) ids.Add(reader.GetInt64(0));domains=ids.Order().ToArray();
                }
                if(domains.Length==0) return new JsonObject { ["state"]="not_collected",["items"]=new JsonArray(),["coverage"]=new JsonObject { ["state"]="not_collected",["reasons"]=new JsonArray("history_not_collected") },["truncated"]=false };
                var cutoff=DateTimeOffset.UtcNow.AddDays(-days);
                await using var command=new NpgsqlCommand("""
                    select jsonb_build_object('manifest_id',manifest_id::text,'previous_manifest_id',previous_manifest_id::text,'domain_id',domain_id,
                      'family',family,'batch_id',batch_id,'record_count',record_count,'records_sha256',records_sha256,'observed_at',observed_at,'coverage_state',coverage_state)
                    from ad_snapshot_history_confirmations where domain_id=any(@domains) and family='gpo_v2'
                      and observed_at>=@from and observed_at<=@to order by observed_at,manifest_id,family limit 50001
                    """,db,tx) { CommandTimeout = 0 };BindDomains(command,domains);command.Parameters.AddWithValue("from",(from>cutoff?from:cutoff).AddHours(-12));command.Parameters.AddWithValue("to",to.AddHours(12));
                await using(var reader=await command.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct)) confirmations.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());await tx.CommitAsync(ct);
            }
            if(confirmations.Count>50000) return new JsonObject { ["state"]="unavailable",["items"]=new JsonArray(),["coverage"]=new JsonObject { ["state"]="unavailable",["reason"]="confirmation_limit" },["truncated"]=false };
            await using var historyDb=await connections.OpenAsync(ct);
            return await GpoChangeHistory.ReadAsync(confirmations,domains,from,to,DateTimeOffset.UtcNow.AddDays(-days),days,query,
                (batch,domain,family,observed,token)=>SnapshotChangeStore.ReadAsync(historyDb,batch,domain,family,observed,token,includeValues:policyId is not null),ct,policyId,guid);
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { return unavailable; }
    }
}
