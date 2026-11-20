using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Control;
using Sli.Server.Sources;
using Sli.Server.Agents.Registry;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Storage.Direct;

internal static class DirectAdDcPacket
{
    internal static async Task ImportAsync(NpgsqlConnection db, NpgsqlTransaction tx, NpgsqlDataSource worker,
        Guid packetId, JsonObject envelopeNode, JsonObject packet, JsonArray rows, string catalogPath, CancellationToken ct,
        Action<AdDcProjectionStep>? reportStep=null)
    {
        reportStep?.Invoke(AdDcProjectionStep.ImportQueueWait);
        using var queue = await new PostgresImportQueue().AcquireAsync(TextOrNull(packet["header"]?["source"]), ct);
        using var admission = AgentAssignmentPluginAdmission.Enter("sli.ad",
            Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        var batch=await PrepareImportAsync(db,tx,worker,packetId,envelopeNode,packet,rows,catalogPath,ct,reportStep);
        if(batch is null)return;
        await batch.WriteAsync(ct);
        await batch.FinalizeAsync(db,tx,ct);
    }
    internal static async Task<DirectAdDcBatch?> PrepareImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,NpgsqlDataSource worker,
        Guid packetId,JsonObject envelopeNode,JsonObject packet,JsonArray rows,string catalogPath,CancellationToken ct,
        Action<AdDcProjectionStep>? reportStep=null)
    {
        reportStep?.Invoke(AdDcProjectionStep.Authorization);
        var capability = await DirectRuntimeAuthorization.LoadAsync(db,tx,DateTime.UtcNow,ct)
            ?? throw new InvalidOperationException("agent_storage_unavailable");
        reportStep?.Invoke(AdDcProjectionStep.PacketValidation);
        var envelope = Envelope.Parse(envelopeNode);
        if (envelope.ModuleId is not (AgentAdDcValidator.Live or AgentAdDcValidator.History) ||
            !Guid.TryParse(envelope.PacketId,out var parsedPacket) || parsedPacket != packetId ||
            !Guid.TryParse(envelope.AgentId,out var agentId)) throw new InvalidDataException("agent_ad_dc_packet_invalid");
        if (!WorkstationJsonEquality.Equals(AgentCollectionRows.ExtractEvents(packet),rows))
            throw new InvalidDataException("agent_ad_dc_packet_invalid");        JsonArray assignments;
        reportStep?.Invoke(AdDcProjectionStep.AgentAssignment);
        // Lifecycle and assignment writers take FOR UPDATE first. KEY SHARE
        // excludes them until commit, but permits identity's NO KEY UPDATE and last_seen.
        bool active;
        await using (var command = new NpgsqlCommand("select status,assigned_modules::text from sli_agents where id=@id for key share",db,tx))
        {
            command.Parameters.AddWithValue("id",agentId);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("agent_disabled");
            active=reader.GetString(0)=="active";
            assignments = JsonNode.Parse(reader.GetString(1))!.AsArray();
        }
        if(!active && !await AgentImportableAsync(db,tx,agentId,packetId,ct))throw new InvalidOperationException("agent_disabled");
        var assigned = assignments.OfType<JsonObject>().Where(x => TextOrNull(x["module_id"]) == envelope.ModuleId).ToArray();
        if (assigned.Length != 1 || assigned[0]["enabled"] is not JsonValue flag || !flag.TryGetValue<bool>(out var enabled) || !enabled)
            throw new InvalidOperationException("agent_module_not_assigned");
        reportStep?.Invoke(AdDcProjectionStep.ReceiptAttestation);
        await using (var receipt = new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx))
        {
            receipt.Parameters.AddWithValue("packet",packetId); receipt.Parameters.AddWithValue("agent",agentId); receipt.Parameters.AddWithValue("module",envelope.ModuleId);
            await using var reader = await receipt.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || !WorkstationJsonEquality.Equals(JsonNode.Parse(reader.GetString(0)),envelopeNode) ||
                reader.GetString(1) != Packets.Digest(envelopeNode) || envelope.PayloadSha256 != Packets.Digest(packet))
                throw new InvalidOperationException("agent_packet_attestation_invalid");
        }
        reportStep?.Invoke(AdDcProjectionStep.PluginAdmission);
        await using (var pluginLock = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",db,tx)) await pluginLock.ExecuteNonQueryAsync(ct);
        await using (var plugin = new NpgsqlCommand("select installed,enabled from read_plugin_states_v1() where plugin_id='sli.ad'",db,tx))
        {
            await using var reader = await plugin.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || !reader.GetBoolean(0) || !reader.GetBoolean(1)) throw new InvalidOperationException("agent_plugin_disabled");
        }
        reportStep?.Invoke(AdDcProjectionStep.SourceBinding);
        string sourceName;
        await using (var binding = new NpgsqlCommand("""
            select source_instance_id,source_name,channel,module_version from sli_agent_module_bindings
            where agent_id=@agent and module_id='sli.windows.ad-dc'
            """,db,tx))
        {
            binding.Parameters.AddWithValue("agent",agentId);
            await using var reader = await binding.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || reader.GetString(0) != envelope.SourceInstanceId ||
                reader.GetString(2) != envelope.Channel || !AgentAdDcValidator.SupportsVersion(envelope.ModuleVersion))
                throw new InvalidOperationException("agent_ad_dc_source_not_bound");
            sourceName = reader.GetString(1);
        }
        string packetSource=TextOrNull(packet["header"]?["source"]) ?? "";
        // A different spelling of the same controller is an alias; any other source can never bind.
        if (!string.Equals(packetSource,sourceName,StringComparison.OrdinalIgnoreCase))
        {
            var bound=await AgentEnrollmentService.ResolveDcAsync(db,tx,sourceName,ct,agentId);
            var claimed=await AgentEnrollmentService.ResolveDcAsync(db,tx,packetSource,ct);
            if (bound is null || claimed is null || claimed.Value.Server!=bound.Value.Server)
                throw new InvalidOperationException("agent_ad_dc_source_not_bound");
        }
        reportStep?.Invoke(AdDcProjectionStep.PacketValidation);
        JsonArray validated;
        try { validated = AgentAdDcValidator.Validate(envelope,packet,null,packetSource); }
        catch (ProtocolException error) when (error.Code == "agent_collection_cursor_invalid")
        { throw new InvalidOperationException("agent_packet_attestation_invalid"); }
        if (!WorkstationJsonEquality.Equals(validated,rows)) throw new InvalidOperationException("agent_packet_attestation_invalid");
        reportStep?.Invoke(AdDcProjectionStep.SourceConfiguration);
        var source=await AgentEnrollmentService.ResolveDcAsync(db,tx,sourceName,ct,agentId)
            ?? throw new InvalidOperationException("agent_ad_dc_source_not_configured");
        // Normalize transport aliases only after validating the retained signed packet.
        // XML and receipt bytes remain intact; two services share the existing event identity.
        var canonicalRows=new JsonArray(rows.OfType<JsonObject>().Select(row=> {
            var canonical=(JsonObject)row.DeepClone(); canonical["computer_name"]=source.Name; canonical["connect_address"]=source.Name;
            return (JsonNode)canonical;
        }).ToArray());
        return await PreparePublicationAsync(db,tx,worker,envelope,packet,rows,catalogPath,source.Name,source.Server,source.Domain,source.Site,ct,publicationRows:canonicalRows,reportStep:reportStep);
    }
    internal static async Task<bool> AgentImportableAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,Guid packet,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("""
            select exists(select 1 from sli_agents a where a.id=@agent and a.status='active')
            """,db,tx);
        query.Parameters.AddWithValue("agent",agent); query.Parameters.AddWithValue("packet",packet);
        return await query.ExecuteScalarAsync(ct) is true;
    }
    internal static async Task<(long Server,long Domain,long? Site)> SourceAsync(NpgsqlConnection db,NpgsqlTransaction tx,string sourceName,CancellationToken ct)
    {
        var source=await AgentEnrollmentService.ResolveDcAsync(db,tx,sourceName,ct)
            ?? throw new InvalidOperationException("agent_ad_dc_source_not_configured");
        return(source.Server,source.Domain,source.Site);
    }
    internal static async Task PublishAsync(NpgsqlConnection db,NpgsqlTransaction tx,NpgsqlDataSource worker,
        Envelope envelope,JsonObject packet,JsonArray rows,string catalogPath,string sourceName,
        long serverId,long domainId,long? siteId,CancellationToken ct,JsonArray? publicationRows=null,
        Action<AdDcProjectionStep>? reportStep=null)
    {
        var batch=await PreparePublicationAsync(db,tx,worker,envelope,packet,rows,catalogPath,sourceName,serverId,domainId,siteId,ct,publicationRows,reportStep);
        if(batch is null)return;
        await batch.WriteAsync(ct);
        await batch.FinalizeAsync(db,tx,ct);
    }
    private static async Task<DirectAdDcBatch?> PreparePublicationAsync(NpgsqlConnection db,NpgsqlTransaction tx,NpgsqlDataSource worker,
        Envelope envelope,JsonObject packet,JsonArray rows,string catalogPath,string sourceName,
        long serverId,long domainId,long? siteId,CancellationToken ct,JsonArray? publicationRows=null,
        Action<AdDcProjectionStep>? reportStep=null)
    {
        if(rows.Count==0) return null;
        var capability = await DirectRuntimeAuthorization.LoadAsync(db,tx,DateTime.UtcNow,ct)
            ?? throw new InvalidOperationException("agent_storage_unavailable");
        // Attest and normalize the complete packet before any worker reservation.
        reportStep?.Invoke(AdDcProjectionStep.PrepareBatch);
        var inputs=PrepareBatch(publicationRows ?? rows);
        reportStep?.Invoke(AdDcProjectionStep.Catalog);
        Direct4624Catalog.RequireSourceCatalog(catalogPath);
        if(inputs.Any(x=>x.Projection.EventKind is 6272 or 6273)) Direct4624Catalog.RequireRadiusCatalog(catalogPath);
        Direct4624Publication.EnsureSupportedMode();
        long logSourceId;
        await using (var source = new NpgsqlCommand("select id from log_sources where name=@channel",db,tx))
        {
            source.Parameters.AddWithValue("channel",TextOrNull(packet["header"]?["channel"]) ?? "");
            if (await source.ExecuteScalarAsync(ct) is not long id) throw new InvalidOperationException("agent_ad_dc_channel_not_configured");
            logSourceId=id;
        }
        await using (var schema = new NpgsqlCommand("""
            select to_regclass('public.entity_state_projection_jobs') is not null
               and to_regclass('public.entity_state_current') is not null
               and exists(select 1 from schema_migrations where version=19 and name='entity_state_projection')
            """,db,tx))
            if (await schema.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("storage_v2_projection_schema_missing");
        var wanted = new List<(string Kind,string Value)> {
            ("channel",inputs[0].Projection.Channel), ("provider",inputs[0].Projection.Provider),
            ("computer",sourceName), ("role","recorder"), ("role","context"), ("extracted_from","event_data")
        };
        foreach(var input in inputs) {
            wanted.Add(("computer",DirectNpsArchiveRows.Computer(input.Row)));
            wanted.Add(("channel",input.Projection.Channel));wanted.Add(("provider",input.Projection.Provider));
            wanted.AddRange(input.Projection.Entities.Select(e=>("entity_type",e.Type)));
            wanted.AddRange(input.Projection.Entities.Select(e=>("role",e.Role)));
            foreach(var key in new[]{"SubjectDomainName","TargetDomainName"})
                if(input.Projection.Data.TryGetValue(key,out var value) && value.Length>0)wanted.Add(("domain",value));
            if(input.Row["keywords"] is not null)wanted.Add(("keywords",input.Row["keywords"]!.GetValue<string>()));
        }
        reportStep?.Invoke(AdDcProjectionStep.Dictionaries);
        var dictionaries=await DirectDictionaries.ResolveAsync(capability,worker,wanted,ct);
        int channel=dictionaries[("channel",inputs[0].Projection.Channel)];
        var reserved=new List<(JsonObject Row,Direct4624Projection Projection,DateTime Time,DirectEventReservation Reservation,int Ordinal)>();
        reportStep?.Invoke(AdDcProjectionStep.EventReservation);
        var reservations=await DirectEventIdentityStore.ReserveBatchAsync(capability,worker,serverId,
            inputs.Select(input=>new DirectEventRequest(dictionaries[("channel",input.Projection.Channel)],input.Row["record_id"]!.GetValue<long>(),input.Time,input.Row,input.Projection.IdentityHash)).ToArray(),ct,localSourceAliases:envelope.ModuleId is AgentAdDcValidator.Live or AgentAdDcValidator.History);
        foreach(var input in inputs) {
            var reservation=reservations[input.Ordinal];
            var prior=reserved.FirstOrDefault(x=>x.Reservation.Id==reservation.Id);
            if(prior.Row is not null) {
                if(!JsonNode.DeepEquals(prior.Row,input.Row))throw new InvalidOperationException("event_representation_pending");
                continue;
            }
            reserved.Add((input.Row,input.Projection,input.Time,reservation,input.Ordinal));
        }
        // The source importer merges one entity cache across the complete batch,
        // keeping the last details and the earliest/latest observation times.
        var merged=new Dictionary<(string Type,string Key),(DirectEntity Entity,DateTime First,DateTime Last)>();
        foreach(var input in inputs) foreach(var entity in input.Projection.Entities) {
            var key=(entity.Type,entity.NaturalKey);
            if(merged.TryGetValue(key,out var previous))
                merged[key]=(entity,input.Time<previous.First?input.Time:previous.First,input.Time>previous.Last?input.Time:previous.Last);
            else merged[key]=(entity,input.Time,input.Time);
        }
        var desired=merged.Values.Select(x=>(dictionaries[("entity_type",x.Entity.Type)],x.Entity.NaturalKey)).ToArray();
        reportStep?.Invoke(AdDcProjectionStep.EntityReservation);
        var allocations=await DirectEntityIdentityStore.ReserveAsync(capability,worker,desired,ct);
        reportStep?.Invoke(AdDcProjectionStep.EntityPreparation);
        var prepared=new Dictionary<(string Type,string Key),DirectPreparedEntity>();
        var preparedBatch=await DirectEntityPreparation.PrepareBatchAsync(db,tx,merged.Values.Select(value=>new DirectEntityRequest(
            allocations[(dictionaries[("entity_type",value.Entity.Type)],value.Entity.NaturalKey)],dictionaries[("entity_type",value.Entity.Type)],value.Entity,value.First,value.Last)).ToArray(),domainId,serverId,ct);
        foreach(var (key,value) in merged) {
            int type=dictionaries[("entity_type",value.Entity.Type)];
            prepared[key]=preparedBatch[allocations[(type,value.Entity.NaturalKey)]];
        }
        var batch=reserved.Select(input=>new DirectBatchProjection(input.Reservation,input.Row,input.Projection,
            input.Projection.Entities.Select(entity=>prepared[(entity.Type,entity.NaturalKey)]).ToArray())).ToArray();
        var roles=inputs.SelectMany(input=>input.Projection.Entities).Select(e=>e.Role).Distinct(StringComparer.Ordinal)
            .ToDictionary(role=>role,role=>checked((short)dictionaries[("role",role)]),StringComparer.Ordinal);
        return new(capability,worker,batch,serverId,domainId,roles,reportStep,Guid.Parse(envelope.PacketId),
            reserved.Select(input => input.Ordinal).ToArray(),envelope.ModuleId==DirectWindowsEventLogPacket.Module);
    }
    internal static List<(JsonObject Row,Direct4624Projection Projection,DateTime Time,int Ordinal)> PrepareBatch(JsonArray rows)
    {
        if(rows.Count==0)throw new InvalidOperationException("storage_v2_event_profile_pending");
        var inputs=new List<(JsonObject,Direct4624Projection,DateTime,int)>();
        for(int ordinal=0;ordinal<rows.Count;ordinal++) {
            if(rows[ordinal] is not JsonObject row)throw new InvalidOperationException("storage_v2_event_profile_pending");
            inputs.Add((row,Direct4624Projection.Create(row),DirectEventTime.Utc(TextOrNull(row["time_created"]) ?? ""),ordinal));
        }
        return inputs;
    }
    private static string? TextOrNull(JsonNode? node) => JsonRead.TryString(node,out var value) ? value : null;
}
