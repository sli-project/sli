using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Storage.Archive;

namespace Sli.Server.Storage.History;

// Read-only adapter; datasource is the existing application reader role, not the archive worker.
internal sealed class EventDetailStore(NpgsqlDataSource source)
{
    const string BlockColumns = "b.archive_set_id,b.archive_kind,b.format_version,b.block_index,b.first_event_id,b.last_event_id,b.row_count,b.raw_bytes,b.compressed_bytes,b.raw_sha256,b.archive_sha256,b.object_location,b.state,b.created_at,b.verified_at";
    internal async Task<JsonObject?> AgentPayloadAsync(JsonObject summary,CancellationToken ct)
    {
        await using var db = await source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("""
            select i.event_rows::text,i.packet::text,i.envelope::text,receipt.envelope_sha256,i.packet_id::text
            from raw_log_files r
            join sli_agent_packet_inbox i on r.file_path='agent-packet:' || i.packet_id::text
            join sli_agent_receipts receipt on receipt.packet_id=i.packet_id and receipt.envelope=i.envelope
            where r.id=@raw and r.server_id=@server and r.log_source_id=@source and i.imported_at is not null
            limit 1
            """,db) { CommandTimeout = 0 };
        foreach (var (parameter,field) in new[] { ("raw","raw_log_file_id"),("server","server_id"),("source","log_source_id") })
            command.Parameters.AddWithValue(parameter,long.Parse(summary[field]!.ToString(),System.Globalization.CultureInfo.InvariantCulture));
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct) || reader.IsDBNull(0) || reader.IsDBNull(1)) return null; // body cleared by inbox retention (351)
        var retained = new JsonObject { ["event_rows"]=JsonNode.Parse(reader.GetString(0)),["attested_packet"]=JsonNode.Parse(reader.GetString(1)),
            ["attested_envelope"]=JsonNode.Parse(reader.GetString(2)),["envelope_sha256"]=reader.GetString(3),["packet_id"]=reader.GetString(4) };
        return AgentEventPayload.Verify(summary,retained);
    }
    internal async Task<Dictionary<long,JsonObject>> SummariesAsync(long[] ids,CancellationToken ct)
    {
        Validate(ids);
        if (ids.Length == 0) return [];
        await using var db = await source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("""
            select e.*, s.hostname as server, provider.value as provider_name, channel.value as channel,
                   computer.value as computer, keywords.value as keywords,
                   subject_domain.value as subject_domain_name, target_domain.value as target_domain_name,
                   facts.process_name, facts.process_id, facts.target_server_name, facts.service_name,
                   facts.task_name, facts.task_action, facts.task_author, facts.run_as, facts.logon_type,
                   facts.result_code, facts.object_name, facts.share_name, facts.message_sample
            from events_v2_core e join servers s on s.id=e.server_id
            left join storage_v2_provider provider on provider.id=e.provider_id
            join storage_v2_channel channel on channel.id=e.channel_id
            left join storage_v2_computer computer on computer.id=e.computer_id
            left join storage_v2_keywords keywords on keywords.id=e.keywords_id
            left join storage_v2_domain_name subject_domain on subject_domain.id=e.subject_domain_id
            left join storage_v2_domain_name target_domain on target_domain.id=e.target_domain_id
            left join event_facts_v2 facts on facts.event_id=e.id where e.id=any(@ids)
            """,db) { CommandTimeout = 3 };
        command.Parameters.AddWithValue("ids",NpgsqlDbType.Array | NpgsqlDbType.Bigint,ids);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = new Dictionary<long,JsonObject>();
        while (await reader.ReadAsync(ct))
        {
            var row = new JsonObject();
            for (int i=0;i<reader.FieldCount;i++)
            {
                object? value = await reader.IsDBNullAsync(i,ct) ? null : reader.GetValue(i);
                row[reader.GetName(i)] = value switch { null => null, byte[] bytes => JsonValue.Create(Convert.ToHexString(bytes)), _ => JsonSerializer.SerializeToNode(value) };
            }
            long id = long.Parse(row["id"]!.ToString(),System.Globalization.CultureInfo.InvariantCulture);
            if (!result.TryAdd(id,row)) throw new InvalidDataException("event_core_duplicate");
        }
        return result;
    }
    internal async Task<List<ArchiveBlock>> BlocksAsync(long[] ids,TimeSpan remaining,CancellationToken ct)
    {
        Validate(ids);
        if (ids.Length == 0) return [];
        if (remaining <= TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(remaining); ct=deadline.Token;
        await using var db = await source.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        int milliseconds=(int)Math.Clamp(Math.Ceiling(remaining.TotalMilliseconds),1,3000);
        await using(var limits=new NpgsqlCommand($"set local statement_timeout={milliseconds}; set local lock_timeout=1000",db,tx) { CommandTimeout=3 })
            await limits.ExecuteNonQueryAsync(ct);
        await using var command = CreateBlocksCommand(db,tx,ids,remaining);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var blocks = new List<ArchiveBlock>(); var seen = new HashSet<(Guid,string,int)>();
        while (await reader.ReadAsync(ct))
        {
            var block = new ArchiveBlock(reader.GetGuid(0),reader.GetString(1),reader.GetInt32(2),reader.GetInt32(3),
                reader.GetInt64(4),reader.GetInt64(5),reader.GetInt32(6),reader.GetInt64(7),reader.GetInt64(8),
                Convert.ToHexString(reader.GetFieldValue<byte[]>(9)),Convert.ToHexString(reader.GetFieldValue<byte[]>(10)),reader.GetString(11),reader.GetString(12),
                reader.GetDateTime(13),reader.IsDBNull(14) ? null : reader.GetDateTime(14));
            if (seen.Add((block.SetId,block.Kind,block.Index))) blocks.Add(block);
            if (blocks.Count > 16) throw new InvalidDataException("event_archive_block_limit");
        }
        await reader.DisposeAsync(); await tx.CommitAsync(ct);
        return blocks;
    }
    internal static NpgsqlCommand CreateBlocksCommand(NpgsqlConnection db,NpgsqlTransaction? tx,long[] ids,TimeSpan remaining)
    {
        Validate(ids);
        if(remaining<=TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
        var command = new NpgsqlCommand($"""
            with requested(event_id,ordinal) as (select event_id,ordinal from unnest(@ids::bigint[]) with ordinality as r(event_id,ordinal))
            select distinct on (requested.ordinal) {BlockColumns} from requested
            join storage_v2_archive_blocks b on b.archive_kind='event' and b.state='published'
              and b.first_event_id<=requested.event_id and b.last_event_id>=requested.event_id
            order by requested.ordinal,b.first_event_id desc,b.block_index desc
            """,db,tx) { CommandTimeout = (int)Math.Clamp(Math.Ceiling(remaining.TotalSeconds),1,3) };
        command.Parameters.AddWithValue("ids",NpgsqlDbType.Array | NpgsqlDbType.Bigint,ids);
        return command;
    }
    internal async Task<Dictionary<long,string>> ServerNamesAsync(long[] ids,CancellationToken ct)
    {
        if (ids.Length == 0) return [];
        await using var db = await source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("select id,hostname from servers where id=any(@ids)",db) { CommandTimeout = 3 };
        command.Parameters.AddWithValue("ids",NpgsqlDbType.Array | NpgsqlDbType.Bigint,ids);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = new Dictionary<long,string>();
        while (await reader.ReadAsync(ct)) result.Add(Convert.ToInt64(reader.GetValue(0),System.Globalization.CultureInfo.InvariantCulture),reader.GetString(1));
        if (result.Count != ids.Distinct().Count()) throw new InvalidDataException("history_server_unknown");
        return result;
    }
    static void Validate(long[] ids) { if (ids.Length > 100 || ids.Any(x => x <= 0)) throw new ArgumentOutOfRangeException(nameof(ids)); }
}
