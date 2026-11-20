using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public sealed record AgentInboxLimits(long AgentCount, long AgentBytes, long ModuleCount, long ModuleBytes,
    long GlobalCount, long GlobalBytes, long StorageBytes)
{
    // Native Debian installs keep PostgreSQL on /srv/sli-db, which may be a separate mount.
    public Func<long> FreeDiskBytes { get; init; } = ReadFreeDiskBytes;
    // Snapshot chunks use a separate queue; preserve its existing default and explicit overrides.
    public long SnapshotAgentBytes { get; init; } = AgentBytes;
    private long requiredDiskBytes = DiskBytes(90 * 1024);

    private static long ReadFreeDiskBytes()
    {
        string path = (OperatingSystem.IsWindows() ? AppContext.BaseDirectory : "/srv/sli-db").TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return DriveInfo.GetDrives().Where(d => path.StartsWith(d.Name.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            .OrderByDescending(d => d.Name.Length).First().AvailableFreeSpace;
    }

    public static long DiskBytes(long packetBytes) => checked(2 * packetBytes + 65536);
    // Keep 10% of currently free space for WAL, PostgreSQL maintenance and other server writes.
    public static long WritableBytes(long freeBytes) => Math.Max(0, freeBytes - freeBytes / 10);
    public long ReadFreeBytes()
    {
        try { return FreeDiskBytes(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException) { return -1; }
    }
    public string CapacityStatus()
    {
        long free = ReadFreeBytes();
        return free < 0 ? "unavailable" : WritableBytes(free) < Interlocked.Read(ref requiredDiskBytes) ? "full" : "ok";
    }
    public void RecordDiskRejection(long bytes)
    {
        long required = DiskBytes(bytes), current;
        do { current = Interlocked.Read(ref requiredDiskBytes); }
        while (required > current && Interlocked.CompareExchange(ref requiredDiskBytes, required, current) != current);
    }

    public static AgentInboxLimits FromEnvironment(Func<string,string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        long Read(string name, long value)
        {
            string? text = environment("SLI_AGENT_INBOX_" + name);
            if (text is null) return value;
            return long.TryParse(text, out long parsed) && parsed > 0 ? parsed : throw new InvalidOperationException("agent_inbox_invalid_limit");
        }
        return new(Read("AGENT_COUNT",4096), Read("AGENT_BYTES",long.MaxValue), Read("MODULE_COUNT",32768),
            Read("MODULE_BYTES",2L*1024*1024*1024), Read("GLOBAL_COUNT",65536), Read("GLOBAL_BYTES",4L*1024*1024*1024),
            Read("STORAGE_BYTES",16L*1024*1024*1024)) { SnapshotAgentBytes = Read("AGENT_BYTES",256L*1024*1024) };
    }
}

public static class AgentInboxQuota
{
    public static async Task<string?> CheckAsync(NpgsqlConnection connection, NpgsqlTransaction tx, Envelope e,
        JsonObject payload, JsonArray? rows, JsonObject receipt, AgentInboxLimits limits, AgentIngressDiagnostics diagnostics, CancellationToken ct)
    {
        await using (var held = new NpgsqlCommand("select pg_advisory_xact_lock(157,1)", connection, tx)) await held.ExecuteNonQueryAsync(ct);
        await using var command = new NpgsqlCommand("""
            with stored as (
              select r.agent_id,r.module_id,i.packet_id is not null and i.imported_at is null as pending,
                1024 + octet_length(r.envelope::text) + octet_length(r.receipt::text)
                + coalesce(i.quota_payload_bytes,1024 + octet_length(i.envelope::text) + octet_length(i.packet::text) + octet_length(i.event_rows::text)) as bytes
              from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id) where i.imported_at is null and i.module_disabled_at is null
            ) select count(*) filter(where pending and agent_id=@agent),coalesce(sum(bytes) filter(where pending and agent_id=@agent),0),
              count(*) filter(where pending and module_id=@module),coalesce(sum(bytes) filter(where pending and module_id=@module),0),
              count(*) filter(where pending),coalesce(sum(bytes) filter(where pending),0),
              (select greatest(count(*),1) from sli_agents where status='active') from stored
            """, connection, tx);
        command.Parameters.AddWithValue("agent",Guid.Parse(e.AgentId)); command.Parameters.AddWithValue("module",e.ModuleId);
        long[] usage = new long[7];
        long agents;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            await reader.ReadAsync(ct);
            for (int i=0;i<6;i++) usage[i] = Convert.ToInt64(reader.GetValue(i));
            agents = reader.GetInt64(6);
        }
        var docs = new List<string>{PacketStorageJson.Serialize(e.ToJson()),PacketStorageJson.Serialize(receipt)};
        long overhead=1024;
        if (rows is not null) { docs.Add(PacketStorageJson.Serialize(e.ToJson())); docs.Add(PacketStorageJson.Serialize(payload)); docs.Add(PacketStorageJson.Serialize(rows)); overhead+=1024; }
        await using var measure = new NpgsqlCommand("""
            select coalesce(sum(octet_length(document::text)),0) from unnest(@docs::jsonb[]) as document
            """, connection, tx);
        measure.Parameters.AddWithValue("docs", NpgsqlDbType.Array | NpgsqlDbType.Jsonb, docs.ToArray());
        long bytes;
        await using (var reader = await measure.ExecuteReaderAsync(ct))
        {
            await reader.ReadAsync(ct); bytes = checked(overhead + Convert.ToInt64(reader.GetValue(0)));
        }
        usage[6] = await LiveStorageBytesAsync(connection, tx, ["sli_agent_receipts", "sli_agent_packet_inbox"], ct);
        long free = limits.ReadFreeBytes();
        string? capacityCode = CheckCapacity(usage[1], usage[5], bytes, agents, free, rows is not null);
        if (capacityCode is not null)
        {
            if (capacityCode != "agent_inbox_agent_bytes_limit") limits.RecordDiskRejection(bytes);
            try { diagnostics.QuotaRejected(new AgentQuotaRejection(Guid.Parse(e.AgentId), e.ModuleId, capacityCode,
                new Dictionary<string,long> { ["agent_bytes"] = usage[1], ["global_bytes"] = usage[5] }, Math.Max(0,free), bytes)); }
            catch (Exception) { }
            return capacityCode;
        }
        long[] bounds=[limits.AgentCount,limits.AgentBytes,limits.ModuleCount,limits.ModuleBytes,limits.GlobalCount,limits.GlobalBytes,limits.StorageBytes];
        string[] names=["agent_count","agent_bytes","module_count","module_bytes","global_count","global_bytes","storage_bytes"];
        for (int i=0;i<bounds.Length;i++)
        {
            long addition=i==6 ? checked(2*bytes+65536) : rows is null ? 0 : i%2==1 ? bytes : 1;
                        if (usage[i] > bounds[i] - addition)
            {
                string code="agent_inbox_" + names[i] + "_limit";
                var metrics=names.Select((name,index)=>(name,value:usage[index])).ToDictionary(x=>x.name,x=>x.value);
                try { diagnostics.QuotaRejected(new AgentQuotaRejection(Guid.Parse(e.AgentId),e.ModuleId,code,metrics,bounds[i],bytes)); }
                catch (Exception) { }
                return code;
            }
        }
        return null;
    }

    public static string? CheckCapacity(long agentBytes, long pendingBytes, long packetBytes, long agents, long freeBytes, bool pending = true)
    {
        if (freeBytes < 0) return "agent_inbox_disk_unavailable";
        long writable = AgentInboxLimits.WritableBytes(freeBytes);
        if (AgentInboxLimits.DiskBytes(packetBytes) > writable) return "agent_inbox_disk_bytes_limit";
        // Share the pending queue plus its remaining physical growth budget among registered agents.
        // The factor two is the same payload/index expansion allowance as the storage guard below.
        long share = pendingBytes / Math.Max(1, agents) + (writable / 2) / Math.Max(1, agents);
        return pending && agentBytes > share - packetBytes ? "agent_inbox_agent_bytes_limit" : null;
    }

    private const double TupleHeaderBytes = 24 + 4;     // heap tuple header + line pointer
    private const double ToastChunkBytes = 2048;        // a TOAST chunk row holds about 2 KB

    /// <summary>
    /// Bytes the live rows of the relations occupy, estimated from catalog statistics only (no table scan).
    /// Relation size never shrinks after retention deletes rows, so the file size is scaled by the share of it
    /// that live rows fill. Without statistics the full relation size is used.
    /// </summary>
    public static async Task<long> LiveStorageBytesAsync(NpgsqlConnection connection, NpgsqlTransaction? tx, string[] relations, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select pg_total_relation_size(c.oid), pg_indexes_size(c.oid),
              case when c.reltuples < 0 and coalesce(s.n_live_tup, 0) = 0 then -1 else greatest(c.reltuples, coalesce(s.n_live_tup, 0)) end::float8,
              (select sum(p.avg_width) from pg_stats p where p.schemaname = n.nspname and p.tablename = c.relname)::float8,
              greatest(coalesce(tc.reltuples, 0), coalesce(ts.n_live_tup, 0))::float8
            from unnest(@names::text[]) as name
            join pg_class c on c.oid = to_regclass(name)
            join pg_namespace n on n.oid = c.relnamespace
            left join pg_stat_all_tables s on s.relid = c.oid
            left join pg_class tc on tc.oid = c.reltoastrelid
            left join pg_stat_all_tables ts on ts.relid = c.reltoastrelid
            """, connection, tx);
        command.Parameters.AddWithValue("names", relations);
        long sum = 0;
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            sum = checked(sum + EstimateLiveBytes(reader.GetInt64(0), reader.GetInt64(1), reader.GetDouble(2),
                reader.IsDBNull(3) ? 0 : reader.GetDouble(3), reader.GetDouble(4)));
        return sum;
    }

    public static long EstimateLiveBytes(long totalBytes, long indexBytes, double liveRows, double avgRowWidth, double liveToastChunks)
    {
        long dataBytes = totalBytes - indexBytes;
        if (liveRows < 0 || avgRowWidth <= 0 || dataBytes <= 0) return totalBytes;
        double live = liveRows * (TupleHeaderBytes + avgRowWidth) + Math.Max(0, liveToastChunks) * ToastChunkBytes;
        return (long)(totalBytes * Math.Min(1.0, live / dataBytes));
    }
}

