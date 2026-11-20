using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.SnapshotPublication;

public sealed record SnapshotTransport(Guid CycleId, string DomainSid, JsonObject Policy,
    IReadOnlyDictionary<string, byte[]> Families, IReadOnlyList<SnapshotCycleRow> Rows, bool PublicationPending, string? SlotStartUtc = null);

// Caller owns connection, transaction and eventual commit. Publication is intentionally separate.
public static class SnapshotTransportReader
{
    public static async Task<SnapshotTransport?> ReadAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid cycleId, CancellationToken ct, string expectedModule=SnapshotPolicy.Gpo)
    {
        Guid agent; string module, slot, domain; JsonObject config;
        await using (var cmd = new NpgsqlCommand("select agent_id,module_id,slot_start_utc,domain_sid,policy::text from sli_agent_snapshot_cycles where cycle_id=@cycle",db,tx))
        {
            cmd.Parameters.AddWithValue("cycle",cycleId);
            await using var r=await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct)) return null;
            agent=r.GetGuid(0); module=r.GetString(1); slot=r.GetString(2); domain=r.GetString(3); config=JsonNode.Parse(r.GetString(4))!.AsObject();
        }
        if (module != expectedModule || module is not (SnapshotPolicy.Gpo or SnapshotPolicy.Ad)) throw new ProtocolException("agent_snapshot_module_invalid");
        var firstRows=await ReadRowsAsync(db,tx,cycleId,true,ct);
        if (firstRows.Count == 0) return null;
        await SnapshotPublicationAuthorization.AuthorizeAsync(db,tx,agent,config,firstRows[0],ct);
        string transport, publication;
        await using (var cmd=new NpgsqlCommand("select transport_state,publication_state from sli_agent_snapshot_cycles where cycle_id=@cycle for update",db,tx))
        {
            cmd.Parameters.AddWithValue("cycle",cycleId);
            await using var r=await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct)) return null;
            transport=r.GetString(0); publication=r.GetString(1);
        }
        if (transport != "pending" && publication != "pending") return null;
        var rows=await ReadRowsAsync(db,tx,cycleId,false,ct);
        var families=SnapshotCycleAssembly.ValidateAndAssemble(cycleId.ToString("D"),agent.ToString("D"),slot,new SnapshotPolicy(module,config),rows);
        if (families is null) return null;
        if (transport == "pending")
        {
            await using var cmd=new NpgsqlCommand("update sli_agent_snapshot_cycles set transport_state='complete',completed_at=clock_timestamp() where cycle_id=@cycle",db,tx);
            cmd.Parameters.AddWithValue("cycle",cycleId); await cmd.ExecuteNonQueryAsync(ct);
        }
        return new(cycleId,domain,config,families,rows,publication == "pending",slot);
    }
    private static async Task<List<SnapshotCycleRow>> ReadRowsAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid cycle,bool first,CancellationToken ct)
    {
        var rows=new List<SnapshotCycleRow>();
        await using var cmd=new NpgsqlCommand("select r.envelope::text,c.payload::text,r.envelope_sha256 from sli_agent_snapshot_chunks c join sli_agent_receipts r using(packet_id) where c.cycle_id=@cycle order by r.sequence"+(first ? " limit 1" : ""),db,tx);
        cmd.Parameters.AddWithValue("cycle",cycle);
        await using var r=await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) rows.Add(new(JsonNode.Parse(r.GetString(0))!.AsObject(),JsonNode.Parse(r.GetString(1))!.AsObject(),r.GetString(2)));
        return rows;
    }
}
