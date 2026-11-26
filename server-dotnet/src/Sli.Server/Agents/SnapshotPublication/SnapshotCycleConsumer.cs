using Npgsql;
using NpgsqlTypes;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;

namespace Sli.Server.Agents.SnapshotPublication;

// Independent cursor and retry clock are held by the single post-collection host.
public sealed class SnapshotCycleConsumer
{
    private (DateTime Slot, Guid Id)? after;
    internal JsonObject? Cursor { get; private set; }
    public async Task<PostCollectionBatch> RunOnceAsync(string connectionString, CancellationToken ct)
    {
        var connection = new NpgsqlConnectionStringBuilder(connectionString) { CommandTimeout = 0, Pooling = false, Multiplexing = false };
        connection.Options = (connection.Options ?? "") + " -c statement_timeout=0 -c lock_timeout=0";
        await using var db = new NpgsqlConnection(connection.ConnectionString);
        await db.OpenAsync(ct);
        await using (var role = new NpgsqlCommand("set role adlog_context_worker", db))
            await role.ExecuteNonQueryAsync(ct);
        var cycles = new List<(Guid Id, string Module, bool PendingTransport, DateTime Slot)>();
        await using (var select = new NpgsqlCommand("""
            select cycle_id,module_id,transport_state='pending',slot_start_utc::timestamptz from sli_agent_snapshot_cycles
            where (transport_state='pending' or publication_state='pending')
              and (@after is null or (slot_start_utc::timestamptz,cycle_id) > (@slot,@after))
            order by slot_start_utc::timestamptz,cycle_id limit 4
            """, db))
        {
            select.Parameters.AddWithValue("after", NpgsqlDbType.Uuid, after is null ? DBNull.Value : after.Value.Id);
            select.Parameters.AddWithValue("slot", NpgsqlDbType.TimestampTz, after is null ? DBNull.Value : after.Value.Slot);
            await using var reader = await select.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) cycles.Add((reader.GetGuid(0), reader.GetString(1), reader.GetBoolean(2), reader.GetDateTime(3)));
        }
        int completed = 0;
        var reasons = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var cycle in cycles)
        {
            ct.ThrowIfCancellationRequested();
            string? reason;
            try
            {
                var result = cycle.Module switch {
                    "sli.gpo-snapshot" => await GpoSnapshotPublisher.ProcessAsync(db, cycle.Id, ct),
                    "sli.ad-snapshot" => await AdSnapshotPublisher.ProcessAsync(db, cycle.Id, ct),
                    _ => throw new ProtocolException("agent_snapshot_cycle_invalid")
                };
                if (cycle.PendingTransport && result.TransportComplete) completed++;
                reason = result.PendingReason;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (ProtocolException e) { reason = SafeReason(e.Code); }
            catch (Exception) { reason = "agent_snapshot_cycle_invalid"; }
            if (reason is not null) reasons[reason] = reasons.GetValueOrDefault(reason) + 1;
            // Advance only after the transaction has ended, including deferred cycles.
            after = (cycle.Slot, cycle.Id);
            Cursor = new() { ["slot_start_utc"] = cycle.Slot.ToString("O"), ["cycle_id"] = cycle.Id.ToString("D") };
        }
        if (cycles.Count == 0) { after = null; Cursor = null; }
        // Snapshot processing also runs against the predecessor during rollback.
        await using var inventory = new NpgsqlCommand("select to_regprocedure('public.advance_workstation_ad_inventory432()') is not null", db);
        if (await inventory.ExecuteScalarAsync(ct) is true)
        {
            inventory.CommandText = "select public.advance_workstation_ad_inventory432()";
            if (await inventory.ExecuteScalarAsync(ct) is long domain)
            {
                Cursor ??= new();
                Cursor["workstation_inventory_domain_id"] = domain;
            }
        }
        return new(cycles.Count, completed, reasons) { Cursor = Cursor };
    }

    internal static string SafeReason(string code) => code is
        "agent_disabled" or "agent_module_not_assigned" or "agent_packet_attestation_invalid" or
        "agent_source_not_bound" or "agent_plugin_disabled" ? code : "agent_snapshot_cycle_invalid";
}
