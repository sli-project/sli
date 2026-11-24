using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.Radius;

internal sealed class RadiusInboxConsumer
{
    private (DateTime Received, Guid Packet)? after;
    internal JsonObject? Cursor { get; private set; }

    // The owning post-collection session retains the process lock throughout this call.
    public async Task<PostCollectionBatch> RunUnderProcessLockAsync(string dsn, RadiusImportBinding binding, int limit, CancellationToken ct)
    {
        var connection = new NpgsqlConnectionStringBuilder(dsn) { Pooling = false, Multiplexing = false, CommandTimeout = 0 };
        connection.Options = (connection.Options ?? "") + " -c statement_timeout=0 -c lock_timeout=0";
        await using var db = new NpgsqlConnection(connection.ConnectionString);
        await db.OpenAsync(ct);
        await using (var role = new NpgsqlCommand("set role adlog_nps_agent_import_worker", db)) await role.ExecuteNonQueryAsync(ct);
        using var admission = AgentAssignmentPluginAdmission.Enter("sli.remote-access", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        int scanned = 0, imported = 0;
        var reasons = new Dictionary<string, int>();
        if (limit is < 1 or > 128) throw new ArgumentOutOfRangeException(nameof(limit));
        for (int i = 0; i < limit; i++)
        {
            ct.ThrowIfCancellationRequested();
            await using var tx = await db.BeginTransactionAsync(ct);
            Guid packet; DateTime received; JsonObject envelope, payload; JsonArray rows;
            await using (var select = new NpgsqlCommand("""
                select packet_id,received_at,envelope::text,packet::text,event_rows::text from sli_agent_packet_inbox i
                where imported_at is null and module_disabled_at is null and envelope->>'module_id'='sli.radius-accounting'
                  and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
                  and (@time is null or (received_at,packet_id) > (@time,@packet))
                order by received_at,packet_id limit 1 for update skip locked
                """, db, tx))
            {
                select.Parameters.AddWithValue("time", NpgsqlDbType.TimestampTz, after is null ? DBNull.Value : after.Value.Received);
                select.Parameters.AddWithValue("packet", NpgsqlDbType.Uuid, after is null ? DBNull.Value : after.Value.Packet);
                await using var reader = await select.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct)) { after = null; Cursor = null; break; }
                packet = reader.GetGuid(0); received = reader.GetDateTime(1);
                envelope = JsonNode.Parse(reader.GetString(2))!.AsObject(); payload = JsonNode.Parse(reader.GetString(3))!.AsObject(); rows = JsonNode.Parse(reader.GetString(4))!.AsArray();
            }
            await tx.SaveAsync("accounting_packet", ct);
            try
            {
                await RadiusAccountingImporter.ImportAsync(db, tx, binding, packet, envelope, payload, rows, ct);
                await using var mark = new NpgsqlCommand("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet", db, tx);
                mark.Parameters.AddWithValue("packet", packet); await mark.ExecuteNonQueryAsync(ct);
                imported++;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error)
            {
                await tx.RollbackAsync("accounting_packet", ct);
                string code = error is RadiusImportPending pending ? SafeReason(pending.Code) : "agent_radius_import_failed";
                reasons[code] = reasons.GetValueOrDefault(code) + 1;
            }
            await tx.CommitAsync(ct);
            scanned++; after = (received, packet);
            Cursor = new() { ["received_at"] = received.ToString("O"), ["packet_id"] = packet.ToString("D") };
        }
        return new(scanned, imported, reasons) { Cursor = Cursor };
    }

    private static string SafeReason(string code) => code is "agent_disabled" or "agent_module_not_assigned" or
        "agent_source_binding_changed" or "agent_packet_attestation_invalid" or "agent_plugin_disabled" or
        "agent_import_schema_304_required" or "agent_nps_source_not_configured" or "agent_nps_import_disabled" or
        "subscription_not_found" or "subscription_not_manually_enabled" or "agent_radius_cursor_conflict" or
        "collection_packet_radius_mismatch" or "empty_progress_invalid" or "cursor_compare_and_swap_failed" ? code : "agent_radius_import_failed";
}
