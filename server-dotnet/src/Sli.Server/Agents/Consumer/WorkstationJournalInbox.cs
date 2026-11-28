using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.Consumer;

internal static class WorkstationJournalInbox
{
    internal static async Task ImportAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        AgentWorkstationInboxConsumer.Inbox row, DirectAdDcRuntime? direct, CancellationToken ct)
    {
        var envelope = Envelope.Parse(row.Envelope);
        if (envelope.ModuleId != WorkstationsModule.ModuleId || envelope.PacketId != row.PacketId.ToString("D")
            || !Guid.TryParseExact(envelope.AgentId, "D", out var agentId)
            || !Guid.TryParseExact(envelope.SourceInstanceId, "D", out var sourceId))
            throw new WorkstationPendingException("agent_packet_attestation_invalid");

        // Serialize publication with the operator assignment and agent lifecycle.
        await using (var agent = new NpgsqlCommand("select id from sli_agents where id=@agent for update", db, tx))
        {
            agent.Parameters.AddWithValue("agent", agentId);
            if (await agent.ExecuteScalarAsync(ct) is null) throw new WorkstationPendingException("module_disabled");
        }
        var scope = await WorkstationJournalAdmission.ReadAsync(db, tx, agentId, envelope.SourceInstanceId, envelope.PolicyRevision, ct)
            ?? throw new WorkstationPendingException("module_disabled");

        bool transportGap;
        await using (var receipt = new NpgsqlCommand("""
            select envelope::text,envelope_sha256,(receipt->'transport_gap'='true'::jsonb) is true from sli_agent_receipts
            where packet_id=@packet and agent_id=@agent and module_id='sli.workstations' and receipt->>'status'='committed'
            """, db, tx))
        {
            receipt.Parameters.AddWithValue("packet", row.PacketId);
            receipt.Parameters.AddWithValue("agent", agentId);
            await using var stored = await receipt.ExecuteReaderAsync(ct);
            if (!await stored.ReadAsync(ct) || !WorkstationJsonEquality.Equals(JsonNode.Parse(stored.GetString(0)), row.Envelope)
                || stored.GetString(1) != Packets.Digest(row.Envelope) || envelope.PayloadSha256 != Packets.Digest(row.Packet))
                throw new WorkstationPendingException("agent_packet_attestation_invalid");
            transportGap = stored.GetBoolean(2);
        }
        JsonArray verified;
        try { verified = AgentWorkstationValidator.Validate(envelope, row.Packet, WorkstationPolicy.Parse(scope.Config), sourceId, transportGap); }
        catch (ProtocolException) { throw new WorkstationPendingException("agent_packet_attestation_invalid"); }
        if (!WorkstationJsonEquality.Equals(verified, row.Rows) || !WorkstationJournalAdmission.MatchesRows(scope, verified))
            throw new WorkstationPendingException("agent_packet_attestation_invalid");
        if (verified.Count == 0) return;
        if (direct is null) throw new WorkstationPendingException("agent_storage_unavailable");

        var authorization = await DirectRuntimeAuthorization.LoadAsync(db, tx, DateTime.UtcNow, ct)
            ?? throw new WorkstationPendingException("agent_storage_unavailable");
        var inputs = DirectAdDcPacket.PrepareBatch(verified);
        var channel = await DirectDictionaries.ResolveAsync(authorization, direct.Worker,
            inputs.Select(input => ("channel", input.Projection.Channel)).Distinct().ToArray(), ct);
        var reservations = await DirectEventIdentityStore.ReserveBatchAsync(authorization, direct.Worker, scope.ServerId,
            inputs.Select(input => new DirectEventRequest(channel[("channel", input.Projection.Channel)],
                input.Row["record_id"]!.GetValue<long>(), input.Time, input.Row, input.Projection.IdentityHash)).ToArray(), ct);
        var events = inputs.Select(input => (ShortEventRow.Create(reservations[input.Ordinal].Id, scope.DomainId, input.Row,
                input.Projection, scope.ServerId, workstation: true) ?? throw new WorkstationPendingException("workstation_journal_event_not_mapped"))
            with { Computer = scope.Computer, PacketId = row.PacketId, PacketOrdinal = input.Ordinal }).ToArray();
        await using var publish = new NpgsqlCommand("select public.write_workstation_journal412(@packet,@events)", db, tx);
        publish.Parameters.AddWithValue("packet", row.PacketId);
        publish.Parameters.AddWithValue("events", NpgsqlDbType.Jsonb, ShortEventWriter.Encode(events).ToJsonString());
        try { await publish.ExecuteNonQueryAsync(ct); }
        catch (PostgresException error) when (error.MessageText == "module_disabled")
        { throw new WorkstationPendingException("module_disabled"); }
    }
}
