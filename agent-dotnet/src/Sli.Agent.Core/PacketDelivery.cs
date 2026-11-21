using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public interface IPacketTransport
{
    /// <summary>Posts one packet and returns the server's answer. A transport failure throws <see cref="TransportException"/>.</summary>
    Task<JsonNode?> PostPacketAsync(SignedPacket packet, CancellationToken cancellationToken);
}

public sealed class TransportException(string code = "agent_transport_failed", int? httpStatus = null) : AgentException(code)
{
    public string Detail => TransportErrors.Detail(Code, httpStatus);
}

public sealed record DeliveryResult(bool Success, int Attempted, int Acknowledged)
{
    public IReadOnlySet<string> DisabledModules { get; init; } = new HashSet<string>();
    public TransportException? TransportFailure { get; init; }
}

/// <summary>
/// Receipt-driven delivery (<c>sli_agent/runtime.py: deliver_once</c>). Per module the oldest packet goes first; a packet that
/// is not exactly acknowledged blocks that module for this cycle and is sent again next time. The server treats a repeat as a duplicate.
/// A matching module-disable refusal closes that module's queue without claiming delivery.
/// </summary>
public sealed class PacketDelivery(IPacketQueue queue, IPacketTransport transport, IPacketSigner? signer = null)
{
    public async Task<DeliveryResult> DeliverOnceAsync(int batchSize = 16, int? limit = null, ISet<string>? batchedModules = null, CancellationToken cancellationToken = default)
    {
        var blocked = new HashSet<string>();
        var disabled = new HashSet<string>();
        var counts = new Dictionary<string, int>();
        var success = true;
        var attempts = 0;
        var acknowledged = 0;
        TransportException? transportFailure = null;
        // Historical backfill goes last so it never delays live evidence.
        var pending = queue.Pending().OrderBy(packet => packet.Envelope.ModuleId == FilePacketQueue.HistoryModuleId).ToList();
        foreach (var packet in pending)
        {
            var module = packet.Envelope.ModuleId;
            if (module == FilePacketQueue.HistoryModuleId && (!success || limit is { } cap && attempts >= cap - 1)) continue;
            counts[module] = counts.GetValueOrDefault(module) + 1;
            if (blocked.Contains(module) || batchedModules?.Contains(module) == true && counts[module] > batchSize) continue;
            if (limit is { } max && attempts >= max) break;
            attempts++;
            var accepted = false;
            try
            {
                var prepared = queue.PrepareDelivery(packet, signer);
                var receipt=await transport.PostPacketAsync(prepared, cancellationToken).ConfigureAwait(false);
                accepted = queue.Acknowledge(prepared,receipt);
                if(accepted && Receipt.IsModuleDisabled(prepared.Envelope,receipt)) {
                    disabled.Add(module); blocked.Add(module);
                    continue;
                }
            }
            catch (AgentException exception) when (!TransportErrors.IsDiagnostic(exception.Code))
            {
                // A failure is not a receipt: keep the packet and retry in the next cycle.
                if (exception is TransportException transportError) transportFailure ??= transportError;
            }
            catch (HttpRequestException)
            {
            }
            catch (IOException)
            {
            }
            if (accepted)
            {
                acknowledged++;
                continue;
            }
            blocked.Add(module);
            if (module != FilePacketQueue.HistoryModuleId) success = false;
        }
        return new DeliveryResult(success, attempts, acknowledged) { DisabledModules = disabled, TransportFailure = transportFailure };
    }
}
