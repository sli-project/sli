using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// Drains a backlog in bounded steps (<c>sli_agent/runtime.py: capture_module</c> for the DC module). Each packet is stored
/// durably before the next read, the burst has a wall-clock budget and a packet budget that counts what is still unsent.
/// </summary>
public static class CaptureRunner
{
    public static readonly TimeSpan WallBudget = TimeSpan.FromSeconds(5);
    public const int MaxBurst = 16;

    public static int Capture(AdDcModule module, IPacketQueue queue, IPacketSigner signer, string agentId, DateTimeOffset now, int batchSize,
        Func<TimeSpan>? clock = null)
    {
        clock ??= static () => TimeSpan.FromTicks(System.Diagnostics.Stopwatch.GetTimestamp() * TimeSpan.TicksPerSecond / System.Diagnostics.Stopwatch.Frequency);
        var deadline = clock() + WallBudget;
        // Backpressure: unsent packets use up the burst, so a slow server cannot create a new burst every cycle.
        var budget = Math.Min(MaxBurst, batchSize) - queue.Pending().Count(packet => packet.Envelope.ModuleId == AdDcModule.ModuleId);
        string? channel = null;
        var captured = 0;
        for (var step = 0; step < Math.Max(0, budget); step++)
        {
            if (clock() >= deadline) break;
            var position = queue.Captured(AdDcModule.ModuleId);
            var result = module.Collect(position, now, channel);
            if (result.Sample is null) break;
            // Only a successful durable capture lets the next read move on.
            queue.Capture(signer, agentId, result.Sample, now);
            captured++;
            channel = result.CatchUpChannel;
            if (channel is null) break;
        }
        return captured;
    }
}
