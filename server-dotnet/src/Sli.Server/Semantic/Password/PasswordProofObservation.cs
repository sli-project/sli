using System.Text.Json.Nodes;

namespace Sli.Server.Semantic.Password;

// One fixed-size summary for the entire producer invocation. In particular,
// these counters live outside the savepoint and survive a rejected attempt.
internal sealed class PasswordProofObservation
{
    private readonly TimeProvider clock;
    private readonly long invocationStarted;
    private long attemptStarted;
    private TimeSpan attemptElapsed, maxAttempt;
    private int attempts, rejectedAttempts, splitAttempts, splitEntities;
    private int windowReads, nativeReads, historyReads, historyRows;
    private long verifiedRefs, verifiedXmlBytes, chargedRefs, chargedXmlBytes;
    private bool attemptSplit;

    internal PasswordProofObservation(TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        invocationStarted = this.clock.GetTimestamp();
    }

    internal void BeginAttempt()
    {
        attempts++;
        attemptSplit = false;
        attemptStarted = clock.GetTimestamp();
    }

    internal void EndAttempt()
    {
        var elapsed = clock.GetElapsedTime(attemptStarted);
        attemptElapsed += elapsed;
        if (elapsed > maxAttempt) maxAttempt = elapsed;
    }

    internal void EnterSplit()
    {
        splitEntities++;
        if (!attemptSplit) splitAttempts++;
        attemptSplit = true;
    }

    internal void RejectAttempt() => rejectedAttempts++;
    internal void ReadWindow() => windowReads++;
    internal void ReadNative() => nativeReads++;
    internal void ReadHistory() => historyReads++;
    internal void ReceiveHistory(int rows) => historyRows += rows;

    // Count native XML rows actually validated from the reader or proof query.
    // Using an already validated in-memory record is not an additional read.
    internal void Verify(int refs, int xmlBytes)
    {
        verifiedRefs += refs;
        verifiedXmlBytes += xmlBytes;
    }

    // A proof unit also charges reused records. Its charge is separate from
    // native I/O and may include the same XML in more than one unit.
    internal void Charge(int xmlBytes)
    {
        chargedRefs++;
        chargedXmlBytes += xmlBytes;
    }

    internal JsonObject? Report(bool committed) => splitAttempts == 0 && rejectedAttempts == 0 ? null : new()
    {
        ["attempts"] = attempts,
        ["rejected_attempts"] = rejectedAttempts,
        ["split_attempts"] = splitAttempts,
        ["split_entities"] = splitEntities,
        ["window_reads"] = windowReads,
        ["native_reads"] = nativeReads,
        ["history_reads"] = historyReads,
        ["history_rows"] = historyRows,
        ["verified_refs"] = verifiedRefs,
        ["verified_xml_bytes"] = verifiedXmlBytes,
        ["charged_refs"] = chargedRefs,
        ["charged_xml_bytes"] = chargedXmlBytes,
        ["attempt_elapsed_ms"] = (long)attemptElapsed.TotalMilliseconds,
        ["max_attempt_ms"] = (long)maxAttempt.TotalMilliseconds,
        ["invocation_elapsed_ms"] = (long)clock.GetElapsedTime(invocationStarted).TotalMilliseconds,
        ["committed"] = committed,
    };

    internal static void Write(JsonObject? report, TextWriter sink)
    {
        if (report == null) return;
        try { sink.WriteLine("password_producer_retained_proof:" + report.ToJsonString()); }
        catch (IOException) { } // Telemetry must not change the committed outcome.
        catch (ObjectDisposedException) { }
    }
}
