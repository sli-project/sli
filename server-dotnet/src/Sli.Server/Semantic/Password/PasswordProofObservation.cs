using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic.Password;

internal enum PasswordProofTiming
{
    WindowRead, WindowParse, Prepare, NativeRead, NativeCheck, HistoryRead, HistoryCheck,
    Rule, Checkpoint, Publication, Finalizer, Commit, Count,
}

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
    private readonly TimeSpan[] phaseElapsed = new TimeSpan[(int)PasswordProofTiming.Count];
    private long windowRows, nativeRows, managedParses, managedParseReuses, memoPayloadBytes;
    private int memoEntries;
    private bool attemptSplit, attemptRejected;
    private readonly ReadMetrics nativeRequests = new(128 * 1024 * 1024), historyRequests = new(1024 * 1024);

    internal PasswordProofObservation(TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        invocationStarted = this.clock.GetTimestamp();
    }

    internal void BeginAttempt()
    {
        attempts++;
        attemptSplit = false;
        attemptRejected = false;
        nativeRequests.Start(nativeReads, nativeRows, phaseElapsed[(int)PasswordProofTiming.NativeRead]);
        historyRequests.Start(historyReads, historyRows, phaseElapsed[(int)PasswordProofTiming.HistoryRead]);
        attemptStarted = clock.GetTimestamp();
    }

    internal void EndAttempt()
    {
        var elapsed = clock.GetElapsedTime(attemptStarted);
        attemptElapsed += elapsed;
        if (elapsed > maxAttempt) maxAttempt = elapsed;
        nativeRequests.Finish(nativeReads, nativeRows, phaseElapsed[(int)PasswordProofTiming.NativeRead], attemptRejected);
        historyRequests.Finish(historyReads, historyRows, phaseElapsed[(int)PasswordProofTiming.HistoryRead], attemptRejected);
    }

    internal void EnterSplit()
    {
        splitEntities++;
        if (!attemptSplit) splitAttempts++;
        attemptSplit = true;
    }

    internal void RejectAttempt()
    {
        rejectedAttempts++;
        attemptRejected = true;
    }

    internal void ReadWindow() => windowReads++;
    internal void ReadNative() => nativeReads++;
    internal void ReadHistory() => historyReads++;
    internal void ReceiveHistory(int rows) => historyRows += rows;
    internal void ReceiveWindow(int rows) => windowRows += rows;
    internal void ReceiveNative(int rows) => nativeRows += rows;
    internal void ParseNative() => managedParses++;
    internal void ReuseParse() => managedParseReuses++;

    internal void ObserveReadRequest(PasswordProofTiming phase, string serialized)
    {
        // One invocation uses a fixed query, scope and execution for each phase.
        // Only the already serialized refs or episode key can vary.
        switch (phase)
        {
            case PasswordProofTiming.NativeRead: nativeRequests.Record(serialized); break;
            case PasswordProofTiming.HistoryRead: historyRequests.Record(serialized); break;
        }
    }

    internal void SizeParseMemo(int items, long bytes)
    {
        memoEntries = items;
        memoPayloadBytes = bytes;
    }

    internal PhaseTimer Measure(PasswordProofTiming phase) => new(this, phase, clock.GetTimestamp());

    internal readonly record struct PhaseTimer(PasswordProofObservation Owner, PasswordProofTiming Phase, long Started) : IDisposable
    {
        public void Dispose() => Owner.phaseElapsed[(int)Phase] += Owner.clock.GetElapsedTime(Started);
    }

    private long Milliseconds(PasswordProofTiming phase) => (long)phaseElapsed[(int)phase].TotalMilliseconds;

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
        ["window_rows"] = windowRows,
        ["native_rows"] = nativeRows,
        ["managed_parses"] = managedParses,
        ["managed_parse_reuses"] = managedParseReuses,
        ["parse_memo_entries"] = memoEntries,
        ["parse_memo_payload_bytes"] = memoPayloadBytes,
        ["phase_ms"] = new JsonObject
        {
            ["window_read"] = Milliseconds(PasswordProofTiming.WindowRead),
            ["window_parse"] = Milliseconds(PasswordProofTiming.WindowParse),
            ["prepare"] = Milliseconds(PasswordProofTiming.Prepare),
            ["native_check"] = Milliseconds(PasswordProofTiming.NativeCheck),
            ["native_read"] = Milliseconds(PasswordProofTiming.NativeRead),
            ["history_read"] = Milliseconds(PasswordProofTiming.HistoryRead),
            ["history_check"] = Milliseconds(PasswordProofTiming.HistoryCheck),
            ["rule"] = Milliseconds(PasswordProofTiming.Rule),
            ["checkpoint"] = Milliseconds(PasswordProofTiming.Checkpoint),
            ["publication"] = Milliseconds(PasswordProofTiming.Publication),
            ["finalizer"] = Milliseconds(PasswordProofTiming.Finalizer),
            ["commit"] = Milliseconds(PasswordProofTiming.Commit),
        },
        ["verified_refs"] = verifiedRefs,
        ["verified_xml_bytes"] = verifiedXmlBytes,
        ["charged_refs"] = chargedRefs,
        ["charged_xml_bytes"] = chargedXmlBytes,
        ["read_attempts"] = new JsonObject
        {
            ["rejected"] = new JsonObject { ["native"] = nativeRequests.Rejected.ToJson(), ["history"] = historyRequests.Rejected.ToJson() },
            ["committed"] = committed
                ? new JsonObject { ["native"] = nativeRequests.Candidate.ToJson(), ["history"] = historyRequests.Candidate.ToJson() }
                : null,
        },
        ["attempt_elapsed_ms"] = (long)attemptElapsed.TotalMilliseconds,
        ["max_attempt_ms"] = (long)maxAttempt.TotalMilliseconds,
        ["invocation_elapsed_ms"] = (long)clock.GetElapsedTime(invocationStarted).TotalMilliseconds,
        ["committed"] = committed,
    };

    private readonly record struct ReadTotals(int Calls, long Rows, TimeSpan Duration, int Repeats, int Untracked)
    {
        public static ReadTotals operator +(ReadTotals left, ReadTotals right) =>
            new(left.Calls + right.Calls, left.Rows + right.Rows, left.Duration + right.Duration,
                left.Repeats + right.Repeats, left.Untracked + right.Untracked);

        public static ReadTotals operator -(ReadTotals left, ReadTotals right) =>
            new(left.Calls - right.Calls, left.Rows - right.Rows, left.Duration - right.Duration,
                left.Repeats - right.Repeats, left.Untracked - right.Untracked);

        internal JsonObject ToJson() => new()
        {
            ["calls"] = Calls, ["rows"] = Rows, ["ms"] = (long)Duration.TotalMilliseconds,
            ["repeats"] = Repeats, ["untracked"] = Untracked,
        };
    }

    private sealed class ReadMetrics(int maxHashedBytes)
    {
        private const int MaxTrackedRequests = 512;
        private readonly HashSet<(ulong, ulong, ulong, ulong)> fingerprints = [];
        private int hashedBytes, repeats, untracked;
        private ReadTotals start;
        internal ReadTotals Rejected { get; private set; }
        internal ReadTotals Candidate { get; private set; }

        internal void Record(string serialized)
        {
            if (serialized.Length > (maxHashedBytes - hashedBytes) / sizeof(char))
            {
                untracked++;
                return;
            }

            // Hash a view over the bound argument, without retaining the request,
            // serializing it again or copying its bytes.
            ReadOnlySpan<byte> bytes = MemoryMarshal.AsBytes(serialized.AsSpan());
            hashedBytes += bytes.Length;
            Span<byte> digest = stackalloc byte[32];
            _ = SHA256.HashData(bytes, digest);
            var words = MemoryMarshal.Cast<byte, ulong>(digest);
            var fingerprint = (words[0], words[1], words[2], words[3]);
            if (fingerprints.Contains(fingerprint))
                repeats++;
            else if (fingerprints.Count < MaxTrackedRequests)
                fingerprints.Add(fingerprint);
            else
                untracked++;
        }

        internal void Start(int calls, long rows, TimeSpan duration) => start = new(calls, rows, duration, repeats, untracked);

        internal void Finish(int calls, long rows, TimeSpan duration, bool rejected)
        {
            var current = new ReadTotals(calls, rows, duration, repeats, untracked) - start;
            if (rejected)
                Rejected += current;
            else
                Candidate = current;
        }
    }

    internal static void Write(JsonObject? report, TextWriter sink)
    {
        if (report == null) return;
        try { sink.WriteLine("password_producer_retained_proof:" + report.ToJsonString()); }
        catch (IOException) { } // Telemetry must not change the committed outcome.
        catch (ObjectDisposedException) { }
    }
}
