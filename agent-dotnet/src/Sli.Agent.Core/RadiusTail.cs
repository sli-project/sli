using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

// Metadata and opaque keys stay inside the source boundary; no path/name is sent in packets or errors.
public sealed record RadiusFile(string Key, string Name, long CreationTimeNs, long ModifiedTimeNs, long Size, string Device, string FileId, bool ReparsePoint = false);
public interface IRadiusReadFile : IDisposable
{
    RadiusFile Metadata { get; }
    byte[] Read(long offset, int count);
}
public interface IRadiusFileSystem
{
    IEnumerable<RadiusFile> Inventory(string directory);
    IRadiusReadFile Open(RadiusFile file);
}
public sealed record RadiusTailBatch(string FileGeneration, long StartOffset, long EndOffset, bool PreviousGenerationEof,
    IReadOnlyList<string> Records, int CandidateCount, int BytesRead, int PartialTrailingBytes,
    bool CursorGenerationRecovered = false, int RotationBacklogGenerations = 0, int PhysicalLines = 0);

/// <summary>Bounded read-only port of sli_collect.radius_tail, including empty progress and recovery fences.</summary>
public sealed class RadiusTailSource(IRadiusFileSystem files) : IRadiusTailSource
{
    public const int MaximumCandidates = 20;
    public const int MaximumReadBytes = 4 * 1024 * 1024;
    public const int MaximumRecordBytes = 65536;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private sealed record Candidate(RadiusFile File, string Generation);
    // NPS uses ASCII in*.log names. Casefold also covers common non-ASCII expansions in supplied names.
    private static string Fold(string text) => text.ToLowerInvariant().Replace("ß", "ss", StringComparison.Ordinal).Replace("ς", "σ", StringComparison.Ordinal);
    public static string DeriveGeneration(string sourceId, string name, long creationTimeNs) =>
        "gen-" + NpsModule.Hash(Fold(sourceId) + "\0" + Fold(name) + "\0" + creationTimeNs.ToString(CultureInfo.InvariantCulture))[..32];

    public RadiusTailBatch Read(string directory, RadiusCursor cursor, int maximumRecords, bool allowExactBoundaryRecovery)
    {
        if (maximumRecords is < 1 or > 1000) throw new AgentException("tail_record_limit_changed");
        var candidates = new List<Candidate>();
        try
        {
            foreach (var file in files.Inventory(directory))
            {
                var name = Fold(file.Name);
                if (!name.StartsWith("in", StringComparison.Ordinal) || !name.EndsWith(".log", StringComparison.Ordinal)) continue;
                if (file.ReparsePoint) throw new AgentException("tail_reparse_point_forbidden");
                candidates.Add(new(file, DeriveGeneration(cursor.SourceId, file.Name, file.CreationTimeNs)));
                if (candidates.Count > MaximumCandidates) throw new AgentException("tail_candidate_limit_exceeded");
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new AgentException("tail_inventory_failed"); }
        if (candidates.Count == 0) throw new AgentException("tail_accounting_file_not_observed");
        var current = candidates.FirstOrDefault(c => c.Generation == cursor.FileGeneration);
        var recoveryBytes = 0;
        var recovered = false;
        if (current is null)
        {
            if (!allowExactBoundaryRecovery) throw new AgentException("tail_cursor_generation_not_found");
            (current, recoveryBytes) = Recover(candidates, cursor);
            current = current with { Generation = cursor.FileGeneration };
            recovered = true;
        }
        if (current.File.Size < cursor.ByteOffset) throw new AgentException("tail_cursor_past_eof");
        var selected = current;
        var start = cursor.ByteOffset;
        var newer = new List<Candidate>();
        if (current.File.Size == start)
        {
            newer = candidates.Where(c => c.File.Key != current.File.Key && Compare(c, current) > 0).Order(Comparer<Candidate>.Create(Compare)).ToList();
            if (newer.Count > 0) { selected = newer[0]; start = 0; }
        }
        var rotated = newer.Count > 0;
        var budget = MaximumReadBytes - recoveryBytes;
        if (budget < 1) throw new AgentException("tail_recovery_exhausted_byte_budget");
        var payload = ReadBytes(selected.File, start, (int)Math.Min(budget, Math.Max(0, selected.File.Size - start)), false);
        var newlines = Enumerable.Range(0, payload.Length).Where(i => payload[i] == 10).ToList();
        if (newlines.Count == 0)
        {
            if (payload.Length > MaximumRecordBytes) throw new AgentException("tail_record_too_large");
            return new(selected.Generation, start, start, rotated, [], candidates.Count, recoveryBytes + payload.Length, payload.Length, recovered, Math.Max(0, newer.Count - 1));
        }
        var boundary = newlines[Math.Min(maximumRecords, newlines.Count) - 1];
        var records = new List<string>();
        var consumed = 0;
        var wireBytes = 0;
        var stopped = false;
        foreach (var physical in SplitLines(payload.AsMemory(0, boundary + 1)))
        {
            var raw = physical.Span;
            while (raw.Length > 0 && raw[^1] is 10 or 13) raw = raw[..^1];
            if (Blank(raw)) { consumed += physical.Length; continue; }
            if (raw.Length > MaximumRecordBytes) throw new AgentException("tail_record_too_large");
            string text;
            try { text = Decode(raw); }
            catch (DecoderFallbackException) { throw new AgentException("tail_record_encoding_invalid"); }
            var size = CanonicalJson.Length(JsonValue.Create(text)) + 100;
            if (wireBytes + size > NpsPolicy.MaxPayloadBytes - 4096)
            {
                if (records.Count == 0) throw new AgentException("tail_record_payload_limit_exceeded");
                boundary = consumed - 1; stopped = true; break;
            }
            records.Add(text); wireBytes += size; consumed += physical.Length;
        }
        if (records.Count > maximumRecords) throw new AgentException("tail_record_limit_exceeded");
        var trailing = payload.Length - boundary - 1;
        if (newlines.Count < maximumRecords && trailing > MaximumRecordBytes && !stopped) throw new AgentException("tail_record_too_large");
        return new(selected.Generation, start, start + boundary + 1, rotated, records, candidates.Count, recoveryBytes + payload.Length,
            trailing, recovered, Math.Max(0, newer.Count - 1), payload.Take(boundary + 1).Count(b => b == 10));
    }

    private static int Compare(Candidate a, Candidate b)
    {
        var result = a.File.ModifiedTimeNs.CompareTo(b.File.ModifiedTimeNs);
        if (result == 0) result = StringComparer.Ordinal.Compare(Fold(a.File.Name), Fold(b.File.Name));
        if (result == 0) result = a.File.CreationTimeNs.CompareTo(b.File.CreationTimeNs);
        if (result == 0) result = StringComparer.Ordinal.Compare(a.Generation, b.Generation);
        return result;
    }
    private byte[] ReadBytes(RadiusFile candidate, long start, int count, bool recovery)
    {
        try
        {
            using var opened = files.Open(candidate);
            var actual = opened.Metadata;
            if (actual.ReparsePoint) throw new AgentException("tail_reparse_point_forbidden");
            if (actual.Device != candidate.Device || actual.FileId != candidate.FileId) throw new AgentException(recovery ? "tail_file_replaced_during_recovery" : "tail_file_replaced_during_open");
            if (!recovery && actual.Size < candidate.Size) throw new AgentException("tail_file_truncated_during_open");
            if (actual.Size < start + count)
            {
                if (recovery) return [];
                if (actual.Size < start) throw new AgentException("tail_cursor_past_eof");
            }
            var bytes = opened.Read(start, count);
            if (bytes.Length > count) throw new AgentException("tail_file_read_failed");
            return bytes;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new AgentException(recovery ? "tail_recovery_read_failed" : "tail_file_read_failed"); }
    }
    private (Candidate, int) Recover(List<Candidate> candidates, RadiusCursor cursor)
    {
        if (cursor.LastRecordSha256 is null || cursor.LastRecordSha256.Length != 64) throw new AgentException("tail_recovery_last_hash_required");
        var matches = new List<Candidate>();
        var bytesRead = 0;
        foreach (var candidate in candidates)
        {
            if (candidate.File.Size < cursor.ByteOffset) continue;
            var length = (int)Math.Min(cursor.ByteOffset, MaximumRecordBytes + 1);
            var bytes = ReadBytes(candidate.File, cursor.ByteOffset - length, length, true);
            bytesRead += bytes.Length;
            if (bytes.Length == 0 || bytes[^1] != 10) continue;
            var lines = SplitLines(bytes).Where(line => !Blank(line.Span)).ToList();
            if (lines.Count == 0) continue;
            try
            {
                var raw = lines[^1].Span;
                while (raw.Length > 0 && raw[^1] is 10 or 13) raw = raw[..^1];
                var line = Decode(raw);
                RadiusAccountingRecord.Validate(line);
                if (NpsModule.Hash(line) == cursor.LastRecordSha256) matches.Add(candidate);
            }
            catch (Exception e) when (e is DecoderFallbackException or AgentException) { }
        }
        if (matches.Count == 0) throw new AgentException("tail_recovery_boundary_not_found");
        if (matches.Count != 1) throw new AgentException("tail_recovery_boundary_ambiguous");
        if (bytesRead >= MaximumReadBytes) throw new AgentException("tail_recovery_exhausted_byte_budget");
        return (matches[0], bytesRead);
    }
    private static bool Blank(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes) if (b is not (9 or 10 or 11 or 12 or 13 or 32)) return false;
        return true;
    }
    private static string Decode(ReadOnlySpan<byte> bytes) => StrictUtf8.GetString(bytes.StartsWith(new byte[] { 239, 187, 191 }) ? bytes[3..] : bytes);
    private static List<ReadOnlyMemory<byte>> SplitLines(ReadOnlyMemory<byte> payload)
    {
        var lines = new List<ReadOnlyMemory<byte>>();
        var start = 0;
        for (var i = 0; i < payload.Length; i++)
        {
            if (payload.Span[i] is not (10 or 13)) continue;
            if (payload.Span[i] == 13 && i + 1 < payload.Length && payload.Span[i + 1] == 10) i++;
            lines.Add(payload[start..(i + 1)]); start = i + 1;
        }
        if (start < payload.Length) lines.Add(payload[start..]);
        return lines;
    }
}
