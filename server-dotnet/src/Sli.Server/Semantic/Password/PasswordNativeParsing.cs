namespace Sli.Server.Semantic.Password;

// This memo only reuses a deterministic managed parse after the caller supplies
// the raw input. SQL authorization and witness/byte/hash comparisons stay with
// the original reader. A failed savepoint never supplies proof for a later one.
internal sealed class PasswordNativeParsing(PasswordProofObservation observation, bool reuse = true)
{
    private const int MaxEntries = 10_000;
    private const int MaxPayloadBytes = 16 * 1024 * 1024;

    private readonly Dictionary<long, Entry> entries = new();
    private long payloadBytes;
    private readonly record struct Entry(PasswordNative Native, bool Normalized);

    internal PasswordNative Parse(PasswordScope scope, long id, string hash, int eventId,
        DateTimeOffset at, string raw, bool normalizeAccount)
    {
        bool hasEntry = entries.TryGetValue(id, out var entry);
        if (hasEntry)
        {
            var known = entry.Native;
            var witness = known.Witness;
            if (entry.Normalized == normalizeAccount && witness.Scope == scope && witness.Sha256 == hash &&
                known.EventId == eventId && witness.At == at && string.Equals(known.SourceXml, raw, StringComparison.Ordinal))
            {
                observation.ReuseParse();
                return known;
            }
        }

        observation.ParseNative();
        var parsed = PasswordNative.Parse(scope, id, hash, eventId, at, raw, normalizeAccount);
        long bytes = (long)raw.Length * sizeof(char);
        if (reuse && !hasEntry && entries.Count < MaxEntries && payloadBytes + bytes <= MaxPayloadBytes)
        {
            entries.Add(id, new(parsed, normalizeAccount));
            payloadBytes += bytes;
            observation.SizeParseMemo(entries.Count, payloadBytes);
        }
        return parsed;
    }
}
