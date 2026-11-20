using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;

namespace Sli.Server.Storage.History;

// Blocks must be selected by the manifest owner using source per-ID supersession order.
internal sealed class EventArchiveHydrator(ArchiveReader reader)
{
    internal async Task<Dictionary<long,JsonObject>> ReadWithAgentPacketsAsync(IReadOnlyList<ArchiveBlock> blocks,
        IReadOnlyDictionary<long,JsonObject> summaries,Func<JsonObject,CancellationToken,Task<JsonObject?>> loadPacket,CancellationToken ct,bool exact=false)
    {
        // Finish archive integrity verification before opening any fallback source.
        var result = ReadCancellable(blocks,summaries,ct,exact,packetFallback:true);
        foreach (var (id,summary) in summaries) if (result[id]["source_payload_state"]?.ToString()=="archive_unavailable") {
            var packet = await loadPacket(summary,ct);
            if (packet is not null) { EventDetailIdentity.Verify(summary,packet); result[id]=packet; }
            else if (!exact && !blocks.Any(b=>b.FirstId<=id && b.LastId>=id)) throw new InvalidDataException("event_archive_payload_missing");
        }
        return result;
    }
    internal Dictionary<long,JsonObject> Read(IReadOnlyList<ArchiveBlock> blocks, IReadOnlyDictionary<long,JsonObject> summaries) => ReadCancellable(blocks,summaries,CancellationToken.None);
    internal Dictionary<long,JsonObject> ReadCancellable(IReadOnlyList<ArchiveBlock> blocks, IReadOnlyDictionary<long,JsonObject> summaries, CancellationToken ct,bool exact=false,bool packetFallback=false)
    {
        if (summaries.Count > 100 || summaries.Keys.Any(x => x <= 0)) throw new ArgumentOutOfRangeException(nameof(summaries));
        if (blocks.Count > 16) throw new InvalidDataException("event_archive_block_limit");
        var result = new Dictionary<long,JsonObject>();
        // The exact route degrades a missing manifest to its compact core. Batch
        // keeps the source's integrity error for an unpublished/missing payload.
        bool unavailable = exact && summaries.Count==1 && blocks.Count==0;
        foreach (var block in blocks)
        {
            ct.ThrowIfCancellationRequested();
            if (block.Kind != "event") throw new InvalidDataException("event_archive_kind_invalid");
            IReadOnlyList<JsonObject> rows;
            try { rows = reader.ReadBlockRowsCancellable(block,ct); }
            catch (EndOfStreamException error) { throw new InvalidDataException("archive_truncated_during_read",error); }
            catch (IOException) { unavailable = true; continue; }
            catch (InvalidDataException e) when (e.Message == "archive_object_outside_root") { unavailable = true; continue; }
            catch (UnauthorizedAccessException) { unavailable = true; continue; }
            foreach (var row in rows)
            {
                ct.ThrowIfCancellationRequested();
                long id = ArchiveCodec.Id(row,"event");
                if (!summaries.TryGetValue(id,out var summary)) continue;
                if (result.ContainsKey(id)) throw new InvalidDataException("event_archive_duplicate");
                EventDetailIdentity.Verify(summary,row);
                var payload = (JsonObject)row.DeepClone(); payload["server"] = summary["server"]?.DeepClone();
                result.Add(id,payload);
            }
        }
        if (unavailable) foreach (var (id, summary) in summaries) if (!result.ContainsKey(id))
        { var fallback = (JsonObject)summary.DeepClone(); fallback["source_payload_state"] = "archive_unavailable"; result.Add(id,fallback); }
        if (packetFallback) foreach (var (id,summary) in summaries) if (!result.ContainsKey(id) && !blocks.Any(b=>b.FirstId<=id && b.LastId>=id))
        { var fallback=(JsonObject)summary.DeepClone(); fallback["source_payload_state"]="archive_unavailable"; result.Add(id,fallback); }
        if (result.Count != summaries.Count) throw new InvalidDataException("event_archive_payload_missing");
        ct.ThrowIfCancellationRequested();
        return result;
    }
}
