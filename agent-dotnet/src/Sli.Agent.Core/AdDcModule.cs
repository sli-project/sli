using System.Numerics;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Where the previous capture of this module ended (read from the queue's checkpoint).</summary>
public sealed record CapturedPosition(string Generation, Cursor CursorAfter);

public sealed record CollectResult(Sample? Sample, string? CatchUpChannel);

/// <summary>
/// <c>sli.windows.ad-dc</c>: filtered capture of the DC channels behind one durable cursor and one sequence
/// The shared event meanings table bounds collection; a signed assignment may narrow it further.
/// </summary>
public sealed class AdDcModule(string hostId, AdDcConfig config, IEventLogSource source, EventCatalog catalog)
{
    public const string ModuleId = "sli.windows.ad-dc";
    public const string PackId = "sli.windows.ad-dc";
    public const string EnvelopeChannel = "ad-dc";

    public AdDcConfig Config { get; } = config;

    public CollectResult Collect(CapturedPosition? captured, DateTimeOffset now, string? channelOverride = null)
    {
        now = Iso8601.Truncate(now);
        var before = captured?.CursorAfter ?? Cursor.Start(DcCursor.Strategy);
        if (captured is not null && captured.Generation != hostId) throw new AgentException("agent_ad_dc_cursor_invalid");
        var state = DcCursor.Parse(before);
        var order = Config.RotationChannels;
        var enabled = order.Where(channel => Config.Channels[channel]).ToList();
        if (enabled.Count == 0) return new CollectResult(null, null);

        var count = order.Count;
        if (state.Next >= count) throw new AgentException("agent_ad_dc_cursor_invalid");
        var index = Enumerable.Range(0, count).Select(offset => (state.Next + offset) % count)
            .First(candidate => enabled.Contains(order[candidate]));
        if (channelOverride is not null)
        {
            if (!enabled.Contains(channelOverride)) throw new AgentException("agent_ad_dc_channel_invalid");
            index = order.ToList().IndexOf(channelOverride);
        }
        var channel = order[index];
        var generation = Config.ChannelGenerations.TryGetValue(channel, out var configured) ? configured : hostId;
        var known = state.Progress.TryGetValue(channel, out var existing);
        var progress = known ? existing! : ChannelProgress.Start(generation);
        var reset = progress.Generation != generation;
        if (reset) progress = ChannelProgress.Start(generation);
        if ((!known || reset) && Config.InitialReadHours is { } hours)
            progress = progress with { SinceUtc = Iso8601.Format(now - TimeSpan.FromHours(hours)) };

        var afterId = progress.RecordId;
        string? readError = null;
        SourceBatch batch;
        try
        {
            batch = source.Read(channel, progress, Config.BatchSize);
        }
        catch (EventLogReadException)
        {
            batch = new SourceBatch([]);
            readError = "agent_ad_dc_read_failed";
        }
        if (batch.Rows.Count > Config.BatchSize) throw new AgentException("agent_ad_dc_range_invalid");

        var records = new List<PacketRecord>();
        var recordBytes = 2; // Canonical array brackets; add each record and its comma once.
        long filtered = 0;
        var payloadFull = false;
        long? previous = afterId;
        foreach (var row in batch.Rows)
        {
            var parsed = EventXml.Parse(row.Xml, Config.SourceName, Config.ConnectAddress, channel);
            if (!JsonRead.TryInteger(parsed["record_id"], out var recordId) || recordId <= 0 || recordId > long.MaxValue
                || previous is { } last && recordId <= last
                || row.Bookmark.Length == 0 || JsonRead.CodePoints(row.Bookmark) > ChannelProgress.MaxBookmarkCodePoints)
            {
                throw new AgentException("agent_ad_dc_range_invalid");
            }
            previous = (long)recordId;
            if (EventXml.NativeChannel(EventXml.ParseBounded(row.Xml)) != channel) throw new AgentException("agent_ad_dc_channel_invalid");

            JsonRead.TryInteger(parsed["event_id"], out var eventId);
            BigInteger? eventIdValue = JsonRead.TryInteger(parsed["event_id"], out _) ? eventId : null;
            var allowed = Config.AllowEventIds is null || eventIdValue is { } id && id >= int.MinValue && id <= int.MaxValue && Config.AllowEventIds.Contains((int)id);
            if (allowed && catalog.AcceptsPayload(parsed))
            {
                var node = new JsonObject
                {
                    ["format"] = "event_xml",
                    ["record_id"] = JsonRead.Integer(recordId),
                    ["payload"] = parsed.DeepClone(),
                };
                // The wire budget is checked on the records list alone, before the rest of the packet is added.
                var addedBytes = CanonicalJson.Length(node) + (records.Count > 0 ? 1 : 0);
                if (recordBytes + addedBytes > AdDcConfig.MaxPayloadBytes - 4096)
                {
                    if (records.Count == 0) throw new AgentException("agent_ad_dc_event_size_limit");
                    payloadFull = true;
                    break;
                }
                records.Add(new PacketRecord("event_xml", recordId, parsed));
                recordBytes += addedBytes;
            }
            else
            {
                filtered++;
            }
            progress = progress with { RecordId = (long)recordId, Bookmark = row.Bookmark, Generation = generation };
        }

        state.Progress[channel] = progress;
        state.Next = (index + 1) % count;
        var catchUp = readError is null && (payloadFull || batch.Rows.Count == Config.BatchSize) ? channel : null;
        var after = state.ToCursor();

        var context = new JsonObject
        {
            ["ad_dc"] = new JsonObject
            {
                ["pack_id"] = PackId,
                ["policy_revision"] = Config.PolicyRevision,
                ["filtered_count"] = filtered,
                ["channel_reset"] = reset,
                ["read_error"] = readError,
                ["channels"] = Config.ToJson()["channels"]!.DeepClone(),
                ["channel_generations"] = Config.ToJson()["channel_generations"]!.DeepClone(),
            },
        };
        if (batch.BookmarkRecovered) context["ad_dc"]!["bookmark_recovered"] = true;
        var cursor = new JsonObject
        {
            ["after_record_id"] = afterId is { } start ? JsonValue.Create(start) : null,
            ["last_record_id"] = progress.RecordId is { } end ? JsonValue.Create(end) : null,
        };
        var payload = CollectionPacket.Make(Config.SourceName, channel, generation, cursor, records, "not_proven", context, now);
        if (CanonicalJson.Length(payload) > AdDcConfig.MaxPayloadBytes) throw new AgentException("agent_ad_dc_event_size_limit");

        var gap = reset || readError is not null || batch.BookmarkRecovered;
        var sample = new Sample(ModuleId, hostId, EnvelopeChannel, hostId, before, after, payload,
            PolicyRevision: Config.PolicyRevision,
            ContinuityState: gap ? "gap" : filtered > 0 ? "filtered" : "not_proven",
            FilteredCount: filtered,
            LostCount: gap ? null : 0);
        return new CollectResult(sample, catchUp);
    }
}
