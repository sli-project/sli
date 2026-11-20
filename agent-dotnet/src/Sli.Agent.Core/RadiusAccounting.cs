using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Only the exact legacy 66-column NPS format can enter a packet; it has no secret/password columns.</summary>
public static class RadiusAccountingRecord
{
    public static void Validate(string line) => _ = ParseFields(line);

    public static IReadOnlyList<string> ParseFields(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) throw new AgentException("record_required");
        if (JsonRead.CodePoints(line) > 65536) throw new AgentException("record_too_large");
        if (line.IndexOfAny(['\0', '\n', '\r']) >= 0) throw new AgentException("single_text_record_required");
        var fields = new List<string>();
        var value = new StringBuilder();
        var quoted = false;
        var closed = false;
        var first = true;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c != '"') value.Append(c);
                else if (i + 1 < line.Length && line[i + 1] == '"') { value.Append('"'); i++; }
                else { quoted = false; closed = true; }
            }
            else if (c == ',') { fields.Add(value.ToString()); value.Clear(); closed = false; first = true; }
            else if (closed) throw new AgentException("invalid_csv");
            else if (c == '"' && first) { quoted = true; first = false; }
            else { value.Append(c); first = false; }
        }
        if (quoted) throw new AgentException("invalid_csv");
        fields.Add(value.ToString());
        var services = new[] { "ias", "nps", "ras", "routing and remote access service" };
        if (fields.Count != 66 || !services.Contains(fields[1].Trim().ToLowerInvariant()) || !PythonInt.TryParse(fields[4].Trim(), out var type)
            || !fields[4].Trim().EnumerateRunes().All(System.Text.Rune.IsDigit) || fields[4].Trim().Length == 0 || type < 0 || type > 255)
            throw new AgentException("database_compatible_shape_required");
        if (type == 4 && !new[] { "1", "2", "3", "7", "8" }.Contains(fields[31].Trim())) throw new AgentException("accounting_status_unsupported_or_missing");
        return fields.AsReadOnly();
    }
}

public interface IRadiusTailSource
{
    RadiusTailBatch Read(string directory, RadiusCursor cursor, int maximumRecords, bool allowExactBoundaryRecovery);
}

public sealed class RadiusAccountingModule(string hostId, NpsPolicy policy, IRadiusTailSource source)
{
    public Sample Collect(CapturedPosition? captured, DateTimeOffset now)
    {
        if (!policy.Active) throw new AgentException("agent_module_paused");
        if (captured is not null && captured.Generation != hostId) throw new AgentException("agent_radius_cursor_invalid");
        var before = captured?.CursorAfter ?? Cursor.Start("file_offset");
        if (before.Strategy != "file_offset") throw new AgentException("agent_radius_cursor_invalid");
        var previous = before.Token.Length == 0 ? policy.Value["initial_cursor"]!.AsObject() : RadiusCursor.Token(before, "file_offset", "agent_radius_cursor_invalid");
        var cursor = RadiusCursor.Parse(previous);
        var initial = RadiusCursor.Parse(policy.Value["initial_cursor"]);
        if (cursor.SourceId != initial.SourceId || cursor.StreamId != initial.StreamId || cursor.TransportBinding != initial.TransportBinding) throw new AgentException("agent_radius_cursor_invalid");
        var recovery = previous["exact_boundary_recovery"]?.GetValue<bool>() ?? true;
        RadiusTailBatch tail;
        try { tail = source.Read(policy.Text("accounting_directory"), cursor, policy.BatchSize, recovery); }
        catch (AgentException e) when (!recovery && e.Code is "tail_cursor_generation_not_found" or "tail_accounting_file_not_observed")
        { throw new AgentException("tail_recovery_unanchored_generation"); }
        foreach (var line in tail.Records) RadiusAccountingRecord.Validate(line);
        var context = new JsonObject
        {
            ["source_timezone_id"] = policy.Text("source_timezone_id"), ["source_utc_offset_minutes"] = policy.Value["source_utc_offset_minutes"]!.DeepClone(),
            ["candidate_count"] = tail.CandidateCount, ["bytes_read"] = tail.BytesRead, ["partial_trailing_bytes"] = tail.PartialTrailingBytes,
            ["rotation_backlog_generations"] = tail.RotationBacklogGenerations, ["cursor_generation_recovered"] = tail.CursorGenerationRecovered,
        };
        var emptyProgress = tail.Records.Count == 0 && (tail.EndOffset > tail.StartOffset || tail.PreviousGenerationEof);
        if (emptyProgress) context["empty_progress_v1"] = new JsonObject { ["skipped_bytes"] = tail.EndOffset - tail.StartOffset, ["physical_lines"] = tail.PhysicalLines };
        var payload = CollectionPacket.Make(cursor.SourceId, cursor.StreamId, tail.FileGeneration,
            new JsonObject { ["before"] = cursor.ToJson(), ["start_offset"] = tail.StartOffset, ["end_offset"] = tail.EndOffset },
            tail.Records.Select(line => new PacketRecord("accounting_line", null, JsonValue.Create(line)!)).ToList(), "complete", context, now);
        payload["continuity"]!["previous_generation_eof"] = tail.PreviousGenerationEof;
        if (CanonicalJson.Length(payload) > NpsPolicy.MaxPayloadBytes) throw new AgentException("agent_radius_size_limit");
        var updated = tail.Records.Count > 0 || emptyProgress ? cursor with
        {
            FileGeneration = tail.FileGeneration, ByteOffset = tail.EndOffset,
            LastRecordSha256 = tail.Records.Count > 0 ? NpsModule.Hash(tail.Records[^1]) : cursor.LastRecordSha256,
        } : cursor;
        var value = updated.ToJson();
        if (tail.Records.Count > 0)
        {
            if (previous.ContainsKey("exact_boundary_recovery")) value["exact_boundary_recovery"] = true;
        }
        else if (before.Token.Length == 0 && cursor.ByteOffset == 0 || emptyProgress && tail.FileGeneration != cursor.FileGeneration)
            value["exact_boundary_recovery"] = false;
        else if (previous.ContainsKey("exact_boundary_recovery")) value["exact_boundary_recovery"] = recovery;
        return new(NpsPolicy.Accounting, cursor.SourceId, cursor.StreamId, hostId, before, new("file_offset", CanonicalJson.Serialize(value)), payload,
            PolicyRevision: policy.Revision, ContinuityState: "not_proven", LostCount: 0);
    }
}
