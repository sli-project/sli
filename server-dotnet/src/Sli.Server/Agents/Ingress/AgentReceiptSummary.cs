using System.Text.Json.Nodes;

namespace Sli.Server.Agents.Ingress;

// Compact transport ledger, not a replacement for an event's own packet proof.
internal static class AgentReceiptSummary
{
    // to_jsonb keeps reads compatible with installations awaiting the new column.
    internal const string LatestSql = """
        select envelope from (
          (select envelope from public.sli_agent_receipts where agent_id=@agent and module_id=@module order by sequence desc limit 1)
          union all
          select to_jsonb(a)->'receipt_summary'->@module->'last_envelope' from public.sli_agents a where id=@agent
          union all
          select to_jsonb(a)->'packet_expiry'->@module->'expired_envelope' from public.sli_agents a where id=@agent
          union all
          select runtime_resume->@module from public.sli_agents where id=@agent
        ) tips where envelope is not null order by (envelope->>'sequence')::bigint desc limit 1
        """;

    internal static JsonObject Merge(JsonObject? prior, IEnumerable<JsonObject> receipts)
    {
        var result = prior?.DeepClone().AsObject() ?? new JsonObject {
            ["contract"] = "sli.agent-receipt-summary.v1", ["ranges"] = new JsonArray(),
            ["gap_ranges"] = new JsonArray(), ["missing_ranges"] = new JsonArray(), ["receipt_count"] = 0L
        };
        var rows = receipts.ToArray();
        result["ranges"] = Ranges(result["ranges"]!.AsArray(), rows.Select(r => r["sequence"]!.GetValue<long>()));
        result["gap_ranges"] = Ranges(result["gap_ranges"]!.AsArray(), rows.Where(r =>
            r["envelope"]?["continuity_state"]?.ToString() == "gap" || r["envelope"]?["lost_count"]?.ToString() is { } lost && lost != "0")
            .Select(r => r["sequence"]!.GetValue<long>()));
        result["has_declared_gaps"] = result["gap_ranges"]!.AsArray().Count > 0;
        result["missing_ranges"] = Ranges(result["missing_ranges"]!.AsArray(), rows.Where(r =>
            r["previous_sequence"]!.GetValue<long>() < r["sequence"]!.GetValue<long>() - 1).Select(r =>
            (First: r["previous_sequence"]!.GetValue<long>() + 1, Last: r["sequence"]!.GetValue<long>() - 1)));
        result["has_sequence_gaps"] = result["missing_ranges"]!.AsArray().Count > 0;
        result["receipt_count"] = result["receipt_count"]!.GetValue<long>() + rows.LongLength;
        foreach (var row in rows) {
            long sequence = row["sequence"]!.GetValue<long>();
            if (result["last_envelope"] is not JsonObject last || sequence > last["sequence"]!.GetValue<long>())
                result["last_envelope"] = row["envelope"]!.DeepClone();
        }
        return result;
    }

    static JsonArray Ranges(JsonArray prior, IEnumerable<long> sequences)
        => Ranges(prior, sequences.Select(s => (First: s, Last: s)));

    static JsonArray Ranges(JsonArray prior, IEnumerable<(long First, long Last)> ranges)
    {
        var spans = prior.Select(r => (First: r![0]!.GetValue<long>(), Last: r[1]!.GetValue<long>()))
            .Concat(ranges).OrderBy(r => r.First);
        var merged = new List<(long First, long Last)>();
        foreach (var span in spans) {
            if (merged.Count == 0 || merged[^1].Last != long.MaxValue && span.First > merged[^1].Last + 1) merged.Add(span);
            else merged[^1] = (merged[^1].First, Math.Max(merged[^1].Last, span.Last));
        }
        return new JsonArray(merged.Select(r => (JsonNode)new JsonArray(JsonValue.Create(r.First), JsonValue.Create(r.Last))).ToArray());
    }
}
