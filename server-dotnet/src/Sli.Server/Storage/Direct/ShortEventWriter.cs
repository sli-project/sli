using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Storage.Direct;

internal static class ShortEventWriter
{
    internal static async Task WriteAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        IReadOnlyList<ShortEventRow> rows, CancellationToken ct, bool genericEventLog = false)
    {
        if (rows.Count == 0) return;
        if (rows.Any(r => r.Layer is not ("fact" or "summary")))
            throw new InvalidDataException("short_event_layer_invalid");
        var payload = new JsonArray();
        foreach (var row in rows.DistinctBy(r => (r.Time, r.EventId))) {
            var method = JsonNode.Parse(row.Method)!.AsObject();
            method.Remove("$packet_id"); method.Remove("$packet_ordinal");
            if (row.PacketId is { } packet) {
                method["$packet_id"] = packet.ToString(); method["$packet_ordinal"] = row.PacketOrdinal;
            }
            payload.Add(new JsonObject {
                ["event_id"] = row.EventId, ["time_created_utc"] = row.Time, ["event_kind"] = row.Kind,
                ["domain_id"] = row.DomainId, ["actor"] = row.Actor, ["target"] = row.Target,
                ["source"] = row.Source, ["computer"] = row.Computer,
                ["method"] = method, ["outcome"] = JsonNode.Parse(row.Outcome),
                ["fields"] = JsonSerializer.SerializeToNode(row.Fields), ["layer"] = row.Layer
            });
        }
        string sql = genericEventLog ? "select * from public.write_generic_short_events388(@rows)"
            : "select * from public.write_short_events349(@rows)";
        string encoded = payload.ToJsonString();
        bool requireProof = rows.Any(r => r.PacketId is not null);
        async Task<bool> WriteOnceAsync()
        {
            await using var write = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
            write.Parameters.AddWithValue("rows", NpgsqlDbType.Jsonb, encoded);
            await using var result = await write.ExecuteReaderAsync(ct);
            if (!await result.ReadAsync(ct) || result.GetInt64(0) != result.GetInt64(1))
                throw new InvalidOperationException("short_event_summary_conflict");
            return !requireProof || result.GetInt64(2) == payload.Count;
        }
        if (await WriteOnceAsync()) return;
        // A concurrent generic insert can commit after the AD writer's UPDATE
        // snapshot but before its INSERT resolves the conflict. Reuse the exact
        // AD admission once with a fresh snapshot of that physical event.
        if (!genericEventLog)
        {
            await using var overlap = new NpgsqlCommand("""
                select exists(
                    select 1 from jsonb_array_elements(@rows) j
                    cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r
                    join public.event_hot h using(event_id,time_created_utc)
                    where h.source_sha256 is null and h.method#>>'{$origin,plugin_id}'='sli.windows-eventlog'
                )
                """, db, tx);
            overlap.Parameters.AddWithValue("rows", NpgsqlDbType.Jsonb, encoded);
            if (await overlap.ExecuteScalarAsync(ct) is true && await WriteOnceAsync()) return;
        }
        throw new InvalidOperationException("short_event_attestation_failed");
    }
}
