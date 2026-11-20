using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// Persistence of an already authorized report; the caller owns the transaction.
public static class AdComputersReportSnapshot
{
    public static async Task<JsonObject> PersistAsync(NpgsqlConnection db, JsonObject report, long domainId, DateTimeOffset capturedAt, CancellationToken ct)
    {
        string? state = report.Text("state");
        if (state is not ("available" or "empty" or "partial" or "stale")) throw new InvalidOperationException("snapshot_source_not_usable");
        if (report.Text("contract_id") != "sli.computers-report.v6") throw new InvalidOperationException("snapshot_contract_mismatch");
        capturedAt = capturedAt.ToUniversalTime();
        var payload = new JsonObject();
        foreach (string key in new[] { "contract_id", "report_key", "state" }) payload[key] = report[key]?.DeepClone();
        payload["captured_at_utc"] = capturedAt.ToString(capturedAt.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
        foreach (string key in new[] { "threshold", "coverage", "summary", "semantic" }) payload[key] = report[key]?.DeepClone() ?? new JsonObject();
        payload["items"] = report["items"]?.DeepClone() ?? new JsonArray();
        int count = payload["items"]!.AsArray().Count;
        long threshold = report["threshold"].Int("selected_days");
        var scope = Obj(new { domain_ids = new[] { domainId }, report_key = "ad.computers.v6", threshold_days = threshold == 0 ? 60 : threshold });
        string hash = AdJobPlugin.Digest(payload);
        Guid? runId = null;
        foreach (var row in report["coverage"]?["domains"]?.AsArray() ?? new JsonArray())
            if (row.Int("domain_id") == domainId) { runId = row.Text("run_id") is {} run ? Guid.Parse(run) : null; break; }
        DateTimeOffset? observed = report["coverage"].Text("latest_observed_at_utc") is {} stamp ? DateTimeOffset.Parse(stamp, CultureInfo.InvariantCulture).ToUniversalTime() : null;
        var bucket = new DateTimeOffset(capturedAt.Year, capturedAt.Month, capturedAt.Day, capturedAt.Hour >= 12 ? 12 : 0, 0, 0, TimeSpan.Zero);
        await using var insert = new NpgsqlCommand("""
            insert into computers_report_v6_snapshots(
                domain_id,source_run_id,contract_id,scope_json,scope_sha256,
                bucket_start_utc,captured_at_utc,source_observed_at_utc,object_count,
                payload_json,payload_sha256,source_state)
            values(@domain,@run,'sli.computers-report.v6',@scope,decode(@scopeHash,'hex'),
                @bucket,@captured,@observed,@count,@payload,decode(@hash,'hex'),@state)
            on conflict(domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version)
            do nothing returning snapshot_id
            """, db) { CommandTimeout = 0 };
        insert.Parameters.AddWithValue("domain", domainId);
        insert.Parameters.AddWithValue("run", NpgsqlDbType.Uuid, (object?)runId ?? DBNull.Value);
        insert.Parameters.AddWithValue("scope", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(scope, false));
        insert.Parameters.AddWithValue("scopeHash", AdJobPlugin.Digest(scope));
        insert.Parameters.AddWithValue("bucket", bucket);
        insert.Parameters.AddWithValue("captured", capturedAt);
        insert.Parameters.AddWithValue("observed", NpgsqlDbType.TimestampTz, (object?)observed ?? DBNull.Value);
        insert.Parameters.AddWithValue("count", count);
        insert.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(payload, false));
        insert.Parameters.AddWithValue("hash", hash);
        insert.Parameters.AddWithValue("state", state);
        if (await insert.ExecuteScalarAsync(ct) is not long id)
            return Obj(new { status = "already_captured", object_count = count, retired_snapshots = 0 });
        await using (var read = new NpgsqlCommand("select object_count,encode(payload_sha256,'hex') from computers_report_v6_snapshots where snapshot_id=@id", db) { CommandTimeout = 0 })
        {
            read.Parameters.AddWithValue("id", id);
            await using var reader = await read.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || reader.GetInt32(0) != count || reader.GetString(1) != hash)
                throw new InvalidOperationException("snapshot_readback_mismatch");
        }
        await using var retire = new NpgsqlCommand("delete from computers_report_v6_snapshots where captured_at_utc < @cutoff", db) { CommandTimeout = 0 };
        retire.Parameters.AddWithValue("cutoff", capturedAt.AddDays(-365));
        int retired = await retire.ExecuteNonQueryAsync(ct);
        return Obj(new { status = "captured", snapshot_id = id, object_count = count, retired_snapshots = Math.Max(0, retired) });
    }
}
