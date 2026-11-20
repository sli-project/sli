using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;
using static Sli.Server.Agents.SnapshotPublication.AdContextStore;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdSourceSnapshots
{
    internal static async Task<string> UsersAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, JsonObject payload, CancellationToken ct)
    {
        DateTime stamp = Time(payload["metadata"]!["observed_at"]); var scope = new JsonObject { ["domain_ids"] = new JsonArray(JsonValue.Create(domain)), ["report_key"] = "ad.users.v2" };
        byte[] hash = GpoIdentityWriter.Hash(payload, false), scopeHash = GpoIdentityWriter.Hash(scope, false);
        await Execute(db, tx, """
            insert into users_report_v2_snapshots(domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            values(@domain,'sli.users-report.v2',@scope::jsonb,@scope_hash,@bucket,@stamp,@stamp,@state,@count,@payload::jsonb,@hash)
            on conflict(domain_id,scope_sha256,source_observed_at_utc,contract_id,schema_version) do nothing
            """, ct, ("domain", domain), ("scope", scope.ToJsonString()), ("scope_hash", scopeHash), ("bucket", stamp.Date.AddHours(stamp.Hour >= 12 ? 12 : 0)), ("stamp", stamp), ("state", Text(payload["metadata"]!["collection_status"])), ("count", payload["users"]!.AsArray().Count), ("payload", payload.ToJsonString()), ("hash", hash));
        await using var c = Command(db, tx, "select snapshot_id,payload_sha256,user_count from users_report_v2_snapshots where domain_id=@domain and scope_sha256=@scope and source_observed_at_utc=@stamp and contract_id='sli.users-report.v2'", ("domain", domain), ("scope", scopeHash), ("stamp", stamp));
        await using var r = await c.ExecuteReaderAsync(ct); Require(await r.ReadAsync(ct) && ((byte[])r.GetValue(1)).AsSpan().SequenceEqual(hash) && Convert.ToInt32(r.GetValue(2)) == payload["users"]!.AsArray().Count);
        string id = Convert.ToInt64(r.GetValue(0)).ToString(System.Globalization.CultureInfo.InvariantCulture); Require(!await r.ReadAsync(ct)); return id;
    }
    internal static async Task<string> ComputersAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain, JsonObject payload, JsonObject policy, CancellationToken ct)
    {
        var m = payload["metadata"]!.AsObject(); Guid id = Guid.Parse(Text(m["snapshot_id"])); DateTime stamp = Time(m["completed_at"]);
        var flags = policy["expensive_flags"]!.AsObject();
        var options = new JsonObject { ["server"] = m["query_dc"]!.DeepClone(), ["search_base"] = m["search_base"]?.DeepClone(), ["skip_dns"] = flags["dns"]?.GetValue<bool>() != true, ["collect_ad_site"] = flags["ad_site"]?.GetValue<bool>() == true, ["collect_exact_last_logon"] = flags["exact_last_logon"]?.GetValue<bool>() == true };
        string baseState = m["sources"]!.AsArray().Where(s => Text(s!["name"]) == "ad").Select(s => Text(s!["status"])).FirstOrDefault() ?? "failed";
        byte[] hash = GpoIdentityWriter.Hash(payload, false);
        await Execute(db, tx, """
            insert into computers_v6_source_snapshots(domain_id,snapshot_uuid,schema_version,source_started_at_utc,source_completed_at_utc,captured_at_utc,query_dc,search_base,collector_version,collector_sha256,collection_status,base_inventory_status,object_count,source_options_json,payload_json,payload_sha256,collector_exit_code)
            values(@domain,@id,@schema,@started,@stamp,@stamp,@dc,@base,@version,@collector,@state,@base_state,@count,@options::jsonb,@payload::jsonb,@hash,0)
            on conflict(domain_id,snapshot_uuid) do nothing
            """, ct, ("domain", domain), ("id", id), ("schema", Text(payload["schema_version"])), ("started", Time(m["started_at"])), ("stamp", stamp), ("dc", Text(m["query_dc"])), ("base", Optional(m["search_base"])), ("version", Text(m["collector_version"])), ("collector", SHA256.HashData(Encoding.UTF8.GetBytes("sli-agent/ad-snapshot/1"))), ("state", Text(m["collection_status"])), ("base_state", baseState), ("count", payload["objects"]!.AsArray().Count), ("options", options.ToJsonString()), ("payload", payload.ToJsonString()), ("hash", hash));
        await using var c = Command(db, tx, "select payload_sha256,object_count from computers_v6_source_snapshots where domain_id=@domain and snapshot_uuid=@id", ("domain", domain), ("id", id));
        await using var r = await c.ExecuteReaderAsync(ct); Require(await r.ReadAsync(ct) && ((byte[])r.GetValue(0)).AsSpan().SequenceEqual(hash) && Convert.ToInt32(r.GetValue(1)) == payload["objects"]!.AsArray().Count); return id.ToString("D");
    }
}
