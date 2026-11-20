using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Auth.Lifecycle.Security;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;
using static Sli.Server.Agents.SnapshotPublication.AdContextStore;

namespace Sli.Server.Agents.SnapshotPublication;

public static class AdSnapshotManifest
{
    public static JsonObject Build(long domain, string sid, string dns, string slotText, JsonObject policy, string assembled, IEnumerable<JsonObject> sources)
    {
        var slot = DateTimeOffset.Parse(slotText, CultureInfo.InvariantCulture);
        if (!slotText.EndsWith('Z') && !slotText.EndsWith("+00:00", StringComparison.Ordinal) || slot.Second != 0 || slot.Ticks % TimeSpan.TicksPerSecond != 0 || DateTimeOffset.Parse(new SnapshotPolicy(SnapshotPolicy.Ad, policy).DueSlot(slot), CultureInfo.InvariantCulture) != slot)
            throw new ProtocolException("agent_ad_schedule_unsupported");
        Require(DateTimeOffset.Parse(assembled, CultureInfo.InvariantCulture) >= slot);
        var schedule = policy["schedule"]!.AsObject();
        bool defaults = Text(schedule["timezone"]) == "Asia/Novosibirsk" && schedule["hours"]!.AsArray().Select(n => n!.GetValue<int>()).SequenceEqual(new[] { 6, 18 });
        string contract = "sli.ad-snapshot-manifest/" + (defaults ? "2.0" : "3.0"), timezone = defaults ? "Asia/Novosibirsk" : "UTC";
        string local = (defaults ? TimeZoneInfo.ConvertTime(slot, TimeZoneInfo.FindSystemTimeZoneById(timezone)) : slot.ToUniversalTime()).ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        string slotUtc = slot.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var ordered = sources.OrderBy(s => Text(s["family"]), StringComparer.Ordinal).ToArray();
        var identity = new JsonObject { ["contract"] = contract, ["domain_id"] = domain, ["slot"] = slotUtc, ["schedule"] = new JsonObject { ["timezone"] = timezone, ["local_at"] = local }, ["members"] = new JsonArray(ordered.Select(s => (JsonNode?)new JsonObject { ["family"] = s["family"]!.DeepClone(), ["source_id"] = s["source_id"]!.DeepClone(), ["sha256"] = s["payload_sha256"]!.DeepClone() }).ToArray()) };
        var manifest = new JsonObject { ["contract_version"] = contract, ["manifest_id"] = AuthAudit.Uuid5(CanonicalJson.Serialize(identity, false)).ToString("D"), ["domain_id"] = domain, ["domain_sid"] = sid, ["domain_dns"] = dns, ["slot_start_utc"] = slotUtc, ["assembled_at_utc"] = assembled, ["coverage_state"] = ordered.All(s => Text(s["source_state"]) == "complete") ? "complete" : "partial", ["members"] = new JsonArray(ordered.Select(s => (JsonNode?)s.DeepClone()).ToArray()), ["schedule_timezone"] = timezone, ["scheduled_local_at"] = local };
        manifest["manifest_sha256"] = Convert.ToHexStringLower(GpoIdentityWriter.Hash(manifest, false)); return manifest;
    }
    internal static JsonObject Member(string family, string contract, string id, string observed, string state, string hash) => new() {
        ["family"] = family, ["contract_id"] = contract, ["source_id"] = id, ["observed_at_utc"] = observed, ["source_state"] = state, ["payload_sha256"] = hash, ["reason_code"] = state == "complete" ? null : family + "_source_partial"
    };
    internal static async Task PublishAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonObject manifest, CancellationToken ct)
    {
        Guid id = Guid.Parse(Text(manifest["manifest_id"])); byte[] hash = Convert.FromHexString(Text(manifest["manifest_sha256"]));
        await Execute(db, tx, """
            insert into ad_snapshot_manifests(manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,assembled_at_utc,contract_version,coverage_state,manifest_sha256)
            values(@id,@domain,@sid,@dns,@slot,@assembled,@contract,@state,@hash)
            on conflict(domain_id,slot_start_utc,contract_version) do nothing
            """, ct, ("id", id), ("domain", manifest["domain_id"]!.GetValue<long>()), ("sid", Text(manifest["domain_sid"])), ("dns", Text(manifest["domain_dns"])), ("slot", Time(manifest["slot_start_utc"])), ("assembled", Time(manifest["assembled_at_utc"])), ("contract", Text(manifest["contract_version"])), ("state", Text(manifest["coverage_state"])), ("hash", hash));
        await using (var c = Command(db, tx, "select manifest_id,manifest_sha256 from ad_snapshot_manifests where domain_id=@domain and slot_start_utc=@slot and contract_version=@contract", ("domain", manifest["domain_id"]!.GetValue<long>()), ("slot", Time(manifest["slot_start_utc"])), ("contract", Text(manifest["contract_version"])))) {
            await using var r = await c.ExecuteReaderAsync(ct); Require(await r.ReadAsync(ct) && r.GetGuid(0) == id && ((byte[])r.GetValue(1)).AsSpan().SequenceEqual(hash));
        }
        foreach (var s in manifest["members"]!.AsArray()) {
            await Execute(db, tx, """
                insert into ad_snapshot_manifest_sources(manifest_id,family,contract_id,source_id,observed_at_utc,source_state,payload_sha256,reason_code)
                values(@id,@family,@contract,@source,@stamp,@state,@hash,@reason) on conflict(manifest_id,family) do nothing
                """, ct, ("id", id), ("family", Text(s!["family"])), ("contract", Text(s["contract_id"])), ("source", Text(s["source_id"])), ("stamp", Time(s["observed_at_utc"])), ("state", Text(s["source_state"])), ("hash", Convert.FromHexString(Text(s["payload_sha256"]))), ("reason", Optional(s["reason_code"])));
            await using var c = Command(db, tx, "select source_id,payload_sha256 from ad_snapshot_manifest_sources where manifest_id=@id and family=@family", ("id", id), ("family", Text(s["family"])));
            await using var r = await c.ExecuteReaderAsync(ct); Require(await r.ReadAsync(ct) && r.GetString(0) == Text(s["source_id"]) && ((byte[])r.GetValue(1)).AsSpan().SequenceEqual(Convert.FromHexString(Text(s["payload_sha256"]))));
        }
        foreach (string key in new[] { "ad.state", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2" })
            await Execute(db, tx, "insert into ad_snapshot_projection_receipts(manifest_id,projection_key,projection_version,status) values(@id,@key,1,'pending') on conflict(manifest_id,projection_key,projection_version) do nothing", ct, ("id", id), ("key", key));
    }
}
