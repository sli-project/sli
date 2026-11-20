using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;
using static Sli.Server.Agents.SnapshotPublication.AdContextStore;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdSnapshotProjections
{
    internal static async Task PublishAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonObject manifest, JsonObject users, JsonObject computers, CancellationToken ct)
    {
        Guid id = Guid.Parse(Text(manifest["manifest_id"]));
        var members = manifest["members"]!.AsArray().ToDictionary(s => Text(s!["family"]), s => s!.AsObject());
        JsonObject state;
        await using (var c = Command(db, tx, "select jsonb_build_object('run_id',run_id::text,'domain_id',domain_id,'observed_at_utc',observed_at_utc,'status',status)::text from ad_context_runs where run_id=@run and status='completed' and bundle_sha256=@hash", ("run", Guid.Parse(Text(members["ad_context_base"]["source_id"]))), ("hash", Convert.FromHexString(Text(members["ad_context_base"]["payload_sha256"]))))) {
            state = JsonNode.Parse(await c.ExecuteScalarAsync(ct) as string ?? throw new ProtocolException("agent_ad_projection_pending"))!.AsObject();
        }
        state["composition"] = new JsonObject { ["version"] = 1, ["parts"] = new JsonArray("base_ad") };
        foreach (var (key, family, output) in new[] { ("ad.state", "ad_context_base", state), ("ad.users.v2", "users_v2", users), ("ad.computers.v6", "computers_v6", computers) }) {
            string? status = null; DateTime? expires = null; int attempts = 0;
            await using (var c = Command(db, tx, "select status,lease_expires_at,attempt_count from ad_snapshot_projection_receipts where manifest_id=@id and projection_key=@key and projection_version=1 for update", ("id", id), ("key", key))) {
                await using var r = await c.ExecuteReaderAsync(ct);
                if (await r.ReadAsync(ct)) { status = r.GetString(0); if (!r.IsDBNull(1)) expires = r.GetDateTime(1); attempts = r.GetInt32(2); }
            }
            if (status is null || status == "running" && expires > DateTime.UtcNow || status != "completed" && attempts >= 4) throw new ProtocolException("agent_ad_projection_pending");
            var member = members[family];
            var input = new JsonObject { ["manifest_id"] = id.ToString("D"), ["manifest_sha256"] = manifest["manifest_sha256"]!.DeepClone(), ["projection_key"] = key, ["projection_version"] = 1, ["family"] = family, ["source_id"] = member["source_id"]!.DeepClone(), ["payload_sha256"] = member["payload_sha256"]!.DeepClone() };
            byte[] inputHash = GpoIdentityWriter.Hash(input, false), outputHash = GpoIdentityWriter.Hash(output, false);
            string identity = $"{id:D}:{key}:v1";
            if (status != "completed") {
                await Execute(db, tx, """
                    update ad_snapshot_projection_receipts set status='running',attempt_count=attempt_count+1,lease_owner='agent-ad-snapshot',lease_expires_at=now()+interval '300 seconds',updated_at=now()
                    where manifest_id=@id and projection_key=@key and projection_version=1
                    """, ct, ("id", id), ("key", key));
                await Execute(db, tx, """
                    insert into ad_snapshot_projection_outputs(manifest_id,projection_key,projection_version,input_sha256,output_sha256,output_identity,payload_json)
                    values(@id,@key,1,@input,@output,@identity,@payload::jsonb) on conflict(manifest_id,projection_key,projection_version) do nothing
                    """, ct, ("id", id), ("key", key), ("input", inputHash), ("output", outputHash), ("identity", identity), ("payload", output.ToJsonString()));
            }
            await using (var c = Command(db, tx, "select input_sha256,output_sha256,output_identity,payload_json::text from ad_snapshot_projection_outputs where manifest_id=@id and projection_key=@key and projection_version=1", ("id", id), ("key", key))) {
                await using var r = await c.ExecuteReaderAsync(ct);
                if (!await r.ReadAsync(ct) || !((byte[])r.GetValue(0)).AsSpan().SequenceEqual(inputHash) || !((byte[])r.GetValue(1)).AsSpan().SequenceEqual(outputHash) || r.GetString(2) != identity || !GpoIdentityWriter.Hash(JsonNode.Parse(r.GetString(3))!, false).AsSpan().SequenceEqual(outputHash)) throw new ProtocolException("agent_ad_projection_pending");
            }
            if (status != "completed") await Execute(db, tx, """
                update ad_snapshot_projection_receipts set status='completed',lease_owner=null,lease_expires_at=null,input_sha256=@input,output_sha256=@output,output_identity=@identity,last_error=null,updated_at=now()
                where manifest_id=@id and projection_key=@key and projection_version=1 and status='running' and lease_owner='agent-ad-snapshot'
                """, ct, ("id", id), ("key", key), ("input", inputHash), ("output", outputHash), ("identity", identity));
        }
    }
}
