using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: ad/context/repository.py:_start_run. Caller holds the source domain advisory lock.
internal static class GpoRunLedger
{
    public static async Task<bool> StartAsync(NpgsqlConnection db,NpgsqlTransaction tx,long domainId,JsonObject bundle,CancellationToken ct)
    {
        var run=Guid.Parse(bundle["run_id"]!.GetValue<string>()); var hash=Convert.FromHexString(bundle["bundle_sha256"]!.GetValue<string>());
        await using (var command=new NpgsqlCommand("select bundle_sha256,status from ad_context_runs where run_id=@run",db,tx))
        {
            command.Parameters.AddWithValue("run",run); await using var reader=await command.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                if (!((byte[])reader.GetValue(0)).AsSpan().SequenceEqual(hash) || reader.GetString(1)!="completed") throw new InvalidDataException("agent_gpo_import_replay_invalid");
                return true;
            }
        }
        var observed=DateTimeOffset.Parse(bundle["observed_at_utc"]!.GetValue<string>(),System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime();
        await using (var command=new NpgsqlCommand("""
            select max(run.observed_at_utc) from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
            where run.domain_id=@domain and run.source_pack_id=@pack and run.status='completed' and section.section_name=any(@sections)
            """,db,tx))
        {
            command.Parameters.AddWithValue("domain",domainId); command.Parameters.AddWithValue("pack",bundle["source_pack_id"]!.GetValue<string>());
            command.Parameters.AddWithValue("sections",bundle["sections"]!.AsArray().Select(s=>s!["name"]!.GetValue<string>()).ToArray());
            var latest=await command.ExecuteScalarAsync(ct);
            if (latest is DateTime value && observed < new DateTimeOffset(value)) throw new Sli.Agent.Protocol.ProtocolException("agent_gpo_snapshot_superseded");
        }
        await using (var command=new NpgsqlCommand("""
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,scope_json,status)
            values(@run,@pack,@version,@domain,@mode,@observed,@hash,@scope,'importing')
            """,db,tx))
        {
            command.Parameters.AddWithValue("run",run); command.Parameters.AddWithValue("pack",bundle["source_pack_id"]!.GetValue<string>());
            command.Parameters.AddWithValue("version",bundle["source_pack_version"]!.GetValue<string>()); command.Parameters.AddWithValue("domain",domainId);
            command.Parameters.AddWithValue("mode",bundle["mode"]!.GetValue<string>()); command.Parameters.AddWithValue("observed",observed);
            command.Parameters.AddWithValue("hash",hash); command.Parameters.AddWithValue("scope",NpgsqlDbType.Jsonb,bundle["scope"]!.ToJsonString());
            await command.ExecuteNonQueryAsync(ct);
        }
        return false;
    }
}
