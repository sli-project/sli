using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: repository._observe_entity and _write_evidence; caller owns transaction.
internal static class GpoEntityObservation
{
    public static async Task WriteAsync(NpgsqlConnection db,NpgsqlTransaction tx,long entity,Guid run,JsonObject bundle,JsonObject record,CancellationToken ct)
    {
        string observed=record["observed_at_utc"]!.GetValue<string>(); var time=DateTimeOffset.Parse(observed,System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime();
        var semantic=(JsonObject)record.DeepClone(); semantic.Remove("observed_at_utc"); byte[] hash=GpoIdentityWriter.Hash(semantic,false);
        string section=record["section"]!.GetValue<string>();
        long? version=null; byte[]? prior=null;
        await using(var c=new NpgsqlCommand("select id,content_sha256 from ad_context_entity_versions where entity_id=@id and source_section=@section and valid_to_utc is null",db,tx))
        { c.Parameters.AddWithValue("id",entity); c.Parameters.AddWithValue("section",section); await using var r=await c.ExecuteReaderAsync(ct); if(await r.ReadAsync(ct)) { version=Convert.ToInt64(r.GetValue(0)); prior=(byte[])r.GetValue(1); } }
        if(version is not null && prior!.AsSpan().SequenceEqual(hash))
        {
            await using var c=new NpgsqlCommand("update ad_context_entity_versions set last_observed_at_utc=greatest(last_observed_at_utc,@time) where id=@id",db,tx);
            c.Parameters.AddWithValue("time",time); c.Parameters.AddWithValue("id",version.Value); await c.ExecuteNonQueryAsync(ct);
        }
        else
        {
            if(version is not null)
            {
                await using var c=new NpgsqlCommand("update ad_context_entity_versions set valid_to_utc=@time where id=@id",db,tx);
                c.Parameters.AddWithValue("time",time); c.Parameters.AddWithValue("id",version.Value); await c.ExecuteNonQueryAsync(ct);
            }
            await using var c2=new NpgsqlCommand("""
                insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                values(@entity,@section,@time,@time,@hash,@record,@run)
                """,db,tx);
            c2.Parameters.AddWithValue("entity",entity); c2.Parameters.AddWithValue("section",section); c2.Parameters.AddWithValue("time",time); c2.Parameters.AddWithValue("hash",hash);
            c2.Parameters.AddWithValue("record",NpgsqlDbType.Jsonb,record.ToJsonString()); c2.Parameters.AddWithValue("run",run); await c2.ExecuteNonQueryAsync(ct);
        }
        string key=record["record_key"]!.GetValue<string>();
        var locator=new JsonObject { ["run_id"]=run.ToString("D"),["record_key"]=key,["section"]=section };
        await using var evidence=new NpgsqlCommand("""
            insert into ad_context_evidence(evidence_key,evidence_type,source_pack_id,source_run_id,observed_at_utc,locator_json,integrity_sha256)
            values(@key,'entity_observation',@pack,@run,@time,@locator,@hash) on conflict(evidence_key) do nothing
            """,db,tx);
        evidence.Parameters.AddWithValue("key",$"adctx:{run:D}:{key}"); evidence.Parameters.AddWithValue("pack",bundle["source_pack_id"]!.GetValue<string>());
        evidence.Parameters.AddWithValue("run",run); evidence.Parameters.AddWithValue("time",time); evidence.Parameters.AddWithValue("locator",NpgsqlDbType.Jsonb,locator.ToJsonString());
        evidence.Parameters.AddWithValue("hash",GpoIdentityWriter.Hash(record,false)); await evidence.ExecuteNonQueryAsync(ct);
    }
}
