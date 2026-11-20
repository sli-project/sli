using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: ad/context/repository.import_bundle, narrowed to GPO entity-only bundles.
internal static class GpoGovernanceStore
{
    public static async Task<Guid> ImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject bundle,CancellationToken ct)
    {
        string sid=bundle["domain"]!["sid"]!.GetValue<string>(),dns=bundle["domain"]!["dns_name"]!.GetValue<string>();
        long domain=await GpoDomainLock.AcquireAsync(db,tx,sid,dns,ct);
        Guid run=Guid.Parse(bundle["run_id"]!.GetValue<string>()); var snapshot=bundle["gpo_v2_snapshot"]!.AsObject();
        bool replay=await GpoRunLedger.StartAsync(db,tx,domain,bundle,ct);
        if(!replay)
        {
            var section=bundle["sections"]![0]!.AsObject();
            await using(var c=new NpgsqlCommand("insert into ad_context_sections(run_id,section_name,status,record_count,duration_ms,error_code) values(@run,'gpo_governance',@status,@count,@duration,@error)",db,tx))
            {
                c.Parameters.AddWithValue("run",run); c.Parameters.AddWithValue("status",section["status"]!.GetValue<string>()); c.Parameters.AddWithValue("count",section["record_count"]!.GetValue<int>());
                c.Parameters.AddWithValue("duration",section["duration_ms"]!.GetValue<long>()); c.Parameters.AddWithValue("error",(object?)section["error_code"]?.GetValue<string>() ?? DBNull.Value);
                await c.ExecuteNonQueryAsync(ct);
            }
            var records=bundle["records"]!.AsArray(); var resolved=await GpoIdentityLookup.ResolveAsync(db,tx,domain,records,ct);
            var observed=new Dictionary<string,(long Id,string? Sid)>(StringComparer.Ordinal); var seen=new List<long>();
            foreach(var node in records)
            {
                var record=node!.AsObject(); string key=record["record_key"]!.GetValue<string>(); var identity=record["identity"]!.AsObject();
                string guid=identity["object_guid"]!.GetValue<string>(), objectSid=identity["object_sid"]?.GetValue<string>() ?? "";
                long? existing=resolved.TryGetValue(key,out var preloaded) ? preloaded : null;
                if(observed.TryGetValue(guid,out var prior))
                {
                    if(prior.Sid is not null && objectSid.Length>0 && UnicodeCaseFold.Fold(prior.Sid)!=UnicodeCaseFold.Fold(objectSid) || existing is not null && existing!=prior.Id)
                        throw new InvalidDataException("agent_gpo_identity_conflict");
                    existing=prior.Id;
                    if(objectSid.Length==0 && prior.Sid is not null) objectSid=prior.Sid;
                }
                long entity=await GpoIdentityWriter.StoreAsync(db,tx,domain,run,record,existing,ct);
                observed[guid]=(entity,objectSid.Length==0 ? null : objectSid); seen.Add(entity);
                await GpoEntityObservation.WriteAsync(db,tx,entity,run,bundle,record,ct);
            }
            if(section["status"]!.GetValue<string>()=="complete" && bundle["mode"]!.GetValue<string>() is "full" or "reconcile")
            {
                await using var c=new NpgsqlCommand("""
                    update ad_context_entity_versions version set valid_to_utc=@time from entities_v2 entity
                    where version.entity_id=entity.id and entity.domain_id=@domain and version.source_section='gpo_governance'
                    and version.valid_to_utc is null and not (version.entity_id=any(@seen))
                    """,db,tx);
                c.Parameters.AddWithValue("time",DateTimeOffset.Parse(bundle["observed_at_utc"]!.GetValue<string>(),System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime());
                c.Parameters.AddWithValue("domain",domain); c.Parameters.AddWithValue("seen",seen.ToArray()); await c.ExecuteNonQueryAsync(ct);
            }
            await GpoSnapshotStore.StoreAndVerifyAsync(db,tx,domain,run,snapshot,true,ct);
            await using var finish=new NpgsqlCommand("update ad_context_runs set status='completed',completed_at=now() where run_id=@run",db,tx);
            finish.Parameters.AddWithValue("run",run); await finish.ExecuteNonQueryAsync(ct);
        }
        else await GpoSnapshotStore.StoreAndVerifyAsync(db,tx,domain,run,snapshot,false,ct);
        return run;
    }
}
