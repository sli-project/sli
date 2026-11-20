using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: context_identity._preload_existing_entity_ids; all lookups precede writes.
internal static class GpoIdentityLookup
{
    public static async Task<Dictionary<string,long>> ResolveAsync(NpgsqlConnection db,NpgsqlTransaction tx,long domain,JsonArray records,CancellationToken ct)
    {
        var entities=records.Select(x=>x!.AsObject()).ToArray();
        string Fold(string s)=>UnicodeCaseFold.TrimAndFold(s);
        var guids=entities.Select(x=>Fold(x["identity"]!["object_guid"]!.GetValue<string>())).Distinct().ToArray();
        var sids=entities.Select(x=>x["identity"]!["object_sid"]?.GetValue<string>()).Where(x=>x is not null && Fold(x).Length>0).Select(x=>Fold(x!)).Distinct().ToArray();
        var guidMap=new Dictionary<string,long>();
        await using(var c=new NpgsqlCommand("select normalized_value,entity_id from ad_context_entity_aliases where domain_id=@d and alias_type='object_guid' and normalized_value=any(@v)",db,tx))
        {
            c.Parameters.AddWithValue("d",domain); c.Parameters.AddWithValue("v",guids); await using var r=await c.ExecuteReaderAsync(ct);
            while(await r.ReadAsync(ct)) guidMap[UnicodeCaseFold.Fold(r.GetString(0))]=Convert.ToInt64(r.GetValue(1));
        }
        var resolved=new Dictionary<string,long>(StringComparer.Ordinal);
        var bySid=entities.Where(x=>Fold(x["identity"]!["object_sid"]?.GetValue<string>() ?? "").Length>0)
            .GroupBy(x=>Fold(x["identity"]!["object_sid"]!.GetValue<string>()),StringComparer.Ordinal).ToDictionary(x=>x.Key,x=>x.ToArray(),StringComparer.Ordinal);
        await using(var c=new NpgsqlCommand("""
            select alias.normalized_value,alias.entity_id,entity.domain_id,entity_type.value
            from ad_context_entity_aliases alias join entities_v2 entity on entity.id=alias.entity_id
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            where alias.domain_id=@d and alias.alias_type='object_sid' and alias.normalized_value=any(@v)
            """,db,tx))
        {
            c.Parameters.AddWithValue("d",domain); c.Parameters.AddWithValue("v",sids); await using var r=await c.ExecuteReaderAsync(ct);
            while(await r.ReadAsync(ct))
            {
                string sid=UnicodeCaseFold.Fold(r.GetString(0)); long id=Convert.ToInt64(r.GetValue(1)), storedDomain=Convert.ToInt64(r.GetValue(2)); string kind=r.GetString(3);
                foreach(var record in bySid.TryGetValue(sid,out var matching) ? matching : [])
                {
                    string guid=Fold(record["identity"]!["object_guid"]!.GetValue<string>());
                    if(storedDomain!=domain || kind!="gpo" || guidMap.TryGetValue(guid,out long byGuid) && byGuid!=id) throw new InvalidDataException("agent_gpo_identity_conflict");
                    resolved[record["record_key"]!.GetValue<string>()]=id;
                }
            }
        }
        var keys=entities.Where(x=>!resolved.ContainsKey(x["record_key"]!.GetValue<string>())).Select(x=>x["record_key"]!.GetValue<string>()).Distinct().ToArray();
        await using(var c=new NpgsqlCommand("select entity.id,entity.natural_key from entities_v2 entity join storage_v2_entity_type kind on kind.id=entity.entity_type_id where kind.value='gpo' and entity.natural_key=any(@keys)",db,tx))
        {
            c.Parameters.AddWithValue("keys",keys); await using var r=await c.ExecuteReaderAsync(ct);
            while(await r.ReadAsync(ct)) resolved[r.GetString(1)]=Convert.ToInt64(r.GetValue(0));
        }
        var unresolved=entities.Where(x=>!resolved.ContainsKey(x["record_key"]!.GetValue<string>()) && Fold(x["identity"]!["object_sid"]?.GetValue<string>() ?? "").Length>0).ToArray();
        var legacySids=unresolved.Select(x=>Fold(x["identity"]!["object_sid"]!.GetValue<string>())).Distinct().ToArray();
        var candidates=new Dictionary<string,List<long>>();
        await using(var c=new NpgsqlCommand("""
            select lower(details.attributes_json->>'sid'),entity.id from entities_v2 entity
            join storage_v2_entity_type kind on kind.id=entity.entity_type_id join entity_details_v2 details on details.entity_id=entity.id
            where entity.domain_id=@d and kind.value='gpo' and lower(details.attributes_json->>'sid')=any(@sids)
            """,db,tx))
        {
            c.Parameters.AddWithValue("d",domain); c.Parameters.AddWithValue("sids",legacySids); await using var r=await c.ExecuteReaderAsync(ct);
            while(await r.ReadAsync(ct)) { string sid=UnicodeCaseFold.Fold(r.GetString(0)); if(!candidates.TryGetValue(sid,out var ids)) candidates[sid]=ids=[]; ids.Add(Convert.ToInt64(r.GetValue(1))); }
        }
        foreach(var record in unresolved)
        {
            string sid=Fold(record["identity"]!["object_sid"]!.GetValue<string>()), guid=Fold(record["identity"]!["object_guid"]!.GetValue<string>());
            if(!candidates.TryGetValue(sid,out var ids) || ids.Count!=1) continue;
            if(guidMap.TryGetValue(guid,out long byGuid) && byGuid!=ids[0]) throw new InvalidDataException("agent_gpo_identity_conflict");
            resolved[record["record_key"]!.GetValue<string>()]=ids[0];
        }
        return resolved;
    }
}
