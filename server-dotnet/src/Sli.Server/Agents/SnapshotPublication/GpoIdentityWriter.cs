using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: context_identity.persist_entity_identity and repository._upsert_entity.
internal static class GpoIdentityWriter
{
    public static async Task<long> StoreAsync(NpgsqlConnection db,NpgsqlTransaction tx,long domain,Guid run,JsonObject record,long? existing,CancellationToken ct,string entityKind="gpo")
    {
        var identity=record["identity"]!.AsObject(); var attrs=record["attributes"]!.AsObject();
        if (entityKind!="gpo" && existing is not null && record["section"]!.GetValue<string>() is "directory_group_graph" or "directory_exact_logon" or "privileged_membership" or "vpn_membership")
        {
            await using var priorCommand=new NpgsqlCommand("select attributes_json::text from entity_details_v2 where entity_id=@id",db,tx);
            priorCommand.Parameters.AddWithValue("id",existing.Value);
            var priorText=await priorCommand.ExecuteScalarAsync(ct) as string;
            var prior=priorText is null ? new JsonObject() : JsonNode.Parse(priorText)!.AsObject();
            var incoming=(JsonObject)attrs.DeepClone();
            if(entityKind is "ad_user" or "ad_computer") incoming.Remove("display_name");
            foreach(var member in incoming) prior[member.Key]=member.Value?.DeepClone();
            attrs=prior;
        }
        string key=record["record_key"]!.GetValue<string>(), observed=record["observed_at_utc"]!.GetValue<string>();
        JsonNode display=GpoGovernanceSettings.IsTruthy(attrs["display_name"]) ? attrs["display_name"]!.DeepClone() : JsonValue.Create(key)!;
        var (displayParameter,displayExpression)=DisplayParameter(display);
        var observedAt=DateTimeOffset.Parse(observed,System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime();
        string kindValue=identity["kind"]!.GetValue<string>(), section=record["section"]!.GetValue<string>();
        bool supplemental=section is "directory_group_graph" or "directory_exact_logon" or "privileged_membership" or "vpn_membership";
        bool ownsName=!supplemental || kindValue is not ("ad_user" or "ad_computer");
        long type;
        if (entityKind!=identity["kind"]!.GetValue<string>()) throw new InvalidDataException("agent_snapshot_identity_kind_invalid");
        await using(var c=new NpgsqlCommand("insert into storage_v2_entity_type(value) values(@kind) on conflict(value) do update set value=excluded.value returning id",db,tx))
        { c.Parameters.AddWithValue("kind",entityKind); type=Convert.ToInt64(await c.ExecuteScalarAsync(ct)); }
        var core=new JsonObject { ["entity_type"]=entityKind,["natural_key"]=key,["display_name"]=display.DeepClone(),["domain_id"]=domain,["observed_at_utc"]=observed };
        var coreHash=Hash(core,false);
        long id;
        if(existing is null)
        {
            await using var c=new NpgsqlCommand($"""
                insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,first_seen_utc,last_seen_utc,source_core_sha256)
                values(@type,@key,{displayExpression},@domain,@time,@time,@hash)
                on conflict(entity_type_id,natural_key) do update set display_name=case when @owns then excluded.display_name else entities_v2.display_name end,
                last_seen_utc=greatest(entities_v2.last_seen_utc,excluded.last_seen_utc),source_core_sha256=case when @owns then excluded.source_core_sha256 else entities_v2.source_core_sha256 end,migrated_at=now() returning id
                """,db,tx);
            c.Parameters.AddWithValue("type",type); c.Parameters.AddWithValue("key",key); c.Parameters.Add(displayParameter); c.Parameters.AddWithValue("domain",domain);
            c.Parameters.AddWithValue("time",observedAt); c.Parameters.AddWithValue("hash",coreHash); c.Parameters.AddWithValue("owns",ownsName); id=Convert.ToInt64(await c.ExecuteScalarAsync(ct));
        }
        else
        {
            id=existing.Value; await using var c=new NpgsqlCommand($"update entities_v2 set display_name=case when @owns then {displayExpression} else display_name end,last_seen_utc=greatest(last_seen_utc,@time),source_core_sha256=case when @owns then @hash else source_core_sha256 end,migrated_at=now() where id=@id",db,tx);
            c.Parameters.AddWithValue("id",id); c.Parameters.Add(displayParameter); c.Parameters.AddWithValue("time",observedAt); c.Parameters.AddWithValue("hash",coreHash); c.Parameters.AddWithValue("owns",ownsName); await c.ExecuteNonQueryAsync(ct);
        }
        var details=(JsonObject)attrs.DeepClone(); details["object_guid"]=identity["object_guid"]!.DeepClone(); details["sid"]=identity["object_sid"]?.DeepClone();
        if(supplemental && existing is not null) {
            await using var read=new NpgsqlCommand("select attributes_json::text from entity_details_v2 where entity_id=@id",db,tx);read.Parameters.AddWithValue("id",id);
            if(await read.ExecuteScalarAsync(ct) is string previous) {
                var merged=JsonNode.Parse(previous)!.AsObject();
                foreach(var pair in details) if(pair.Key!="display_name" || ownsName) merged[pair.Key]=pair.Value?.DeepClone();
                details=merged;
            } else if(!ownsName) details.Remove("display_name");
        } else if(supplemental && !ownsName) details.Remove("display_name");
        await using(var c=new NpgsqlCommand("""
            insert into entity_details_v2(entity_id,attributes_json,source_details_sha256) values(@id,@attributes,@hash)
            on conflict(entity_id) do update set attributes_json=excluded.attributes_json,source_details_sha256=excluded.source_details_sha256,migrated_at=now()
            """,db,tx))
        {
            c.Parameters.AddWithValue("id",id); c.Parameters.AddWithValue("attributes",NpgsqlDbType.Jsonb,details.ToJsonString()); c.Parameters.AddWithValue("hash",Hash(details,true));
            await c.ExecuteNonQueryAsync(ct);
        }
        foreach(var (kind,node) in new[] { ("object_guid",identity["object_guid"]),("object_sid",identity["object_sid"]),("distinguished_name",record["attributes"]!["distinguished_name"]),("sam_account_name",entityKind is "ad_user" or "ad_computer" ? record["attributes"]!["sam_account_name"] : null) })
        {
            if(!GpoGovernanceSettings.IsTruthy(node)) continue;
            string value=Sli.Gpo.SnapshotModel.GpoSnapshotDocument.PythonString(System.Text.Json.JsonSerializer.SerializeToElement(node));
            await using var c=new NpgsqlCommand("""
                insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                values(@id,@domain,@kind,@value,@normalized,@time,@time,@run)
                on conflict(domain_id,alias_type,normalized_value) do update set last_seen_utc=greatest(ad_context_entity_aliases.last_seen_utc,excluded.last_seen_utc),source_run_id=excluded.source_run_id
                where ad_context_entity_aliases.entity_id=excluded.entity_id
                """,db,tx);
            c.Parameters.AddWithValue("id",id); c.Parameters.AddWithValue("domain",domain); c.Parameters.AddWithValue("kind",kind); c.Parameters.AddWithValue("value",value);
            c.Parameters.AddWithValue("normalized",UnicodeCaseFold.TrimAndFold(value)); c.Parameters.AddWithValue("time",observedAt); c.Parameters.AddWithValue("run",run);
            if(await c.ExecuteNonQueryAsync(ct)!=1) throw new InvalidDataException("agent_gpo_identity_conflict");
        }
        return id;
    }
    private static (NpgsqlParameter Parameter,string Expression) DisplayParameter(JsonNode value)
    {
        var kind=value.GetValueKind();
        if(kind==System.Text.Json.JsonValueKind.String) return (new NpgsqlParameter("display",NpgsqlDbType.Text) { Value=value.GetValue<string>() },"@display");
        if(kind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False) return (new NpgsqlParameter("display",NpgsqlDbType.Boolean) { Value=value.GetValue<bool>() },"@display");
        if(kind==System.Text.Json.JsonValueKind.Number && JsonRead.TryInteger(value,out var integer))
        {
            if(integer>=long.MinValue && integer<=long.MaxValue) return (new NpgsqlParameter("display",NpgsqlDbType.Bigint) { Value=(long)integer },"@display");
            return (new NpgsqlParameter("display",NpgsqlDbType.Text) { Value=integer.ToString(System.Globalization.CultureInfo.InvariantCulture) },"@display::numeric");
        }
        if(kind==System.Text.Json.JsonValueKind.Number && double.TryParse(value.ToJsonString(),System.Globalization.NumberStyles.Float,System.Globalization.CultureInfo.InvariantCulture,out var number) && double.IsFinite(number))
            return (new NpgsqlParameter("display",NpgsqlDbType.Double) { Value=number },"@display");
        throw new InvalidDataException("agent_gpo_governance_invalid");
    }
    internal static byte[] Hash(JsonNode value,bool defaultSeparators)
    {
        string text=CanonicalJson.Serialize(value,false);
        if(defaultSeparators)
        {
            var b=new StringBuilder(); bool quoted=false,escaped=false;
            foreach(char ch in text)
            {
                b.Append(ch);
                if(quoted) { if(escaped) escaped=false; else if(ch=='\\') escaped=true; else if(ch=='"') quoted=false; }
                else if(ch=='"') quoted=true;
                else if(ch is ',' or ':') b.Append(' ');
            }
            text=b.ToString();
        }
        return SHA256.HashData(new UTF8Encoding(false,true).GetBytes(text));
    }
}
