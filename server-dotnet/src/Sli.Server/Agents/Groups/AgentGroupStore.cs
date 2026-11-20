using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Groups;

// All commands use the caller's connection and transaction. No repository
// commits, reconnects, or substitutes a different authority/profile.
internal static class AgentGroupStore
{
    internal static NpgsqlCommand Query(NpgsqlConnection c,NpgsqlTransaction t,string sql,params (string Key,object? Value)[] args)
    {
        var q=new NpgsqlCommand(sql,c,t);
        foreach(var (key,value) in args)
            if(value is null)q.Parameters.Add(key,NpgsqlDbType.Text).Value=DBNull.Value;
            else q.Parameters.AddWithValue(key,value);
        return q;
    }
    internal static async Task<int> Execute(NpgsqlConnection c,NpgsqlTransaction t,string sql,CancellationToken ct,params (string,object?)[] args)
    {await using var q=Query(c,t,sql,args);return await q.ExecuteNonQueryAsync(ct);}
    internal static async Task<object?> Scalar(NpgsqlConnection c,NpgsqlTransaction t,string sql,CancellationToken ct,params (string,object?)[] args)
    {await using var q=Query(c,t,sql,args);return await q.ExecuteScalarAsync(ct);}
    internal static async Task<List<JsonObject>> Rows(NpgsqlConnection c,NpgsqlTransaction t,string sql,CancellationToken ct,params (string,object?)[] args)
    {
        await using var q=Query(c,t,"select row_to_json(r)::text from ("+sql+") r",args);
        await using var reader=await q.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();
        while(await reader.ReadAsync(ct))rows.Add(AgentControlJson.Row(reader.GetString(0)));
        return rows;
    }
    internal static async Task LockHost(NpgsqlConnection c,NpgsqlTransaction t,Guid host,CancellationToken ct)
        => _=await Scalar(c,t,"select pg_advisory_xact_lock(hashtext(@key))",ct,("key","sli-agent-host:"+host));
    internal static Guid Id(JsonObject r,string key)=>Guid.Parse(r[key]!.GetValue<string>());
    internal static long Long(JsonObject r,string key)=>r[key]!.GetValue<long>();
    internal static string Text(JsonObject r,string key)=>r[key]!.GetValue<string>();
    internal static DateTimeOffset Time(JsonObject r,string key)=>DateTimeOffset.Parse(Text(r,key),System.Globalization.CultureInfo.InvariantCulture);
    internal static bool Available(JsonObject token,DateTimeOffset now,int seconds=0)=>token["revoked_at"] is null && Time(token,"expires_at")>now.AddSeconds(seconds);
    internal static GroupBinding Binding(JsonObject row)=>new(Id(row,"host_id"),AgentGroupInput.Text(row["instance_name"]),Text(row,"key_fingerprint"),Long(row,"computer_entity_id"));
    internal static async Task<bool> HostConflict(NpgsqlConnection c,NpgsqlTransaction t,GroupBinding b,CancellationToken ct)
        =>await Scalar(c,t,b.Instance is null?"select id from sli_agents where host_id=@host":"select id from sli_agents where host_id=@host and (instance_name=@instance or key_fingerprint=@fp)",ct,("host",b.Host),("instance",b.Instance),("fp",b.Fingerprint)) is not null;
    internal static JsonObject Approved(Guid request,string token,DateTimeOffset expiry)=>new(){["request_id"]=request.ToString(),["status"]="approved",["token"]=token,["expires_at"]=AgentControlJson.Stamp(expiry,true)};
    internal static JsonArray Array(IEnumerable<JsonObject> items)=>new(items.Select(x=>(JsonNode)x).ToArray());
}

internal static class AgentGroupDirectory
{
    internal static async Task<(long Version,string[] Dn)> ResolveAsync(NpgsqlConnection c,NpgsqlTransaction t,long entity,long domain,bool ou,CancellationToken ct)
    {
        await using var q=AgentGroupStore.Query(c,t,"select v.id,v.attributes_json from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id join ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section where e.id=@id and e.domain_id=@domain and v.source_section=@section and v.valid_to_utc is null and r.status='completed' and s.status='complete' and v.last_observed_at_utc between clock_timestamp()-interval '24 hours' and clock_timestamp()",("id",entity),("domain",domain),("section",ou?"domain_posture":"directory_accounts"));
        await using var reader=await q.ExecuteReaderAsync(ct);
        if(!await reader.ReadAsync(ct))throw new AgentControlException("invalid_group_enrollment_scope");
        var record=JsonNode.Parse(reader.GetString(1));
        return(reader.GetInt64(0),Record(record,ou));
    }
    internal static string[] Record(JsonNode? record,bool ou)
    {
        if(record is not JsonObject r || r["attributes"] is not JsonObject attrs || r["identity"] is not JsonObject identity
            || (ou?AgentGroupInput.Text(identity["kind"])!="security_principal" || AgentGroupInput.Text(attrs["infrastructure_role"])!="organizational_unit"
                :AgentGroupInput.Text(identity["kind"])!="ad_computer" || attrs["enabled"]?.GetValueKind()!=System.Text.Json.JsonValueKind.True))
            throw new AgentControlException("invalid_group_enrollment_scope");
        try{return AgentEnrollmentService.ParseDirectoryDn(AgentGroupInput.Text(attrs["distinguished_name"]),ou);}
        catch(FormatException){throw new AgentControlException("invalid_group_enrollment_scope");}
    }
    internal static bool Within(string[] dn,string[] suffix)=>dn.Length>suffix.Length && dn.TakeLast(suffix.Length).SequenceEqual(suffix,StringComparer.Ordinal);
    internal static async Task<long> CheckScope(NpgsqlConnection c,NpgsqlTransaction t,JsonObject token,long computer,CancellationToken ct)
    {
        long domain=AgentGroupStore.Long(token,"domain_id");
        var found=await ResolveAsync(c,t,computer,domain,false,ct);
        var selected=token["computer_entity_ids"] as JsonArray;
        if(selected is {Count:>0} && !selected.Any(x=>x!.GetValue<long>()==computer))throw new AgentControlException("invalid_group_enrollment_scope");
        if(token["ou_entity_ids"] is JsonArray {Count:>0} ous)
        {
            bool match=false;
            foreach(var ou in ous)if(Within(found.Dn,(await ResolveAsync(c,t,ou!.GetValue<long>(),domain,true,ct)).Dn)){match=true;break;}
            if(!match)throw new AgentControlException("invalid_group_enrollment_scope");
        }
        return found.Version;
    }
}
