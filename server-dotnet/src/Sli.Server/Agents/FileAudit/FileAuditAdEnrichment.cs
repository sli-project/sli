using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Auth;

namespace Sli.Server.Agents.FileAudit;

// Source sli.ad/file_audit_enrichment.py; reads retained observations only.
internal sealed class FileAuditAdEnrichment(FileAuditHookAdmission admission)
{
    internal static async Task<System.Text.Json.JsonElement> SearchAccounts(NpgsqlConnection db, NpgsqlTransaction tx,
        JsonObject? body, Principal principal, CapabilityDecisionSet access, CancellationToken ct)
    {
        if (principal.Role != "admin" && !access.IsOwner) throw new AgentControlException("file_audit_request_denied", 403);
        if (body is null || !Sli.Agent.Protocol.JsonRead.HasExactly(body, "q", "sids")
            || S(body["q"]) is not string search || search.Length > 128 || body["sids"] is not JsonArray { Count: <= 100 } selected
            || selected.Any(item => S(item) is not string sid || sid.Length > 184
                || !System.Text.RegularExpressions.Regex.IsMatch(sid, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z")))
            throw new AgentControlException("file_audit_request_invalid");
        using var read = new NpgsqlCommand("""
            with accounts as (
                select alias.normalized_value as sid,d.id as domain_id,alias.entity_id,
                    coalesce(nullif(d.netbios_name,''),d.fqdn)||chr(92)||
                    coalesce(nullif(v.attributes_json#>>'{attributes,sam_account_name}',''),
                        nullif(v.attributes_json#>>'{attributes,display_name}','')) as name
                from public.ad_context_entity_aliases alias
                join public.domains d on d.id=alias.domain_id and not d.is_archived
                join public.ad_context_entity_versions v on v.entity_id=alias.entity_id and v.valid_to_utc is null
                join public.ad_context_runs run on run.run_id=v.source_run_id and run.status='completed'
                where alias.alias_type='object_sid'
                    and alias.normalized_value ~ '^s-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$'
                    and (v.source_section='directory_accounts' and v.attributes_json#>>'{identity,kind}'='ad_user'
                        or v.source_section='directory_group_graph' and v.attributes_json#>>'{identity,kind}'='ad_group')
            )
            select distinct sid,domain_id,entity_id,left(name,256) as name
            from accounts where name is not null and (sid=any(@sids) or
                (char_length(@search)>=2 and strpos(lower(name),lower(@search))>0))
            order by name,sid limit 200
            """, db, tx);
        read.Parameters.AddWithValue("sids", selected.Select(sid => S(sid)!.ToLowerInvariant()).ToArray());
        read.Parameters.AddWithValue("search", search.Trim());
        var items = new List<object>();
        await using var rows = await read.ExecuteReaderAsync(ct);
        while (await rows.ReadAsync(ct))
        {
            IReadOnlyList<IReadOnlyList<AccessResource>> group = [[new("entity", rows.GetInt64(2)) { DomainId = rows.GetInt64(1) }]];
            if (access.DecideForResourceGroups("field.identity_basic", group).Allowed
                && access.DecideForResourceGroups("field.technical", group).Allowed)
                items.Add(new { sid = rows.GetString(0).ToUpperInvariant(), name = rows.GetString(3) });
        }
        return System.Text.Json.JsonSerializer.SerializeToElement(new { items });
    }

    internal static bool PythonTruthy(JsonNode? node)
    {
        if(node is null) return false;
        if(node is JsonArray array) return array.Count!=0;
        if(node is JsonObject obj) return obj.Count!=0;
        var e=System.Text.Json.JsonSerializer.SerializeToElement(node);
        return e.ValueKind switch { System.Text.Json.JsonValueKind.True=>true, System.Text.Json.JsonValueKind.False or System.Text.Json.JsonValueKind.Null=>false,
            System.Text.Json.JsonValueKind.String=>e.GetString()!.Length!=0, System.Text.Json.JsonValueKind.Number=>!System.Numerics.BigInteger.TryParse(e.GetRawText(),out var n) ? e.GetDouble()!=0 : n!=0, _=>false };
    }
    private static string? S(JsonNode? n)=>n is JsonValue v && v.TryGetValue<string>(out var s)?s:null;
    private static string Stamp(DateTimeOffset value)=>AgentControlJson.Stamp(value.ToUniversalTime(),true);
    public async Task<JsonObject> Principals(NpgsqlConnection db,NpgsqlTransaction tx,long? domain,IReadOnlyCollection<string> sids,string at,CancellationToken ct)
    {
        var result=new JsonObject(); if(domain is null || sids.Count>2048 || !admission.Present("sli.ad")) return result;
        using var guard=AgentAssignmentPluginAdmission.Enter("sli.ad",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        if(!admission.Present("sli.ad")) return result;
        var instant=DateTimeOffset.Parse(at,System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime();
        var rows=new List<(string Sid,long Entity,JsonObject Record,DateTimeOffset Observed,string Run)>();
        await using(var query=new NpgsqlCommand("""
            select a.normalized_value,v.entity_id,v.attributes_json::text,v.last_observed_at_utc,v.source_run_id::text
            from ad_context_entity_aliases a join ad_context_entity_versions v on v.entity_id=a.entity_id
            join ad_context_runs r on r.run_id=v.source_run_id and r.status='completed'
            where a.domain_id=@domain and a.alias_type='object_sid' and a.normalized_value=any(@sids)
              and v.source_section in ('directory_accounts','directory_group_graph')
              and v.valid_from_utc<=@instant and (v.valid_to_utc is null or v.valid_to_utc>@instant)
            order by a.normalized_value,v.valid_from_utc desc limit 2049
            """,db,tx))
        {
            query.Parameters.AddWithValue("domain",domain.Value);query.Parameters.AddWithValue("sids",sids.Select(x=>x.ToLowerInvariant()).ToArray());query.Parameters.AddWithValue("instant",instant.UtcDateTime);
            await using var reader=await query.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) rows.Add((reader.GetString(0),reader.GetInt64(1),JsonNode.Parse(reader.GetString(2))!.AsObject(),new DateTimeOffset(reader.GetDateTime(3).ToUniversalTime()),reader.GetString(4)));
        }
        if(rows.Count>2048) return result;
        foreach(var row in rows)
        {
            var identity=row.Record["identity"] as JsonObject ?? new();var attributes=row.Record["attributes"] as JsonObject ?? new(); string? sid=S(identity["object_sid"]),kind=S(identity["kind"]);
            if(sid is null || !sids.Contains(sid) || result.ContainsKey(sid) || kind is not ("ad_user" or "ad_group")) continue;
            var observed=row.Observed<instant?row.Observed:instant;bool fresh=row.Observed<=instant && instant-observed<=TimeSpan.FromDays(1);
            bool? enabled=attributes["enabled"] is JsonValue ev && ev.TryGetValue<bool>(out var flag)?flag:null;
            var principal=new JsonObject { ["kind"]=kind=="ad_user"?"user":"group",["enabled"]=fresh && enabled is not null?JsonValue.Create(enabled.Value):null,["domain_users"]=kind=="ad_group" && sid.EndsWith("-513",StringComparison.Ordinal),["group_sids"]=new JsonArray(),["complete"]=false,["observed_at"]=Stamp(observed),["evidence_ref"]=$"ad-context:{row.Run}:{row.Entity}" };
            if(fresh && kind=="ad_user")
            {
                var groups=new List<(int Depth,string? Sid,bool Complete,string? Run)>();
                await using var query=new NpgsqlCommand("""
                    with recursive graph as (
                      select r.run_id,r.observed_at_utc,r.mode,s.status from ad_context_runs r join ad_context_sections s on s.run_id=r.run_id
                      where r.domain_id=@domain and r.status='completed' and s.section_name='directory_group_graph' and r.observed_at_utc between @instant-interval '1 day' and @instant
                      order by r.observed_at_utc desc,r.run_id limit 1
                    ), membership(entity_id,depth,visited) as (
                      select @entity::bigint,0,array[@entity::bigint] from graph union all
                      select relation.target_entity_id,m.depth+1,m.visited||relation.target_entity_id from graph,membership m join ad_context_relation_versions relation on relation.source_entity_id=m.entity_id
                      where relation.domain_id=@domain and relation.source_section='directory_group_graph' and relation.last_observed_at_utc>=graph.observed_at_utc
                        and relation.valid_from_utc<=graph.observed_at_utc and (relation.valid_to_utc is null or relation.valid_to_utc>graph.observed_at_utc)
                        and m.depth<16 and not relation.target_entity_id=any(m.visited)
                    ) select m.depth,a.normalized_value,(graph.status='complete' and graph.mode in ('full','reconcile')),graph.run_id::text
                    from graph,membership m left join ad_context_entity_aliases a on a.entity_id=m.entity_id and a.alias_type='object_sid' and a.domain_id=@domain
                    order by m.depth,a.normalized_value limit 2049
                    """,db,tx);
                query.Parameters.AddWithValue("domain",domain.Value);query.Parameters.AddWithValue("instant",instant.UtcDateTime);query.Parameters.AddWithValue("entity",row.Entity);
                await using(var reader=await query.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct)) groups.Add((reader.GetInt32(0),reader.IsDBNull(1)?null:reader.GetString(1),reader.GetBoolean(2),reader.IsDBNull(3)?null:reader.GetString(3)));
                bool complete=groups.Count>0 && groups.Count<=2048 && groups.All(g=>g.Complete && g.Sid is not null && g.Depth<16);
                var memberships=groups.Where(g=>g.Depth>0 && g.Sid is not null).Select(g=>g.Sid!.ToUpperInvariant()).Distinct().Order(StringComparer.Ordinal).ToList();
                if(groups.Count>0 && groups[0].Run is string graphRun) principal["membership_evidence_ref"]=$"ad-context:{graphRun}:directory_group_graph";
                string? primary=attributes["primary_group_id"]?.ToString(); if(primary is not null && primary.Length>0 && primary.All(char.IsAsciiDigit)) memberships.Add(sid[..sid.LastIndexOf('-')]+"-"+primary); else complete=false;
                if(PythonTruthy(attributes["unresolved_group_dns"]) || PythonTruthy(attributes["unresolved_primary_group_sid"])) complete=false;
                principal["group_sids"]=new JsonArray(memberships.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());principal["complete"]=complete;
            }
            result[sid]=principal;
        }
        return result;
    }
}


