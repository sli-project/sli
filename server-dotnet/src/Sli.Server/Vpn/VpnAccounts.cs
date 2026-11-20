using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Access;

namespace Sli.Server.Vpn;

public static class VpnAccounts
{
    const string AccountsCte="""
        with vpn_accounts as (
          select distinct source_entity.id,source_entity.domain_id,source_entity.id::text as object_id,
              source_entity.display_name,source_entity.natural_key,
              (account.attributes_json->'attributes'->>'enabled')::boolean as enabled,
              account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,
              case when account.attributes_json->'attributes'->>'enabled' is null then 'unknown'
                   when (account.attributes_json->'attributes'->>'enabled')::boolean is false then 'disabled'
                   when not coalesce((account.attributes_json->'attributes'->>'last_logon_utc') ~ 'T.*(Z|[+-][0-9]{2}:[0-9]{2})$',false)
                     or not coalesce(pg_input_is_valid(account.attributes_json->'attributes'->>'last_logon_utc','timestamp with time zone'),false)
                     or account.last_observed_at_utc is null then 'unknown'
                   when (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz>account.last_observed_at_utc then 'unknown'
                   when (account.attributes_json->'attributes'->>'last_logon_utc')::timestamptz<account.last_observed_at_utc-($2 * interval '1 day') then 'inactive'
                   else 'active' end as activity_state,
              (account.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,
              (account.attributes_json->'attributes'->>'admin_count')::integer as admin_count,
              account.attributes_json->'attributes'->>'department' as department,
              account.attributes_json->'attributes'->>'title' as title,
              account.attributes_json->'attributes'->>'email' as email,
              exists(select 1 from ad_context_relation_versions privileged where privileged.source_entity_id=source_entity.id
                  and privileged.valid_to_utc is null and privileged.relation_kind='member_of'
                  and privileged.source_section='privileged_membership') as privileged_overlap,
              greatest(account.last_observed_at_utc,source_entity.last_seen_utc) as observed_at
          from ad_context_relation_versions relation
          join entities_v2 source_entity on source_entity.id=relation.source_entity_id
          join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id
          left join lateral (
              select current.attributes_json,current.last_observed_at_utc from ad_context_entity_versions current
              where current.entity_id=source_entity.id and current.source_section in ('directory_accounts','vpn_membership')
                and current.valid_to_utc is null
              order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                  current.last_observed_at_utc desc,current.id desc limit 1
          ) account on true
          where ($1::jsonb->>'kind'='all'
            or ($1::jsonb->>'kind'='domain' and source_entity.domain_id=any(array(select value::bigint from jsonb_array_elements_text($1->'ids'))))
            or ($1::jsonb->>'kind'='server' and source_entity.server_id=any(array(select value::bigint from jsonb_array_elements_text($1->'ids')))))
              and relation.valid_to_utc is null and relation.relation_kind='member_of'
              and relation.source_section='vpn_membership' and entity_type.value='ad_user' and entity_v2_is_active(source_entity.id)
        )
        """;
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,IQueryCollection query,string action,CancellationToken ct)
    {
        string Get(string key,string fallback="")=>query[key].FirstOrDefault()??fallback;
        int limit=VpnReports.ParseInt(Get("limit","200"),"report_limit_invalid");if(limit is <1 or >200) throw new VpnInputException("report_limit_invalid");if(action=="export") limit=200;
        string activity=Get("activity");if(activity!="" && activity is not ("active" or "inactive" or "disabled" or "unknown")) throw new VpnInputException("report_parameter_invalid:activity");
        string search=Get("q").Trim();if(search.Length>256) throw new VpnInputException("report_parameter_too_long:q");
        long cursor=action=="export"?0:DecodeCursor(Get("cursor"));
        var domains=await db.ReadAsync("select id from domains order by id limit 10001",[],ct);if(domains.Count>10000) throw new VpnInputException("vpn_account_domain_bound_exceeded");
        var grants=access.Grants(action);if(grants.Count>32) throw new VpnInputException("report_grant_branch_limit_exceeded");
        if(grants.Any(g=>g.Scope.TryGetProperty("mode",out _))) throw new VpnPermissionException("report_scope_not_executable");
        int days=(int)((await db.ReadAsync("select value from platform_settings where key='ad.inactivity_days'",[],ct)).FirstOrDefault().Number("value"));if(days is <1 or >3650) days=90;
        var definitions=await db.ReadAsync("""
            select d.fields_json,r.definition_json from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key='vpn.audit' and r.status='published' order by r.version desc limit 1
            """,[],ct);
        var definition=definitions.FirstOrDefault()??throw new VpnInputException("report_definition_not_found");
        if(action=="export" && definition["definition_json"].Text("export_policy")!="controlled") throw new VpnPermissionException("report_export_denied");
        var fields=definition["fields_json"]?.AsArray().OfType<JsonObject>().ToArray()??[];
        var columns=definition["definition_json"]?["columns"]?.AsArray().Select(x=>x is JsonObject c?c.Text("key"):x?.ToString()??"").ToHashSet(StringComparer.Ordinal)??fields.Select(f=>f.Text("key")).ToHashSet(StringComparer.Ordinal);
        var combined=new List<JsonObject>();var exportFields=new List<JsonObject>();bool more=false;long? count=null;JsonObject? summary=null;string? next=null;int branchCount=0;
        foreach(var grant in grants)
        {
            var scope=JsonNode.Parse(grant.Scope.GetRawText())!.AsObject();string kind=scope.Text("kind");if(kind is not ("all" or "domain" or "server")) continue;
            if(kind!="all")
            {
                if(scope["ids"] is not JsonArray ids || ids.Count==0) continue;
                var parsed=new JsonArray();foreach(var id in ids.Take(100)) {if(!long.TryParse(id?.ToString(),out long n)) throw new VpnInputException("invalid_report_scope");parsed.Add(n);}scope["ids"]=parsed;
            }
            var selected=fields.Where(f=>columns.Contains(f.Text("key")) && grant.FieldCategories.Contains(f.Text("category"))).ToArray();if(selected.Length==0) continue;branchCount++;
            foreach(var field in selected) if(!exportFields.Any(f=>f.Text("key")==field.Text("key"))) exportFields.Add((JsonObject)field.DeepClone());
            string filter=" where ($3='' or strpos(lower(concat_ws(' ',display_name,natural_key)),lower($4))>0) and ($5='' or activity_state=$5)";
            object?[] parameters=[scope,days,search,search,activity];
            var totals=(await db.ReadAsync(AccountsCte+" select count(*) as filtered_count from vpn_accounts"+filter,parameters,ct)).FirstOrDefault();
            var rows=await db.ReadAsync(AccountsCte+" select * from vpn_accounts"+filter+" and id>$6 order by id limit $7",[..parameters,action=="export"?0:cursor,limit+1],ct);
            more|=rows.Count>limit;if(rows.Count>limit) next=EncodeCursor(rows[limit-1].Text("object_id"));
            var collection=await Collection(db,scope,ct);
            foreach(var source in rows.Take(limit))
            {
                var row=new JsonObject();foreach(var field in selected) {string key=field.Text("key");row[key]=source[key]?.DeepClone();}
                Present(row,collection["privileged_membership"].Text("state"));combined.Add(row);
            }
            var aggregates=(await db.ReadAsync(AccountsCte+"""
                select count(*) as total_users,count(*) filter(where activity_state='active') as active_users,
                  count(*) filter(where activity_state='inactive') as inactive_users,count(*) filter(where enabled is false) as disabled_users,
                  count(*) filter(where privileged_overlap) as privileged_overlap_users,max(observed_at) as latest_observed_at_utc
                from vpn_accounts
                """,[scope,days],ct)).FirstOrDefault()??new JsonObject();
            summary=new JsonObject();foreach(var (key,category) in new[]{("total_users","identity_basic"),("active_users","security"),("inactive_users","security"),("disabled_users","security"),("privileged_overlap_users","privilege"),("latest_observed_at_utc","security")}) if(grant.FieldCategories.Contains(category)) summary[key]=aggregates[key]?.DeepClone();
            summary["collection"]=collection;
            count=totals?.Number("filtered_count");
        }
        if(branchCount>1) {summary=null;count=null;next=null;}
        combined=combined.DistinctBy(r=>r.ToJsonString()).OrderBy(r=>long.TryParse(r.Text("object_id"),out long id)?id:long.MaxValue).ToList();
        var collectionStates=summary?["collection"]?.AsObject().Select(x=>x.Value.Text("state")).ToArray()??[];
        string state=collectionStates.Contains("failed")?"error":collectionStates.Any(s=>s is "partial" or "skipped" or "not_collected" or "")?"partial":combined.Count==0?"empty":"ok";
        var result=VpnReports.Result("vpn.accounts",state,combined.Take(limit));
        result["has_more"]=more;result["next_cursor"]=next;result["filtered_count"]=count;
        var metrics=new List<JsonObject>();foreach(var (key,label,tone) in new[]{("total_users","Всего VPN-пользователей","accent"),("active_users","Активные","success"),("inactive_users","Неактивные по входу","warning"),("disabled_users","Отключённые","warning"),("privileged_overlap_users","VPN и привилегии","danger")})
        {
            var metric=VpnJson.Obj(new {key,label,value=summary?[key]?.DeepClone(),tone=summary.Number(key)>0?tone:"neutral"});
            if(key is "active_users" or "inactive_users" or "disabled_users") metric["filter"]=VpnJson.Obj(new {activity=key[..^6]});
            metrics.Add(metric);
        }
        result["metrics"]=VpnJson.Array(metrics);
        string[] limitations=[
            "Состав VPN определяется только членством в явно заданных группах AD.",
            "Неактивность — признак гигиены по последнему входу, а не подтверждённый инцидент.",
            "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов.",
            "Неизвестно: дата входа или наблюдения отсутствует, некорректна либо дата входа позже наблюдения. Такие записи не классифицируются по политике.",
            "Состояние учётной записи берётся из отдельного directory_accounts, а до его появления — из ограниченного снимка участника VPN-группы.",
            "Отсутствующий снимок учётной записи показывается как неопределённое состояние, а не как отключение.",
            "События подключения VPN-шлюза этим срезом не собираются."];
        result["limitations"]=VpnJson.Array(limitations.Select((text,index)=>VpnJson.Obj(new {code=$"vpn_accounts_{index}",text})));
        result["coverage"]=VpnJson.Obj(new {state,observed_at_utc=summary?["latest_observed_at_utc"]?.DeepClone(),missing_sources=summary?["collection"]?.AsObject().Where(x=>x.Value.Text("state") is not ("complete" or "completed" or "available")).Select(x=>x.Key).ToArray()??Array.Empty<string>()});
        if(action=="export") result["_export_fields"]=VpnJson.Array(exportFields);return result;
    }
    static async Task<JsonObject> Collection(IVpnReadSession db,JsonObject scope,CancellationToken ct)
    {
        string[] names=["vpn_membership","directory_accounts","privileged_membership"];var collection=new JsonObject();
        if(scope.Text("kind")=="server") {foreach(string name in names) collection[name]=VpnJson.Obj(new {state="scope_not_applicable",domain_count=0,complete_domain_count=0,partial_domain_count=0,failed_domain_count=0,skipped_domain_count=0,latest_observed_at_utc=(string?)null});return collection;}
        var rows=await db.ReadAsync("""
            with ranked as (
              select run.domain_id,section.section_name,section.status,run.observed_at_utc,
                row_number() over(partition by run.domain_id,section.section_name order by run.observed_at_utc desc,run.created_at desc,run.run_id desc) as position
              from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
              where section.section_name=any($1) and run.status='completed'
                and ($2::jsonb->>'kind'='all' or run.domain_id=any(array(select value::bigint from jsonb_array_elements_text($2->'ids'))))
            ) select section_name,count(*) as domain_count,count(*) filter(where status='complete') as complete_domain_count,
                count(*) filter(where status='partial') as partial_domain_count,count(*) filter(where status='failed') as failed_domain_count,
                count(*) filter(where status='skipped') as skipped_domain_count,max(observed_at_utc) as latest_observed_at_utc
              from ranked where position=1 group by section_name order by section_name
            """,[names,scope],ct);
        foreach(string name in names)
        {
            var row=rows.FirstOrDefault(r=>r.Text("section_name")==name)??VpnJson.Obj(new {domain_count=0,complete_domain_count=0,partial_domain_count=0,failed_domain_count=0,skipped_domain_count=0,latest_observed_at_utc=(string?)null});
            row=(JsonObject)row.DeepClone();long domains=row.Number("domain_count");row.Remove("section_name");row["state"]=domains==0?"not_collected":row.Number("failed_domain_count")==domains?"failed":row.Number("skipped_domain_count")==domains?"skipped":row.Number("complete_domain_count")==domains?"complete":"partial";collection[name]=row;
        }
        return collection;
    }
    public static void Present(JsonObject row,string? privilegeCoverage)
    {
        bool department=row.ContainsKey("department"),password=row.ContainsKey("password_never_expires"),privilege=row.ContainsKey("privileged_overlap");
        row["activity"]=row.Text("activity_state","unknown").ToLowerInvariant();
        row["department_text"]=department?row.Text("department") is {Length:>0} text?text:"Не указано":"Поле недоступно";
        row["password_text"]=password?row.Flag("password_never_expires")?"Без ограничения срока":"С ограничением срока":"Поле недоступно";
        row["privilege_text"]=row.Flag("privileged_overlap")?"Есть пересечение":!privilege?"Поле недоступно":privilegeCoverage=="complete"?"Не обнаружено":privilegeCoverage=="partial"?"Не обнаружено в неполном срезе":"Срез не собран";
        row["department_text_code"]=!department?"unavailable":row.Text("department")==""?"unspecified":null;
        row["password_text_code"]=!password?"unavailable":row.Flag("password_never_expires")?"never_expires":"expires";
        row["privilege_text_code"]=row.Flag("privileged_overlap")?"overlap":!privilege?"unavailable":privilegeCoverage=="complete"?"not_detected":privilegeCoverage=="partial"?"not_detected_partial":"not_collected";
    }
    public static long DecodeCursor(string value)
    {
        if(value=="") return 0;
        try {if(value.Length>512) throw new FormatException();string clean=value.Replace('-','+').Replace('_','/');clean=clean.PadRight((clean.Length+3)/4*4,'=');var row=JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(clean)));string id=row.Text("object_id");if(id.Length==0 || id.Any(c=>c is <'0' or >'9') || !long.TryParse(id,out long n)||n<=0) throw new FormatException();return n;}
        catch(Exception e) when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException) {throw new VpnInputException("invalid_report_cursor");}
    }
    public static string EncodeCursor(string id)=>Convert.ToBase64String(Encoding.UTF8.GetBytes(new JsonObject {["object_id"]=id}.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
}
