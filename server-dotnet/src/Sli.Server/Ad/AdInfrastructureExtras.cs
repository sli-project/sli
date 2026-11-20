using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdInfrastructureExtras
{
    internal static List<JsonObject> SpnRows(IEnumerable<JsonObject> rows,JsonObject parameters,DateTimeOffset now,out int unknownIdentity,out int unknownSpn,out bool truncated)
    {
        unknownIdentity=0;unknownSpn=0;truncated=false;int values=0;
        var groups=new Dictionary<(long,string,string),Dictionary<long,JsonObject>>();
        foreach(var row in rows)
        {
            var record=JsonNode.Parse(row.Text("attributes_json")??"{}")!;var attrs=record["attributes"];var identity=record["identity"];
            if((identity.Text("object_guid")??identity.Text("object_sid")) is null||row.Int("entity_id")<=0||row.Text("run_id") is null){unknownIdentity++;continue;}
            if(attrs?["service_principal_names"] is not JsonArray names){unknownSpn++;continue;}
            var password=AdInventoryRows.Date(attrs["password_last_set_utc"]);int? age=password<=now?(int?)(now-password.Value).TotalDays:null;
            var owner=new JsonObject();foreach(string field in new[]{"entity_id","entity_type","domain_id","run_id","observed_at_utc"})owner[field]=row[field]?.DeepClone();
            owner["password_last_set_utc"]=password.HasValue?Iso(password.Value):null;owner["password_age_days"]=age;
            foreach(string key in new[]{"enabled","trusted_for_delegation","trusted_to_auth_for_delegation","does_not_require_preauth"})owner[key]=AdInventoryRows.Bool(attrs?[key]);
            owner["msds_supported_encryption_types"]=attrs?["msds_supported_encryption_types"]?.DeepClone();
            owner["owner_quality"]=age is null||new[]{"enabled","trusted_for_delegation","trusted_to_auth_for_delegation","does_not_require_preauth","msds_supported_encryption_types"}.Any(k=>owner[k] is null)?"unknown":"known";
            var at=AdInventoryRows.Date(row["observed_at_utc"]);owner["source_freshness"]=at is null?"unknown":at<now.AddHours(-36)?"stale":"fresh";
            foreach(var name in names)
            {
                if(name?.GetValueKind()!=System.Text.Json.JsonValueKind.String||name.ToString().Length==0)continue;if(++values>50000){truncated=true;break;}
                var key=(row.Int("domain_id"),row.Text("run_id")!,name.ToString().ToLowerInvariant());if(!groups.TryGetValue(key,out var entries))groups[key]=entries=[];var entry=(JsonObject)owner.DeepClone();entry["spn"]=name.DeepClone();entries[row.Int("entity_id")]=entry;
            }
            if(truncated)break;
        }
        var result=new List<JsonObject>();foreach(var(key,owners)in groups.OrderBy(g=>g.Key.Item1).ThenBy(g=>g.Key.Item2,StringComparer.Ordinal).ThenBy(g=>g.Key.Item3,StringComparer.Ordinal))
        {
            if(parameters.Text("spn_collisions_only")!="false"&&owners.Count<2||parameters.Text("spn_service") is {} service&&key.Item3.Split('/')[0]!=service.ToLowerInvariant())continue;
            foreach(var owner in owners.Values)
            {
                var flags=new[]{"trusted_for_delegation","trusted_to_auth_for_delegation","does_not_require_preauth"}.Select(k=>AdInventoryRows.Bool(owner[k])).ToArray();bool? flagged=flags.Contains(true)?true:flags.All(v=>v==false)?false:null;
                if(parameters.Text("spn_enabled") is "true" or "false"&&AdInventoryRows.Bool(owner["enabled"])!=(parameters.Text("spn_enabled")=="true")||parameters.Text("spn_delegation") is "true" or "false"&&flagged!=(parameters.Text("spn_delegation")=="true")||parameters["spn_password_days"] is not null&&(owner["password_age_days"] is null||owner.Int("password_age_days")<parameters.Int("spn_password_days"))||parameters.Text("q") is {} q&&!owner.Text("spn")!.Contains(q,StringComparison.OrdinalIgnoreCase))continue;
                owner["owner_count"]=owners.Count;owner["normalized_spn"]=key.Item3;owner["row_id"]=$"{key.Item1}:{key.Item2}:{key.Item3}:{owner.Int("entity_id")}";result.Add(owner);
            }
        }
        truncated|=result.Count>5000;return result.Take(5000).ToList();
    }
    internal static async Task<JsonObject> SpnAsync(NpgsqlConnection db,AdV2Request request,CancellationToken ct)
    {
        long[] domains=request.Domains;if(request.Params["spn_domain"] is not null){long domain=request.Params.Int("spn_domain");if(!domains.Contains(domain))throw new AdAccessException("report_scope_not_executable");domains=[domain];}
        var now=DateTimeOffset.UtcNow;var sources=await AdJson.ReadAsync(db,"""
            select distinct on(run.domain_id) run.run_id::text,run.domain_id,run.observed_at_utc,run.scope_json::text,run.status as run_status,section.status as section_status,section.record_count
            from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id
            where section.section_name='directory_accounts' and run.mode in ('full','reconcile') and run.status<>'importing'
              and run.observed_at_utc>=$1 and run.observed_at_utc<=$2 and run.domain_id=any($3)
            order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc limit 101
            """,ct,now.AddDays(-31),now,domains);
        var eligible=sources.Take(100).Where(r=>r.Text("run_status")=="completed"&&r.Text("section_status") is "complete" or "partial"&&JsonNode.Parse(r.Text("scope_json")??"{}")!.Text("search_base") is not null).ToArray();
        var rows=await AdJson.ReadAsync(db,"""
            select entity.id as entity_id,entity.domain_id,kind.value as entity_type,evidence.source_run_id::text as run_id,evidence.observed_at_utc,version.attributes_json::text
            from ad_context_evidence evidence join ad_context_runs run on run.run_id=evidence.source_run_id
            join entities_v2 entity on entity.domain_id=run.domain_id join storage_v2_entity_type kind on kind.id=entity.entity_type_id
            join ad_context_entity_versions version on version.entity_id=entity.id and version.source_section='directory_accounts'
              and version.attributes_json->>'record_key'=evidence.locator_json->>'record_key' and version.valid_from_utc<=evidence.observed_at_utc
              and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
            where evidence.source_run_id=any($1) and evidence.evidence_type='entity_observation' and evidence.locator_json->>'section'='directory_accounts'
              and kind.value in ('ad_user','ad_computer') order by entity.domain_id,entity.id limit 5001
            """,ct,eligible.Select(r=>Guid.Parse(r.Text("run_id")!)).ToArray());
        var items=SpnRows(rows.Take(5000),request.Params,now,out int unknownIdentity,out int unknownSpn,out bool truncated);truncated|=sources.Count>100||rows.Count>5000;
        bool missing=eligible.Sum(s=>s.Int("record_count"))>rows.Count;bool partial=truncated||missing||domains.Except(eligible.Select(s=>s.Int("domain_id"))).Any()||unknownIdentity>0||unknownSpn>0||eligible.Length!=sources.Count||eligible.Any(s=>s.Text("section_status")!="complete");
        string state=eligible.Length==0?"error":partial?"partial":eligible.Any(s=>s.Time("observed_at_utc")<now.AddHours(-36))?"stale":items.Count>0?"ok":"empty";
        var coverage=Obj(new{state=state=="error"?"unavailable":state,sources=sources.Take(100).Select(s=>new{domain_id=s.Int("domain_id"),run_id=s.Text("run_id"),observed_at_utc=s.Text("observed_at_utc"),section_status=s.Text("section_status"),run_status=s.Text("run_status"),search_base=JsonNode.Parse(s.Text("scope_json")??"{}")!.Text("search_base")}),unknown_identity_count=unknownIdentity,unknown_spn_count=unknownSpn,missing_records=missing,truncated});
        var result=AdV2Store.Result(request.Key,state,coverage:coverage);result["collections"]!["spn_collisions"]=Array(items);result["filtered_count"]=items.Count;
        var owners=items.DistinctBy(i=>(i.Int("domain_id"),i.Text("run_id"),i.Int("entity_id"))).ToArray();bool known=!truncated&&!missing&&eligible.Length>0;
        result["metrics"]=Array(new[]{("spn_collisions","SPN с несколькими владельцами",items.Where(i=>i.Int("owner_count")>1).DistinctBy(i=>(i.Int("domain_id"),i.Text("run_id"),i.Text("normalized_spn"))).Count()),("spn_disabled","Отключённых владельцев SPN",owners.Count(i=>AdInventoryRows.Bool(i["enabled"])==false)),("spn_flagged","Владельцев с delegation/preauth-флагами",owners.Count(i=>new[]{"trusted_for_delegation","trusted_to_auth_for_delegation","does_not_require_preauth"}.Any(k=>AdInventoryRows.Bool(i[k])==true))),("spn_unknown","Владельцев с неизвестными параметрами",owners.Count(i=>i.Text("owner_quality")=="unknown"))}.Select(m=>Obj(new{key=m.Item1,label=m.Item2,value=known?(int?)m.Item3:null})));result["limitations"]=new JsonArray(Obj(new{code="spn_scope",text="Владельцы сравниваются только внутри одного запуска сбора directory_accounts и его SearchBase. Разные домены и снимки не объединяются; область сбора может быть неполной."}),Obj(new{code="spn_encryption",text="Поддерживаемое шифрование аккаунта не доказывает фактическое шифрование Kerberos-билета. Неизвестные атрибуты не считаются безопасными."}));return result;
    }
    internal static async Task<JsonObject> PrivilegedAsync(NpgsqlConnection db,AdV2Request request,CancellationToken ct)
    {
        var period=request.Params["period"]!;var start=period.Time("from_utc");var end=period.Time("to_utc");if(!int.TryParse(request.Cursor??"0",out int offset)||offset<0)throw new AdInputException("report_cursor_invalid");
        var history=await AdJson.ReadAsync(db,"select run.domain_id,min(run.observed_at_utc) as history_from,max(run.observed_at_utc) as observed_at_utc from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id where run.domain_id=any($1) and run.status='completed' and section.section_name='privileged_membership' and section.status='complete' and run.observed_at_utc<=$2 group by run.domain_id order by run.domain_id",ct,request.Domains,end);
        var rows=await AdJson.ReadAsync(db,"""
            select relation.id,relation.source_entity_id as entity_id,relation.target_entity_id as group_id,change.kind,change.at as observed_at_utc
            from ad_context_relation_versions relation cross join lateral(values(relation.valid_from_utc,'added'),(relation.valid_to_utc,'removed'))change(at,kind)
            where relation.domain_id=any($1) and relation.source_section='privileged_membership' and relation.relation_kind='member_of' and change.at>=$2 and change.at<$3
              and not exists(select 1 from ad_context_relation_versions adjacent where adjacent.domain_id=relation.domain_id and adjacent.relation_key=relation.relation_key and adjacent.source_section=relation.source_section and adjacent.id<>relation.id and ((change.kind='added' and adjacent.valid_to_utc=change.at) or (change.kind='removed' and adjacent.valid_from_utc=change.at)))
              and (change.kind='removed' or exists(select 1 from ad_context_runs run join ad_context_sections section on section.run_id=run.run_id where run.domain_id=relation.domain_id and run.status='completed' and section.section_name='privileged_membership' and section.status='complete' and run.observed_at_utc<relation.valid_from_utc))
            order by change.at desc,relation.id desc,change.kind limit $4 offset $5
            """,ct,request.Domains,start,end,request.Limit+1,offset);
        bool more=rows.Count>request.Limit;rows=rows.Take(request.Limit).ToList();foreach(var row in rows)row["row_id"]=row.Int("id")+":"+row.Text("kind");var domains=history.Select(h=>h.Int("domain_id")).ToArray();
        var result=AdV2Store.Result(request.Key,history.Count>0?"partial":"not_collected",rows,Obj(new{observed_at_utc=history.Select(h=>h.Text("observed_at_utc")).Order().FirstOrDefault(),domain_ids=domains,missing_domains=request.Domains.Except(domains).Order()}));result["collections"]!["privileged_changes"]=Array(rows);result["has_more"]=more;result["next_cursor"]=more?(offset+rows.Count).ToString(CultureInfo.InvariantCulture):null;result["limitations"]=new JsonArray(Obj(new{code="snapshot_observations",text="Изменения — наблюдения импортированной истории членства; время изменения в AD и непрерывное покрытие событий не подтверждены. Первоначальный состав не считается изменением."}));return result;
    }
}
