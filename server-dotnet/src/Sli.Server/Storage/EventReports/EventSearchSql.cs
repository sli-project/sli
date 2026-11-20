using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Entities;

namespace Sli.Server.Storage.EventReports;

// Only compiler-owned identifiers enter SQL; all values use PostgreSQL parameters.
internal sealed class EventSearchSql
{
    internal static readonly string[] TextFields=["channel","provider","ip","subject_user_name","target_user_name","message_sample"];
    internal readonly Dictionary<string,object> Parameters=[];
    internal string Value(object value)
    {
        string name="p"+Parameters.Count; Parameters[name]=value; return "@"+name;
    }
    internal string Expr(string field)
    {
        if(field is not ("action" or "outcome")) return field switch {
            "channel" => "e.channel", "provider" => "e.provider_name", "ip" => "e.source",
            "subject_user_name" => "e.method#>>'{$principals,SubjectUserName}'", "target_user_name" => "e.method#>>'{$principals,TargetUserName}'",
            "reason" => "coalesce(e.outcome->>'Status',e.fields->>'Status')",
            "logon_type" => "e.method->>'LogonType'",
            "message_sample" or "task_identity" or "process_identity" or "file_identity" or "title" => "null::text",
            "group_identity_complete" => "false", "source_payload_state" => "'expired'",
            "id" or "event_id" or "server_id" or "domain_id" or "time_created_utc" => "e."+field,
            _ => throw new EventSearchException("unsupported_field") };
        if(field=="action") return $"case when {Expr("provider")}='Microsoft-Windows-Security-Auditing' and {Expr("channel")}='Security' and {Expr("event_id")} in (4624,4625) then 'authentication.logon' end";
        if(field=="outcome")
        {
            string code=Expr("reason"),trim="btrim";
            return $"case when {Expr("provider")}='Microsoft-Windows-Security-Auditing' and {Expr("channel")}='Security' then case when {Expr("event_id")} in (4625,4771,6273) then 'failure' when {Expr("event_id")} in (4624,6272) then 'success' when {Expr("event_id")}=4776 and nullif({trim}({code}),'') is not null then case when lower({trim}({code})) in ('0','0x0','0x00000000','00000000') then 'success' else 'failure' end end end";
        }
        throw new EventSearchException("unsupported_field");
    }
    internal string Links(string field,string? role=null)
    {
        string extra=field is "account" or "account_kind" ? " and kind.value in ('ad_user','ad_computer','security_principal') and role.value "+(role is "actor" or "target"?"="+Value(role):"in ('actor','target')"):
            field=="source_station"?" and role.value='source' and kind.value in ('workstation','asset','ad_computer')":"";
        return """
            from public.short_event_entity_links339(e.event_id,e.actor,e.target,e.source,e.computer,e.method,e.fields) extracted
            join entities_v2_active entity on entity.domain_id is null or entity.domain_id=e.domain_id
            cross join lateral public.entity_event_keys339(entity.id) keys
            cross join lateral (select entity.id as entity_id,extracted.link_role) link
            cross join lateral (select link.link_role as value) role
            join storage_v2_entity_type kind on kind.id=entity.entity_type_id
            where extracted.natural_key=any(keys.natural_keys)
            """+extra;
    }
    internal string Condition(SearchCondition condition)
    {
        string key=condition.Field,op=condition.Operator;
        if(key is "account" or "source_station" or "related_object")
        {
            string links=Links(key,condition.Role);
            if(condition.Values.Length>0) links+=" and link.entity_id in ("+string.Join(",",condition.Values.Select(v=>Value(v.GetValue<long>())))+")";
            return (op is "not_in" or "missing"?"not ":"")+"exists (select 1 "+links+")";
        }
        string expr=Expr(key);
        if(op is "exists" or "missing") return expr+" is "+(op=="exists"?"not ":"")+"null";
        string values=string.Join(",",condition.Values.Select(v=>Value(EventSearchInput.IdFields.Contains(key) || key=="event_id" ? (object)v.GetValue<long>():v.GetValue<string>())));
        return op=="not_in"?$"({expr} is null or {expr} not in ({values}))":$"{expr} in ({values})";
    }
    internal string Scope(IEnumerable<JsonElement> scopes)
    {
        var branches=new List<string>();
        foreach(var raw in scopes)
        {
            var scope=ReportScopeResolver.ParseScope(raw);
            if(scope.Invalid) throw new EventSearchException("policy_denied");
            if(scope.All) return "true";
            foreach(var clause in scope.Clauses)
            {
                if(clause.Get("plugin_ids").Items().Any() || clause.Get("source_instance_ids").Items().Any()) throw new EventSearchException("policy_denied");
                var parts=new List<string>();
                foreach(string dim in new[]{"device_ids","collection_scope_ids","entity_ids"})
                {
                    var alternatives=new List<string>();
                    foreach(var value in clause.Get(dim).Items())
                    {
                        string v=value.ToString();
                        if(dim=="entity_ids")
                        {
                            long id=value.GetInt64();
                            if(id>int.MaxValue) { alternatives.Add("false"); continue; }
                            string entity=Value(id);
                            alternatives.Add(EntityShortSql.Matches(entity,"e",allowGlobal:true));
                        }
                        else if(dim=="device_ids" && System.Text.RegularExpressions.Regex.IsMatch(v,@"\Aserver:[1-9][0-9]*\z") && long.TryParse(v.AsSpan(7),out long server)) alternatives.Add(Expr("server_id")+"="+Value(server));
                        else if(dim=="collection_scope_ids" && System.Text.RegularExpressions.Regex.IsMatch(v,@"\Aad-domain:[1-9][0-9]*\z") && long.TryParse(v.AsSpan(10),out long domain)) alternatives.Add(Expr("domain_id")+"="+Value(domain));
                        else if(dim=="collection_scope_ids" && v.StartsWith("channel:",StringComparison.Ordinal) && v.Length>8) alternatives.Add(Expr("channel")+"="+Value(v[8..]));
                        else throw new EventSearchException("policy_denied");
                    }
                    if(alternatives.Count>0) parts.Add("("+string.Join(" or ",alternatives)+")");
                }
                if(parts.Count==0) throw new EventSearchException("policy_denied");
                branches.Add("("+string.Join(" and ",parts)+")");
            }
        }
        return branches.Count==0?"false":"("+string.Join(" or ",branches)+")";
    }
    internal string Predicate(EventSearchInput search,EventSearchPolicy policy)
    {
        var parts=new List<string> { Scope(policy.Scopes),Expr("time_created_utc")+">="+Value(search.From),Expr("time_created_utc")+"<"+Value(search.To) };
        parts.AddRange(search.Conditions.Select(Condition));
        if(search.Q is {} q)
            parts.Add("("+string.Join(" or ",policy.Definition.Get("evsearch_q_fields").Strings().Select(f=>$"strpos(lower({Expr(f)}),lower({Value(q)}))>0"))+")");
        if(search.ExcludeMachine) parts.Add("not exists (select 1 "+Links("account",search.AccountRole)+" and (kind.value='ad_computer' or entity.natural_key ~* '^sid:.+:s-1-5-(18|19|20)$'))");
        if(search.Question is {} question)
        {
            var ids=EventSearchInput.Questions[question];
            string standard=$"({Expr("provider")}='Microsoft-Windows-Security-Auditing' and {Expr("channel")}='Security' and {Expr("event_id")} in ({string.Join(",",ids)}))";
            if(question=="failed_logons") standard+=$" and ({Expr("event_id")}<>4776 or {Expr("outcome")}='failure')";
            if(question=="log_cleared") standard=$"({standard} or ({Expr("provider")}='Microsoft-Windows-Eventlog' and {Expr("channel")}='System' and {Expr("event_id")}=104))";
            parts.Add(standard);
        }
        foreach(var f in policy.Definition.Get("filters").Items())
        {
            if(f.Get("field").ValueKind==JsonValueKind.Undefined && f.Get("value").ValueKind==JsonValueKind.Undefined) continue;
            string field=f.Text("field"),op=f.Text("op"); var value=f.Get("value"); string expr=Expr(field);
            object Typed(JsonElement v) => field=="time_created_utc"?DateTimeOffset.Parse(v.GetString()!,CultureInfo.InvariantCulture):EventSearchInput.IdFields.Contains(field) || field=="event_id"?v.GetInt64():v.GetString()!;
            if(op=="in") { if(value.ValueKind!=JsonValueKind.Array || value.GetArrayLength()==0) throw new EventSearchException("history_predicate_unavailable"); parts.Add(expr+" in ("+string.Join(",",value.Items().Select(v=>Value(Typed(v))))+")"); }
            else if(op is "eq" or "gte" or "lte") parts.Add(expr+(op=="eq"?"=":op=="gte"?">=":"<=")+Value(Typed(value)));
            else if(op=="contains") parts.Add(expr+" ilike "+Value("%"+value.GetString()+"%"));
            else throw new EventSearchException("history_predicate_unavailable");
        }
        return string.Join(" and ",parts.Select(p=>"("+p+")"));
    }
    internal string Select(string field)
    {
        if(field is "account" or "account_kind")
            return "coalesce((select jsonb_agg(p order by p->>'role',p->>'entity_id') from (select distinct jsonb_build_object('entity_id',link.entity_id,'role',role.value"+(field=="account_kind"?",'kind',case when kind.value='ad_computer' then 'machine' when entity.natural_key ~* '^sid:.+:s-1-5-(18|19|20)$' then 'system' else 'unknown' end":"")+") p "+Links(field,"any")+") participants),'[]'::jsonb)";
        if(field is "source_station" or "related_object") return "array(select distinct link.entity_id "+Links(field)+" order by link.entity_id)";
        return Expr(field);
    }
}
