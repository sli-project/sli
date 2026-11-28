using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Entities;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal sealed class AdSecurityQuery
{
    public List<object?> Args { get; } = [];
    public string SelectSql { get; private set; } = "";
    internal string DailySql { get; private set; } = "";
    internal object?[] DailyArgs { get; private set; } = [];
    private string categorySql = "";
    private object?[] categoryArgs = [];
    internal string CategorySql => categorySql;
    internal object?[] CategoryArgs => categoryArgs;
    private int[] selected = [];
    internal int[] Selected=>selected;
    internal bool ChangeCounts { get; private set; }
    private string Param(object value) { Args.Add(value); return "$" + Args.Count; }
    const string TargetSid = "coalesce(nullif(nullif(btrim(event.target_user_sid),'-'),''),nullif(nullif(btrim(facts.account_target_sid),'-'),''))";
    const string TargetName = "coalesce(nullif(nullif(btrim(event.target_user_name),'-'),''),nullif(nullif(btrim(facts.account_target_name),'-'),''))";
    public static AdSecurityQuery Create(AdReportRequest r,JsonArray? cold=null,DateTimeOffset? cutoff=null,bool useColdFacts=false,IConfiguration? config=null,bool maintenance=false)
    {
        var q = new AdSecurityQuery(); var f = r.Filters;
        bool changes = f["changes_view"] is not null;
        string joins=AdColdFactsSql.Joins(config,authentication:!changes);
        string metadata=",event.day,event.event_count,event.first_seen_utc,event.last_seen_utc,event.summary_key,event.actor,event.target,event.source,event.computer,event.fields::text as compact_fields,event.fields->>'CallerComputerName' as caller_computer ";
        q.selected = f["event_id"] is not null ? [checked((int)f.Int("event_id"))]
            : (changes ? AdSecurity.ChangeEventIds() : AdReportStore.EventIds("security"))
                .Where(id => f.Text("category") is null || AdSecurity.Family(id) == f.Text("category")).ToArray();
        if (changes) q.selected = q.selected.Where(id => AdSecurity.ChangeView(id) is not null).ToArray();
        string groupKey = "event.summary_key";
        string idKey = "coalesce(event.id,0)";
        string domain = q.Param(r.Domain), codes = q.Param(q.selected);
        string start = q.Param(r.Period!.Start.UtcDateTime), end = q.Param(r.Period.End.UtcDateTime);
        string day = "event.day";
        const string securityChannel = "(channel.value='Security' and ((event.event_id=1102 and provider.value='Microsoft-Windows-Eventlog') or (event.event_id<>1102 and provider.value='Microsoft-Windows-Security-Auditing')))";
        string where = $" where event.domain_id={domain} and server.role='domain_controller' and event.event_id=any({codes}) and {securityChannel} and (case when {day} is null then event.time_created_utc>={start} else {day}>=({start} at time zone 'UTC')::date end) and event.time_created_utc<{end}";
        void Identity(string name, string sid, string value)
        {
            if (f.Text(name) is not {} filter) return;
            string p = q.Param(filter); where += $" and (lower(coalesce({sid},''))=lower({p}) or lower(coalesce({value},''))=lower({p}))";
        }
        string actorName = changes ? "coalesce(event.method->'$principals'->>'SubjectUserName',event.subject_user_name)" : "event.subject_user_name";
        string actorSid = changes ? "coalesce(event.method->'$principals'->>'SubjectUserSid',event.subject_user_sid)" : "event.subject_user_sid";
        string targetName = changes ? $"coalesce(event.method->'$principals'->>'TargetUserName',{TargetName})" : TargetName;
        if (changes && maintenance)
        {
            if (q.selected.Contains(4719))
                where += " and case when event.event_id=4719 then public.sli_audit_apply421(event.id,event.time_created_utc) is null else true end";
            if (q.selected.Any(id => id is 5136 or 5137 or 5141) && AdSecurity.OwnAuditGpo(config, r.Domain) is { } objectId)
                where += $" and (event.event_id not in (5136,5137,5141) or lower(trim(both '{{}}' from event.target)) is distinct from {q.Param(objectId.ToString())})";
        }
        Identity("actor", actorSid, actorName);
        if (changes && f.Text("target_account") is {} account)
        {
            // A member is the affected object on a membership change.
            string member = q.Param(account);
            where += $" and ((not event.event_id=any({q.Param(AdHistory.Ids("SECURITY_EVENTS_GROUP_EVENT_IDS"))}) and (lower({TargetSid})=lower({member}) or lower({targetName})=lower({member}))) or lower(facts.membership_member_sid)=lower({member}) or lower(facts.membership_member_name)=lower({member}))";
        }
        else
        {
            Identity("target_account", TargetSid, targetName);
            if (f["target_account"] is not null) where += $" and not event.event_id=any({q.Param(AdHistory.Ids("SECURITY_EVENTS_GROUP_EVENT_IDS"))})";
        }
        Identity("group", TargetSid, targetName);
        if (f["group"] is not null) where += $" and event.event_id=any({q.Param(AdHistory.Ids("SECURITY_EVENTS_GROUP_EVENT_IDS"))})";
        if (f.Text("source_host") is {} host) where += $" and lower(server.hostname)=lower({q.Param(host)})";
        if (f.Text("q") is {} text)
        {
            string fields = changes ? ",event.fields::text, facts.account_name_before, facts.account_name_after" : "";
            where += $" and concat_ws(' ',{actorSid},{actorName},{TargetSid},{targetName},facts.membership_member_sid,facts.membership_member_name,server.hostname{fields}) ilike {q.Param("%" + text.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%")}";
        }
        if (f["event_db_id"] is not null) where += $" and event.id={q.Param(f.Int("event_db_id"))}";
        if (f["entity_id"] is not null)
        {
            string entity = q.Param(f.Int("entity_id"));
            where += " and " + EntityShortSql.Matches(entity);
        }
        if (f.Text("outcome") is {} outcome)
        {
            string mixed = q.Param(AdHistory.Ids("SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS"));
            string Match(string value)
            {
                var values = AdHistory.Taxonomy["SECURITY_AUDIT_" + value.ToUpperInvariant() + "_KEYWORDS"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
                return $"(lower(coalesce(keywords.value,''))=any({q.Param(values)}) or replace(lower(coalesce(keywords.value,'')),' ','') like '%audit{value}%')";
            }
            string Success()=>$"(event.event_id=4624 or (event.event_id=any({mixed}) and {Match("success")}))";
            string Failure()=>$"(event.event_id in (4625,4771) or (event.event_id=any({mixed}) and {Match("failure")}))";
            where += outcome switch { "success" => " and " + Success(), "failure" => " and " + Failure(), _ => $" and not ({Success()} or {Failure()})" };
        }
        // Find present kinds in one pass. The short-store time indexes do not
        // index Windows event kinds: a probe for every absent kind repeatedly
        // scanned the same retained window. Cursor paging must not narrow it.
        string categoryJoins = joins;
        q.categorySql = $"""
            with present as materialized (
                select event.event_id {categoryJoins} {where} group by event.event_id
            )
            select selected.event_id,case when exists(select 1 from semantic_processing_outbox
                where job_kind='normalize_event' and status in ('queued','leased')) then exists(select 1 {categoryJoins}
                {where} and event.event_id=selected.event_id
                and exists(select 1 from semantic_processing_outbox job where job.source_event_id=event.id
                    and job.job_kind='normalize_event' and job.status in ('queued','leased') offset 0)
                offset 0) else false end as processing_unfinished
            from present selected
            """;
        q.categoryArgs = q.Args.ToArray();
        q.DailyArgs = q.Args.ToArray();
        q.DailySql = $"select to_char(event.time_created_utc at time zone ${q.Args.Count + 1},'YYYY-MM-DD') as date,event.event_id,sum(event.event_count) as count " + joins + where + " group by 1,event.event_id order by 1,event.event_id";
        if (changes)
        {
            q.SelectChanges(r, joins, where, actorName, actorSid, targetName);
            return q;
        }
        string pageWhere = "attempt_row=1", windowWhere = where;
        if (!string.IsNullOrEmpty(r.Cursor))
        {
            var before = AdSecurity.DecodeGroupCursor(r.Cursor, r.Domain, r.Period, f);
            string time = q.Param(before.Time.UtcDateTime);
            windowWhere += $" and event.time_created_utc<={time}";
            pageWhere += $" and (time_created_utc,coalesce(event_db_id,0),summary_key)<({time},{q.Param(before.Id)},{q.Param(before.Group)})";
        }
        string limit = q.Param(r.Limit + 1);
        string timeLimit = string.IsNullOrEmpty(r.Cursor) ? limit : $"({limit}+1)";
        // Each distinct timestamp contributes at least one displayed row. Seek at
        // most limit+1 timestamps using the time index (one extra for a fully
        // consumed cursor timestamp), then keep every event at
        // those times so reimports/pairs stay intact, including at the cursor.
        // This bounds the pairing windows without cutting a group in half.
        // Pair different Windows failure event kinds one-to-one, without a time bucket.
        // Missing client/account identities cannot establish a shared attempt.
        // Both grouping steps precede the cursor so a pair cannot cross pages.
        string attempt = "summary_key," + "server_id,time_created_utc,target_key,client_key,attempt_ordinal,case when failed and target_key is not null and client_key is not null and target_key<>'—' and client_key<>'—' and target_key!~'^%%[0-9]+$' and client_key!~'^%%[0-9]+$' then 0 else event_db_id end";
        q.SelectSql = $"""
            with page_times as materialized (
                select distinct event.time_created_utc {categoryJoins} {windowWhere}
                order by event.time_created_utc desc limit {timeLimit}
            ), source_rows as (
                select event.id as event_db_id,event.domain_id,event.server_id,event.channel_id,event.provider_id,event.event_record_id,event.event_id,event.time_created_utc,
                    server.hostname as source_host,keywords.value as audit_keywords,event.subject_user_sid,event.subject_user_name,
                    {TargetSid} as target_user_sid,{TargetName} as target_user_name,
                    facts.membership_member_sid,facts.membership_member_name,facts.account_name_before,facts.account_name_after,facts.result_code,event.source_core_sha256,facts.source_facts_sha256 {metadata},
                    lower(coalesce(nullif(nullif(btrim({TargetName}),'-'),''),nullif(nullif(btrim({TargetSid}),'-'),''))) as target_key,
                    lower(coalesce(nullif(nullif(btrim(event.ip_address),'-'),''),nullif(nullif(btrim(event.workstation_name),'-'),''))) as client_key,
                    (event.event_id in (4625,4771) or event.event_id=4776 and lower(coalesce(keywords.value,''))=any({q.Param(AdHistory.Taxonomy["SECURITY_AUDIT_FAILURE_KEYWORDS"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray())})) as failed,
                    row_number() over(partition by {groupKey},event.server_id,event.channel_id,event.provider_id,event.event_record_id,event.event_id,event.time_created_utc,
                        case when event.event_record_id>0 then 0 else {idKey} end order by event.id desc) as import_row
                {joins} {windowWhere}
                    and event.time_created_utc>=(select min(time_created_utc) from page_times)
            ), attempt_events as (
                select *,row_number() over(partition by summary_key,server_id,time_created_utc,target_key,client_key,event_id,failed order by event_db_id desc) as attempt_ordinal
                from source_rows where import_row=1
            ), attempt_rows as (
                select *,row_number() over(partition by {attempt} order by event_db_id desc) as attempt_row,
                    array_remove(array_agg(event_db_id) over(partition by {attempt}),null) as related_event_db_ids
                from attempt_events
            )
            select * from attempt_rows where {pageWhere} order by time_created_utc desc,coalesce(event_db_id,0) desc,summary_key desc limit {limit}
            """;
        return q;
    }

    private void SelectChanges(AdReportRequest request, string joins, string where, string actorName, string actorSid, string targetName)
    {
        ChangeCounts = true;
        string view = Param(request.Filters.Text("changes_view")!);
        var categories = AdSecurity.ChangeViews.Skip(1).Select(name =>
            (Name: name, Codes: Param(selected.Where(id => AdSecurity.ChangeView(id) == name).ToArray()))).ToArray();
        string category = string.Join(" ", categories.Select(pair => $"when event.event_id=any({pair.Codes}) then '{pair.Name}'"));
        string counts = string.Join(", ", AdSecurity.ChangeViews.Select(name =>
            $"count(*) filter (where tab='{name}') as \"{name}\""));
        string groupId = request.Filters.Text("repeat_mode") == "collapsed"
            ? "case when initiator_key is null or object_key is null then event_db_id else 0 end"
            : "event_db_id";
        string filter = request.Filters["batch"] is not null
            ? $"group_anchor={Param(request.Filters.Int("batch"))}"
            : "group_anchor=event_db_id";
        bool ascending = request.Filters.Text("changes_order") == "asc";
        string order = ascending ? "asc" : "desc";
        string comparison = ascending ? ">" : "<";
        string seek = "";
        if (request.Cursor is {} cursor)
        {
            var after = AdSecurity.DecodeGroupCursor(cursor, request.Domain, request.Period!, request.Filters);
            seek = $"where (time_created_utc,event_db_id){comparison}({Param(after.Time.UtcDateTime)},{Param(after.Id)})";
        }
        string limit = Param(request.Limit + 1);
        string NativeValue(string value) => $"btrim(coalesce({value},'')) not in ('','-','—')";
        string AttributeValue(string group)
        {
            var names = AdHistory.Taxonomy[$"_SECURITY_EVENT_{group}_ATTRIBUTE_FIELDS"]!.AsArray()
                .Where(pair => pair![1]!.ToString() != "old_user_account_control")
                .SelectMany(pair => pair![0]!.AsArray().Select(name => name!.ToString())).ToArray();
            return $"exists(select 1 from jsonb_each_text(fields) attribute where attribute.key=any({Param(names)}) and {NativeValue("attribute.value")})";
        }
        string accountAttributes = AttributeValue("ACCOUNT");
        string groupAttributes = AttributeValue("GROUP");
        string mixedOutcomes = Param(AdHistory.Ids("SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS"));
        string namedMember = $"({NativeValue("membership_member_name")} or {NativeValue("membership_member_sid")})";
        string namedGroup = $"({NativeValue("target_user_name")} or {NativeValue("target_user_sid")})";
        string singleChange = request.Filters["batch"] is null ? "where repeat_count=1" : "";
        SelectSql = $"""
            with candidates as (
                select event.id as event_db_id,event.domain_id,event.server_id,event.event_record_id,event.event_id,event.time_created_utc,
                    server.hostname as source_host,channel.value as event_channel,keywords.value as audit_keywords,
                    {actorSid} as subject_user_sid, {actorName} as subject_user_name,
                    {TargetSid} as target_user_sid,{targetName} as target_user_name,
                    facts.membership_member_sid,facts.membership_member_name,facts.account_name_before,facts.account_name_after,
                    facts.result_code,event.source_core_sha256,facts.source_facts_sha256,event.fields::text as compact_fields,
                    case {category} end as change_view,
                    case when event.event_id in (5136,5137,5141) then nullif(event.fields->>'ObjectDN','') end as directory_object,
                    case when {actorSid} ~* '^S-1-[0-9]+(-[0-9]+)+$' and {actorSid}<>'S-1-0-0' then
                        case when {actorSid} in ('S-1-5-18','S-1-5-19','S-1-5-20') then server.id||':' else '' end || upper({actorSid})
                    end as initiator_key,
                    case when event.event_id in (5136,5137,5141) then 'directory:'||lower(nullif(btrim(event.target,chr(123)||chr(125)),''))
                         when event.event_id=4719 then 'audit:'||server.id
                         when event.event_id=4739 then 'domain:'||event.domain_id
                         when {TargetSid} ~* '^S-1-[0-9]+(-[0-9]+)+$' and {TargetSid}<>'S-1-0-0' then upper({TargetSid})
                    end as object_key,
                    case when event.event_id in (4728,4729,4732,4733,4756,4757)
                            then lower(coalesce(nullif(nullif(btrim(facts.membership_member_sid),'-'),''),
                                                nullif(nullif(btrim(facts.membership_member_name),'-'),'')))
                         when event.event_id=5136 then lower(nullif(btrim(event.fields->>'AttributeLDAPDisplayName'),''))
                         when event.event_id=4719 then lower(nullif(btrim(event.fields->>'SubcategoryGuid'),''))
                    end as object_field
                {joins} {where} and event.day is null and event.id>0
            ), grouped as materialized (
                select candidates.*,tabs.tab,first_value(event_db_id) over batch as group_anchor,
                    count(*) over batch as repeat_count,min(time_created_utc) over batch as first_seen_utc
                from candidates cross join lateral (values ('all'),(change_view)) tabs(tab)
                window batch as (partition by tab,initiator_key,object_key,event_id,object_field,{groupId},
                    date_bin(interval '1 minute',time_created_utc,timestamptz '2000-01-01')
                    order by time_created_utc desc,event_db_id desc rows between unbounded preceding and unbounded following)
            ), selected_rows as materialized (
                select * from grouped where tab={view} and {filter}
            ), column_values as (
                select event_id,audit_keywords,
                    case event_id
                        when 4738 then {accountAttributes}
                        when 4735 then {groupAttributes}
                        when 4737 then {groupAttributes}
                        when 4758 then {groupAttributes}
                        when 4764 then {NativeValue("coalesce(fields->>'NewGroupType',fields->>'new_group_type')")}
                        when 4781 then {NativeValue("account_name_after")}
                        when 4719 then {NativeValue("coalesce(fields->>'AuditPolicyChanges',fields->>'audit_policy_changes')")}
                        when 4739 then {NativeValue("fields->>'MinPasswordLength'")} or {NativeValue("fields->>'PasswordHistoryLength'")} or {NativeValue("fields->>'LockoutThreshold'")}
                        when 5136 then lower(fields->>'AttributeLDAPDisplayName') in ('description','displayname','userprincipalname')
                            and {NativeValue("fields->>'AttributeValue'")}
                        else event_id in (4720,4722,4725,4726,4727,4730,4731,4734,4740,4754,4755,4767)
                            or (event_id in (4728,4729,4732,4733,4756,4757) and {namedMember} and {namedGroup})
                    end as has_value, event_id in (4723,4724)
                        or event_id=5136 and {NativeValue("fields->>'AttributeLDAPDisplayName'")} as field_only
                from selected_rows cross join lateral (select compact_fields::jsonb as fields) native
                {singleChange}
            ), columns as (
                select coalesce(bool_or(has_value or field_only),false) as column_field,
                       coalesce(bool_or(has_value),false) as column_value,
                       jsonb_agg(distinct jsonb_build_object('event_id',event_id,'audit_keywords',audit_keywords))
                            filter (where event_id=any({mixedOutcomes})) as column_outcomes
                from column_values
            ), counts as (
                select {counts},(select count(*) from selected_rows) as display_count from grouped
            ), page as (
                select * from selected_rows {seek} order by time_created_utc {order},event_db_id {order} limit {limit}
            )
            select page.*,counts.*,columns.* from counts cross join columns left join page on true
                order by page.time_created_utc {order},page.event_db_id {order}
            """;
    }
    public async Task<JsonObject> CategoriesAsync(NpgsqlConnection db, CancellationToken ct)
    {
        var rows = await ReadAsync(db, categorySql, ct, categoryArgs); var result = new JsonObject();
        foreach (string family in AdHistory.Map("_SECURITY_EVENT_FAMILY_BY_EVENT_ID").Select(p => p.Value!.GetValue<string>()).Distinct().Order(StringComparer.Ordinal))
        {
            var matches = rows.Where(r => AdSecurity.Family(r.Int("event_id")) == family).ToArray();
            string state = !selected.Any(id => AdSecurity.Family(id) == family) ? "not_selected" : matches.Any(r => r["processing_unfinished"]?.GetValue<bool>() == true) ? "processing_unfinished" : matches.Length > 0 ? "retained_match_present" : "no_retained_match";
            result[family] = Obj(new { state });
        }
        return result;
    }
    public static async Task ResolveEntitiesAsync(NpgsqlConnection db, List<JsonObject> events, long domain, CancellationToken ct)
    {
        var sids = events.SelectMany(e => new[] { e.Text("subject_user_sid"), e.Text("target_user_sid"), e.Text("membership_member_sid") }).Where(s => s is not null).Select(s => s!.ToLowerInvariant()).Distinct().ToArray();
        if (sids.Length == 0) return;
        var aliases = await ReadAsync(db, """
            select alias.normalized_value,min(alias.entity_id) as entity_id from ad_context_entity_aliases alias
            join entities_v2 entity on entity.id=alias.entity_id
            where alias.domain_id=$1 and alias.alias_type='object_sid' and alias.normalized_value=any($2)
            and entity.domain_id=$1 and entity_v2_is_active(entity.id)
            group by alias.normalized_value having count(distinct alias.entity_id)=1
            """, ct, domain, sids);
        foreach (var e in events) foreach (var (field, key) in new[] { ("subject_user_sid", "actor_entity_id"), ("target_user_sid", "target_entity_id"), ("membership_member_sid", "member_entity_id") })
            if (aliases.FirstOrDefault(a => a.Text("normalized_value") == e.Text(field)?.ToLowerInvariant()) is {} alias) e[key] = alias["entity_id"]!.DeepClone();
    }
}
