using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

internal sealed record JournalOptions(bool Collapse, long? Expand, long? Before, string View, string Result, string Pivot, long? Domain)
{
    internal long? ServerId { get; init; }
    internal string? SourceInstanceId { get; init; }
    internal string? SourcePlugin { get; init; }
}

internal static class JournalPage
{
    private static readonly long[] GroupChanges = [4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4704, 4705];
    private static readonly long[] Audit = [1100, 1102, 4616, 4719, 4902, 4904, 4905, 4906, 4907, 4912];

    internal static IReadOnlyDictionary<string, long[]> Views { get; } = new Dictionary<string, long[]>
    {
        ["authentication"] = ReportQuery.EventViews["authentication"].Union([4672L]).ToArray(),
        ["accounts"] = ReportQuery.EventViews["accounts"].Except(GroupChanges).ToArray(),
        ["groups"] = GroupChanges,
        ["audit"] = Audit,
    };

    internal static async Task<JsonObject> ReadAsync(IReportSession db, ReportQuery sql, string scope, JsonObject definition,
        string[] fields, IReadOnlyDictionary<string, string> query, JournalOptions options, int limit, DateTimeOffset boundary, CancellationToken ct)
    {
        const string Dataset = "events.v2";
        bool identity = fields.Contains("id");
        bool security = fields.Contains("event_id") && fields.Contains("time_created_utc");
        bool technical = fields.Contains("channel");
        bool accounts = security && fields.Contains("subject_user_name") && fields.Contains("target_user_name");
        bool canGroup = identity && accounts && technical;
        bool groupRepeats = canGroup && options.Before is null && (options.Collapse || options.Expand.HasValue);
        sql.Definition(Dataset, definition, 90);
        var filters = new Dictionary<string, string>();
        string search = query.GetValueOrDefault("q", "").Trim();
        string server = query.GetValueOrDefault("server", "");
        if (technical && server.Length > 0) filters["server"] = server;
        if (security && query.TryGetValue("view", out var oldView) && oldView is "attention" or "tasks" && options.View == oldView) filters["view"] = oldView;
        sql.Interactive(Dataset, filters, 90);
        if (!technical && server.Length > 0 || !security && options.View != "all" ||
            !(security && technical) && options.Result != "" ||
            (!canGroup && options.Expand.HasValue) || (!(identity && security && technical) && options.Before.HasValue))
            sql.Predicates.Add("false");
        if (options.Domain is { } domain) sql.Add("event.domain_id=", domain);
        if (options.ServerId is { } station) sql.Add("event.server_id=", station);
        if (options.SourceInstanceId is { } sourceInstance)
        {
            // A filter only narrows the already authorized grant. Keep it
            // before groups, totals and cursors, including retained daily rows.
            if (!technical) sql.Predicates.Add("false");
            sql.Predicates.Add("event.method#>>'{$origin,source_instance_id}'=" + sql.Parameter(sourceInstance));
        }
        if (options.SourcePlugin is { } sourcePlugin)
        {
            if (!technical) sql.Predicates.Add("false");
            sql.Predicates.Add("event.method#>>'{$origin,plugin_id}'=" + sql.Parameter(sourcePlugin));
        }
        if (search.Length > 0)
        {
            string term = "lower(" + sql.Parameter(search) + ")";
            var matches = new List<string>();
            if (options.Pivot == "account" && accounts)
                matches.Add(term + " in (lower(subjects.account),lower(subjects.initiator))");
            else if (options.Pivot == "computer" && technical)
                matches.Add("lower(coalesce(nullif(event.computer,''),server.hostname))=" + term);
            else if (options.Pivot == "address" && accounts)
                matches.Add("lower(event.source)=" + term);
            else if (options.Pivot == "")
            {
                if (accounts) foreach (string column in new[] { "subjects.account", "subjects.initiator", "event.actor", "event.target", "event.source" })
                    matches.Add($"strpos(lower({column}),{term})>0");
                if (technical) foreach (string column in new[] { "event.computer", "server.hostname" })
                    matches.Add($"strpos(lower({column}),{term})>0");
                if (security && long.TryParse(search, NumberStyles.None, CultureInfo.InvariantCulture, out long code))
                    matches.Add("event.event_id=" + sql.Parameter(code));
            }
            sql.Predicates.Add(matches.Count > 0 ? string.Join(" or ", matches) : "false");
        }

        var start = DateTimeOffset.Parse(query["time_from"], CultureInfo.InvariantCulture);
        string from = sql.Parameter(start);
        string to = sql.Parameter(DateTimeOffset.Parse(query["time_to"], CultureInfo.InvariantCulture));
        string hotBoundary = sql.Parameter(boundary);
        string source = EntityShortSql.Source(hotBoundary, daily: start < boundary)
            .Replace("from event_hot h where ", $"from event_hot h where h.time_created_utc>={from} and h.time_created_utc<{to} and ", StringComparison.Ordinal)
            .Replace("from event_cold_facts h where ", $"from event_cold_facts h where h.time_created_utc>={from} and h.time_created_utc<{to} and ", StringComparison.Ordinal)
            .Replace("from event_cold_daily d where ", $"from event_cold_daily d where d.day>=({from} at time zone 'UTC')::date and d.day<=(({to}-interval '1 microsecond') at time zone 'UTC')::date and ", StringComparison.Ordinal);
        string where = scope + (sql.Predicates.Count == 0 ? "" :
            (scope.Length > 0 ? " and " : " where ") + string.Join(" and ", sql.Predicates.Select(p => "(" + p + ")")));

        string category = "null::text";
        if (security)
            category = "case " + string.Join(" ", Views.Select(view => $"when event_id=any({sql.Parameter(view.Value)}) then '{view.Key}'")) + " end";
        string outcome = security && technical ? """
            case when channel='Security' and provider_name='Microsoft-Windows-Security-Auditing' then
                case when event_id in (4625,4771,6273) then 'failure'
                     when event_id in (4624,4672,6272) then 'success'
                     when event_id=4776 and nullif(btrim(outcome->>'Status'),'') is not null
                     then case when lower(btrim(outcome->>'Status')) in ('0','0x0','0x00000000','00000000') then 'success' else 'failure' end
                     when lower(replace(btrim(outcome->>'keywords'),' ','')) in
                         ('auditfailure','4503599627370496','0x10000000000000','0x8010000000000000','-9218868437227405312') then 'failure'
                     when lower(replace(btrim(outcome->>'keywords'),' ','')) in
                         ('auditsuccess','9007199254740992','0x20000000000000','0x8020000000000000','-9214364837600034816') then 'success'
                end
            end
            """ : "null::text";
        const string NativeSecurity = "channel='Security' and provider_name='Microsoft-Windows-Security-Auditing'";
        string service = accounts && technical ? $"""
            coalesce(({NativeSecurity} and event_id=any({sql.Parameter(Views["authentication"])})
                and (right(journal_account,1)='$' or journal_account_sid in ('S-1-5-18','S-1-5-19','S-1-5-20')
                     or (event_id in (4624,4625) and journal_logon_type='5')))
                or (channel='System' and provider_name='Service Control Manager' and event_id in (7035,7036))
                or lower(channel) like '%taskscheduler%',false)
            """ : "false";
        // 4672 has no native address or logon type. 4776 may retain a
        // workstation as its source, and reports its outcome via Status.
        string repeatKey = groupRepeats ? $"""
            case when id is not null and {NativeSecurity} and event_id in (4624,4625,4672,4776)
                and coalesce(journal_account_sid,journal_account) is not null
                and (event_id=4672 or source is not null)
                and (event_id in (4672,4776) or journal_logon_type is not null)
                and (event_id <> 4776 or journal_result is not null)
                then array[(floor(extract(epoch from time_created_utc)/600))::text,
                     domain_id::text,server_id::text,lower(journal_computer),channel,provider_name,event_id::text,
                     lower(coalesce(journal_account_sid,journal_account)),lower(source),
                     journal_logon_type,journal_result,journal_status,journal_substatus]
            end
            """ : "null::text[]";
        string statement = $"""
            with short_events as ({source}),
            scoped as (
                select event.id,event.time_created_utc,event.event_id,event.domain_id,event.server_id,
                       event.actor,event.target,nullif(nullif(nullif(btrim(event.source),''),'-'),'—') as source,event.channel,event.provider_name,
                       event.day,event.event_count,event.first_seen_utc,event.last_seen_utc,event.summary_key,
                       origin.computer as journal_computer,server.role as journal_server_role,
                       subjects.account as journal_account,subjects.initiator as journal_initiator,
                       subjects.account_sid as journal_account_sid,
                       coalesce(event.outcome->>'LogonType',event.method->>'LogonType',event.fields->>'LogonType') as journal_logon_type,
                       lower(event.outcome->>'Status') as journal_status,lower(event.outcome->>'SubStatus') as journal_substatus,
                       {category} as journal_category,{outcome} as journal_result
                from (select e.*,e.actor as subject_user_name,e.target as target_user_name,e.source as ip_address,
                             e.source as workstation_name,e.fields->>'TargetLogonId' as logon_id from short_events e) event
                join servers server on server.id=event.server_id and server.domain_id=event.domain_id
                cross join lateral (select event.channel as value) channel
                cross join lateral (select coalesce(nullif(event.computer,''),server.hostname) as computer) origin
                {SubjectJoin(accounts)}
                {where}
            ),
            candidates as materialized (
                select *,{service} as journal_service,{repeatKey} as repeat_key from scoped
                {(options.Result.Length > 0 ? "where journal_result=" + sql.Parameter(options.Result) : "")}
            )
            """;
        const string Failure = "journal_category='authentication' and journal_result='failure'";
        string categoryWhere = options.View switch
        {
            "all" when options.Before is null => "where not journal_service",
            "authentication" => "where journal_category='authentication' and not journal_service",
            "failures" => "where " + Failure,
            "service" => "where journal_service",
            _ when Views.ContainsKey(options.View) => "where journal_category=" + sql.Parameter(options.View),
            _ => "",
        };
        if (options.Before is { } before)
        {
            // Compare stored account identities inside the anchor's domain.
            string accountMatch = accounts ? """
                lower(peer.journal_account)=lower(anchor.journal_account)
                or peer.journal_account_sid=anchor.journal_account_sid
                """ : "false";
            string computerMatch = technical ? "nullif(lower(peer.journal_computer),'')=nullif(lower(anchor.journal_computer),'')" : "false";
            statement += $"""
                , anchor as materialized (select * from candidates where id={sql.Parameter(before)}),
                visible as (
                    select peer.*,false as journal_expandable,({accountMatch}) is true as journal_account_match
                    from candidates peer cross join anchor
                    where peer.domain_id=anchor.domain_id and peer.last_seen_utc<anchor.time_created_utc
                      and ({computerMatch} or {accountMatch})
                )
                """;
        }
        else if (groupRepeats)
        {
            statement += $", keyed as not materialized (select * from candidates {categoryWhere})";
            if (options.Expand is { } expand)
                statement += $"""
                    , visible as (
                        select member.*,false as journal_expandable from keyed member
                        where member.repeat_key=(select anchor.repeat_key from keyed anchor where anchor.id={sql.Parameter(expand)})
                    )
                    """;
            else
                // A single window pass keeps selective views from repeatedly
                // joining each candidate to the same materialized slice.
                statement += """
                    , repeated as (
                        select *,min(time_created_utc) over w as group_start,max(time_created_utc) over w as group_end,
                               count(*) over w as group_count,row_number() over w as repeat_rank,
                               case when count(journal_initiator) over w=count(*) over w
                                    and min(lower(journal_initiator)) over w=max(lower(journal_initiator)) over w
                                    then journal_initiator end as group_initiator
                        from keyed where repeat_key is not null
                        window w as (partition by repeat_key order by time_created_utc desc,id desc
                                     rows between unbounded preceding and unbounded following)
                    ),
                    visible as (
                        select *,group_count>1 as journal_expandable from repeated where repeat_rank=1
                        union all
                        select *,null,null,null,null,null,false from keyed where repeat_key is null
                    )
                    """;
        }
        else
            statement += $", visible as (select *,false as journal_expandable from candidates {categoryWhere})";

        sql.Predicates.Clear();
        if (query.TryGetValue("cursor", out var cursor)) sql.Interactive(Dataset, new Dictionary<string, string> { ["cursor"] = cursor }, 90);
        string after = sql.Predicates.Count > 0 ? "where " + string.Join(" and ", sql.Predicates) : "";
        bool metadata = options.Expand is null && options.Before is null;
        string counts = "null::jsonb";
        string eventCount = "null::numeric";
        string totalsFrom = "";
        if (metadata && security)
        {
            // Counts cover the admitted candidates before grouping or applying the page cursor.
            const string All = "not journal_service";
            var predicates = Views.Keys.ToDictionary(key => key, key => $"journal_category='{key}'");
            predicates["all"] = All;
            predicates["authentication"] += " and " + All;
            predicates["failures"] = Failure;
            predicates["service"] = "journal_service";
            string sums = string.Join(",", predicates.Select(entry =>
                $"coalesce(sum(event_count) filter (where {entry.Value}),0) as {entry.Key}_count"));
            statement += $", totals as (select coalesce(sum(event_count),0) as total_count,{sums} from candidates)";
            totalsFrom = "from totals";
            eventCount = predicates.ContainsKey(options.View) ? $"totals.{options.View}_count" : "totals.total_count";
            counts = "jsonb_build_object(" + string.Join(",", predicates.Keys.Select(key => $"'{key}',totals.{key}_count")) + ")";
        }
        else if (metadata)
            eventCount = $"(select coalesce(sum(event_count),0) from candidates {categoryWhere})";
        string priority = options.Before.HasValue ? "journal_account_match desc," : "";
        statement += $"""
            , page as (
                select event.* from visible event {after}
                order by {priority}event.time_created_utc desc,coalesce(event.id,0) desc,event.summary_key desc limit {sql.Parameter(limit + 1)}
            ),
            meta as (
                select (select count(*) from visible) as filtered_count,
                       {eventCount} as journal_event_count,
                       {counts} as journal_counts
                {totalsFrom}
            )
            select meta.*,(
                select coalesce(jsonb_agg(
                    to_jsonb(page)-array['repeat_key','repeat_rank','journal_status','journal_substatus','journal_account_sid','journal_account_match','journal_service']
                    order by {priority}page.time_created_utc desc,coalesce(page.id,0) desc,page.summary_key desc
                ),'[]'::jsonb) from page
            ) as items from meta
            """;
        // Compile-time partition pruning still leaves a large plan on retained
        // hosts. LLVM compilation is more expensive than this bounded scan.
        await db.QueryAsync("set local jit=off", [], ct);
        var meta = (await db.QueryAsync(statement, sql.Values, ct)).Single();
        var rows = meta.Array("items").OfType<JsonObject>().ToArray();
        bool more = rows.Length > limit && security && !options.Before.HasValue &&
            (identity || rows[limit - 1]["day"] is not null);
        var items = Nodes(rows.Take(limit).Select(storedRow =>
        {
            var sourceRow = storedRow.Copy();
            bool grouped = storedRow.Flag("journal_expandable");
            if (grouped)
            {
                foreach (var (field, aggregate) in new[] { ("first_seen_utc","group_start"), ("last_seen_utc","group_end"), ("event_count","group_count") })
                    sourceRow[field] = storedRow[aggregate]?.DeepClone();
                sourceRow["journal_initiator"] = storedRow["group_initiator"]?.DeepClone();
            }
            var row = EventReadService.ShortRow(sourceRow);
            var item = new JsonObject();
            foreach (string field in fields) item[field] = row[field]?.DeepClone();
            if (security)
                foreach (string field in new[] { "day", "summary_key", "event_count", "first_seen_utc", "last_seen_utc", "journal_result" })
                    item[field] = row[field]?.DeepClone();
            if (technical) item["journal_computer"] = row["journal_computer"]?.DeepClone();
            if (identity && security && technical)
                item["_journal_origin"] = new JsonObject
                {
                    ["domain_id"] = storedRow["domain_id"]?.DeepClone(),
                    ["server_id"] = storedRow["server_id"]?.DeepClone(),
                    ["provider_name"] = storedRow["provider_name"]?.DeepClone(),
                    ["server_role"] = storedRow["journal_server_role"]?.DeepClone(),
                };
            if (accounts)
            {
                item["journal_account"] = storedRow["journal_account"]?.DeepClone();
                item["journal_initiator"] = row["journal_initiator"]?.DeepClone();
                item["journal_address"] = row["source"]?.DeepClone();
                item["logon_type"] = storedRow["journal_logon_type"]?.DeepClone();
                foreach (string field in new[] { "actor", "target", "ip_address" })
                    item[field] = row[field]?.DeepClone();
            }
            item["journal_expandable"] = grouped;
            return item;
        }));
        return new JsonObject
        {
            ["items"] = items, ["state"] = items.Count > 0 ? "available" : "empty",
            ["has_more"] = more, ["next_cursor"] = more ? ReportQuery.Cursor(EventReadService.ShortCursor(rows[limit - 1])) : null,
            ["limits"] = new JsonObject { ["rows"] = limit },
            ["filtered_count"] = meta["filtered_count"]?.DeepClone(),
            ["journal_event_count"] = metadata ? meta["journal_event_count"]?.DeepClone() : null,
            ["journal_counts"] = metadata && security ? meta["journal_counts"]?.DeepClone() : null,
        };
    }

    private static string SubjectJoin(bool accounts)
    {
        if (!accounts) return "cross join lateral (select null::text as account,null::text as initiator,null::text as account_sid) subjects";

        static string Clean(string value) => $"nullif(nullif(nullif(btrim({value}),''),'-'),'—')";
        static string Principal(string kind)
        {
            string name = Clean($"event.method#>>'{{$principals,{kind}UserName}}'");
            string domain = Clean($"event.method#>>'{{$principals,{kind}DomainName}}'");
            return $"case when {domain} is not null and strpos({name},chr(92))=0 and strpos({name},'@')=0 then left({domain}||chr(92)||{name},256) else {name} end";
        }
        string actor = $"nullif({Clean("event.actor")},'S-1-0-0')";
        string target = Clean("event.target");
        string subjectSid = Clean("event.method#>>'{$principals,SubjectUserSid}'");
        string targetSid = $"coalesce({Clean("event.method#>>'{$principals,TargetUserSid}'")},{Clean("event.method#>>'{$principals,TargetSid}'")})";
        return $"""
            cross join lateral (select {Principal("Target")} as target_name,{Principal("Subject")} as subject_name,
                nullif({targetSid},'S-1-0-0') as target_sid,nullif({subjectSid},'S-1-0-0') as subject_sid,
                case when lower({actor}) not in (lower(origin.computer),split_part(lower(origin.computer),'.',1)) then {actor} end as actor,
                case when lower({target}) not in (lower(origin.computer),split_part(lower(origin.computer),'.',1)) then {target} end as target
                offset 0
            ) principals
            cross join lateral (
                select case when event.channel='Security' and event.provider_name='Microsoft-Windows-Security-Auditing' then event.event_id end as native_code
            ) native
            cross join lateral (
                select case native.native_code
                    when 4624 then coalesce(principals.target_name,principals.actor)
                    when 4625 then coalesce(principals.target_name,principals.actor)
                    when 4672 then coalesce(principals.subject_name,principals.target_name,principals.actor)
                    when 4776 then case when principals.actor=principals.target_sid then coalesce(principals.target_name,principals.actor) else principals.actor end
                    else coalesce(principals.target_name,principals.target,principals.subject_name,principals.actor)
                    end as account,
                    case when native.native_code in (4672,4776) then null
                         when native.native_code in (4624,4625) then principals.subject_name
                         else coalesce(principals.subject_name,principals.actor) end as initiator,
                    case when native.native_code=4672 then coalesce(principals.subject_sid,
                             case when principals.subject_name is null then principals.target_sid end)
                         when native.native_code=4776 then case when lower(principals.actor)=lower(principals.target_name)
                             then principals.target_sid end
                         else principals.target_sid end as named_sid
                offset 0
            ) roles
            cross join lateral (
                select roles.account,case when lower(roles.initiator) is distinct from lower(roles.account) then roles.initiator end as initiator,
                       coalesce(roles.named_sid,case when native.native_code in (4624,4625,4672,4776)
                           and principals.actor ~* '^S-1-[0-9]+(-[0-9]+)+$' and principals.actor<>'S-1-0-0' then principals.actor end) as account_sid
            ) subjects
            """;
    }
}
