using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

internal sealed record JournalOptions(bool Collapse, long? Expand, long? Before, string View, string Result, string Pivot, long? Domain, long? Member = null);

internal static class JournalPage
{
    private static readonly long[] GroupChanges = [4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4704, 4705];
    private static readonly long[] Audit = [1100, 1102, 4616, 4719, 4902, 4904, 4905, 4906, 4907, 4912];

    internal static IReadOnlyDictionary<string, long[]> Views { get; } = new Dictionary<string, long[]>
    {
        ["authentication"] = ReportQuery.EventViews["authentication"],
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
        sql.Definition(Dataset, definition, 90);
        var filters = new Dictionary<string, string>();
        string search = query.GetValueOrDefault("q", "").Trim();
        string server = query.GetValueOrDefault("server", "");
        if (technical && server.Length > 0) filters["server"] = server;
        if (security && query.TryGetValue("view", out var oldView) && oldView is "attention" or "tasks" && options.View == oldView) filters["view"] = oldView;
        sql.Interactive(Dataset, filters, 90);
        if (!technical && server.Length > 0 || !security && options.View != "all" ||
            !(security && technical) && options.Result != "" ||
            !(identity && security && technical) && (options.Expand.HasValue || options.Before.HasValue))
            sql.Predicates.Add("false");
        if (options.Domain is { } domain) sql.Add("event.domain_id=", domain);
        if (search.Length > 0)
        {
            string term = "lower(" + sql.Parameter(search) + ")";
            var matches = new List<string>();
            if (options.Pivot == "account" && accounts)
                matches.Add(term + " in (lower(event.actor),lower(event.target))");
            else if (options.Pivot == "computer" && technical)
                matches.Add("lower(coalesce(nullif(event.computer,''),server.hostname))=" + term);
            else if (options.Pivot == "address" && accounts)
                matches.Add("lower(event.source)=" + term);
            else if (options.Pivot == "")
            {
                if (accounts) foreach (string column in new[] { "event.actor", "event.target", "event.source" })
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
                     when event_id in (4624,6272) then 'success'
                     when event_id=4776 and nullif(btrim(outcome->>'Status'),'') is not null
                     then case when lower(btrim(outcome->>'Status')) in ('0','0x0','0x00000000','00000000') then 'success' else 'failure' end
                     when lower(replace(btrim(outcome->>'keywords'),' ','')) in
                         ('auditfailure','4503599627370496','0x10000000000000','0x8010000000000000','-9218868437227405312') then 'failure'
                     when lower(replace(btrim(outcome->>'keywords'),' ','')) in
                         ('auditsuccess','9007199254740992','0x20000000000000','0x8020000000000000','-9214364837600034816') then 'success'
                end
            end
            """ : "null::text";
        // Apply the grant and all common filters before counting or deriving any group.
        string statement = $"""
            with short_events as ({source}),
            scoped as (
                select event.*,coalesce(nullif(event.computer,''),server.hostname) as journal_computer,
                       {category} as journal_category,{outcome} as journal_result
                from (select e.*,e.actor as subject_user_name,e.target as target_user_name,e.source as ip_address,
                             e.source as workstation_name,e.fields->>'TargetLogonId' as logon_id from short_events e) event
                join servers server on server.id=event.server_id and server.domain_id=event.domain_id
                cross join lateral (select event.channel as value) channel
                {where}
            ),
            candidates as materialized (
                select * from scoped {(options.Result.Length > 0 ? "where journal_result=" + sql.Parameter(options.Result) : "")}
            )
            """;
        string categoryWhere = Views.ContainsKey(options.View) ? "where journal_category=" + sql.Parameter(options.View) : "";
        if (options.Before is { } before)
        {
            // Compare full stored account values inside the anchor's domain. A
            // short name on another domain or an unreadable anchor cannot match.
            string accountMatch = accounts ? """
                nullif(lower(peer.actor),'') in (nullif(lower(anchor.actor),''),nullif(lower(anchor.target),''))
                or nullif(lower(peer.target),'') in (nullif(lower(anchor.actor),''),nullif(lower(anchor.target),''))
                """ : "false";
            string computerMatch = technical ? "nullif(lower(peer.journal_computer),'')=nullif(lower(anchor.journal_computer),'')" : "false";
            statement += $"""
                , anchor as (select * from candidates where id={sql.Parameter(before)}),
                visible as (
                    select peer.*,false as journal_expandable,({accountMatch}) is true as journal_account_match
                    from candidates peer cross join anchor
                    where peer.domain_id=anchor.domain_id and peer.last_seen_utc<anchor.time_created_utc
                      and ({computerMatch} or {accountMatch})
                )
                """;
        }
        else if (identity && security && technical && (options.Collapse || options.Expand.HasValue))
        {
            // Status and logon type keep different kinds of repeated failures apart.
            // Native daily summaries retain their existing identity and cannot expand.
            statement += $"""
                , keyed as (
                    select *, case when id is not null and journal_result='failure' and event_id in (4625,4771,4776,6273)
                        then jsonb_build_array(domain_id,server_id,channel,provider_name,event_id,lower(journal_computer),
                             outcome->'Status',outcome->'SubStatus',method->'LogonType')
                        end as repeat_key
                    from candidates {categoryWhere}
                )
                """;
            if (options.Expand is { } expand)
            {
                statement += $"""
                    , members as (
                        select member.*,date_trunc('minute',member.time_created_utc,'UTC') as minute
                        from keyed member
                        join keyed anchor on anchor.id={sql.Parameter(expand)} and member.repeat_key=anchor.repeat_key
                    )
                    """;
                if (options.Member is { } member)
                    statement += $"""
                        , visible as (
                            select event.*,false as journal_expandable from members event
                            join members anchor on anchor.id={sql.Parameter(member)} and event.minute=anchor.minute
                              and lower(event.actor) is not distinct from lower(anchor.actor)
                              and lower(event.target) is not distinct from lower(anchor.target)
                              and lower(event.source) is not distinct from lower(anchor.source)
                        )
                        """;
                else
                    statement += """
                        , buckets as (
                            select *,count(*) over w as group_count,min(first_seen_utc) over w as group_start,
                                   max(last_seen_utc) over w as group_end,
                                   first_value(id) over (w order by time_created_utc desc,id desc) as representative,
                                   actor as group_actor,target as group_target,source as group_source
                            from members
                            window w as (partition by minute,lower(actor),lower(target),lower(source))
                        ),
                        visible as (select *,group_count>1 as journal_expandable from buckets where id=representative)
                        """;
            }
            else
                // Rank repeats and collect their facts in the same pass over each group.
                statement += """
                    , repeated as (
                        select *,min(first_seen_utc) over w as group_start,max(last_seen_utc) over w as group_end,
                               count(*) over w as group_count,row_number() over w as repeat_rank,
                               case when count(actor) over w=count(*) over w and min(actor) over w=max(actor) over w then min(actor) over w end as group_actor,
                               case when count(target) over w=count(*) over w and min(target) over w=max(target) over w then min(target) over w end as group_target,
                               case when count(source) over w=count(*) over w and min(source) over w=max(source) over w then min(source) over w end as group_source
                        from keyed where repeat_key is not null
                        window w as (partition by repeat_key order by time_created_utc desc,id desc
                                     rows between unbounded preceding and unbounded following)
                    ),
                    visible as (
                        select *,group_count>1 as journal_expandable from repeated where repeat_rank=1
                        union all
                        select *,null,null,null,null,null,null,null,false from keyed where repeat_key is null
                    )
                    """;
        }
        else
            statement += $", visible as (select *,false as journal_expandable from candidates {categoryWhere})";

        sql.Predicates.Clear();
        if (query.TryGetValue("cursor", out var cursor)) sql.Interactive(Dataset, new Dictionary<string, string> { ["cursor"] = cursor }, 90);
        string after = sql.Predicates.Count > 0 ? "where " + string.Join(" and ", sql.Predicates) : "";
        bool metadata = options.Expand is null && options.Before is null;
        string counts = metadata ? "(select jsonb_build_object('all',coalesce(sum(event_count),0)" +
            string.Concat(Views.Keys.Select(key => $",'{key}',coalesce(sum(event_count) filter (where journal_category='{key}'),0)")) +
            ") from candidates)" : "null::jsonb";
        string eventCount = metadata ? $"(select coalesce(sum(event_count),0) from candidates {categoryWhere})" : "null::numeric";
        string priority = options.Before.HasValue ? "event.journal_account_match desc," : "";
        statement += $"""
            , page as (
                select event.* from visible event {after}
                order by {priority}event.time_created_utc desc,coalesce(event.id,0) desc,event.summary_key desc limit {sql.Parameter(limit + 1)}
            ),
            meta as (
                select (select count(*) from visible) as filtered_count,
                       {eventCount} as journal_event_count,
                       {counts} as journal_counts
            )
            select meta.*,(
                select coalesce(jsonb_agg(
                    (to_jsonb(page)-array['fields','method','outcome','repeat_key','minute','representative','repeat_rank',
                         'subject_user_name','target_user_name','ip_address','workstation_name','logon_id','journal_account_match'])
                    || jsonb_build_object('journal_logon_type',coalesce(page.outcome->>'LogonType',page.method->>'LogonType',page.fields->>'LogonType'))
                    order by page.time_created_utc desc,coalesce(page.id,0) desc,page.summary_key desc
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
                foreach (var (field, aggregate) in new[] { ("actor","group_actor"), ("target","group_target"), ("source","group_source"),
                    ("first_seen_utc","group_start"), ("last_seen_utc","group_end"), ("event_count","group_count") })
                    sourceRow[field] = storedRow[aggregate]?.DeepClone();
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
                };
            if (accounts)
            {
                foreach (string field in new[] { "actor", "target", "ip_address" })
                    item[field] = row[field]?.DeepClone();
                item["logon_type"] = storedRow["journal_logon_type"]?.DeepClone();
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
}
