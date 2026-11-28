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
    internal string? StationProgram { get; init; }
    internal bool PageOnly { get; init; }
}

internal static class JournalPage
{
    private const string NativeSecurity = "channel='Security' and provider_name='Microsoft-Windows-Security-Auditing'";
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
        bool workstation = technical && options.SourcePlugin == "sli.workstations";
        bool canGroup = (identity || workstation && options.ServerId is not null) && accounts && technical;
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
        if (options.StationProgram is { Length: > 0 } program)
            sql.Predicates.Add(workstation && security && options.ServerId is not null
                ? "event.event_id=4688 and event.channel='Security' and event.provider_name='Microsoft-Windows-Security-Auditing' and "
                  + Fold("replace(event.fields->>'NewProcessName','/',chr(92))") + "="
                  + Fold("replace(" + sql.Parameter(program) + "::text,'/',chr(92))")
                : "false");
        if (search.Length > 0)
        {
            string term = Fold(sql.Parameter(search));
            var matches = new List<string>();
            if (options.Pivot == "account" && accounts)
                matches.Add($"{term} in ({Fold("subjects.account")},{Fold("subjects.initiator")},{Fold("local_account.display_name")})");
            else if (options.Pivot == "computer" && technical)
                matches.Add(Fold("origin.computer") + "=" + term);
            else if (options.Pivot == "address" && accounts)
                matches.Add("address.value=" + term);
            else if (options.Pivot == "")
            {
                if (accounts) foreach (string column in new[] { "subjects.account", "subjects.initiator", "local_account.display_name", "event.actor", "event.target", "address.value", "source_fields.workstation" })
                    matches.Add($"strpos({Fold(column)},{term})>0");
                if (technical) foreach (string column in new[] { "event.computer", "server.hostname" })
                    matches.Add($"strpos({Fold(column)},{term})>0");
                if (security && long.TryParse(search, NumberStyles.None, CultureInfo.InvariantCulture, out long code))
                    matches.Add("event.event_id=" + sql.Parameter(code));
            }
            sql.Predicates.Add(matches.Count > 0 ? string.Join(" or ", matches) : "false");
        }

        var start = DateTimeOffset.Parse(query["time_from"], CultureInfo.InvariantCulture).ToUniversalTime();
        var end = DateTimeOffset.Parse(query["time_to"], CultureInfo.InvariantCulture).ToUniversalTime();
        bool pageOnly = options.PageOnly && options.Before is null && start >= boundary;
        int scanStartIndex = sql.Values.Count;
        string from = sql.Parameter(start);
        string to = sql.Parameter(end);
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
                case when event_id in (4625,4740,4771,6273) then 'failure'
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
        string service = accounts && technical ? $"""
            coalesce(({NativeSecurity} and event_id=any({sql.Parameter(Views["authentication"])})
                and (right(journal_account,1)='$' or journal_account_sid in ('S-1-5-18','S-1-5-19','S-1-5-20')
                     or (event_id in (4624,4625) and journal_logon_type='5')))
                or (channel='System' and provider_name='Service Control Manager' and event_id in (7035,7036))
                or lower(channel) like '%taskscheduler%',false)
            """ : "false";
        string workstationFields = workstation && security ? """
            case when event.channel='Security' and event.provider_name='Microsoft-Windows-Security-Auditing' then
                case event.event_id when 4688 then jsonb_strip_nulls(jsonb_build_object(
                    'image_path',left(nullif(btrim(event.fields->>'NewProcessName'),'-'),256),
                    'parent_image_path',left(nullif(btrim(event.fields->>'ParentProcessName'),'-'),256),
                    'command_line',left(nullif(btrim(event.fields->>'CommandLine'),'-'),1024)))
                when 6416 then jsonb_strip_nulls(jsonb_build_object(
                    'device_name',left(event.fields->>'DeviceDescription',512),
                    'device_class',left(coalesce(event.fields->>'ClassName',event.fields->>'ClassId'),512))) end
            end
            """ : "null::jsonb";
        string statement = $"""
            with short_events as ({source}),
            scoped as (
                select event.id,event.time_created_utc,event.event_id,event.domain_id,event.server_id,
                       event.actor,event.target,nullif(nullif(nullif(btrim(event.source),''),'-'),'—') as source,event.channel,event.provider_name,
                       event.day,event.event_count,event.first_seen_utc,event.last_seen_utc,event.summary_key,
                       origin.computer as journal_computer,server.role as journal_server_role,
                       coalesce(local_account.display_name,subjects.account) as journal_account,
                       subjects.account as journal_reported_account,subjects.initiator as journal_initiator,
                       {Fold("local_account.name")} as local_account_key,subjects.account_sid as journal_account_sid,
                       address.value as journal_address,
                       {(accounts ? "coalesce(source_fields.workstation,case when address.value is null then left(nullif(nullif(nullif(btrim(event.source),''),'-'),'—'),256) end)" : "null::text")} as journal_workstation,
                       coalesce(event.outcome->>'LogonType',event.method->>'LogonType',event.fields->>'LogonType') as journal_logon_type,
                       lower(coalesce(event.method->>'AuthenticationPackageName',event.fields->>'AuthenticationPackageName')) as auth_package,
                       nullif(ltrim(lower(substring(case event.event_id
                           when 4624 then event.fields->>'TargetLogonId'
                           when 4672 then event.fields->>'SubjectLogonId'
                           end from '^0[xX]([0-9a-fA-F]+)$')),'0'),'') as logon_session,
                       {category} as journal_category,{outcome} as journal_result,{workstationFields} as workstation_event
                from (select e.*,e.actor as subject_user_name,e.target as target_user_name,e.source as ip_address,
                             e.source as workstation_name,e.fields->>'TargetLogonId' as logon_id from short_events e) event
                join servers server on server.id=event.server_id and server.domain_id=event.domain_id
                cross join lateral (select event.channel as value) channel
                cross join lateral (select coalesce(nullif(event.computer,''),server.hostname) as computer) origin
                {SubjectJoin(accounts, workstation)}
                {ConnectionJoin(accounts)}
                {where}
            ),
            candidates as materialized (
                select *,{service} as journal_service from scoped
                {(options.Result.Length > 0 ? "where journal_result=" + sql.Parameter(options.Result) : "")}
            )
            """;
        const string Failure = "(journal_category='authentication' or event_id=4740) and journal_result='failure'";
        string serviceColumn = groupRepeats ? "action_service" : "journal_service";
        string population = groupRepeats ? "classified" : "candidates";
        string categoryWhere = options.View switch
        {
            "all" when options.Before is null => $"where not {serviceColumn}",
            "authentication" => $"where journal_category='authentication' and not {serviceColumn}",
            "failures" => "where " + Failure,
            "service" => $"where {serviceColumn}",
            _ when Views.ContainsKey(options.View) => "where journal_category=" + sql.Parameter(options.View),
            _ => "",
        };
        if (options.Before is { } before)
        {
            // Compare stored account identities inside the anchor's domain.
            string accountMatch = accounts ? $"""
                {Fold("peer.journal_account")}={Fold("anchor.journal_account")}
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
            statement += PairMatches + $"""
                , classified as not materialized (
                    select candidates.*,coalesce(pairs.primary_service,candidates.journal_service) as action_service
                    from candidates left join pairs on pairs.companion_id=candidates.id
                ),
                selected as (select * from classified {categoryWhere})
                """ + PairedActions(workstation);
            if (options.Expand is { } expand)
                statement += $"""
                    , anchor as materialized (
                        select id,repeat_key from actions where id={sql.Parameter(expand)} limit 1
                    ),
                    expanded_ids as materialized (
                        select unnest(array[member.id,member.companion_id]) as id
                        from actions member
                        where member.repeat_key=(select repeat_key from anchor)
                           or (member.repeat_key is null and member.id=(select id from anchor))
                    )
                    , visible as (
                        select member.*,false as journal_expandable
                        from selected member
                        where member.id in (select id from expanded_ids)
                    )
                    """;
            else
                statement += """
                    , repeated as (
                        select *,min(time_created_utc) over w as group_start,max(time_created_utc) over w as group_end,
                               count(*) over w as group_count,row_number() over w as repeat_rank,
                               count(*) over w + count(companion_id) over w as source_count,
                               case when count(journal_initiator) over w=count(*) over w
                                    and min(lower(journal_initiator)) over w=max(lower(journal_initiator)) over w
                                    then journal_initiator end as group_initiator,
                               case when min(lower(journal_computer)) over w=max(lower(journal_computer)) over w
                                    then journal_computer end as group_computer
                        from actions where repeat_key is not null
                        window w as (partition by repeat_key order by time_created_utc desc,id desc
                                     rows between unbounded preceding and unbounded following)
                    ),
                    visible as (
                        select *,source_count>1 as journal_expandable from repeated where repeat_rank=1
                        union all
                        select *,null,null,1,null,case when companion_id is null then 1 else 2 end,
                               journal_initiator,journal_computer,companion_id is not null
                        from actions where repeat_key is null
                    )
                    """;
        }
        else
            statement += $", visible as (select *,false as journal_expandable from candidates {categoryWhere})";

        sql.Predicates.Clear();
        int cursorIndex = sql.Values.Count;
        if (query.TryGetValue("cursor", out var cursor)) sql.Interactive(Dataset, new Dictionary<string, string> { ["cursor"] = cursor }, 90);
        var cursorTime = sql.Values.Count > cursorIndex ? (DateTimeOffset?)sql.Values[cursorIndex] : null;
        int windowIndex = sql.Values.Count;
        if (pageOnly && options.Expand is null)
        {
            sql.Add("event.time_created_utc>=", start);
            sql.Add("event.time_created_utc<", end);
        }
        string after = sql.Predicates.Count > 0 ? "where " + string.Join(" and ", sql.Predicates) : "";
        // Exact totals and column variation require a separate full-period read.
        bool metadata = !pageOnly && options.Expand is null && options.Before is null;
        string counts = "null::jsonb";
        string eventCount = "null::numeric";
        bool includeTotals = metadata && security;
        if (includeTotals)
        {
            // Counts cover the admitted candidates before grouping or applying the page cursor.
            string all = $"not {serviceColumn}";
            var predicates = Views.Keys.ToDictionary(key => key, key => $"journal_category='{key}'");
            predicates["all"] = all;
            predicates["authentication"] += " and " + all;
            predicates["failures"] = Failure;
            predicates["service"] = serviceColumn;
            string sums = string.Join(",", predicates.Select(entry =>
                $"coalesce(sum(event_count) filter (where {entry.Value}),0) as {entry.Key}_count"));
            statement += $", totals as (select coalesce(sum(event_count),0) as total_count,{sums} from {population})";
            eventCount = predicates.ContainsKey(options.View) ? $"totals.{options.View}_count" : "totals.total_count";
            counts = "jsonb_build_object(" + string.Join(",", predicates.Keys.Select(key => $"'{key}',totals.{key}_count")) + ")";
        }
        else if (metadata)
            eventCount = $"(select coalesce(sum(event_count),0) from candidates {categoryWhere})";
        string priority = options.Before.HasValue ? "journal_account_match desc," : "";
        bool includeMembers = groupRepeats && options.Expand is null;
        string memberLookup = includeMembers ? """
            , page_actions as (
                select page.id as anchor_id,action.id,action.companion_id,action.server_id
                from page join actions action using(repeat_key)
                where page.journal_expandable
                union all
                select id,id,companion_id,server_id from page where repeat_key is null and companion_id is not null
            ),
            page_members as (
                select anchor_id,jsonb_agg(jsonb_build_array(member.id,server_id) order by member.id,server_id) as members
                from page_actions cross join lateral unnest(array[id,companion_id]) member(id)
                where member.id is not null
                group by anchor_id
            )
            """ : "";
        string shape = pageOnly && options.Expand is null ? "null::bigint as filtered_count,null::jsonb as journal_varying_columns"
            : $"count(*) as filtered_count,{(metadata ? VaryingColumns(includeMembers, security, technical, accounts) : "null::jsonb")} as journal_varying_columns from visible";
        int limitIndex = sql.Values.Count;
        statement += $"""
            , page as (
                select event.* from visible event {after}
                order by {priority}event.time_created_utc desc,coalesce(event.id,0) desc,event.summary_key desc limit {sql.Parameter(limit + 1)}
            )
            {memberLookup}
            , shape as (
                select {shape}
            ),
            meta as (
                select shape.*,
                       {eventCount} as journal_event_count,
                       {counts} as journal_counts
                from shape {(includeTotals ? "cross join totals" : "")}
            )
            select meta.*,(
                select coalesce(jsonb_agg(
                    (to_jsonb(page)-array['repeat_key','repeat_rank','journal_account_sid','journal_account_match','journal_service','action_service'])
                    {(includeMembers ? "||jsonb_build_object('_journal_members',page_members.members)" : "")}
                    order by {priority}page.time_created_utc desc,coalesce(page.id,0) desc,page.summary_key desc
                ),'[]'::jsonb) from page {(includeMembers ? "left join page_members on page_members.anchor_id=page.id" : "")}
            ) as items from meta
            """;
        // LLVM compilation is more expensive than running these report queries.
        await db.QueryAsync("set local jit=off", [], ct);
        JsonObject meta = new();
        JsonObject[] rows;
        if (pageOnly)
            rows = await ReadWindowsAsync(db, statement, sql.Values, start, end, cursorTime, options.Expand, groupRepeats,
                scanStartIndex, windowIndex, limitIndex, limit + 1, ct);
        else
        {
            meta = (await db.QueryAsync(statement, sql.Values, ct)).Single();
            rows = meta.Array("items").OfType<JsonObject>().ToArray();
        }
        bool more = rows.Length > limit && security && !options.Before.HasValue &&
            (identity || rows[limit - 1]["day"] is not null);
        var items = Nodes(rows.Take(limit).Select(storedRow =>
        {
            var sourceRow = storedRow.Copy();
            bool grouped = storedRow.Flag("journal_expandable");
            if (grouped)
            {
                foreach (var (field, aggregate) in new[] { ("first_seen_utc","group_start"), ("last_seen_utc","group_end"), ("event_count","group_count") })
                    if (storedRow[aggregate] is { } value) sourceRow[field] = value.DeepClone();
                sourceRow["journal_initiator"] = storedRow["group_initiator"]?.DeepClone();
                sourceRow["journal_computer"] = storedRow["group_computer"]?.DeepClone();
            }
            var row = EventReadService.ShortRow(sourceRow);
            var item = new JsonObject();
            foreach (string field in fields) item[field] = row[field]?.DeepClone();
            if (security)
                foreach (string field in new[] { "day", "summary_key", "event_count", "first_seen_utc", "last_seen_utc", "journal_result" })
                    item[field] = row[field]?.DeepClone();
            if (technical) item["journal_computer"] = row["journal_computer"]?.DeepClone();
            if (storedRow["workstation_event"] is JsonObject workstationEvent)
                item["_workstation_event"] = workstationEvent.DeepClone();
            if (identity && security && technical)
            {
                item["_journal_origin"] = new JsonObject
                {
                    ["domain_id"] = storedRow["domain_id"]?.DeepClone(),
                    ["server_id"] = storedRow["server_id"]?.DeepClone(),
                    ["provider_name"] = storedRow["provider_name"]?.DeepClone(),
                    ["server_role"] = storedRow["journal_server_role"]?.DeepClone(),
                };
                if (storedRow["_journal_members"] is JsonArray members)
                    item["_journal_members"] = members.DeepClone();
                item["journal_action"] = storedRow["journal_action"]?.DeepClone();
                item["journal_source_count"] = storedRow["source_count"]?.DeepClone();
            }
            if (accounts)
            {
                item["journal_account"] = storedRow["journal_account"]?.DeepClone();
                if (!grouped) item["journal_reported_account"] = storedRow["journal_reported_account"]?.DeepClone();
                item["journal_initiator"] = row["journal_initiator"]?.DeepClone();
                item["journal_address"] = row[includeMembers ? "action_address" : "journal_address"]?.DeepClone();
                item["journal_workstation"] = row[includeMembers ? "action_workstation" : "journal_workstation"]?.DeepClone();
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
            ["journal_varying_columns"] = meta["journal_varying_columns"]?.DeepClone(),
            ["journal_event_count"] = metadata ? meta["journal_event_count"]?.DeepClone() : null,
            ["journal_counts"] = metadata && security ? meta["journal_counts"]?.DeepClone() : null,
        };
    }

    private static async Task<JsonObject[]> ReadWindowsAsync(IReportSession db, string statement, List<object?> values,
        DateTimeOffset start, DateTimeOffset end, DateTimeOffset? cursor, long? expand, bool grouped,
        int scanStartIndex, int windowIndex, int limitIndex, int take, CancellationToken ct)
    {
        // Windows align with repeat_key. A pair can span two seconds. Its
        // mutual ranking can depend on a competing event two seconds farther.
        var bucket = TimeSpan.FromMinutes(10);
        var pairingMargin = TimeSpan.FromSeconds(grouped ? 4 : 0);
        var rows = new List<JsonObject>(take);
        var upper = expand is null && cursor is { } at && at < end ? at.AddTicks(10) : end;
        string idFilter = expand.HasValue ? "and event_id=@p2" : "";
        string seek = $"""
            select greatest(
                (select time_created_utc from event_hot where time_created_utc>=@p0 and time_created_utc<@p1 {idFilter}
                    order by time_created_utc desc limit 1),
                (select time_created_utc from event_cold_facts where time_created_utc>=@p0 and time_created_utc<@p1 {idFilter}
                    order by time_created_utc desc limit 1)
            ) as window_event
            """;
        while (rows.Count < take && upper > start)
        {
            object?[] seekValues = expand.HasValue ? [start, upper, expand.Value] : [start, upper];
            var newest = (await db.QueryAsync(seek, seekValues, ct)).Single()["window_event"];
            if (newest is null) break;
            var stamp = DateTimeOffset.Parse(newest.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
            var bucketStart = new DateTimeOffset(stamp.Ticks - stamp.Ticks % bucket.Ticks, TimeSpan.Zero);
            var bucketEnd = bucketStart.Add(bucket);
            var scanStart = bucketStart.Subtract(pairingMargin);
            var scanEnd = bucketEnd.Add(pairingMargin);
            values[scanStartIndex] = scanStart > start ? scanStart : start;
            values[scanStartIndex + 1] = scanEnd < end ? scanEnd : end;
            if (!expand.HasValue)
            {
                values[windowIndex] = bucketStart;
                values[windowIndex + 1] = bucketEnd;
            }
            values[limitIndex] = take - rows.Count;
            var page = (await db.QueryAsync(statement, values, ct)).Single();
            rows.AddRange(page.Array("items").OfType<JsonObject>());
            if (expand.HasValue) break;
            upper = bucketStart;
        }
        return rows.ToArray();
    }

    // Logon IDs are local to the recording computer. NTLM validation does not
    // have that ID, so only pair mutually closest witnesses in a short window.
    private static readonly string PairMatches = $"""
        , pairable as materialized (
            select id,event_id,domain_id,server_id,time_created_utc,journal_address,journal_workstation,journal_service,
                   case when event_id in (4624,4672) then 'session:'||logon_session
                        when journal_server_role='domain_controller' and journal_result='failure'
                             and (event_id=4776 or auth_package is null or auth_package in ('ntlm','negotiate'))
                        then 'ntlm:'||local_account_key end as match_key,
                   (floor(extract(epoch from time_created_utc)/2))::bigint as bucket
            from candidates where id is not null and {NativeSecurity}
                and ((event_id in (4624,4672) and logon_session is not null)
                     or (event_id in (4625,4776) and local_account_key is not null and journal_result='failure'))
        ),
        matches as (
            select primary_event.id as primary_id,companion.id as companion_id,
                   primary_event.event_id=4624 as privileged,
                   primary_event.journal_service as primary_service,
                   primary_event.journal_address as primary_address,
                   companion.journal_address as companion_address,companion.journal_workstation as companion_workstation,
                   (primary_event.journal_address=companion.journal_address) is true as same_address,
                   abs(extract(epoch from primary_event.time_created_utc-companion.time_created_utc)) as delta
            from pairable primary_event
            cross join lateral generate_series(primary_event.bucket-1,primary_event.bucket+1) buckets(bucket)
            join pairable companion on companion.domain_id=primary_event.domain_id and companion.server_id=primary_event.server_id
                and companion.bucket=buckets.bucket and companion.match_key=primary_event.match_key
                and companion.event_id=case primary_event.event_id when 4624 then 4672 when 4625 then 4776 end
            where abs(extract(epoch from primary_event.time_created_utc-companion.time_created_utc))<=2
              and (primary_event.event_id=4624 or
                   (companion.time_created_utc<=primary_event.time_created_utc
                    and (primary_event.journal_address is null or companion.journal_address is null
                         or primary_event.journal_address=companion.journal_address)))
        ),
        ranked as (
            select *,
                   rank() over (partition by primary_id order by same_address desc,delta) as primary_rank,
                   rank() over (partition by companion_id order by same_address desc,delta) as companion_rank,
                   count(*) over (partition by primary_id,same_address,delta) as primary_ties,
                   count(*) over (partition by companion_id,same_address,delta) as companion_ties,
                   min(primary_address) over (partition by companion_id) as first_address,
                   max(primary_address) over (partition by companion_id) as last_address
            from matches
        ),
        pairs as materialized (
            select primary_id,companion_id,privileged,primary_service,companion_address,companion_workstation from ranked
            where primary_rank=1 and companion_rank=1 and primary_ties=1 and companion_ties=1
              and (privileged or same_address or first_address is not distinct from last_address)
        )
        """;
    private static string PairedActions(bool workstation)
    {
        string processRepeat = workstation ? $"""
            when id is not null and {NativeSecurity} and event_id=4688
                and nullif(workstation_event->>'image_path','') is not null
                and coalesce(journal_account_sid,journal_account) is not null
            then array[(floor(extract(epoch from time_created_utc)/60))::text,domain_id::text,server_id::text,'4688',
                        {Fold("coalesce(journal_account_sid,journal_account)")},
                        {Fold("journal_initiator")},workstation_event->>'image_path',workstation_event->>'parent_image_path',
                        workstation_event->>'command_line',journal_result]
            """ : "";
        return $"""
        , actions as materialized (
            select selected.*,pairs.companion_id,
                   coalesce(journal_address,pairs.companion_address) as action_address,
                   coalesce(journal_workstation,pairs.companion_workstation) as action_workstation,
                   case when pairs.privileged then 'privileged_logon'
                        when id is not null and event_id=4625 and {NativeSecurity} then 'failed_logon' end as journal_action,
                   case when id is not null and {NativeSecurity}
                        and event_id in (4624,4625,4776)
                        and coalesce(local_account_key,journal_account_sid,journal_account) is not null
                        and coalesce(journal_address,pairs.companion_address) is not null
                        and (event_id=4776 or journal_logon_type is not null)
                        and (event_id<>4776 or journal_result is not null)
                        then array[(floor(extract(epoch from time_created_utc)/600))::text,domain_id::text,
                             case when local_account_key is null then server_id::text end,
                             case when pairs.privileged then 'privileged' else event_id::text end,
                             {Fold("coalesce(local_account_key,journal_account_sid,journal_account)")},
                             coalesce(journal_address,pairs.companion_address),journal_logon_type,journal_result]
                        {processRepeat}
                   end as repeat_key
            from selected left join pairs on pairs.primary_id=selected.id
            where not exists(select 1 from pairs companion where companion.companion_id=selected.id)
        )
        """;
    }

    private static string VaryingColumns(bool grouped, bool security, bool technical, bool accounts)
    {
        var values = new (string Key, string Expression, bool Visible)[]
        {
            ("time", "time_created_utc", security),
            ("account", Fold("coalesce(journal_account,'')"), accounts),
            ("initiator", grouped ? "lower(coalesce(group_initiator,''))" : "lower(coalesce(journal_initiator,''))", accounts),
            ("computer", grouped ? "lower(coalesce(group_computer,''))" : "lower(coalesce(journal_computer,''))", technical),
            ("address", grouped ? "lower(coalesce(action_address,action_workstation,''))"
                                : "lower(coalesce(journal_address,journal_workstation,''))", accounts),
            ("logonType", "case when journal_logon_type in ('2','3','4','5','7','8','9','10','11','12','13') then journal_logon_type else '' end", accounts),
            ("result", "coalesce(journal_result,'')", security && technical),
            ("code", "coalesce(event_id,0)", security),
        };
        return "to_jsonb(array_remove(array[" + string.Join(",", values.Where(entry => entry.Visible).Select(entry =>
            $"case when min({entry.Expression})<>max({entry.Expression})" +
            (entry.Key == "time" && grouped ? " or min(coalesce(group_start,time_created_utc))<>max(coalesce(group_start,time_created_utc))" : "") +
            $" then '{entry.Key}' end")) + "]::text[],null))";
    }

    private static string Fold(string value) => $"casefold(({value}) collate pg_catalog.pg_unicode_fast)";

    private static string ValidatedAddress(string value) => $$"""
        case when length({{value}})<=64
            and ({{value}} ~ '^[0-9]+(\.[0-9]+){3}$' or {{value}} ~ '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$')
            and pg_input_is_valid({{value}},'inet') then {{value}}::inet end
        """;

    private static string ConnectionJoin(bool accounts) => !accounts ? """
        cross join lateral (select null::text as name,null::text as display_name) local_account
        cross join lateral (select null::text as workstation) source_fields
        cross join lateral (select null::text as value) address
        """ : $$"""
        left join domains dc_domain on server.role='domain_controller' and dc_domain.id=server.domain_id
        cross join lateral (
            select case when dc_domain.id is not null and native.native_code in (4625,4776)
                        and subjects.account !~* '^S-1-[0-9]+(-[0-9]+)+$'
                        then nullif(btrim(split_part(regexp_replace(subjects.account,'^.*'||chr(92)||chr(92),''),'@',1)),'') end as name
        ) local_name
        cross join lateral (
            select local_name.name,left(coalesce(nullif(dc_domain.netbios_name,''),dc_domain.fqdn)||chr(92)||local_name.name,256) as display_name
        ) local_account
        cross join lateral (
            select left(coalesce(
                nullif(nullif(nullif(btrim(event.method#>>'{$principals,WorkstationName}'),''),'-'),'—'),
                nullif(nullif(nullif(btrim(event.method#>>'{$principals,Workstation}'),''),'-'),'—')),256) as workstation
        ) source_fields
        cross join lateral (
            select btrim(event.method#>>'{$principals,IpAddress}') as ip,
                   btrim(event.method#>>'{$principals,ClientAddress}') as client,
                   btrim(event.method#>>'{$principals,SourceNetworkAddress}') as network,
                   btrim(event.source) as stored
        ) inputs
        cross join lateral (
            select coalesce({{ValidatedAddress("inputs.ip")}},{{ValidatedAddress("inputs.client")}},{{ValidatedAddress("inputs.network")}},
                case when native.native_code is distinct from 4776
                          and lower(inputs.stored) is distinct from lower(source_fields.workstation)
                     then {{ValidatedAddress("inputs.stored")}} end) as value
        ) source
        cross join lateral (
            select regexp_replace(host(source.value),'^::ffff:([0-9.]+)$','\1') as value offset 0
        ) address
        """;

    private static string SubjectJoin(bool accounts, bool workstation)
    {
        if (!accounts) return "cross join lateral (select null::text as account,null::text as initiator,null::text as account_sid) subjects";

        static string Clean(string value) => $"nullif(nullif(nullif(btrim({value}),''),'-'),'—')";
        static string Principal(string kind)
        {
            string name = Clean($"event.method#>>'{{$principals,{kind}UserName}}'");
            string domain = Clean($"event.method#>>'{{$principals,{kind}DomainName}}'");
            return $"case when {domain} is not null and strpos({name},chr(92))=0 and strpos({name},'@')=0 then left({domain}||chr(92)||{name},256) else left({name},256) end";
        }
        string actor = $"nullif({Clean("event.actor")},'S-1-0-0')";
        string target = Clean("event.target");
        string subjectSid = Clean("event.method#>>'{$principals,SubjectUserSid}'");
        string targetSid = $"coalesce({Clean("event.method#>>'{$principals,TargetUserSid}'")},{Clean("event.method#>>'{$principals,TargetSid}'")})";
        string processAccount = workstation ? """
            when 4688 then coalesce(principals.target_name,principals.target_sid,principals.subject_name,principals.subject_sid,
                case when principals.actor ~* '^S-1-[0-9]+(-[0-9]+)+$' then principals.actor end)
            """ : "";
        string processSid = workstation ? """
            when native.native_code=4688 then case when principals.target_name is not null or principals.target_sid is not null
                then principals.target_sid else principals.subject_sid end
            """ : "";
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
                    {processAccount}
                    else coalesce(principals.target_name,principals.target,principals.subject_name,principals.actor)
                    end as account,
                    case when native.native_code in (4672,4776) then null
                         when native.native_code in (4624,4625) then principals.subject_name
                         else coalesce(principals.subject_name,principals.actor) end as initiator,
                    case when native.native_code=4672 then coalesce(principals.subject_sid,
                             case when principals.subject_name is null then principals.target_sid end)
                         when native.native_code=4776 then case when lower(principals.actor)=lower(principals.target_name)
                             then principals.target_sid end
                         {processSid}
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
