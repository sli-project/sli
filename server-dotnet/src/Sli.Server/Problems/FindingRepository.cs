using System.Data;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Problems;

public sealed partial class ProblemRepository
{
    public async Task<JsonObject> LegacyFindingsAsync(string query, int limit, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(tx, "set transaction read only; set local jit=off", new(), ct);
        var rows = await Rows(tx, """
            select * from findings_active where lower(coalesce(title,'')) like lower(@q) or lower(coalesce(actor,'')) like lower(@q)
              or lower(coalesce(target,'')) like lower(@q) or lower(coalesce(source,'')) like lower(@q) or lower(coalesce(summary,'')) like lower(@q)
            order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
              coalesce(last_seen_utc,updated_at::text) desc limit @limit
            """, new() { ["q"] = "%" + query + "%", ["limit"] = Math.Clamp(limit, 1, 1000) }, ct);
        var summary = await Rows(tx, "select severity,status,count(*) as count from findings_active group by severity,status", null, ct);
        await AttachDetails(tx, rows, ct);
        await AttachKerberosFacts(tx, rows.OfType<JsonObject>().ToArray(), ct);
        var refresh = await Sli.Server.Legacy.LegacyFindings.ReadStatusAsync((sql,token) => Rows(tx,sql,null,token),ct);
        await tx.CommitAsync(ct);
        return new() { ["generated_at_utc"] = clock.GetUtcNow(), ["status"] = "ok", ["backend"] = "postgres", ["items"] = rows, ["summary"] = summary,
            ["filters"] = new JsonObject { ["status"] = null, ["severity"] = null, ["q"] = query, ["limit"] = limit, ["refresh"] = false }, ["refresh_result"] = null, ["refresh_status"] = refresh?.DeepClone(),
            ["lifecycle"] = System.Text.Json.JsonSerializer.SerializeToNode(new { valid_statuses = FindingStatusInput.Statuses, allowed_transitions = FindingStatusInput.Transitions }), ["limitations"] = new JsonArray() };
    }
    public async Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var args = new Dictionary<string, object?> { ["id"] = id };
        var current = await One(tx, "select * from findings where id=@id for update", args, ct)
            ?? throw new ProblemException("not_found", 404, $"Finding {id} was not found");
        var change = input.Apply(current);
        args["status"] = input.Status; args["assignee"] = change.Assignee; args["reason"] = change.Reason;
        args["closed"] = input.Status == "closed" ? current["closed_at"]?.ToString() ?? ProblemJson.Iso(clock.GetUtcNow()) : null;
        var updated = await Returning(tx, """
            update findings set status=@status,assigned_to=@assignee,status_reason=@reason,closed_at=@closed::timestamptz,updated_at=now()
            where id=@id returning to_jsonb(findings.*)
            """, args, ct) ?? throw new InvalidOperationException("finding_update_missing");
        if (change.Audit)
        {
            args["old"] = ProblemJson.Text(current["status"]) is { Length: > 0 } old ? old : "new";
            args["actor"] = actor.Trim();
            args["note"] = input.Status == "closed" && !input.ReasonSupplied ? null : input.Note ?? change.Reason;
            await Execute(tx, """
                insert into finding_status_history(finding_id,old_status,new_status,changed_by,note)
                values(@id,@old,@status,@actor,@note)
                """, args, ct);
        }
        updated["status_history"] = await Rows(tx, "select id,finding_id,old_status,new_status,changed_at,changed_by,note from finding_status_history where finding_id=@id order by id desc limit 50", args, ct);
        await tx.CommitAsync(ct);
        return new() { ["status"] = "ok", ["backend"] = "postgres", ["changed"] = change.Changed, ["finding"] = updated };
    }
    private static Task<JsonArray> AuditRows(NpgsqlTransaction tx, long id, long? before, bool page, CancellationToken ct) => Rows(tx, """
        select id,action,actor,occurred_at,details from semantic_control_audit
        where details->'rule'->>'kind'='risk_acceptance' and details->'rule'->>'finding_id'=@finding
          and (@before::bigint is null or id<@before::bigint) order by id desc limit
        """ + (page ? " 51" : " 50"), new() { ["finding"] = id.ToString(CultureInfo.InvariantCulture), ["before"] = before }, ct);
    public async Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var args = new Dictionary<string, object?> { ["finding"] = id, ["actor"] = input.Actor };
        JsonObject? row;
        if (input.Action == "create")
        {
            // Keep the expiry trigger's suppression-before-finding lock order.
            await Execute(tx, """
                update semantic_suppressions set state='expired',changed_by='system:expiry'
                where finding_id=@finding and kind='risk_acceptance' and state='active' and expires_at<=clock_timestamp()
                """, args, ct);
            var finding = await One(tx, "select id,rule_code from findings where id=@finding and is_semantic_finding_published_v1(id) for update", args, ct)
                ?? throw new ProblemException("not_found", 404);
            args["responsible"] = input.Responsible;
            if (await One(tx, "select id from auth_users where id=@responsible and is_active=true for share", args, ct) is null) throw new ProblemException("responsible_not_found");
            if (await One(tx, "select id from semantic_suppressions where finding_id=@finding and kind='risk_acceptance' and state='active'", args, ct) is not null)
                throw new ProblemException("risk_already_accepted", 409);
            args["expiry"] = input.Expires; args["rule"] = ProblemJson.Text(finding["rule_code"]); args["scope"] = id.ToString(CultureInfo.InvariantCulture); args["reason"] = input.Reason;
            row = await Returning(tx, """
                with decision as materialized (select @expiry::timestamptz as expiry,clock_timestamp() as at)
                insert into semantic_suppressions(semantic_type,scope_kind,scope_value,kind,finding_id,responsible_user_id,reason,expires_at,created_at,created_by)
                select @rule,'finding',@scope,'risk_acceptance',@finding,@responsible,@reason,expiry,at,@actor from decision
                where expiry>at and expiry<=at+interval '2160 hours' returning to_jsonb(semantic_suppressions.*)
                """, args, ct) ?? throw new ProblemException("invalid_expiry");
        }
        else
        {
            args["acceptance"] = input.Id;
            row = await Returning(tx, """
                update semantic_suppressions set state='revoked',changed_by=@actor
                where finding_id=@finding and id=@acceptance and kind='risk_acceptance' and state='active'
                  and expires_at>clock_timestamp() returning to_jsonb(semantic_suppressions.*)
                """, args, ct) ?? throw new ProblemException("risk_not_active", 409);
        }
        // The existing semantic_suppressions_audit trigger snapshots the entire
        // decision and its actor in this same transaction.
        var audit = await AuditRows(tx, id, null, false, ct); await tx.CommitAsync(ct);
        return new() { ["status"] = "ok", ["acceptance"] = row, ["risk_audit"] = audit };
    }
    public async Task<JsonObject> ResponsiblesAsync(CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var rows = await Rows(tx, "select id,username from auth_users where is_active=true order by lower(username),id limit 500", null, ct);
        await tx.CommitAsync(ct); return new() { ["items"] = rows };
    }
    public async Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var rows = await AuditRows(tx, id, before, true, ct); bool more = rows.Count > 50;
        if (more) rows.RemoveAt(50); await tx.CommitAsync(ct); return new() { ["items"] = rows, ["has_more"] = more };
    }

    internal const string EffectiveStatus = "case when risk.state='active' and risk.expires_at<=statement_timestamp() then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end else findings.status end";
    internal const string Accepted = "coalesce(risk.state='active' and risk.expires_at>statement_timestamp(),false)";
    // Most rules have no active exception. Only classify event witnesses when
    // a rule can actually suppress this finding; the authoritative check still
    // decides domain/subject coverage for every matching exception.
    internal const string Suppressed = """
        case when exists(select 1 from semantic_suppressions active_rule
            where active_rule.kind='suppression' and active_rule.state='active'
              and active_rule.expires_at>statement_timestamp() and active_rule.semantic_type=findings.rule_code)
        then semantic_finding_suppressed_v160(findings.id,findings.rule_code) else false end
        """;
    private const string QueueSuppressed = """
        case when (findings.id,findings.rule_code) in (
            select copy.finding_id,rule.semantic_type from semantic_suppressions rule
            join finding_event_copies337 copy on copy.domain_id=rule.domain_id
                and left(copy.method#>>'{$principals,SubjectUserSid}',256)=left(rule.scope_value,256)
                and copy.method#>>'{$principals,SubjectUserSid}'=rule.scope_value
            where rule.kind='suppression' and rule.state='active' and rule.expires_at>statement_timestamp()
                and rule.scope_kind='subject_sid'
            union
            select copy.finding_id,rule.semantic_type from semantic_suppressions rule
            join finding_event_copies337 copy on copy.domain_id=rule.domain_id and copy.event_kind=4719
            where rule.kind='suppression' and rule.state='active' and rule.expires_at>statement_timestamp()
                and rule.scope_kind='bucket')
        then semantic_finding_suppressed_v160(findings.id,findings.rule_code) else false end
        """;
    internal const string QueueWorkMem = "work_mem='8MB'";
    private const string Population = "from findings_active findings";
    private const string PageRisk = """
         left join lateral (
            select s.*,u.username as responsible_username from semantic_suppressions s join auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance' order by s.id desc limit 1
        ) risk on true
        """;
    private const string QueueRisk = """
         left join (
            select distinct on (s.finding_id) s.finding_id,s.state,s.expires_at
            from semantic_suppressions s join auth_users u on u.id=s.responsible_user_id
            where s.kind='risk_acceptance' order by s.finding_id,s.id desc
        ) risk on risk.finding_id=findings.id
        """;
    private const string QueueEvidence = " left join problem_queue_evidence438 witnesses on witnesses.finding_id=findings.id";
    private const string QueueExternal = " left join problem_queue_external438 external_evidence on external_evidence.finding_id=findings.id";
    private static string QueueState(string status) =>
        $"case ({status}) when 'deferred' then 'deferred' when 'active' then 'active' when 'review' then 'active' when 'closed' then 'resolved' when 'false_positive' then 'resolved' else 'open' end";
    private static bool IsQueueList(FindingQuery query) => query.QueueList && query.QueueView is not null && query.Cohort is null;
    // Keep the Home caller signature without selecting a retired event source.
    internal static (string Page, string Summary, Dictionary<string, object?> Arguments) FindingsQueries(FindingQuery query, bool populationOnly = false, bool shortEvents = true, bool usePasswordProjection = false, bool useQueueRead = false)
    {
        useQueueRead &= IsQueueList(query);
        var args = new Dictionary<string, object?>();
        string effectiveStatus = query.QueueView is null ? EffectiveStatus : $"case when d.until_at>statement_timestamp() and findings.status in ('new','confirmed','repeated') then 'deferred' else ({EffectiveStatus}) end";
        string queueState = QueueState(effectiveStatus);
        var admission = new List<string>();
        if (!useQueueRead) admission.Add("is_semantic_finding_published_v1(findings.id)");
        if (!useQueueRead || query.Domains is null)
            admission.Add("(findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))");
        var clauses = new List<string>();
        if (query.Risk == "accepted") clauses.Add(Accepted); else if (query.Risk != "all") clauses.Add("not " + Accepted);
        if (!query.Suppressed && query.Risk != "accepted")
            admission.Add("not (" + (useQueueRead ? QueueSuppressed : Suppressed) + ")");
        if (query.Domains is not null) {
            args["domains"] = query.Domains;
            string coreDomainMatch = query.Domains.Length == 1
                ? "cardinality(witnesses.domain_ids)=1 and witnesses.domain_ids[1]=(@domains::bigint[])[1]"
                : "witnesses.domain_ids <@ @domains::bigint[]";
            admission.Add(useQueueRead ? $"""
                case when external_evidence.finding_id is not null or findings.rule_code='semantic.qw.file-acl-broad-write'
                    then semantic_finding_in_domains_v265(findings.id,@domains::bigint[])
                    else coalesce({coreDomainMatch},false) end
                """ : "semantic_finding_in_domains_v265(findings.id,@domains::bigint[])");
        }
        if (query.EntityId is not null) { args["entity"] = query.EntityId; clauses.Add("exists(select 1 from finding_entities linked where linked.finding_id=findings.id and linked.entity_id=@entity)"); }
        if (!string.IsNullOrEmpty(query.Status)) {
            if (query.PageQueue && query.Status == "new") clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated')");
            else if (query.PageQueue && query.Status == "active") clauses.Add($"({EffectiveStatus}) in ('active','review')");
            else { args["status"] = query.Status; clauses.Add($"({EffectiveStatus})=@status"); }
        }
        if (!string.IsNullOrEmpty(query.Severity)) {
            args["severity"] = query.Severity;
            const string queueSeverity = """
                case when findings.rule_code in ('semantic.qw.account-decoy','semantic.qw.file-decoy')
                    or (findings.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                        and exists(select 1 from finding_event_details337 e where e.finding_id=findings.id and e.event_id=4624))
                then 'critical' else findings.severity end
                """;
            clauses.Add(query.QueueView is null ? "findings.severity=@severity" : $"({queueSeverity})=@severity");
        }
        if (query.QueueAssignee is {} assignee) {
            args["assignee_filter"] = assignee;
            clauses.Add("coalesce(findings.assigned_to,'')=@assignee_filter");
        }
        if (!string.IsNullOrEmpty(query.From)) { args["from"] = query.From; clauses.Add("findings.last_seen_utc::timestamptz>=@from::timestamptz"); }
        if (!string.IsNullOrEmpty(query.To)) { args["to"] = query.To; clauses.Add("findings.last_seen_utc::timestamptz<@to::timestamptz"); }
        if (!string.IsNullOrEmpty(query.Search)) {
            args["q"] = "%" + query.Search + "%";
            const string search = "(findings.title ilike @q or findings.actor ilike @q or findings.target ilike @q or findings.summary ilike @q or findings.rule_code ilike @q)";
            clauses.Add(useQueueRead
                ? $"findings.id in (select findings.id from findings_active findings where {search})" : search);
        }
        if (query.FindingId is {} finding) { args["finding"] = finding; clauses.Add("findings.id=@finding"); }
        if (query.RuleCode is {} rule) { args["rule"] = rule; clauses.Add("findings.rule_code=@rule"); }
        if (query.CreatedFrom is {} createdFrom) { args["created_from"] = createdFrom; clauses.Add("findings.created_at>=@created_from::timestamptz"); }
        if (query.CreatedTo is {} createdTo) { args["created_to"] = createdTo; clauses.Add("findings.created_at<@created_to::timestamptz"); }
        if (query.Population == "attention") clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated')");
        if (query.Population == "open" && (query.QueueView is not null && query.EntityId is not null
            || string.IsNullOrEmpty(query.Status) && string.IsNullOrEmpty(query.Risk)))
            clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated','active','review') and not ({Accepted})");
        if (query.ExcludeDeferred) clauses.Add("not exists(select 1 from finding_queue_deferrals deferred where deferred.finding_id=findings.id and deferred.until_at>statement_timestamp() and findings.status in ('new','confirmed','repeated'))");
        // In the queue, apply status and risk filters before classifying event
        // witnesses. In particular, closed findings should not incur suppression
        // and domain checks just because an exception is active for their rule.
        string where = query.QueueList && clauses.Count > 0
            ? $" where case when {string.Join(" and ", clauses)} then {string.Join(" and ", admission)} else false end"
            : " where " + string.Join(" and ", admission.Concat(clauses));
        args["limit"] = query.Limit + 1;
        string deferral = query.QueueView is null ? "" : " left join finding_queue_deferrals d on d.finding_id=findings.id";
        string population = useQueueRead
            ? "from problem_queue_visible438 findings" + QueueRisk + deferral +
                (query.GroupQueue || query.Domains is not null ? QueueEvidence : "") + (query.Domains is null ? "" : QueueExternal)
            : Population + PageRisk + deferral;
        string prefix = "", groupFields = "", summaryPopulation = population, summaryWhere = where;
        if (query.GroupQueue) {
            args["cohort_zone"] = query.Timezone;
            if (!useQueueRead)
                population = population.Replace("from findings_active findings", "from queue_findings findings", StringComparison.Ordinal);
            prefix = ProblemCohorts.Queue(population, where, effectiveStatus, Accepted,
                query.QueueView is null ? "" : $", ({queueState}), (({effectiveStatus})='false_positive')" +
                    (query.QueueAssigneesVisible ? ", coalesce(findings.assigned_to,'')" : ""),
                query.QueueAssigneesVisible, usePasswordProjection, useQueueRead);
            if (!useQueueRead)
                prefix = "with queue_findings as materialized (select * from findings_active)," + prefix[5..];
            population += " join queue_groups on queue_groups.id=findings.id";
            where = " where true"; summaryPopulation = "from queue_groups"; summaryWhere = "";
            groupFields = ",queue_groups.problem_cohort,queue_groups.occurrence_count,queue_groups.queue_cursor_id,queue_groups.first_seen_utc::text as first_seen_utc,queue_groups.last_seen_utc::text as last_seen_utc,queue_groups.severity as severity,queue_groups.password_facts - 'cohort_key' as presentation_facts";
            if (usePasswordProjection && query.QueueView is not null && !query.Compact)
                groupFields += ",queue_groups.password_aliases as queue_attack_aliases";
        }
        else if (query.Cohort is {} cohort) {
            var key = ProblemCohorts.Parse(cohort);
            if (key[0]!.ToString() == "finding") { args["cohort_id"] = key[1]!.GetValue<long>(); where += " and findings.id=@cohort_id"; }
            else { args["cohort_zone"] = query.Timezone; args["cohort"] = key.ToJsonString(); population += ProblemCohorts.Sql(key[0]!.ToString() == "queue" ? "legacy-queue-cohort" : key[0]!.ToString() is "rule-object" or "rule-source" or "rule-entity" or "password" ? "queue-cohort" : "cohort"); where += " and cohort.key=@cohort::jsonb"; }
            summaryPopulation = population; summaryWhere = where;
        }
        if (populationOnly) return (prefix, "", args);
        string pageWhere = where;
        if (query.QueueView is not (null or "all")) {
            args["queue_view"] = query.QueueView;
            pageWhere += $" and ({(useQueueRead && query.GroupQueue ? QueueState("queue_groups.status") : queueState)})=@queue_view";
            if (useQueueRead && !query.GroupQueue)
                pageWhere += query.QueueView switch {
                    "active" => " and findings.status in ('active','review')",
                    "deferred" => " and findings.status in ('new','confirmed','repeated')",
                    "resolved" => " and findings.status in ('closed','false_positive')",
                    _ => ""
                };
        }
        string seen = query.GroupQueue ? "queue_groups.last_seen_utc" : "coalesce(findings.last_seen_utc,findings.updated_at::text)::timestamptz";
        string cursorId = query.GroupQueue ? "queue_groups.queue_cursor_id" : "findings.id";
        string candidateSeen = useQueueRead && !query.GroupQueue ? "coalesce(findings.last_seen_utc,findings.updated_at)" : seen;
        if (query.BeforeId is {} before) {
            args["before"] = before;
            if (query.BeforeSeen is {} stamp) {
                args["before_seen"] = stamp;
                pageWhere += $" and ({candidateSeen},{cursorId}) {(query.OldestFirst ? ">" : "<")} (@before_seen,@before)";
            } else pageWhere += $" and {cursorId}<@before";
        }
        string order = query.GroupQueue ? "queue_groups.queue_cursor_id desc," : query.PageQueue ? "findings.id desc," : $"case ({EffectiveStatus}) when 'new' then 1 when 'repeated' then 2 when 'confirmed' then 3 when 'active' then 4 when 'review' then 5 when 'false_positive' then 6 when 'closed' then 7 else 8 end,";
        if (query.QueueView is not null) {
            string direction = query.OldestFirst ? "asc" : "desc";
            order = $"{seen} {direction},{cursorId} {direction},";
            if (useQueueRead) {
                string candidates = query.GroupQueue ? "from queue_groups" : population;
                string columns = query.GroupQueue ? "queue_groups.*" : "findings.id,findings.superseded_by_finding_id";
                string representative = query.GroupQueue ? "offset 0" :
                    "and f.superseded_by_finding_id is not distinct from queue_groups.superseded_by_finding_id limit 1";
                population = $"""
                    from (select {columns} {candidates}{pageWhere}
                        order by {candidateSeen} {direction},{cursorId} {direction} limit @limit) queue_groups
                    join lateral (select * from findings_active f where f.id=queue_groups.id {representative}) findings on true
                    {PageRisk}{deferral}
                    """;
                pageWhere = "";
            }
        }
        string riskAudit = query.QueueList ? "null::jsonb" : """
            (select coalesce(jsonb_agg(to_jsonb(a) order by a.id desc),'[]'::jsonb) from (
                select id,action,actor,occurred_at,details from semantic_control_audit where details->'rule'->>'kind'='risk_acceptance'
                and details->'rule'->>'finding_id'=findings.id::text order by id desc limit 50) a)
            """;
        const string review = "semantic_finding_review_v160(findings.id)";
        string reviewHint = query.QueueList
            ? $"case when findings.rule_code not in ('semantic.qw.password-brute-force','semantic.qw.password-spray') then {(useQueueRead ? ProblemCohorts.Sql("queue-review") : review)} end"
            : review;
        string page = $"""
            {prefix}
            select findings.*,({effectiveStatus}) as status{groupFields},
              {(query.QueueView is null ? "" : $"case when findings.status in ('new','confirmed','repeated') then d.until_at end as deferred_until,{seen} as queue_sort_at,")}
              case when risk.id is not null then to_jsonb(risk)||jsonb_build_object('state',case when risk.state='active' and risk.expires_at<=statement_timestamp() then 'expired' else risk.state end) else null end as risk_acceptance,
              {riskAudit} as risk_audit,
              {reviewHint} as review_hint,
              ({Suppressed}) as suppressed,
              case when findings.rule_code in ('semantic.qw.account-decoy','semantic.qw.file-decoy') then public.finding_decoy_context(findings.id) end as decoy_label
            {population}{pageWhere}
            order by {order}
              case findings.severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
              coalesce(findings.last_seen_utc,findings.updated_at::text)::timestamptz desc,findings.id desc limit @limit
            """;
        string groupedOwner = query.QueueAssigneesVisible ? ", queue_assignee" : "";
        string rawOwner = query.QueueAssigneesVisible ? ", findings.assigned_to" : "";
        string summary = query.GroupQueue ? $"{prefix} select severity,status,risk_accepted{groupedOwner},count(*) as count,sum(occurrence_count) as occurrences from queue_groups group by severity,status,risk_accepted{groupedOwner}" :
            $"select findings.severity,({effectiveStatus}) as status,({Accepted}) as risk_accepted{rawOwner},count(*) as count {summaryPopulation}{summaryWhere} group by findings.severity,({effectiveStatus}),({Accepted}){rawOwner}";
        return (page, summary, args);
    }
    public async Task<JsonObject> FindingsAsync(FindingQuery query, ProblemAccess access, CancellationToken ct)
    {
        // Fallback aliases and the authorized queue page must see the same witnesses.
        var isolation = query.QueueView is not null && !query.Compact ? IsolationLevel.RepeatableRead : IsolationLevel.ReadCommitted;
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(isolation, ct);
        if (query.PageQueue) await Execute(tx, "set transaction read only; set local jit=off", new(), ct);
        // Validate the persisted authorization before reading the population.
        await DirectRuntimeAuthorization.LoadAsync(db, tx, clock.GetUtcNow().UtcDateTime, ct);
        bool usePasswordProjection = query.GroupQueue && query.QueueList &&
            (await One(tx, "select to_regprocedure('public.password_queue_presentation399(bigint,text)') is not null as enabled", null, ct))?["enabled"]?.GetValue<bool>() == true;
        bool useQueueRead = IsQueueList(query) &&
            (await One(tx, "select to_regclass('public.problem_queue_visible438') is not null as enabled", null, ct))?["enabled"]?.GetValue<bool>() == true;
        if (useQueueRead && query.GroupQueue) await Execute(tx, "set local " + QueueWorkMem, new(), ct);
        var (page, summarySql, args) = FindingsQueries(query, usePasswordProjection: usePasswordProjection, useQueueRead: useQueueRead);
        JsonArray rows, summary;
        if (query.GroupQueue) {
            // Page and counters share the same classified population and
            // statement snapshot. Do not evaluate every finding twice.
            string prefix = FindingsQueries(query, populationOnly: true, usePasswordProjection: usePasswordProjection, useQueueRead: useQueueRead).Page;
            var bundle = await One(tx, prefix + $"""
                select (select coalesce(jsonb_agg(to_jsonb(item)),'[]'::jsonb) from ({page[prefix.Length..]}) item) as items,
                    (select coalesce(jsonb_agg(to_jsonb(counter)),'[]'::jsonb) from ({summarySql[prefix.Length..]}) counter) as summary
                """, args, ct) ?? throw new InvalidOperationException("finding_queue_read_missing");
            rows = bundle["items"]!.AsArray(); summary = bundle["summary"]!.AsArray();
            bundle.Remove("items"); bundle.Remove("summary");
        }
        else {
            rows = await Rows(tx, page, args, ct);
            summary = await Rows(tx, summarySql, args, ct);
        }
        bool more = rows.Count > query.Limit; if (more) rows.RemoveAt(query.Limit);
        if (usePasswordProjection && query.QueueView is not null && !query.Compact)
            foreach (var row in rows.OfType<JsonObject>())
                if (row["queue_attack_aliases"] is null) row.Remove("queue_attack_aliases");
        var passwordRows = rows.OfType<JsonObject>().Where(row => ProblemPresentation.IsPasswordFinding(ProblemJson.Text(row["rule_code"])))
            .ToDictionary(row => ProblemJson.Long(row["id"]));
        if (passwordRows.Count > 0 && !query.Compact && !query.GroupQueue) {
            var passwordFacts = await Rows(tx, $"""
                select findings.id,({ProblemCohorts.PasswordFacts("findings")}) - 'cohort_key' as facts
                from unnest(@ids::bigint[],@rules::text[]) findings(id,rule_code)
                """, new() { ["ids"] = passwordRows.Keys.ToArray(),
                    ["rules"] = passwordRows.Values.Select(row => ProblemJson.Text(row["rule_code"])).ToArray() }, ct);
            foreach (var fact in passwordFacts.OfType<JsonObject>())
                passwordRows[ProblemJson.Long(fact["id"])]["presentation_facts"] = fact["facts"]?.DeepClone();
        }
        long[] aliasIds = query.QueueView is not null && !query.Compact
            ? passwordRows.Where(pair => pair.Value["queue_attack_aliases"] is null).Select(pair => pair.Key).ToArray() : [];
        if (aliasIds.Length > 0) {
            // Project the two bounded text values before sorting, without carrying the retained event JSON.
            var aliases = await Rows(tx, """
                select finding_id,
                    (array_agg(distinct account order by account) filter(where account is not null))[1:8] as accounts,
                    (array_agg(distinct address order by address) filter(where address is not null))[1:8] as addresses
                from (
                    select finding_id,
                        case when target_user_name not in ('','-') and event_id<>4624
                            then left(btrim(target_user_name),256) end as account,
                        case when ip_address not in ('','-','::','::1','0.0.0.0','127.0.0.1')
                            then left(btrim(ip_address),256) end as address
                    from finding_event_details337 where finding_id=any(@ids) and event_id in (4624,4625,4771,4776)
                    offset 0
                ) aliases group by finding_id
                """, new() { ["ids"] = aliasIds }, ct);
            foreach (var alias in aliases.OfType<JsonObject>()) passwordRows[ProblemJson.Long(alias["finding_id"])]["queue_attack_aliases"] = alias.DeepClone();
        }
        foreach (var row in rows.OfType<JsonObject>())
            if (row["review_hint"] is JsonObject hint)
                foreach (var (key, value) in ProblemPresentation.ClassifyAuditChange(hint)) hint[key] = value?.DeepClone();
        var heartbeat = await One(tx, "select status,phase,heartbeat_at,expected_interval_seconds,details_json from runtime_worker_heartbeats where worker_name='semantic' limit 1", null, ct) ?? new();
        var generated = clock.GetUtcNow(); var runtime = ProblemPresentation.Runtime(heartbeat, generated);
        var limitations = new JsonArray();
        // The refresh status is optional in the reference; use a savepoint so an
        // unavailable status table cannot invalidate mandatory population reads.
        await tx.SaveAsync("refresh_status", ct);
        try
        {
            var refresh = await One(tx, "select * from findings_refresh_state where pipeline_name='events_to_findings_v1'", null, ct);
            if (ProblemJson.Text(refresh?["last_status"]) == "failed") limitations.Add("последнее обновление Findings завершилось ошибкой: " + ProblemJson.Text(refresh?["last_error"]));
            await tx.ReleaseAsync("refresh_status", ct);
        }
        catch (PostgresException) { await tx.RollbackAsync("refresh_status", ct); limitations.Add("состояние инкрементального обновления Findings временно недоступно"); }
        string runtimeState = ProblemJson.Text(runtime["findings_state"]);
        if (runtimeState == "stale") limitations.Add("Нет свежего подтверждения работы проверки; проблемы показаны по сохранённым данным, а полнота текущего состояния не подтверждена.");
        else if (ProblemJson.Text(runtime["facts_state"]) == "active" && ProblemJson.Text(runtime["relations_state"]) == "active" && runtimeState == "inactive") limitations.Add("Факты и связи обрабатываются, но оценка риска и публикация новых проблем в этом режиме не включены.");
        else if (runtimeState is "inactive" or "unknown") limitations.Add("Работа проверки сейчас не подтверждена; отсутствие новых результатов нельзя считать отсутствием проблем.");
        foreach (var row in rows.OfType<JsonObject>()) {
            if (row["decoy_label"] is JsonObject label) { row["decoy_id"] = label["decoy_id"]?.DeepClone(); row["decoy_revision"] = label["decoy_revision"]?.DeepClone(); }
            row.Remove("decoy_label");
        }
        if (!query.Compact) {
            await AttachDetails(tx, rows, ct, query.QueueList);
            if (query.PageQueue) await AttachQueueNames(rows, (family, domains, token) => Sli.Server.Ad.AdV2Store.Snapshots(db, family, domains, token), ct);
            var detectionIds = rows.OfType<JsonObject>().Where(r => ProblemPresentation.CatalogDetection(ProblemJson.Text(r["rule_code"]))).Select(r => ProblemJson.Long(r["id"])).ToArray();
            if (detectionIds.Length > 0) AttachDetectionPresentation(rows.OfType<JsonObject>(), (await Rows(tx,
                DetectionPresentationSql, new() { ["ids"] = detectionIds }, ct)).OfType<JsonObject>());
            await AttachIdentities(tx, rows, ct);
            if (!query.QueueList) await AttachCases(tx, rows, access, ct);
        }
        await AttachKerberosFacts(tx, rows.OfType<JsonObject>().ToArray(), ct);
        await tx.CommitAsync(ct);
        var result = new JsonObject { ["generated_at_utc"] = ProblemJson.Iso(generated), ["status"] = "ok", ["source"] = "semantic_production_findings",
            ["state"] = runtimeState == "stale" ? "stale" : runtimeState is "inactive" or "unknown" ? "partial" : rows.Count > 0 ? "available" : "empty",
            ["items"] = rows, ["summary"] = summary, ["has_more"] = more, ["limits"] = new JsonObject { ["limit"] = query.Limit, ["details_per_finding"] = 20 },
            ["lifecycle"] = System.Text.Json.JsonSerializer.SerializeToNode(new { valid_statuses = FindingStatusInput.Statuses, allowed_transitions = FindingStatusInput.Transitions }),
            ["semantic_runtime"] = runtime, ["limitations"] = limitations };
        return result;
    }
    internal static async Task AttachDetails(NpgsqlTransaction tx, JsonArray rows, CancellationToken ct, bool queueList = false)
    {
        var ids = rows.OfType<JsonObject>().Where(r => !queueList || !ProblemPresentation.IsPasswordFinding(ProblemJson.Text(r["rule_code"])))
            .Select(r => ProblemJson.Long(r["id"])).ToArray();
        if (ids.Length == 0) return;
        var args = new Dictionary<string, object?> { ["ids"] = ids };
        var evidence = await Rows(tx, """
            select * from (select e.*,
                min(domain_id) over(partition by finding_id) as identity_domain_min,
                max(domain_id) over(partition by finding_id) as identity_domain_max,
                count(*) over(partition by finding_id) as identity_event_count,
                row_number() over(partition by finding_id order by time_created_utc desc,event_db_id desc) as rn
                from finding_event_details337 e where finding_id=any(@ids)) ranked
            where rn<=20 order by finding_id,time_created_utc desc,event_db_id desc
            """, args, ct);
        var entities = await Rows(tx, """
            with deduplicated as(select distinct finding_id,entity_type,display_name,entity_role from finding_entities where finding_id=any(@ids) and coalesce(display_name,'')<>''),
            ranked as(select *,row_number() over(partition by finding_id order by case entity_role when 'actor' then 1 when 'target' then 2 when 'source' then 3 else 4 end,display_name) as rn from deduplicated)
            select finding_id,entity_type,display_name,entity_role from ranked where rn<=25 order by finding_id,rn
            """, args, ct);
        var history = queueList ? new JsonArray() : await Rows(tx, """
            select id,finding_id,old_status,new_status,changed_at,changed_by,note from (
              select *,row_number() over(partition by finding_id order by changed_at desc,id desc) as rn from finding_status_history where finding_id=any(@ids)
            ) ranked where rn<=20 order by finding_id,changed_at desc,id desc
            """, args, ct);
        foreach (var row in rows.OfType<JsonObject>())
        {
            long id = ProblemJson.Long(row["id"]);
            foreach (var (key, source) in new[] { ("evidence", evidence), ("entities", entities), ("status_history", history) })
                row[key] = new JsonArray(source.OfType<JsonObject>().Where(r => ProblemJson.Long(r["finding_id"]) == id).Select(r => r.DeepClone()).ToArray());
            var observations = ProblemJson.Array(row["evidence"]).OfType<JsonObject>().ToArray();
            if (observations.Length > 0 && observations.Length == ProblemJson.Long(row["evidence_count"])) {
                string? Unique(Func<JsonObject, string> field) {
                    var values = observations.Select(field).Select(value => value.Trim()).Distinct().ToArray();
                    return values.Length == 1 && values[0] is not ("" or "-") ? values[0] : null;
                }
                string Account(JsonObject e, string name, string domain) => ProblemJson.Text(e[name]) is { Length: > 0 } user && user != "-"
                    ? ProblemJson.Text(e[domain]) is "" or "-" ? user : ProblemJson.Text(e[domain]) + "\\" + user : "";
                row["presentation_facts"] ??= new JsonObject {
                    ["account"] = Unique(e => Account(e, "target_user_name", "target_domain_name")),
                    ["actor"] = observations.All(e => ProblemJson.Text(e["channel"]) == "Security" &&
                        ProblemJson.Text(e["identity_provider"]) is "Microsoft-Windows-Security-Auditing" or "Microsoft-Windows-Eventlog")
                        ? Unique(e => Account(e, "subject_user_name", "subject_domain_name")) : null,
                    ["computer"] = Unique(e => ProblemJson.Text(e["hostname"])),
                    ["source"] = Unique(e => ProblemJson.Text(e["ip_address"])) };
            }
        }
    }

    internal static async Task AttachKerberosFacts(NpgsqlTransaction tx, IReadOnlyList<JsonObject> rows, CancellationToken ct)
    {
        // Aggregate the complete linked proof, independently of the 20-row detail preview.
        // The API login cannot read the worker's private QW signal documents.
        long Id(JsonObject row) => ProblemJson.Long(row["id"] ?? row["representative"]?["id"]);
        var kerberosIds = rows.Where(r => ProblemJson.Text(r["rule_code"]) is
            "semantic.qw.kerberoasting" or "semantic.qw.asrep-roasting").Select(Id).Where(id => id > 0).Distinct().ToArray();
        if (kerberosIds.Length > 0) {
            var kerberos = await Rows(tx, """
                with latest_client as (
                    select distinct on(finding_id) finding_id,ip_address from finding_event_details337
                    where finding_id=any(@ids) and event_id in(4768,4769)
                    order by finding_id,time_created_utc desc,event_db_id desc
                )
                select e.finding_id,jsonb_build_object(
                    'account',case when count(distinct (e.target_domain_name,e.target_user_name))=1
                        then min(case when nullif(e.target_user_name,'-') is not null
                            then concat_ws('\',nullif(e.target_domain_name,'-'),e.target_user_name) end) end,
                    'source',case when count(distinct e.ip_address)=1 then min(nullif(e.ip_address,'-')) end,
                    'count',count(distinct lower(btrim(e.service_name))) filter(where e.event_id=4769),
                    'minutes',greatest(1,ceil(extract(epoch from (max(e.time_created_utc)-min(e.time_created_utc)))/60)),
                    'time',to_char(max(e.time_created_utc) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')
                ) as presentation_facts
                from latest_client client join finding_event_details337 e on e.finding_id=client.finding_id
                    and e.ip_address is not distinct from client.ip_address
                where e.event_id in(4768,4769) group by e.finding_id
                """, new() { ["ids"] = kerberosIds }, ct);
            foreach (var row in rows) {
                var facts = kerberos.OfType<JsonObject>().FirstOrDefault(r => ProblemJson.Long(r["finding_id"]) == Id(row));
                if (facts is not null) row["presentation_facts"] = facts["presentation_facts"]?.DeepClone();
            }
        }
    }

}
