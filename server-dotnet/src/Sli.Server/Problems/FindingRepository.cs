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
        var (updated, changed) = await ApplyStatus(tx, current, input, actor, ct);
        updated["status_history"] = await Rows(tx, "select id,finding_id,old_status,new_status,changed_at,changed_by,note from finding_status_history where finding_id=@id order by id desc limit 50", args, ct);
        await tx.CommitAsync(ct);
        return new() { ["status"] = "ok", ["backend"] = "postgres", ["changed"] = changed, ["finding"] = updated };
    }
    private async Task<(JsonObject Updated, bool Changed)> ApplyStatus(NpgsqlTransaction tx, JsonObject current, FindingStatusInput input, string actor, CancellationToken ct)
    {
        var args = new Dictionary<string, object?> { ["id"] = ProblemJson.Long(current["id"]) };
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
        return (updated, change.Changed);
    }
    public async Task<JsonObject> BulkStatusAsync(long[] ids, FindingStatusInput input, string actor, ProblemAccess access, CancellationToken ct)
    {
        var domains = access.Scope("security.queue").Domains();
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await DirectRuntimeAuthorization.LoadAsync(db, tx, clock.GetUtcNow().UtcDateTime, ct);
        var args = new Dictionary<string, object?> { ["ids"] = ids, ["domains"] = domains };
        var locked = await Rows(tx, "select * from findings where id=any(@ids) order by id for update", args, ct);
        var admitted = await Rows(tx, $"""
            select findings.id {Population} where findings.id=any(@ids)
              and is_semantic_finding_published_v1(findings.id) and not ({Accepted}) and not ({Suppressed})
              and (@domains::bigint[] is null and findings.rule_code<>'semantic.qw.file-acl-broad-write'
                   or semantic_finding_in_domains_v265(findings.id,@domains::bigint[]))
            """, args, ct);
        if (locked.Count != ids.Length || admitted.Count != ids.Length) throw new ProblemException("not_found", 404);
        int changed = 0;
        foreach (var row in locked.OfType<JsonObject>())
        {
            string status = ProblemJson.Text(row["status"]);
            if (status == input.Status) continue;
            if ((status is "closed" or "false_positive") != (input.Status == "active"))
                throw new ProblemException("invalid_transition", 409);
            await ApplyStatus(tx, row, input, actor, ct);
            changed++;
        }
        await tx.CommitAsync(ct);
        return new() { ["status"] = "ok", ["changed"] = changed };
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
    private const string SeverityOrder = "case findings.severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end";
    private const string EventTime = "coalesce(findings.last_seen_utc,findings.updated_at::text)::timestamptz";
    // Most rules have no active exception. Only classify event witnesses when
    // a rule can actually suppress this finding; the authoritative check still
    // decides domain/subject coverage for every matching exception.
    internal const string Suppressed = """
        case when exists(select 1 from semantic_suppressions active_rule
            where active_rule.kind='suppression' and active_rule.state='active'
              and active_rule.expires_at>statement_timestamp() and active_rule.semantic_type=findings.rule_code)
        then semantic_finding_suppressed_v160(findings.id,findings.rule_code) else false end
        """;
    internal const string Population = """
        from findings_active findings left join lateral (
            select s.*,u.username as responsible_username from semantic_suppressions s join auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance' order by s.id desc limit 1
        ) risk on true
        """;
    // Keep the Home caller signature without selecting a retired event source.
    internal static (string Page, string Summary, Dictionary<string, object?> Arguments) FindingsQueries(FindingQuery query, bool populationOnly = false, bool shortEvents = true)
    {
        var args = new Dictionary<string, object?>();
        var admission = new List<string> { "is_semantic_finding_published_v1(findings.id)", "(findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))" };
        var clauses = new List<string>();
        if (query.Risk == "accepted") clauses.Add(Accepted); else if (query.Risk != "all") clauses.Add("not " + Accepted);
        if (!query.Suppressed && query.Risk != "accepted") admission.Add("not (" + Suppressed + ")");
        if (query.Domains is not null) { args["domains"] = query.Domains; admission.Add("semantic_finding_in_domains_v265(findings.id,@domains::bigint[])"); }
        if (query.EntityId is not null) { args["entity"] = query.EntityId; clauses.Add("exists(select 1 from finding_entities linked where linked.finding_id=findings.id and linked.entity_id=@entity)"); }
        if (!string.IsNullOrEmpty(query.Status)) {
            if (query.PageQueue && query.Status == "new") clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated')");
            else if (query.PageQueue && query.Status == "active") clauses.Add($"({EffectiveStatus}) in ('active','review')");
            else { args["status"] = query.Status; clauses.Add($"({EffectiveStatus})=@status"); }
        }
        if (!string.IsNullOrEmpty(query.Severity)) {
            args["severity"] = query.Severity;
            clauses.Add(query.WorkplaceTab is not null && query.Severity == "high" ? "findings.severity in ('critical','high')" : "findings.severity=@severity");
        }
        if (!string.IsNullOrEmpty(query.From)) { args["from"] = query.From; clauses.Add("findings.last_seen_utc::timestamptz>=@from::timestamptz"); }
        if (!string.IsNullOrEmpty(query.To)) { args["to"] = query.To; clauses.Add("findings.last_seen_utc::timestamptz<@to::timestamptz"); }
        if (!string.IsNullOrEmpty(query.Search)) {
            if (query.WorkplaceTab is null) {
                args["q"] = "%" + query.Search + "%";
                clauses.Add("(lower(coalesce(findings.title,'')) like lower(@q) or lower(coalesce(findings.actor,'')) like lower(@q) or lower(coalesce(findings.target,'')) like lower(@q) or lower(coalesce(findings.summary,'')) like lower(@q))");
            } else {
                args["q"] = query.Search;
                string source = query.SearchTechnical ? ",nullif(findings.source,'semantic-production')" : "";
                string hosts = query.SearchTechnical ? ",e.ip_address,e.workstation_name,e.hostname" : "";
                clauses.Add($"""
                    (strpos(lower(concat_ws(' ',findings.actor,findings.target{source})),lower(@q))>0
                     or exists(select 1 from finding_entities linked where linked.finding_id=findings.id and strpos(lower(linked.display_name),lower(@q))>0)
                     or exists(select 1 from finding_event_details337 e where e.finding_id=findings.id
                         and strpos(lower(concat_ws(' ',concat_ws('\',e.target_domain_name,e.target_user_name),
                             concat_ws('\',e.subject_domain_name,e.subject_user_name){hosts})),lower(@q))>0))
                    """);
            }
        }
        if (query.FindingId is {} finding) { args["finding"] = finding; clauses.Add("findings.id=@finding"); }
        if (query.RuleCode is {} rule) { args["rule"] = rule; clauses.Add("findings.rule_code=@rule"); }
        if (query.CreatedFrom is {} createdFrom) { args["created_from"] = createdFrom; clauses.Add("findings.created_at>=@created_from::timestamptz"); }
        if (query.CreatedTo is {} createdTo) { args["created_to"] = createdTo; clauses.Add("findings.created_at<@created_to::timestamptz"); }
        if (query.Population == "attention") clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated')");
        if (query.Population == "open" && string.IsNullOrEmpty(query.Status) && string.IsNullOrEmpty(query.Risk))
            clauses.Add($"({EffectiveStatus}) in ('new','confirmed','repeated','active','review') and not ({Accepted})");
        // In the queue, apply status and risk filters before classifying event
        // witnesses. In particular, closed findings should not incur suppression
        // and domain checks just because an exception is active for their rule.
        string where = query.QueueList && clauses.Count > 0
            ? $" where case when {string.Join(" and ", clauses)} then {string.Join(" and ", admission)} else false end"
            : " where " + string.Join(" and ", admission.Concat(clauses));
        args["limit"] = query.Limit + 1;
        string population = Population, prefix = "", groupFields = "", summaryPopulation = population, summaryWhere = where;
        if (!query.GroupQueue && query.Cohort is {} cohort) {
            var key = ProblemCohorts.Parse(cohort);
            if (key[0]!.ToString() == "finding") { args["cohort_id"] = key[1]!.GetValue<long>(); where += " and findings.id=@cohort_id"; }
            else { args["cohort_zone"] = query.Timezone; args["cohort"] = key.ToJsonString(); population += ProblemCohorts.Sql(key[0]!.ToString() == "queue" ? "legacy-queue-cohort" : key[0]!.ToString() is "rule-object" or "rule-source" or "rule-entity" ? "queue-cohort" : "cohort"); where += " and cohort.key=@cohort::jsonb"; }
            summaryPopulation = population; summaryWhere = where;
        }
        if (query.WorkplaceTab is not null) {
            prefix = $"with workplace_findings as materialized (select findings.id,findings.severity,({EffectiveStatus}) as status {population}{where})";
            population = Population + " join workplace_findings workplace on workplace.id=findings.id";
            where = query.WorkplaceTab switch {
                "open" => " where workplace.status in ('new','confirmed','repeated','active','review')",
                "closed" => " where workplace.status in ('closed','false_positive')",
                _ => " where true"
            };
        }
        else if (query.GroupQueue) {
            args["cohort_zone"] = query.Timezone;
            // findings_active is a security-barrier view. Rejoining it for
            // every representative can rescan the full view per group. Keep
            // its admission boundary, but evaluate it once for this statement.
            population = population.Replace("from findings_active findings", "from queue_findings findings", StringComparison.Ordinal);
            prefix = "with queue_findings as materialized (select * from findings_active)," +
                ProblemCohorts.Queue(population, where, EffectiveStatus, Accepted)[5..];
            population += " join queue_groups on queue_groups.id=findings.id";
            where = " where true"; summaryPopulation = "from queue_groups"; summaryWhere = "";
            groupFields = ",queue_groups.problem_cohort,queue_groups.occurrence_count,queue_groups.queue_cursor_id,queue_groups.first_seen_utc::text as first_seen_utc,queue_groups.last_seen_utc::text as last_seen_utc";
        }
        if (populationOnly) return (prefix, "", args);
        string pageWhere = where;
        if (query.BeforeId is {} before) {
            args["before"] = before;
            pageWhere += query.GroupQueue ? " and queue_groups.queue_cursor_id<@before" : " and findings.id<@before";
        }
        if (query.WorkplacePosition is {} position) {
            args["position_rank"] = position.Severity; args["position_time"] = position.LastSeen; args["position_id"] = position.Id;
            pageWhere += $" and (({SeverityOrder})>@position_rank or (({SeverityOrder})=@position_rank and ({EventTime},findings.id)<(@position_time,@position_id)))";
        }
        string order = query.WorkplaceTab is not null ? "" : query.GroupQueue ? "queue_groups.queue_cursor_id desc," : query.PageQueue ? "findings.id desc," : $"case ({EffectiveStatus}) when 'new' then 1 when 'repeated' then 2 when 'confirmed' then 3 when 'active' then 4 when 'review' then 5 when 'false_positive' then 6 when 'closed' then 7 else 8 end,";
        string riskAudit = query.QueueList ? "null::jsonb" : """
            (select coalesce(jsonb_agg(to_jsonb(a) order by a.id desc),'[]'::jsonb) from (
                select id,action,actor,occurred_at,details from semantic_control_audit where details->'rule'->>'kind'='risk_acceptance'
                and details->'rule'->>'finding_id'=findings.id::text order by id desc limit 50) a)
            """;
        const string review = "semantic_finding_review_v160(findings.id)";
        string reviewHint = query.QueueList
            ? $"case when findings.rule_code not in ('semantic.qw.password-brute-force','semantic.qw.password-spray') then {review} end"
            : review;
        string page = $"""
            {prefix}
            select findings.*,({EffectiveStatus}) as status{groupFields},
              case when risk.id is not null then to_jsonb(risk)||jsonb_build_object('state',case when risk.state='active' and risk.expires_at<=statement_timestamp() then 'expired' else risk.state end) else null end as risk_acceptance,
              {riskAudit} as risk_audit,
              {reviewHint} as review_hint,
              ({Suppressed}) as suppressed,
              case when findings.rule_code in ('semantic.qw.account-decoy','semantic.qw.file-decoy') then public.finding_decoy_context(findings.id) end as decoy_label
            {population}{pageWhere}
            order by {order}
              {SeverityOrder},{EventTime} desc,findings.id desc limit @limit
            """;
        string summary = query.WorkplaceTab is not null ? $"{prefix} select severity,status,count(*) as count from workplace_findings group by severity,status" :
            query.GroupQueue ? $"{prefix} select severity,status,risk_accepted,count(*) as count,sum(occurrence_count) as occurrences from queue_groups group by severity,status,risk_accepted" :
            $"select findings.severity,({EffectiveStatus}) as status,({Accepted}) as risk_accepted,count(*) as count {summaryPopulation}{summaryWhere} group by findings.severity,({EffectiveStatus}),({Accepted})";
        return (page, summary, args);
    }
    public async Task<JsonObject> FindingsAsync(FindingQuery query, ProblemAccess access, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        if (query.PageQueue) await Execute(tx, "set transaction read only; set local jit=off", new(), ct);
        var (page, summarySql, args) = FindingsQueries(query);
        // Validate the persisted authorization before reading the population.
        await DirectRuntimeAuthorization.LoadAsync(db, tx, clock.GetUtcNow().UtcDateTime, ct);
        JsonArray rows, summary;
        if (query.GroupQueue || query.WorkplaceTab is not null) {
            // Page and counters share the same classified population and
            // statement snapshot. Do not evaluate every finding twice.
            string prefix = FindingsQueries(query, populationOnly: true).Page;
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
        var passwordRows = rows.OfType<JsonObject>().Where(row => ProblemPresentation.IsPasswordFinding(ProblemJson.Text(row["rule_code"])))
            .ToDictionary(row => ProblemJson.Long(row["id"]));
        if (passwordRows.Count > 0 && (!query.Compact || query.GroupQueue)) {
            var passwordFacts = await Rows(tx, $"""
                select findings.id,{ProblemCohorts.PasswordFacts("findings", workplace: query.WorkplaceTab is not null, breakdown: query.FindingId is not null)} as facts
                from unnest(@ids::bigint[],@rules::text[]) findings(id,rule_code)
                """, new() { ["ids"] = passwordRows.Keys.ToArray(),
                    ["rules"] = passwordRows.Values.Select(row => ProblemJson.Text(row["rule_code"])).ToArray() }, ct);
            foreach (var fact in passwordFacts.OfType<JsonObject>())
                passwordRows[ProblemJson.Long(fact["id"])]["presentation_facts"] = fact["facts"]?.DeepClone();
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
              select *,row_number() over(partition by finding_id order by id desc) as rn from finding_status_history where finding_id=any(@ids)
            ) ranked where rn<=20 order by finding_id,id desc
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
