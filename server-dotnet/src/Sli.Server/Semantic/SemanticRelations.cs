using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Semantic;

public sealed class SemanticRelations(ISemanticDatabase database, TimeProvider? timeProvider = null, IConfiguration? configuration = null)
{
    internal static readonly string[] RuleIds = ["investigation.account.lockout.preceded-by-failures", "investigation.account.unlock.after-lock", "investigation.group.membership.removed-after-add", "investigation.account.created-then-group-add", "investigation.password.reset-then-logon"];
    internal static readonly string[] RequiredCapabilities = ["semantic.review", "evidence.exact", "field.security", "events.view"];
    internal const string Report = "security.events.chains";
    private static readonly HashSet<string> Fields = ["security", "technical", "raw_evidence"];
    private sealed record CursorState(DateTimeOffset Expires, string Binding, JsonArray Rules, DateTimeOffset Time, Guid Id);
    private static readonly Dictionary<string, CursorState> Cursors = new(); private static readonly object CursorLock = new();
    private static readonly Dictionary<string, int[]> Families = new()
    {
        ["account_lock"] = [4740, 4767], ["password_operation"] = [4723, 4724], ["account_lifecycle"] = [4720, 4722, 4725, 4726], ["account_change"] = [4738, 4781],
        ["group_membership"] = [4728, 4729, 4732, 4733, 4756, 4757], ["group_lifecycle"] = [4727, 4730, 4731, 4734, 4735, 4737, 4754, 4755, 4758, 4764],
        ["authentication"] = [4624, 4625, 4771, 4776], ["audit_configuration"] = [4719, 1102]
    };
    internal static readonly int[] EventIds = Families.Values.SelectMany(x => x).Distinct().Order().ToArray();
    private static bool Allowed(AccessDecision access, JsonArray evidence)
    {
        if (evidence.Count == 0 || evidence.Any(x => x.Number("server_id") <= 0 || x.Number("domain_id") <= 0 || string.IsNullOrWhiteSpace(x.Text("channel")))) return false;
        var groups = evidence.Select(x => (IReadOnlyList<AccessResource>)new AccessResource[] { new("server", x.Number("server_id")), new("domain", x.Number("domain_id")), new("channel", Value: x.Text("channel")) }).ToArray();
        return ResourceAccessDecisions.ReportAction(access, Report, "view", groups, Fields).Allowed && RequiredCapabilities.All(c => access.Capabilities.DecideForResourceGroups(c, groups).Allowed);
    }
    private static string ScopeState(JsonElement scope, long domain)
    {
        if (scope.ValueKind != JsonValueKind.Object || !scope.TryGetProperty("kind", out var kind)) return "deny";
        return kind.GetString() switch { "all" => "allow", "server" or "channel" => "potential", "domain" => scope.TryGetProperty("ids", out var ids) && ids.ValueKind == JsonValueKind.Array && ids.EnumerateArray().Any(x => x.TryGetInt64(out long id) && id == domain) ? "allow" : "deny", _ => "deny" };
    }
    internal static string Preflight(AccessDecision access, long domain)
    {
        var report = access.Reports.FirstOrDefault(x => x.ReportKey == Report && x.Allowed);
        var reports = report?.Grants.Where(x => x.AllowedActions.Contains("view") && Fields.IsSubsetOf(x.FieldCategories)).Select(x => ScopeState(x.Scope, domain)).ToArray() ?? [];
        if (!reports.Contains("allow") && !reports.Contains("potential")) return "deny";
        bool potential = !reports.Contains("allow");
        if (!access.Capabilities.IsOwner) foreach (string cap in RequiredCapabilities)
        {
            var policies = access.Capabilities.Policies.Where(x => x.CapabilityKey == cap).ToArray();
            if (policies.Any(x => !x.Valid && x.Effect == "deny")) return "deny";
            var denies = policies.Where(x => x.Valid && x.Effect == "deny").Select(x => ScopeState(x.Scope, domain)).ToArray();
            if (denies.Contains("allow")) return "deny";
            var allows = policies.Where(x => x.Valid && x.Effect == "allow").Select(x => ScopeState(x.Scope, domain)).ToArray();
            if (!access.Capabilities.Capabilities.Contains(cap) && !allows.Contains("allow")) { if (!allows.Contains("potential")) return "deny"; potential = true; }
            potential |= denies.Contains("potential");
        }
        return potential ? "potential" : "allow";
    }
    public async Task<JsonObject> ReadAsync(SemanticQuery q, AccessDecision access, CancellationToken ct)
    {
        const string code = "invalid_semantic_relation_filter";
        q.Only(code, "domain_id", "time_from", "time_to", "timezone", "limit", "cursor", "category", "event_id", "outcome", "actor", "target", "group", "source", "q", "event_db_id", "entity_id", "rule_version", "relation_kind");
        foreach (string key in new[] { "domain_id", "time_from", "time_to", "timezone" }) if (string.IsNullOrWhiteSpace(q.Get(key))) throw new SemanticInputException(code);
        long domain = SemanticQuery.Positive(q.Get("domain_id"), code); var (s, e) = q.Bounds(code); var start = s!.Value; var end = e!.Value;
        int limit = q.Integer("limit", 100, code); if (limit is < 1 or > 200 || end - start > TimeSpan.FromDays(31)) throw new SemanticInputException(code);
        var filters = new JsonObject();
        foreach (string key in new[] { "category", "outcome", "actor", "target", "group", "source", "q", "relation_kind" })
        {
            string? value = q.Get(key); if (string.IsNullOrEmpty(value)) continue;
            if (value.EnumerateRunes().Count() > (key == "relation_kind" ? 200 : 256)) throw new SemanticInputException(code);
            if (key is "category" or "outcome") value = value.ToLowerInvariant();
            if (key == "category" && !Families.ContainsKey(value) || key == "outcome" && value is not ("success" or "failure" or "unknown")) throw new SemanticInputException(code);
            filters[key switch { "target" => "target_account", "source" => "source_host", _ => key }] = value;
        }
        foreach (string key in new[] { "event_id", "event_db_id", "entity_id", "rule_version" }) if (q.Get(key) is { } raw) filters[key] = SemanticQuery.Positive(raw, code);
        if (filters["event_id"] is not null && (!EventIds.Contains((int)filters.Number("event_id")) || filters.Text("category") is { } family && !Families[family].Contains((int)filters.Number("event_id")))) throw new SemanticInputException(code);
        string binding = SemanticJson.Hash(new JsonArray(domain, SemanticJson.Stamp(start), SemanticJson.Stamp(end), filters.Copy()));
        CursorState? cursor = null;
        if (q.Get("cursor") is { } token)
        {
            lock (CursorLock) if (token.Length > 128 || !Cursors.TryGetValue(token, out cursor) || cursor.Expires <= (timeProvider ?? TimeProvider.System).GetUtcNow() || cursor.Binding != binding) throw new SemanticInputException("invalid_cursor");
        }
        string preflight = Preflight(access, domain);
        if (preflight == "deny") return Payload("not_authorized", domain, start, end, filters, new(), false, null, limit, null, false, null);
        JsonArray? rules = cursor?.Rules;
        if (rules is null)
        {
            // Optional coverage metadata has its own transaction: a failed inventory
            // query must not abort the repeatable-read relation snapshot below.
            try
            {
                await using var inventory = await database.OpenAsync(false, ct);
                rules = await inventory.QueryAsync("with current_supported as(select rule_id,rule_version,lifecycle_status,row_number() over(partition by rule_id order by rule_version desc) as version_rank from semantic_correlation_rules where rule_id=any($1) and lifecycle_status in('shadow','enabled')) select rule_id,rule_version,lifecycle_status from current_supported where version_rank=1 order by rule_id,rule_version", ct, (object)RuleIds);
            }
            catch (Exception error) when (error is not OperationCanceledException) { rules = null; }
        }
        ct.ThrowIfCancellationRequested();
        await using var postgres = await database.OpenAsync(false, ct);
        await using var session = await SemanticHistorySession.CreateAsync(postgres,configuration,ct);
        string? revision = rules is null ? null : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("sli.semantic-relations.rules.v1\0" + new JsonArray(rules.Select(x => (JsonNode)new JsonArray(x!["rule_id"].Copy(), x["rule_version"].Copy(), x["lifecycle_status"].Copy())).ToArray()).ToJsonString())));
        var authorized = new List<JsonObject>(); JsonObject? last = null; bool hasMore = false, limited = false;
        DateTimeOffset? before = cursor?.Time; Guid? beforeId = cursor?.Id;
        try
        {
            while (authorized.Count <= limit)
            {
                ct.ThrowIfCancellationRequested();
                var rows = await Candidates(session, domain, start, end, filters, rules, limit, before, beforeId, ct);
                var candidates = rows.GroupBy(x => x.Text("candidate_id")!).Select(group => new JsonObject { ["candidate_id"] = group.Key, ["window_end_utc"] = group.First()!["window_end_utc"].Copy(), ["evidence"] = SemanticJson.Array(group) }).ToArray();
                hasMore = candidates.Length > limit;
                foreach (var candidate in candidates.Take(limit)) { last = candidate; if (Allowed(access, candidate["evidence"]!.AsArray())) authorized.Add(candidate); }
                if (authorized.Count > limit || !hasMore || preflight == "allow") break;
                if (last is null) break; before = SigmaProjection.At(last, "window_end_utc"); beforeId = Guid.Parse(last.Text("candidate_id")!);
            }
            bool rawMore = authorized.Count > limit || preflight == "allow" && authorized.Count == limit && hasMore;
            limited = rawMore && rules is null;
            bool more = rules is not null && rawMore;
            var ids = authorized.Take(limit).Select(x => Guid.Parse(x.Text("candidate_id")!)).ToArray(); var items = new JsonArray();
            if (ids.Length > 0)
            {
                var hydrated = await session.QueryAsync("""
                    select candidate.candidate_id,candidate.rule_id,candidate.rule_version,candidate.relation_kind,candidate.partition_key,candidate.window_start_utc,candidate.window_end_utc,candidate.confidence,candidate.explanation,
                      evidence.evidence_order,core.id as event_db_id,core.event_id,core.time_created_utc,normalized.semantic_type,server.hostname as source_host,core.server_id,core.domain_id,channel.value as channel
                    from semantic_correlation_candidates candidate join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
                    join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id join semantic_event_rows core on core.id=normalized.source_event_id
                    join servers server on server.id=core.server_id join storage_v2_channel channel on channel.id=core.channel_id where candidate.candidate_id=any($1::uuid[])
                    order by candidate.window_end_utc desc,candidate.candidate_id desc,evidence.evidence_order
                    """, ct, ids);
                foreach (Guid id in ids)
                {
                    var group = hydrated.Where(x => x.Text("candidate_id") == id.ToString()).ToArray();
                    if (group.Length == 0 || !Allowed(access, SemanticJson.Array(group))) return Payload("empty", domain, start, end, filters, new(), false, null, limit, rules, limited, revision);
                    var item = new JsonObject(); foreach (string key in new[] { "candidate_id", "rule_id", "rule_version", "relation_kind", "window_start_utc", "window_end_utc", "confidence", "explanation" }) item[key] = group[0]![key].Copy();
                    var evidence = new JsonArray();
                    foreach (var row in group) { var atom = new JsonObject(); foreach (string key in new[] { "event_db_id", "event_id", "time_created_utc", "semantic_type", "source_host", "channel", "evidence_order" }) atom[key] = row![key].Copy(); evidence.Add(atom); }
                    item["evidence"] = evidence;
                    if (IdentityBasis(group[0].Text("partition_key")) is { } identity) item["identity_basis"] = identity;
                    if (item.Number("rule_version") >= 2 && RuleIds.Skip(1).Contains(item.Text("rule_id")))
                    {
                        var ordered = evidence.OrderBy(x => x.Number("evidence_order")).ToArray(); for (int i = 0; i < ordered.Length; i++) ordered[i]!["evidence_role"] = i == 0 ? "anchor" : "alternative_continuation";
                        item["evidence"] = SemanticJson.Array(ordered); item["continuation_state"] = ordered.Length == 2 ? "unique" : "ambiguous"; item["possible_continuation_count"] = Math.Max(0, ordered.Length - 1);
                    }
                    items.Add(item);
                }
            }
            string? next = null;
            if (more)
            {
                var anchor = authorized[Math.Min(limit, authorized.Count) - 1];
                next = "v2." + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                lock (CursorLock)
                {
                    foreach (var key in Cursors.Where(x => x.Value.Expires <= (timeProvider ?? TimeProvider.System).GetUtcNow()).Select(x => x.Key).ToArray()) Cursors.Remove(key);
                    while (Cursors.Count >= 4096) Cursors.Remove(Cursors.First().Key);
                    Cursors[next] = new((timeProvider ?? TimeProvider.System).GetUtcNow().AddHours(1), binding, (JsonArray)rules!.DeepClone(), SigmaProjection.At(anchor, "window_end_utc"), Guid.Parse(anchor.Text("candidate_id")!));
                }
            }
            return Payload(items.Count > 0 ? "available" : "empty", domain, start, end, filters, items, more, next, limit, rules, limited, revision);
        }
        catch (PostgresException error) when (error.SqlState == "42P01") { return Payload("schema_unavailable", domain, start, end, filters, new(), false, null, limit, null, false, revision); }
    }
    internal static JsonObject? IdentityBasis(string? partition)
    {
        if (partition is null) return null;
        var pieces = new Dictionary<string, string>(); foreach (string part in partition.Split('|')) { string[] pair = part.Split(':', 2); if (pair.Length != 2 || !pieces.TryAdd(pair[0], pair[1])) return null; }
        if (!pieces.TryGetValue("domain", out string? domain) || !long.TryParse(domain, out long id) || id < 1 || id.ToString() != domain) return null;
        string[] names = pieces.Keys.Where(x => x != "domain").Order().ToArray();
        string? kind = string.Join(",", names) switch { "account_sid" => "exact_domain_account_sid", "account_member_sid" => "exact_domain_account_member_sid", "group_sid,member_sid" => "exact_domain_member_group_sid", _ => null };
        if (kind is null || names.Any(x => pieces[x].Length > 184 || !Regex.IsMatch(pieces[x], @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z"))) return null;
        var result = new JsonObject { ["kind"] = kind, ["domain_id"] = id }; foreach (string name in names) result[name] = pieces[name]; return result;
    }
    private static JsonObject Payload(string state, long domain, DateTimeOffset start, DateTimeOffset end, JsonObject filters, JsonArray items, bool more, string? next, int limit, JsonArray? rules, bool limited, string? revision)
    {
        var observed = items.GroupBy(x => (x.Text("rule_id"), x.Number("rule_version"))).OrderBy(x => x.Key.Item1, StringComparer.Ordinal).ThenBy(x => x.Key.Item2).Select(x => (JsonNode)new JsonObject { ["rule_id"] = x.Key.Item1, ["rule_version"] = x.Key.Item2 }).ToArray();
        var limitations = new JsonArray("Покрытие относится только к разрешённой ограниченной странице сохранённых связей.", "Тестовый или пустой результат не доказывает наличие либо полноту retained-истории.");
        if (limited) limitations.Add("Продолжение страницы недоступно без подтверждённой версии правил; более поздние разрешённые связи могли не быть прочитаны.");
        var coverage = new JsonObject { ["state"] = state, ["matched_relation_count"] = state == "available" ? items.Count : null, ["matched_relation_state"] = state == "available" ? "bounded_page" : state, ["limitation_codes"] = new JsonArray("bounded_retained_page", "no_completeness_proof"), ["supported_rules"] = rules.Copy() ?? new JsonArray(), ["observed_rules"] = new JsonArray(observed), ["limitations"] = limitations };
        if (rules is not null) coverage["supported_rules_state"] = "available"; else if (state != "not_authorized") coverage["supported_rules_state"] = "check_unavailable";
        return new JsonObject { ["contract_id"] = "sli.semantic-relations.v1", ["state"] = state, ["domain_id"] = domain, ["time_bounds"] = new JsonObject { ["from_utc"] = SemanticJson.Stamp(start).Replace("+00:00", "Z", StringComparison.Ordinal), ["to_utc_exclusive"] = SemanticJson.Stamp(end).Replace("+00:00", "Z", StringComparison.Ordinal) }, ["filters"] = filters.Copy(), ["result_revision"] = revision, ["items"] = items, ["has_more"] = more, ["next_cursor"] = next, ["coverage"] = coverage, ["limits"] = new JsonObject { ["max_period_days"] = 31, ["row_limit"] = limit, ["max_row_limit"] = 200, ["bounded"] = true } };
    }
    private async Task<JsonArray> Candidates(ISemanticSession session, long domain, DateTimeOffset start, DateTimeOffset end, JsonObject filters, JsonArray? rules, int limit, DateTimeOffset? before, Guid? beforeId, CancellationToken ct)
    {
        var values = new List<object?>(); string P(object? value) { values.Add(value); return "$" + values.Count; }
        string d = P(domain), s = P(start), e = P(end);
        var clauses = new List<string> { "candidate.candidate_status='matched'", "candidate.window_start_utc<" + e, "candidate.window_end_utc>=" + s,
            $"exists(select 1 from semantic_correlation_candidate_evidence de join normalized_events dn on dn.normalized_event_id=de.normalized_event_id join semantic_event_rows ev on ev.id=dn.source_event_id where de.candidate_id=candidate.candidate_id and ev.domain_id={d})",
            $"not exists(select 1 from semantic_correlation_candidate_evidence fe left join normalized_events fn on fn.normalized_event_id=fe.normalized_event_id left join semantic_event_rows ev on ev.id=fn.source_event_id where fe.candidate_id=candidate.candidate_id and (ev.id is null or ev.domain_id<>{d}))" };
        if (rules is null) clauses.Add("not exists(select 1 from semantic_correlation_rules newer where newer.rule_id=candidate.rule_id and newer.rule_version>candidate.rule_version and newer.lifecycle_status in('shadow','enabled'))");
        else clauses.Add(rules.Count == 0 ? "false" : "(" + string.Join(" or ", rules.Select(r => "(candidate.rule_id=" + P(r.Text("rule_id")) + " and candidate.rule_version=" + P((int)r.Number("rule_version")) + ")")) + ")");
        int[] ids = filters["event_id"] is not null ? [(int)filters.Number("event_id")] : filters.Text("category") is { } category ? Families[category] : EventIds;
        string filter = SecurityPredicate(filters, P);
        clauses.Add($"""
            exists(select 1 from semantic_correlation_candidate_evidence se join normalized_events sn on sn.normalized_event_id=se.normalized_event_id
              join semantic_event_rows ev on ev.id=sn.source_event_id join servers srv on srv.id=ev.server_id join storage_v2_channel ch on ch.id=ev.channel_id
              join storage_v2_provider provider on provider.id=ev.provider_id left join storage_v2_keywords kw on kw.id=ev.keywords_id left join semantic_event_fields facts on facts.event_id=ev.id
              where se.candidate_id=candidate.candidate_id and ev.domain_id={d} and srv.role='domain_controller' and ev.event_id=any({P(ids)}) and ch.value='Security'
              and ((ev.event_id=1102 and provider.value='Microsoft-Windows-Eventlog') or(ev.event_id<>1102 and provider.value='Microsoft-Windows-Security-Auditing'))
              and ev.time_created_utc>={s} and ev.time_created_utc<{e} {filter})
            """);
        if (filters["rule_version"] is not null) clauses.Add("candidate.rule_version=" + P((int)filters.Number("rule_version")));
        if (filters.Text("relation_kind") is { } relation) clauses.Add("candidate.relation_kind=" + P(relation));
        if (before is not null) clauses.Add("(candidate.window_end_utc,candidate.candidate_id)<(" + P(before) + "," + P(beforeId) + ")");
        string limitSql = P(limit + 1);
        return await session.QueryAsync($"""
            with candidate_page as(select candidate.candidate_id,candidate.window_end_utc from semantic_correlation_candidates candidate where {string.Join(" and ", clauses)}
              order by candidate.window_end_utc desc,candidate.candidate_id desc limit {limitSql})
            select candidate.candidate_id,candidate.window_end_utc,normalized.source_event_id as event_db_id,event.server_id,event.domain_id,channel.value as channel
            from candidate_page candidate join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
            join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id join semantic_event_rows event on event.id=normalized.source_event_id
            join storage_v2_channel channel on channel.id=event.channel_id order by candidate.window_end_utc desc,candidate.candidate_id desc,evidence.evidence_order
            """, ct, values.ToArray());
    }
    private string SecurityPredicate(JsonObject f, Func<object?, string> p)
    {
        string target = "coalesce(nullif(btrim(ev.target_user_sid),''),nullif(btrim(facts.account_target_sid),''))", name = "coalesce(nullif(btrim(ev.target_user_name),''),nullif(btrim(facts.account_target_name),''))";
        var clauses = new List<string>(); int[] groups = [.. Families["group_membership"], .. Families["group_lifecycle"]];
        void Identity(string key, string sid, string label) { if (f.Text(key) is { } value) { string param = p(value); clauses.Add("(lower(coalesce(" + sid + ",''))=lower(" + param + ") or lower(coalesce(" + label + ",''))=lower(" + param + "))"); } }
        Identity("actor", "ev.subject_user_sid", "ev.subject_user_name"); Identity("target_account", target, name); Identity("group", target, name);
        if (f["target_account"] is not null) clauses.Add("not ev.event_id=any(" + p(groups) + ")");
        if (f["group"] is not null) clauses.Add("ev.event_id=any(" + p(groups) + ")");
        if (f.Text("source_host") is { } host) clauses.Add("lower(srv.hostname)=lower(" + p(host) + ")");
        if (f.Text("q") is { } text) clauses.Add("concat_ws(' ',ev.subject_user_sid,ev.subject_user_name," + target + "," + name + ",facts.membership_member_sid,facts.membership_member_name,srv.hostname) ilike " + p("%" + text.Replace("%", "\\%").Replace("_", "\\_") + "%"));
        if (f["event_db_id"] is not null) clauses.Add("ev.id=" + p(f.Number("event_db_id")));
        if (f["entity_id"] is not null)
        {
            string entity = p(f.Number("entity_id"))+"::integer";
            clauses.Add(EntityShortSql.MatchesStored(entity,p(EventReadService.ShortBoundary(configuration)),"ev"));
        }
        string[] success = ["auditsuccess", "audit success", "9007199254740992", "0x20000000000000", "0x8020000000000000", "-9214364837600034816"], failure = ["auditfailure", "audit failure", "4503599627370496", "0x10000000000000", "0x8010000000000000", "-9218868437227405312"];
        if (f.Text("outcome") is { } outcome)
        {
            string mixed = "ev.event_id in(4723,4724,4776)", keyword = "lower(coalesce(kw.value,''))", compact = "replace(" + keyword + ",' ','')";
            clauses.Add(outcome == "unknown" ? $"(ev.event_id not in(4624,4625,4771,4723,4724,4776) or({mixed} and {keyword}<>all({p(success.Concat(failure).ToArray())}) and {compact} not like '%auditsuccess%' and {compact} not like '%auditfailure%'))" :
                "(" + (outcome == "success" ? "ev.event_id=4624" : "ev.event_id in(4625,4771)") + $" or({mixed} and({keyword}=any({p(outcome == "success" ? success : failure)}) or {compact} like '%audit{outcome}%')))" );
        }
        return clauses.Count == 0 ? "" : "and " + string.Join(" and ", clauses);
    }
}
