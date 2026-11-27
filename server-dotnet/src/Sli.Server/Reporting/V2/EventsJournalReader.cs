using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Ad;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Entities;
using Sli.Server.Problems;

namespace Sli.Server.Reporting.V2;

public sealed class EventsJournalReader(ReportRunner runner, IAccessFactsRepository facts, ISemanticDatabase database, BuiltinReportExports exports) : IReportV2Reader
{
    private static readonly HashSet<int> DomainChangeCodes = AdSecurity.ChangeEventIds().ToHashSet();

    public string OwnerId => "sli.core";
    public bool Handles(string key) => key == "events.journal";
    public Task<ReportExport> ExportAsync(ReportQueryContext c, CancellationToken ct) => exports.ExportAsync(c, ct);
    public async Task<JsonObject> QueryAsync(ReportQueryContext c, CancellationToken ct)
    {
        var subject = await facts.LoadAsync(c.Principal, ct);
        var projection = JsonSerializer.SerializeToNode(AccessReadProjection.Compose(c.Principal, subject, c.Access.Capabilities, c.Access, false))!.AsObject();
        var filters = new Dictionary<string, string> { ["time_from"] = c.Params["period"]!["from_utc"]!.ToString(), ["time_to"] = c.Params["period"]!["to_utc"]!.ToString() };
        foreach (string key in new[] { "view", "q", "server" }) if (c.Params[key]?.ToString() is { Length: > 0 } value && (key != "view" || value != "all")) filters[key] = value;
        if (!string.IsNullOrEmpty(c.Paging.Cursor)) filters["cursor"] = c.Paging.Cursor;
        JsonObject raw;
        var journal = Options(c);
        try { raw = await runner.ExecuteAsync(new(c.Principal, subject, c.Access.Capabilities, projection), "events.explorer", Math.Min(c.Paging.Limit, 200), null, "view", filters, ct, journal); }
        catch (ReportException e) { throw new ReportRequestException(e.Message, e.Status); }
        var rows = raw.Objects("items");
        // Dependencies belong to one projected row, never a union of grant branches.
        var identities = rows.Select(Identity).Where(i => i.HasValue).Select(i => i!.Value).ToHashSet();
        var titles = new Dictionary<(string Key, long EventId, string Channel), JsonObject>();
        var exactAccess = new HashSet<long>();
        var evidence = new Dictionary<JsonObject, HashSet<long>>(ReferenceEqualityComparer.Instance);
        var exactScopes = new Dictionary<(long Domain, long Server, string Channel), bool>();
        bool CanReadExact(long domain, long server, string channel)
        {
            if (domain <= 0 || server <= 0) return false;
            var scope = (domain, server, channel);
            if (exactScopes.TryGetValue(scope, out bool allowed)) return allowed;
            IReadOnlyList<IReadOnlyList<AccessResource>> resources = [[new("server", server), new("domain", domain), new("channel", Value: channel)]];
            allowed = ResourceAccessDecisions.ReportAction(c.Access, "events.explorer", "view", resources, new HashSet<string> { "security", "technical", "raw_evidence" }).Allowed
                && new[] { "field.security", "field.technical", "field.raw_evidence", "evidence.exact" }.All(cap => ResourceAccessDecisions.Capability(c.Access.Capabilities, cap, resources).Allowed);
            exactScopes.Add(scope, allowed);
            return allowed;
        }
        void AdmitTitle(JsonObject source)
        {
            if (Identity(source) is not {} identity || !identities.Contains(identity)
                || !Integer(source["domain_id"], out long domain) || !Integer(source["server_id"], out long server)
                || !CanReadExact(domain, server, identity.Channel)) return;
            if (Integer(source["id"], out long eventId)) exactAccess.Add(eventId);
            string provider = source["provider_name"]?.ToString().Trim() ?? "";
            if (provider.Length == 0) return;
            var lookup = source.Copy(); lookup["provider_name"] = provider; lookup["channel"] = identity.Channel.Trim();
            if (EventListProjection.ExactTitleEntry(lookup) is not {} entry) return;
            string code = $"events.semantic.{entry["channel"]}:{entry["provider_name"]}:{identity.EventId}.title";
            string english = ReportResult.Message(code, true).Text("text");
            if (english == code) english = ReportResult.Message("events.unknown_type", true).Text("text");
            string russian = identity.EventId is 4688 or 6416 ? ReportResult.Message(code, false).Text("text") : code;
            if (russian == code) russian = entry["title"]!.GetValue<string>();
            var title = ReportResult.Message("events.catalog_title");
            title["params"] = new JsonObject { ["ru"] = russian, ["en"] = english };
            title["text"] = russian;
            titles[identity] = title;
        }

        if (journal is not null)
        {
            foreach (var row in rows)
            {
                var members = row["_journal_members"] as JsonArray;
                row.Remove("_journal_members");
                if (row["_journal_origin"] is not JsonObject origin) continue;
                row.Remove("_journal_origin");
                foreach (string field in new[] { "id", "event_id", "day", "summary_key", "channel" })
                    origin[field] = row[field]?.DeepClone();
                AdmitTitle(origin);
                if (Identity(origin) is not {} identity || !Integer(row["id"], out long id)
                    || !Integer(origin["domain_id"], out long domain) || !Integer(origin["server_id"], out long server)) continue;
                var ids = new HashSet<long>();
                if (CanReadExact(domain, server, identity.Channel))
                {
                    ids.Add(id);
                    if (DomainChangeDomain(c.Access, origin) is { } changeDomain) row["journal_change_domain"] = changeDomain;
                }
                else row.Remove("journal_action");
                if (members is not null)
                    foreach (var member in members.OfType<JsonArray>())
                        if (member.Count == 2 && Integer(member[0], out long memberId) && memberId > 0
                            && Integer(member[1], out long memberServer) && CanReadExact(domain, memberServer, identity.Channel))
                            ids.Add(memberId);
                if (ids.Count > 0) evidence.Add(row, ids);
            }
        }
        else if (identities.Count > 0)
        {
            long[] ids = identities.Where(i => !i.Key.Contains(':')).Select(i => long.Parse(i.Key,CultureInfo.InvariantCulture)).Distinct().Order().ToArray();
            string[] groups = identities.Where(i => i.Key.Contains(':')).Select(i => i.Key).ToArray();
            try
            {
                await using var db = await database.OpenAsync(false, ct);
                var sources = await db.QueryAsync("with short_events as ("+EntityShortSql.Source("$3")+") select e.id,e.event_id,e.server_id,e.domain_id,e.channel,e.provider_name,e.day,e.summary_key "+EventReadService.ShortJoins+" where s.id is not null and (e.id=any($1) or (e.day::text || ':' || e.summary_key)=any($4)) limit $2", ct, ids, identities.Count, runner.ShortRetentionBoundary, groups);
                foreach (var source in sources.OfType<JsonObject>()) AdmitTitle(source);
            }
            catch (Npgsql.PostgresException e) when (e.SqlState == "57014") { }
            catch (TimeoutException) { }
        }
        foreach (var row in rows)
        {
            string? Clean(string key) => row[key]?.ToString().Trim() is { Length: > 0 } s && s is not ("-" or "—") ? s : null;
            string? target = Clean("target_user_name"), actor = Clean("subject_user_name");
            if(target is null && actor is null)
                actor=Clean("actor")??Clean("target");
            var title = Identity(row) is {} identity && titles.TryGetValue(identity, out var admitted) ? admitted.Copy() : ReportResult.Message("events.unknown_type");
            row["title_text"] = title["text"]!.DeepClone(); row["participant"] = target ?? actor ?? ReportResult.Message("events.participant_unknown").Text("text");
            row["on_behalf"] = actor is not null && actor != (target ?? actor) ? actor : null;
            row["presentation_messages"] = new JsonObject { ["title_text"] = title };
            if (target is null && actor is null) row["presentation_messages"]!["participant"] = ReportResult.Message("events.participant_unknown");
            if (c.WorkstationServerId is not null)
                row["journal_evidence_available"] = row["journal_expandable"]?.GetValue<bool>() != true
                    && Integer(row["id"], out long eventId) && exactAccess.Contains(eventId);
        }
        if (evidence.Count > 0) await LinkProblemsAsync(c, evidence, ct);
        return Render(c, raw, rows);
    }
    internal static JournalOptions? Options(ReportQueryContext c)
    {
        long? Id(string key) => c.Params[key] is null ? null : long.TryParse(c.Params[key]!.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out long id) && id > 0
            ? id : throw new ReportRequestException("report_parameter_invalid:" + key);
        long? expand = Id("expand"), before = Id("before");
        if (c.Action == "export" && (expand.HasValue || before.HasValue)) throw new ReportRequestException("report_parameter_invalid:expand");
        string view = c.Params.Text("view", "all"), result = c.Params.Text("result"), pivot = c.Params.Text("pivot");
        if (expand.HasValue && before.HasValue) throw new ReportRequestException("report_parameter_invalid:before");
        string? source = c.Params["source_instance_id"]?.GetValue<string>();
        if (source is not null && (!Guid.TryParseExact(source, "D", out var sourceId) || sourceId == Guid.Empty))
            throw new ReportRequestException("report_parameter_invalid:source_instance_id");
        if (source is not null) source = Guid.Parse(source).ToString("D");
        string? plugin = c.Params["source_plugin"]?.GetValue<string>();
        if (plugin is not null && (plugin != "sli.workstations" || source is null))
            throw new ReportRequestException("report_parameter_invalid:source_plugin");
        return source is not null || c.WorkstationServerId.HasValue || c.Params["collapse"] is not null || expand.HasValue || before.HasValue || result.Length > 0 ||
            pivot.Length > 0 || view is "groups" or "audit" or "failures" or "service"
            ? new(c.Action == "view" && c.Params.Text("collapse") != "off", expand, before, view, result, pivot, Id("domain"))
                {
                    ServerId = c.WorkstationServerId, SourceInstanceId = source, SourcePlugin = plugin,
                    PageOnly = c.Action == "view" && c.WorkstationServerId is null && source is null && before is null,
                } : null;
    }

    private async Task LinkProblemsAsync(ReportQueryContext c, Dictionary<JsonObject, HashSet<long>> evidence, CancellationToken ct)
    {
        long[]? domains;
        try { domains = new ProblemAccess(c.Access).Scope("security.queue").Domains(); }
        catch (ProblemException) { return; }

        long[] ids = evidence.Values.SelectMany(group => group).Distinct().ToArray();
        await using var db = await database.OpenAsync(false, ct);
        var links = await db.QueryAsync(ProblemLinksSql, ct, ids, domains);
        var byId = links.OfType<JsonObject>().Where(link => Integer(link["event_db_id"], out _) && Integer(link["finding_id"], out _))
            .ToDictionary(link => link["event_db_id"]!.GetValue<long>(), link => (Id: link["finding_id"]!.GetValue<long>(), Priority: link["priority"]!.GetValue<int>()));
        foreach (var (row, group) in evidence)
        {
            var link = group.Where(byId.ContainsKey).Select(id => byId[id])
                .DefaultIfEmpty().MinBy(link => (link.Priority, -link.Id));
            if (link.Id > 0) row["journal_finding_id"] = link.Id;
        }
    }

    internal static readonly string ProblemLinksSql = $"""
            select distinct on (linked.event_db_id) linked.event_db_id,findings.id as finding_id,
                   case findings.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end as priority
            from (select distinct event_db_id,finding_id from finding_event_details337 where event_db_id=any($1)) linked
            join findings_active findings on findings.id=linked.finding_id
            where is_semantic_finding_published_v1(findings.id)
              and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))
              and ($2::bigint[] is null or semantic_finding_in_domains_v265(findings.id,$2::bigint[]))
              and not ({ProblemRepository.Suppressed})
              and not exists(select 1 from semantic_suppressions risk where risk.finding_id=findings.id
                  and risk.kind='risk_acceptance' and risk.state='active' and risk.expires_at>statement_timestamp())
            order by linked.event_db_id,priority,findings.id desc
            """;

    internal static long? DomainChangeDomain(AccessDecision access, JsonObject origin) =>
        origin.Text("server_role") == "domain_controller" && origin.Text("channel") == "Security" &&
        Integer(origin["event_id"], out long code) && code is > 0 and <= int.MaxValue && DomainChangeCodes.Contains((int)code) &&
        origin.Text("provider_name") == (code == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing") &&
        Integer(origin["domain_id"], out long domain) && domain > 0 && AdReportEndpoints.Allowed(access, "security", domain) ? domain : null;
    internal static JsonObject Render(ReportQueryContext c, JsonObject raw, JsonObject[] rows)
    {
        string state = ReportResult.SourceState(raw.Text("state")); if (state == "ok" && rows.Length == 0) state = "empty";
        var result = ReportResult.Create(c.Definition.Key, state, new JsonArray(rows.Select(r => (JsonNode?)r.DeepClone()).ToArray()), raw["coverage"] as JsonObject,
            limitations: new JsonArray(new JsonObject { ["code"] = "no_risk_in_slice", ["text"] = "Оценка риска не входит в этот срез. Название показывается только при точном совпадении источника и разрешённом доступе к доказательству; неизвестный участник не восстанавливается." }));
        result["has_more"] = raw["has_more"]?.DeepClone() ?? JsonValue.Create(false); result["next_cursor"] = raw["next_cursor"]?.DeepClone();
        foreach (string field in new[] { "filtered_count", "journal_event_count", "journal_counts", "journal_varying_columns" })
            if (raw[field] is { } value) result[field] = value.DeepClone();
        result["window"] = new JsonObject { ["from_utc"] = c.Params["period"]!["from_utc"]!.DeepClone(), ["to_utc_exclusive"] = c.Params["period"]!["to_utc"]!.DeepClone() };
        return result;
    }
    static bool Integer(JsonNode? node, out long value)
    {
        value = 0;
        return node is JsonValue && node.GetValueKind() == JsonValueKind.Number
            && long.TryParse(node.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }
    static (string Key, long EventId, string Channel)? Identity(JsonObject row) =>
        Integer(row["event_id"], out long eventId)
        && row["channel"] is JsonValue channel && channel.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)
        && (Integer(row["id"], out long id) && id > 0 ? id.ToString(CultureInfo.InvariantCulture) : DateTimeOffset.TryParse(row["day"]?.ToString(),CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out var day) && row["summary_key"]?.ToString() is { Length:64 } key && key.All(Uri.IsHexDigit) ? day.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture)+":"+key : null) is {} identity
            ? (identity, eventId, text) : null;

    internal static void Localize(JsonObject payload, bool english)
    {
        foreach (var row in payload.Objects("items"))
        {
            if (row["presentation_messages"] is not JsonObject messages) continue;
            foreach (string field in new[] { "title_text", "participant" })
            {
                if (messages[field] is not JsonObject envelope) continue;
                string code = envelope.Text("code");
                if (code == "events.catalog_title" && field == "title_text")
                    envelope["text"] = envelope["params"]?[english ? "en" : "ru"]?.DeepClone();
                else if (code is "events.unknown_type" or "events.participant_unknown")
                    envelope["text"] = ReportResult.Message(code, english)["text"]!.DeepClone();
                else continue;
                row[field] = envelope["text"]?.DeepClone();
            }
        }
    }
}
