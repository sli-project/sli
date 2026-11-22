using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Storage.EventReports;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Domains.HomeJson;
using static Sli.Server.Domains.HomePresentation;

namespace Sli.Server.Domains;

internal sealed class HomePeriodSummary(HomeSummaryReaders reads, IGpoReadStore? gpo, IConfiguration? configuration)
{
    internal async Task<JsonObject> Build(IReadOnlyList<HomeReport> reports, IReadOnlyList<DomainItem> domains,
        HomeSummaryQuery query, CancellationToken ct)
    {
        var window = query.Period!;
        var candidates = domains.Where(d => d.Id == query.Domain || !d.IsArchived).ToArray();
        var chosen = query.Domain is { } domain ? candidates.First(d => d.Id == domain) : candidates.FirstOrDefault();
        DomainItem[] selection = chosen is null ? [] : [chosen];
        var windowArgs = new (string Key, object? Value)[] { ("from", window.From), ("to", window.To) };
        var links = new Dictionary<string, object?> { ["domain"] = chosen?.Id };
        var filters = new Dictionary<string, object?>(links) {
            ["period"] = "custom", ["from"] = HomeWindow.Iso(window.From), ["to"] = HomeWindow.Iso(window.To)
        };
        HomeReport? Report(string key) => reports.FirstOrDefault(r => r.Key == key && r.Registered && r.Available());
        long[] Ids(HomeReport? report) => report?.Intersect(selection) ?? [];

        var queue = Report("security.problems");
        var infrastructure = Report("ad.infrastructure");
        var journal = Report("events.journal");
        var domainChanges = Report("security.events.chains");
        var policies = Report("ad.gpo.v2");
        var queueIds = Ids(queue);
        var dcIds = Ids(infrastructure);
        var policyIds = Ids(policies);
        var eventScope = chosen is null ? null : EventScope(journal, chosen.Id);
        var retention = eventScope is null ? window.From : EventReadService.ShortBoundary(configuration);
        bool queueIdentity = queueIds.Length > 0 && queue!.Fields(queueIds, "identity_basic");
        bool queueTechnical = queueIds.Length > 0 && queue!.Fields(queueIds, "technical");
        bool queueEvidence = queueTechnical && queue!.Fields(queueIds, "raw_evidence");
        bool eventLinks = chosen is not null && journal?.Fields([chosen.Id], "raw_evidence") == true;
        bool objectLinks = infrastructure?.Capabilities?.Decide("entity.view").Allowed == true
            || queue?.Capabilities?.Decide("entity.view").Allowed == true;

        var problemsTask = queueIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([])
            : reads.Read(HomePeriodSql.Problems, ct, [.. windowArgs, ("ids", queueIds), ("identity", queueIdentity), ("technical", queueTechnical)]);
        var controllerTask = dcIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([])
            : reads.Read(HomePeriodSql.Controllers, ct, ("ids", dcIds), ("to", window.To));
        var passwordTask = dcIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([])
            : reads.Read(HomePeriodSql.PasswordPolicyChanges, ct, [.. windowArgs, ("ids", dcIds)]);
        var gpoTask = policyIds.Length == 0 || gpo is null ? Task.FromResult<IEnumerable<JsonObject>>([]) : ReadGpo();
        var activityTask = eventScope is { } activityScope ? ReadActivity(activityScope) : Task.FromResult<IReadOnlyList<JsonObject>>([]);
        var eventsTask = eventScope is { } changeScope ? ReadEventChanges(changeScope) : Task.FromResult<IReadOnlyList<JsonObject>>([]);
        await Task.WhenAll(problemsTask, controllerTask, passwordTask, gpoTask, activityTask, eventsTask);

        var counts = (await problemsTask).SingleOrDefault();
        var problemRows = Rows(counts?["items"]).Select(row =>
        {
            long id = row.Number("id");
            var (name, fact) = HomePresentation.PeriodProblem(row, query, queueIdentity);
            var subject = row["subject"];
            var lookup = DisplayName(subject.Text("group_name")) ?? (row["password"].Number("accounts") <= 1 ? name : null);
            var entity = row["entity"];
            var observations = Rows(row["observations"]).Select(observation => new {
                at = observation.Stamp("at"), event_id = observation.Number("event_kind"),
                source = DisplayName(observation.Text("source")),
                href = queueEvidence && eventLinks && eventScope is not null ? "/app/events/" + observation.Number("event_id") : null
            }).ToArray();
            return new {
                id, name, fact,
                severity = row.Text("severity"), at = row.Stamp("first_seen"), source = observations.FirstOrDefault()?.source,
                observations,
                href = HomeSummaryQuery.Href("security.problems", new Dictionary<string, object?>(links) { ["id"] = id }),
                object_href = objectLinks && lookup is not null && entity.Number("id") > 0
                    && string.Equals(lookup, DisplayName(entity.Text("name")), StringComparison.OrdinalIgnoreCase)
                    ? "/app/entities/" + entity.Number("id") : null,
                events_href = eventScope is not null && lookup is not null
                    ? HomeSummaryQuery.Href("events.journal", new Dictionary<string, object?>(filters) { ["q"] = lookup }) : null
            };
        }).ToArray();
        var problemsById = problemRows.ToDictionary(row => row.id);

        var eventChanges = (await eventsTask).Select(row => Object(new {
            at = row.Stamp("at"), name = DisplayName(row.Text("name")), event_id = row.Number("event_id"),
            initiator = DisplayName(row.Text("initiator")), value = DisplayName(row.Text("value")),
            href = eventLinks && row.Stamp("at") >= retention ? "/app/events/" + row.Number("id") : null
        }));
        var passwordChanges = (await passwordTask).Select(row => Object(new {
            at = row.Stamp("at"), name = row.Text("name"), kind = "password", field = row.Text("field"),
            before = Scalar(row["before"]), after = Scalar(row["after"])
        }));
        return Object(new {
            domains = candidates.Select(d => new { id = d.Id, name = d.DisplayName }), domain_id = chosen?.Id,
            from = window.From, to = window.To, updated_at = query.Now,
            problems = new {
                new_count = counts?["new_count"], closed_count = counts?["closed_count"], open_count = counts?["open_count"],
                items = problemRows, href = counts is not null ? HomeSummaryQuery.Href("security.problems",
                    new Dictionary<string, object?>(links) { ["population"] = "open" }) : null
            },
            controllers = new {
                items = (await controllerTask).OrderBy(row => row.Text("name"), StringComparer.Ordinal)
                    .Select(row => Controller(row, window.To, objectLinks)),
                href = dcIds.Length > 0 ? HomeSummaryQuery.Href("ad.infrastructure", links) : null
            },
            changes = new {
                items = eventChanges.Concat(passwordChanges).Concat(await gpoTask).OrderByDescending(row => row.Stamp("at")).Take(200),
                href = Ids(domainChanges).Length > 0 ? HomeSummaryQuery.Href("security.events.chains", filters)
                    : eventScope is not null ? HomeSummaryQuery.Href("events.journal", filters)
                    : dcIds.Length > 0 ? HomeSummaryQuery.Href("ad.infrastructure", new Dictionary<string, object?>(filters) { ["tab"] = "changes" })
                    : policyIds.Length > 0 ? HomeSummaryQuery.Href("ad.gpo.v2", new Dictionary<string, object?>(filters) { ["tab"] = "changes" }) : null
            },
            activity = new {
                hours = await activityTask,
                markers = Rows(counts?["markers"]).Select(row => {
                    var problem = problemsById.GetValueOrDefault(row.Number("id"));
                    return new { at = row.Stamp("at"), severity = row.Text("severity"), name = problem?.name, fact = problem?.fact };
                })
            }
        });

        async Task<IEnumerable<JsonObject>> ReadGpo()
        {
            var history = await gpo!.HistoryAsync(policyIds, window.From, window.To, "", ct);
            var changes = Rows(history["items"]).Where(row => row.Text("id") is not null).OrderByDescending(row => row.Stamp("observed_at")).Take(200).ToArray();
            if (changes.Length == 0) return [];
            var details = await reads.Read(HomePeriodSql.GpoPresentation, ct,
                [.. windowArgs, ("ids", policyIds), ("records", changes.Select(row => row.Text("id")!).ToArray())]);
            var byRecord = details.ToLookup(row => row.Text("record_id"), StringComparer.Ordinal);
            var href = HomeSummaryQuery.Href("ad.gpo.v2", new Dictionary<string, object?>(filters) { ["tab"] = "changes" });
            return changes.Select(row =>
            {
                var detail = byRecord[row.Text("id")].FirstOrDefault();
                var before = VerifiedValue(detail.Text("before_value"), row.Text("before_sha256"));
                var after = VerifiedValue(detail.Text("after_value"), row.Text("after_sha256"));
                return Object(new {
                    at = row.Stamp("observed_at"), kind = "gpo", operation = row.Text("kind"),
                    name = detail.Text("name") ?? (row.Text("field") == "display_name" ? after ?? before : null),
                    label = detail.Text("label"), before, after, href
                });
            });
        }

        Task<IReadOnlyList<JsonObject>> ReadEventChanges((string Sql, Dictionary<string, object> Parameters) scope)
        {
            return reads.Read(HomePeriodSql.EventChanges(EventReadService.ShortSource("@from", daily: false), scope.Sql), ct,
                [.. windowArgs, ("ids", new[] { chosen!.Id }),
                 .. scope.Parameters.Select(p => (p.Key, (object?)p.Value))]);
        }

        Task<IReadOnlyList<JsonObject>> ReadActivity((string Sql, Dictionary<string, object> Parameters) scope)
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(query.TimeZone);
            var local = TimeZoneInfo.ConvertTime(window.From, zone);
            var hour = local.AddTicks(-(local.Ticks % TimeSpan.TicksPerHour)).ToUniversalTime();
            var localStart = DateOnly.FromDateTime(local.DateTime);
            DateTimeOffset Midnight(DateOnly date)
            {
                var midnight = date.ToDateTime(TimeOnly.MinValue);
                while (zone.IsInvalidTime(midnight)) midnight = midnight.AddMinutes(1);
                return new(TimeZoneInfo.ConvertTimeToUtc(midnight, zone));
            }
            var history = Midnight(localStart.AddDays(-7));
            return reads.Read(HomePeriodSql.Activity(EventReadService.ShortSource("@read_from", daily: false), scope.Sql), ct,
                [.. windowArgs, ("ids", new[] { chosen!.Id }), ("zone", query.TimeZone), ("hour", hour),
                 ("read_from", history > retention ? history : retention),
                 .. scope.Parameters.Select(p => (p.Key, (object?)p.Value))]);
        }
    }

    private static (string Sql, Dictionary<string, object> Parameters)? EventScope(HomeReport? journal, long domain)
    {
        if (journal?.Capabilities is not { } capabilities || !journal.Fields([domain], "security", "technical")) return null;
        const string auditing = "e.domain_id=any(@ids) and (e.provider_name='Microsoft-Windows-Security-Auditing' "
            + "or lower(e.provider_name)='microsoft-windows-security-auditing')";
        var compiler = new EventSearchSql();
        if (capabilities.IsOwner)
            return (auditing + " and (e.channel='Security' or lower(e.channel)='security')", compiler.Parameters);
        if (!capabilities.Capabilities.Contains("events.view") && !capabilities.ResourceCapabilities.Contains("events.view")) return null;
        var rules = capabilities.Policies.Where(p => p.CapabilityKey == "events.view").ToArray();
        var parts = new List<string> { auditing, "e.channel='Security'",
            "exists (select 1 from servers s where s.id=e.server_id and s.domain_id=e.domain_id)" };
        try
        {
            if (!capabilities.Capabilities.Contains("events.view"))
                parts.Add(compiler.Scope(rules.Where(p => p.Valid && p.Effect == "allow").Select(p => p.Scope)));
            foreach (var deny in rules.Where(p => p.Effect == "deny"))
                parts.Add(deny.Valid ? "not (" + compiler.Scope([deny.Scope]) + ")" : "false");
        }
        catch (EventSearchException) { return null; }
        return (string.Join(" and ", parts.Select(part => "(" + part + ")")), compiler.Parameters);
    }

    private static object Controller(JsonObject row, DateTimeOffset end, bool link)
    {
        var attributes = row["attributes"];
        var checks = new List<object>();
        int passed = 0;
        void Check(string key, bool ok, string? actual)
        {
            if (ok) passed++;
            else checks.Add(new { key, actual });
        }
        foreach (var (field, key) in new[] {
            ("dns_state", "dns"), ("sysvol_state", "sysvol"), ("services_state", "services"),
            ("connectivity_state", "connectivity"), ("advertising_state", "advertising"), ("time_service_state", "time")
        })
        {
            var value = attributes.Text(field)?.ToLowerInvariant();
            if (value is "passed" or "failed" or "running" or "stopped")
                Check(key, value is "passed" or "running", value);
        }
        var os = attributes.Text("operating_system");
        if (AdComputerPosture.SupportEnd(os, attributes.Text("operating_system_version")) is { } supportEnd)
            Check("os", end < supportEnd, os);
        return new {
            id = row.Number("entity_id"), name = DisplayName(row.Text("name")), at = row.Stamp("observed_at"), passed, failures = checks,
            href = link ? "/app/entities/" + row.Number("entity_id") : null
        };
    }

    private static IEnumerable<JsonObject> Rows(JsonNode? node) => (node as JsonArray ?? []).OfType<JsonObject>();
    private static string? VerifiedValue(string? value, string? hash)
    {
        if (value is null || string.IsNullOrEmpty(hash)) return null;
        bool Matches(JsonNode node) => string.Equals(hash, LifecycleJson.Hash(node), StringComparison.OrdinalIgnoreCase);
        if (Matches(JsonValue.Create(value))) return value;
        try { return JsonNode.Parse(value) is JsonValue scalar && Matches(scalar) ? value : null; }
        catch (JsonException) { return null; }
    }
    private static string? Scalar(JsonNode? node) => node is JsonValue ? node.ToString() : null;
}
