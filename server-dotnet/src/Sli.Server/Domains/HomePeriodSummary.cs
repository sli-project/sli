using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Gpo;
using Sli.Server.Reporting.V2;
using Sli.Server.Storage.EventReports;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Domains.HomeJson;
using static Sli.Server.Domains.HomePresentation;

namespace Sli.Server.Domains;

internal sealed class HomePeriodSummary(HomeSummaryReaders reads, IGpoReadStore? gpo, IConfiguration? configuration,
    ILogger<HomeSummaryService>? logger, IAdV2Store? ad)
{
    private sealed record WeakSpot(string Key, string? Label, long Count, string Href, string? LabelKey = null);

    internal async Task<JsonObject> Build(IReadOnlyList<HomeReport> reports, IReadOnlyList<DomainItem> domains,
        Principal principal, HomeSummaryQuery query, CancellationToken ct)
    {
        var window = query.Period!;
        bool openQueue = query.OpenQueue;
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
        bool eventIdentity = chosen is not null && journal?.Fields([chosen.Id], "identity_basic") == true;
        bool objectLinks = infrastructure?.Capabilities?.Decide("entity.view").Allowed == true
            || queue?.Capabilities?.Decide("entity.view").Allowed == true;

        var operatorTask = ReadBlock("operators", openQueue && queueIds.Length > 0
            ? reads.Read(HomePeriodSql.OperatorContext, ct, ("session", principal.Type == "session"), ("user", principal.Id))
            : Task.FromResult<IReadOnlyList<JsonObject>>([]));
        var checkReaders = new (string Key, Task<WeakSpot[]?> Read)[]
        {
            ("ad.infrastructure", ReadAdWeakSpots(infrastructure, "controls")),
            ("ad.users.v2", ReadAdWeakSpots(Report("ad.users.v2"), "checks")),
            ("ad.computers.v6", ReadAdWeakSpots(Report("ad.computers.v6"), "checks")),
            ("ad.gpo.v2", ReadBlock("ad.gpo.v2", openQueue && policyIds.Length > 0 && gpo is not null
                ? ReadGpoWeakSpots() : Task.FromResult<WeakSpot[]>([])))
        };
        var problemsTask = ReadBlock("problems", queueIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([]) : ReadProblems());
        var deltaTask = ReadSignInDelta();
        var controllerTask = ReadBlock("controllers", openQueue || dcIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([])
            : reads.Read(HomePeriodSql.Controllers, ct, ("ids", dcIds), ("to", window.To)));
        var passwordTask = ReadBlock("changes", dcIds.Length == 0 ? Task.FromResult<IReadOnlyList<JsonObject>>([])
            : reads.Read(HomePeriodSql.PasswordPolicyChanges, ct, [.. windowArgs, ("ids", dcIds)]));
        var gpoTask = ReadBlock("changes", policyIds.Length == 0 || gpo is null ? Task.FromResult<IEnumerable<JsonObject>>([]) : ReadGpo());
        var activityTask = ReadBlock("activity", !openQueue && eventScope is { } activityScope ? ReadActivity(activityScope) : Task.FromResult<IReadOnlyList<JsonObject>>([]));
        var eventsTask = ReadBlock("changes", eventScope is { } changeScope ? ReadEventChanges(changeScope) : Task.FromResult<IReadOnlyList<JsonObject>>([]));
        await Task.WhenAll([problemsTask, deltaTask, controllerTask, passwordTask, gpoTask, activityTask, eventsTask,
            .. checkReaders.Select(reader => (Task)reader.Read)]);

        var problems = await problemsTask;
        var controllers = await controllerTask;
        var events = await eventsTask;
        var passwords = await passwordTask;
        var gpoChanges = await gpoTask;
        var hours = await activityTask;
        var counts = problems?.SingleOrDefault();
        var problemRows = Rows(counts?["items"]).Select(row =>
        {
            long id = row.Number("id");
            var (name, fact) = HomePresentation.PeriodProblem(row, query, queueIdentity);
            var subject = row["subject"];
            var accountCount = row["password_totals"]?["accounts"] is null
                ? row["password"].Number("accounts") : row["password_totals"].Number("accounts");
            var lookup = DisplayName(subject.Text("group_name")) ?? (accountCount <= 1 ? name : null);
            var entity = row["entity"];
            var observations = Rows(row["observations"]).Select(observation => new {
                at = observation.Stamp("at"), event_id = observation.Number("event_kind"),
                source = DisplayName(observation.Text("source")),
                href = queueEvidence && eventLinks && eventScope is not null && (!openQueue || observation.Stamp("at") >= retention) ? "/app/events/" + observation.Number("event_id") : null
            }).ToArray();
            return new {
                id, name, fact,
                severity = row.Text("severity") ?? "unknown",
                at = row.Stamp(openQueue ? "last_seen" : "first_seen"),
                source = openQueue && queueTechnical
                    ? DisplayName(row.Text("source")) ?? observations.FirstOrDefault()?.source
                    : observations.FirstOrDefault()?.source,
                status = row.Text("status"), assignee = row.Text("assignee"), assignee_state = row.Text("assignee_state"),
                occurrence_count = row.Number("occurrence_count"),
                repeats_href = openQueue && queueIdentity && queueTechnical && row.Number("occurrence_count") > 1
                    && row["key"] is JsonArray key ? HomeSummaryQuery.Href("security.problems",
                        new Dictionary<string, object?>(links) { ["population"] = "open", ["cohort"] = key.ToJsonString() }) : null,
                observations,
                observations_are_sample = row["password_totals"].Number("attempts") >
                    observations.Count(observation => observation.event_id is 4625 or 4771 or 4776),
                href = HomeSummaryQuery.Href("security.problems", new Dictionary<string, object?>(links) { ["id"] = id }),
                object_href = objectLinks && lookup is not null && entity.Number("id") > 0
                    && string.Equals(lookup, DisplayName(entity.Text("name")), StringComparison.OrdinalIgnoreCase)
                    ? "/app/entities/" + entity.Number("id") : null,
                events_href = !openQueue && eventScope is not null && lookup is not null
                    ? HomeSummaryQuery.Href("events.journal", new Dictionary<string, object?>(filters) { ["q"] = lookup }) : null
            };
        }).ToArray();
        var problemsById = problemRows.ToDictionary(row => row.id);

        var eventChanges = events?.Select(row => Object(new {
            at = row.Stamp("at"), name = DisplayName(row.Text("name")), event_id = row.Number("event_id"),
            initiator = DisplayName(row.Text("initiator")), value = DisplayName(row.Text("value")),
            before = DisplayName(row.Text("before")), after = DisplayName(row.Text("after")),
            href = eventLinks && row.Stamp("at") >= retention ? "/app/events/" + row.Number("id") : null
        }));
        var passwordChanges = passwords?.Select(row => Object(new {
            at = row.Stamp("at"), name = row.Text("name"), kind = "password", field = row.Text("field"),
            before = Scalar(row["before"]), after = Scalar(row["after"]), before_at = row.Stamp("before_at")
        }));
        var result = Object(new {
            domains = candidates.Select(d => new { id = d.Id, name = d.DisplayName }), domain_id = chosen?.Id,
            from = window.From, to = window.To, updated_at = query.Now,
            problems = problems is null ? null : new {
                new_count = counts?["new_count"], closed_count = counts?["closed_count"], open_count = counts?["open_count"],
                unassigned_count = counts?["unassigned_count"], in_work_count = counts?["in_work_count"],
                page = counts?["page"], items = problemRows, href = counts is not null ? HomeSummaryQuery.Href("security.problems",
                    new Dictionary<string, object?>(links) { ["population"] = "open" }) : null
            },
            controllers = controllers is null ? null : new {
                items = controllers.OrderBy(row => row.Text("name"), StringComparer.Ordinal)
                    .Select(row => Controller(row, window.To, objectLinks)),
                href = dcIds.Length > 0 ? HomeSummaryQuery.Href("ad.infrastructure", openQueue ? filters : links) : null
            },
            changes = eventChanges is null || passwordChanges is null || gpoChanges is null ? null : new {
                items = eventChanges.Concat(passwordChanges).Concat(gpoChanges).OrderByDescending(row => row.Stamp("at")).Take(openQueue ? 10 : 200),
                href = Ids(domainChanges).Length > 0 ? HomeSummaryQuery.Href("security.events.chains", filters)
                    : openQueue ? null : eventScope is not null ? HomeSummaryQuery.Href("events.journal", filters)
                    : dcIds.Length > 0 ? HomeSummaryQuery.Href("ad.infrastructure", new Dictionary<string, object?>(filters) { ["tab"] = "changes" })
                    : policyIds.Length > 0 ? HomeSummaryQuery.Href("ad.gpo.v2", new Dictionary<string, object?>(filters) { ["tab"] = "changes" }) : null
            },
            activity = hours is null ? null : new {
                hours,
                markers = Rows(counts?["markers"]).Select(row => {
                    var problem = problemsById.GetValueOrDefault(row.Number("id"));
                    return new { at = row.Stamp("at"), severity = row.Text("severity"), name = problem?.name, fact = problem?.fact };
                })
            }
        });
        if (openQueue)
        {
            result.Remove("activity");
            result.Remove("controllers");
            result["active_operator_count"] = (await operatorTask)?.SingleOrDefault()?["active_operator_count"].Copy();
            result["since_previous_login"] = await deltaTask;
            var checkResults = await Task.WhenAll(checkReaders.Select(async reader => (reader.Key, Items: await reader.Read)));
            result["weak_spots"] = Object(new {
                items = checkResults.SelectMany(source => (source.Items ?? [])
                    .OrderByDescending(item => item.Count).ThenBy(item => item.Key, StringComparer.Ordinal)
                    .Select((item, index) => new { item, index, report = source.Key }))
                    .OrderBy(row => row.index).ThenByDescending(row => row.item.Count)
                    .ThenBy(row => row.report, StringComparer.Ordinal).Take(10)
                    .Select(row => new { id = row.report + ":" + row.item.Key, label = row.item.Label, label_key = row.item.LabelKey,
                        count = row.item.Count, href = row.item.Href, row.report }),
                failed = checkResults.Where(source => source.Items is null).Select(source => source.Key)
            });
        }
        return result;

        async Task<IReadOnlyList<JsonObject>> ReadProblems()
        {
            if (!openQueue)
                return await reads.Read(HomePeriodSql.Problems, ct, [.. windowArgs, ("ids", queueIds), ("identity", queueIdentity), ("technical", queueTechnical)]);
            var operators = (await operatorTask)?.SingleOrDefault();
            bool showAssignment = queueIdentity && operators.Number("active_operator_count") >= 2;
            bool reset = query.QueueFilter == "unassigned" && !showAssignment;
            return await reads.Read(HomePeriodSql.OpenQueue, ct, ("ids", queueIds), ("identity", queueIdentity),
                ("assignment", showAssignment), ("technical", queueTechnical), ("queue", reset ? "all" : query.QueueFilter),
                ("limit", query.QueueLimit), ("offset", reset ? 0L : (query.QueuePage - 1L) * query.QueueLimit));
        }

        async Task<JsonObject?> ReadSignInDelta()
        {
            var since = (await operatorTask)?.SingleOrDefault().Stamp("previous_login_at");
            if (since is null || since >= query.Now) return null;
            var rows = await ReadBlock("sign-in", reads.Read(HomePeriodSql.SincePreviousLogin, ct, ("ids", queueIds),
                ("since", since.Value), ("now", query.Now)));
            if (rows?.SingleOrDefault() is not { } row) return null;
            return Object(new {
                from = since.Value, to = query.Now, new_count = row.Number("new_count"), closed_count = row.Number("closed_count"),
                new_href = HomeSummaryQuery.Href("security.problems", new Dictionary<string, object?>(links) {
                    ["queue_view"] = "all", ["fold"] = "false",
                    ["created_from"] = HomeSummaryQuery.Iso(since.Value), ["created_to"] = HomeSummaryQuery.Iso(query.Now)
                })
            });
        }

        async Task<WeakSpot[]?> ReadAdWeakSpots(HomeReport? report, string tab)
        {
            var ids = Ids(report);
            if (!openQueue || ad is null || report is null || ids.Length == 0) return [];
            bool accounts = report.Key == "ad.users.v2";
            var definition = AdV2Endpoints.Definitions[report.Key];
            bool Fields(IEnumerable<string> required) => report.Fields(ids, required.ToArray());
            if (!Fields(AdV2Endpoints.Strings(definition?["view_fields"]?[tab])
                .Concat(AdV2Endpoints.Strings(definition?["param_fields"]?[tab == "controls" ? "q" : "check"]))
                .Concat(accounts ? AdV2Endpoints.Strings(definition?["param_fields"]?["account_rows"]) : []))) return [];
            var parameters = tab == "controls" ? new JsonObject { ["qualification"] = "failed" } : new JsonObject();
            if (accounts) parameters["account_rows"] = "yes";
            var request = new AdV2Request(report.Key, "view", null, ids, parameters, tab, null, false, 200, null, query.TimeZone);
            var data = await ReadBlock(report.Key, ad.ReadAsync(request, Fields, ct));
            if (!report.Available() || data.Text("state") == "denied") return [];
            if (data is null || data.Text("state") is "error" or "unavailable") return null;
            bool english = DomainHttp.SelectEnglish(query.Language);
            if (tab == "controls")
            {
                var localized = ReportPresentation.Apply(data, english);
                return Rows(localized["items"]).Where(row => row.Text("qualification") == "failed" && row.Text("control_id") is not null)
                    .GroupBy(row => row.Text("control_id")!).Select(group =>
                    {
                        var label = group.First().Text("label");
                        return new WeakSpot(group.Key, label, group.Select(row => row.Number("entity_id")).Distinct().LongCount(),
                            HomeSummaryQuery.Href(report.Key, new Dictionary<string, object?>(links) {
                                ["tab"] = tab, ["qualification"] = "failed", ["q"] = label
                            }));
                    }).ToArray();
            }
            AdReviewChecks.Localize(data, english);
            var checks = accounts ? Rows(data["filter_options"]?["check"]) : Rows(data["items"]);
            string keyField = accounts ? "value" : "key", countField = accounts ? "count" : "total";
            return checks.Where(row => row.Number(countField) > 0 && row.Text(keyField) is not (null or "new_computer"))
                .Select(row =>
                {
                    var check = row.Text(keyField)!;
                    var checkFilters = new Dictionary<string, object?>(links) { ["tab"] = tab };
                    if (accounts)
                    {
                        checkFilters["check"] = check;
                        checkFilters["account_rows"] = "yes";
                    }
                    return new WeakSpot(check, row.Text(accounts ? "label" : "title"), row.Number(countField), HomeSummaryQuery.Href(report.Key, checkFilters));
                }).ToArray();
        }

        async Task<WeakSpot[]> ReadGpoWeakSpots()
        {
            var pair = await gpo!.PairAsync(policyIds, ct);
            if (pair["current"] is not JsonObject snapshot)
            {
                if (pair.Text("state") is "error" or "unavailable") throw new GpoSourceException();
                return [];
            }
            if (policies?.Available() != true) return [];
            var count = GpoInventory.Filter(snapshot, "attention").Total;
            if (count == 0) return [];
            return [new WeakSpot("version_mismatch", null, count, HomeSummaryQuery.Href("ad.gpo.v2",
                new Dictionary<string, object?>(links) { ["tab"] = "gpos", ["view"] = "attention" }),
                "reports.v2.ad.gpo.v2.reasons.version_mismatch.title")];
        }

        async Task<T?> ReadBlock<T>(string block, Task<T> read) where T : class
        {
            try { return await read; }
            catch (Exception error) when (!ct.IsCancellationRequested && error is (Npgsql.NpgsqlException or TimeoutException or GpoSourceException))
            {
                logger?.LogWarning("Home block read failed for {Block} ({ErrorType})", block, error.GetType().Name);
                return null;
            }
        }

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
            var source = EventReadService.ShortSource("@from", daily: false);
            (string Key, object? Value)[] args = [
                .. windowArgs, ("ids", new[] { chosen!.Id }), .. scope.Parameters.Select(p => (p.Key, (object?)p.Value))
            ];
            return openQueue
                ? reads.Read(HomePeriodSql.OpenQueueChanges(source, scope.Sql), ct,
                    [.. args, ("queue_access", queueIds.Length > 0), ("assignment", false), ("event_identity", eventIdentity),
                     ("kinds", AdSecurity.ChangeEventIds().Where(id => id is not (4723 or 4724)).Distinct().ToArray())])
                : reads.Read(HomePeriodSql.EventChanges(source, scope.Sql), ct, args);
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
            return reads.ReadActivity(HomePeriodSql.Activity(EventReadService.ShortSource("@read_from", daily: false), scope.Sql), ct,
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
