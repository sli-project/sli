using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Investigations;

public static class InvestigationWorkspaceEndpoints
{
    public static IServiceCollection AddInvestigationWorkspace(this IServiceCollection services)
    {
        services.AddInvestigationNotes(); services.AddEventReads(); services.AddSecurityCandidates();
        services.TryAddScoped<IInvestigationEntityHistory, InvestigationEntityHistory>(); return services;
    }
    public static IEndpointRouteBuilder MapInvestigationWorkspace(this IEndpointRouteBuilder endpoints)
    { endpoints.MapGet("/api/v1/investigations", InvestigationEndpoints.HandleDisabledAsync); return endpoints; }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var input = InvestigationWorkspaceInput.Parse(context.Request);
            var session = await InvestigationRequest.Authorize(context, false, ct); if (session is null) return;
            var access = session.Value.Access;
            bool entity = input.Event is null && input.Entity.HasValue;
            if (entity && await InvestigationRequest.Module(context, access, false, ct, "objects.view") is null) return;
            string? report = await InvestigationRequest.Module(context, access, false, ct); if (report is null) return;
            var reader = context.RequestServices.GetRequiredService<IEventReadService>();
            var decisions = new Dictionary<long, bool>();
            async Task<bool> Allowed(long id, CancellationToken token)
            {
                if (decisions.TryGetValue(id, out bool cached)) return cached;
                IReadOnlyList<AccessResource> resources;
                try { resources = await reader.ResourcesAsync(id, token); }
                catch (InvestigationException e) when (e.Code is "event_not_found" or "not_found") { return decisions[id] = false; }
                if (resources.Count == 0) return decisions[id] = false;
                bool allowed = InvestigationList.Allowed(access, report, [resources]);
                if (entity)
                    allowed &= new[] { "objects.view", "evidence.exact", "field.security" }.All(cap => access.Capabilities.DecideForResourceGroups(cap, [resources]).Allowed) &&
                        ResourceAccessDecisions.ReportAction(access, report, "view", [resources], new HashSet<string> { "security" }).Allowed;
                return decisions[id] = allowed;
            }
            if (input.Event is { } anchor)
            {
                var resources = await reader.ResourcesAsync(anchor, ct);
                if (resources.Count == 0) throw new InvestigationException("event_not_found", $"Event {anchor} was not found", 404);
                if (!InvestigationList.Allowed(access, report, [resources])) throw InvestigationRequest.Hidden();
                decisions[anchor] = true;
            }
            else if (!entity && !InvestigationList.Allowed(access, report, [])) throw InvestigationRequest.Hidden();
            if (input.Event is null && input.Cursor is not null) throw new InvestigationException("invalid_cursor", "invalid_cursor");
            if (input.Event is null && !entity) throw new InvestigationException("storage_v2_investigation_requires_exact_event_id", "storage_v2_investigation_requires_exact_event_id", 409);
            input = input.Normalize();
            JsonObject response = entity ? await Entity(input, access, report, context.RequestServices.GetRequiredService<IInvestigationEntityHistory>(), Allowed, ct) : await Anchor(input, reader, Allowed, ct);
            await DomainHttp.WriteAsync(context, response, 200, ct);
        }
        catch (InvestigationException e) { await InvestigationRequest.Error(context, e, ct); }
        catch (SecurityCandidateException e) { await DomainHttp.WriteAsync(context, new { error = e.Code }, 400, ct); }
        catch (InvalidDataException e) when (e.Message == "invalid_cursor") { await DomainHttp.WriteAsync(context, new { error = "invalid_cursor" }, 400, ct); }
        catch (Exception e) when (e is IOException or InvalidDataException or NpgsqlException) { await Unavailable(context, ct); }
        catch (TimeoutException) { await Unavailable(context, ct); }
        catch (EventReadConfigurationException) { await Unavailable(context, ct); }
        catch (InvalidOperationException e) when (e.Message is "source_normalizer_bundle_unsupported" or "plugin_generation_unavailable" or "plugin_update_draining") { await Unavailable(context, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (OperationCanceledException) { await Unavailable(context, ct); }
        catch (Exception e) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, e, ct, login: false); }
    }
    static Task Unavailable(HttpContext c, CancellationToken ct) => DomainHttp.WriteAsync(c, new { error = "unavailable" }, 503, ct);
    static JsonObject Base(InvestigationWorkspaceInput input, bool entity) => new()
    {
        ["api_version"] = "v1", ["next_cursor"] = null, ["query"] = entity ? "" : input.Query.Length > 0 ? input.Query : $"Event DB {input.Event}",
        ["anchor_event_db_id"] = input.Event, ["context"] = new JsonObject { ["event_db_id"] = input.Event, ["entity_id"] = input.Entity, ["time_from_utc"] = input.From, ["time_to_utc_exclusive"] = input.To, ["timezone"] = input.Zone, ["anchor_in_window"] = null },
        ["scope"] = input.Scope ?? (entity ? "all" : "important"), ["state"] = "ok", ["findings"] = new JsonArray(), ["next_checks"] = new JsonArray(), ["next_check_codes"] = new JsonArray(), ["timeline"] = new JsonArray(),
        ["limits"] = new JsonObject { ["timeline"] = 100, ["full_history"] = false }
    };
    static DateTimeOffset? Instant(JsonNode? raw) => InvestigationTimeline.Instant(raw);
    internal static async Task<JsonObject> Anchor(InvestigationWorkspaceInput input, IEventReadService reader, Func<long, CancellationToken, Task<bool>> allowed, CancellationToken ct)
    {
        string? relationCursor = input.DecodeCursor(); long id = input.Event!.Value;
        var response = Base(input, false);
        var rows = await reader.DetailsAsync([id], true, allowed, ct);
        if (rows.Keys.Any(key => key != id)) throw new InvalidDataException("unauthorized_hydration_result");
        if (!rows.TryGetValue(id, out var anchor))
        {
            response["state"] = "empty";
            response["summary"] = Summary(0, false, "Опорное событие не найдено.", "Цепочка не построена без точного доказательства.");
            response["limits"] = new JsonObject { ["timeline"] = 0, ["relations"] = 0, ["full_history"] = false }; return response;
        }
        var page = await reader.RelationsPageAsync(id, 40, relationCursor, allowed, ct);
        var relations = new List<(long Id, string Reason)>();
        foreach (var raw in page["items"] as JsonArray ?? [])
        {
            if (!long.TryParse(raw?["related_event_db_id"]?.ToString(), out long related) || related <= 0) continue;
            if (await allowed(related, ct)) relations.Add((related, raw?["reason"]?.ToString() ?? raw?["explanation"]?.ToString() ?? "Связанное доказательство."));
        }
        var ids = relations.Select(r => r.Id).Distinct().ToArray();
        var details = ids.Length == 0 ? [] : await reader.DetailsAsync(ids, false, allowed, ct);
        if (details.Keys.Any(key => !ids.Contains(key))) throw new InvalidDataException("unauthorized_hydration_result");
        anchor["event_db_id"] = id;
        var (anchorItem, card) = InvestigationTimeline.Build(anchor, "Опорное событие расследования.");
        var timeline = new List<JsonObject>();
        if (input.Cursor is null) timeline.Add(anchorItem);
        foreach (var relation in relations) if (details.TryGetValue(relation.Id, out var row))
        { row["event_db_id"] = relation.Id; timeline.Add(InvestigationTimeline.Build(row, relation.Reason).Item); }
        DateTimeOffset? start = Instant(JsonValue.Create(input.From)), end = Instant(JsonValue.Create(input.To));
        bool InWindow(JsonObject item) => Instant(item["time_utc"]) is { } time && (start is null || time >= start) && (end is null || time < end);
        response["context"]!["anchor_in_window"] = Instant(anchorItem["time_utc"]) is null ? null : InWindow(anchorItem);
        int unknown = timeline.Count(item => Instant(item["time_utc"]) is null);
        if (start is not null || end is not null) timeline = timeline.Where(InWindow).ToList();
        timeline = timeline.OrderByDescending(item => item["time_utc"]?.ToString() ?? "", StringComparer.Ordinal).ThenByDescending(item => item["event_db_id"]!.GetValue<long>()).Take(100).ToList();
        response["timeline"] = new JsonArray(timeline.Select(item => (JsonNode?)item).ToArray());
        response["state"] = timeline.Count > 0 ? "ok" : "empty";
        response["next_cursor"] = input.EncodeCursor(page["next_cursor"]?.ToString());
        var summary = Summary(timeline.Count, page["truncated"]?.GetValue<bool>() ?? false, card["story"]!.ToString(), "Цепочка начинается с выбранного точного evidence и содержит только объяснимые связи.");
        summary["anchor_classification"] = new JsonObject { ["risk"] = card["risk"]!.DeepClone(), ["classification_origin"] = card["classification_origin"]!.DeepClone(), ["card_completeness"] = card["card_completeness"]!.DeepClone() };
        summary["story_code"] = card["story_code"]?.DeepClone(); summary["why_it_matters_code"] = "investigations.exact_chain"; response["summary"] = summary;
        response["next_checks"] = new JsonArray(card["checks"]!.AsArray().Take(7).Select(n => n?.DeepClone()).ToArray());
        response["next_check_codes"] = new JsonArray(card["check_codes"]!.AsArray().Take(7).Select(n => n?.DeepClone()).ToArray());
        response["limits"]!["relations"] = 40; response["limits"]!["anchor_contract"] = "exact_event_db_id"; response["limits"]!["events_with_unknown_time"] = unknown;
        return response;
    }
    internal static async Task<JsonObject> Entity(InvestigationWorkspaceInput input, AccessDecision access, string report, IInvestigationEntityHistory history, Func<long, CancellationToken, Task<bool>> allowed, CancellationToken ct)
    {
        var ids = await history.CandidatesAsync(input, access, report, ct);
        if (ids.Length > 101 || ids.Any(id => id <= 0)) throw new InvalidDataException("investigation_candidate_invalid");
        var permitted = new List<long>();
        foreach (long id in ids.Distinct()) if (await allowed(id, ct)) permitted.Add(id);
        var response = Base(input, true); response["limits"]!["coverage"] = "bounded_exact_entity_evidence";
        bool security = input.From is not null && input.To is not null;
        long[] metadataIds = (security ? permitted : permitted.Take(100)).ToArray();
        var rows = metadataIds.Length == 0 ? [] : await history.MetadataAsync(input, metadataIds, ct);
        var returnedIds = rows.Select(r => r["event_db_id"]!.GetValue<long>()).ToArray();
        if (returnedIds.Length != metadataIds.Length || returnedIds.Distinct().Count() != returnedIds.Length || !returnedIds.ToHashSet().SetEquals(metadataIds))
            throw new InvestigationException("unavailable", "unavailable", 503);
        string reason = security ? "Точное совпадение SID события или сохранённой связи с сущностью; совпадение имени не использовалось." : "Точное evidence сущности; связь не доказывает причинность.";
        var timeline = rows.OrderByDescending(r => Instant(r["time_created_utc"])).ThenByDescending(r => r["event_db_id"]!.GetValue<long>()).Take(100).Select(r => (JsonNode?)InvestigationTimeline.Build(r, reason, true).Item).ToArray();
        response["timeline"] = new JsonArray(timeline);
        response["summary"] = timeline.Length == 0
            ? Summary(0, false, "Для объекта нет подтверждённых событий в выбранном периоде.", "Отсутствие связи в сохранённых данных не доказывает отсутствие активности.")
            : Summary(timeline.Length, permitted.Count > 100, "Показаны только события, где объект подтверждён точным идентификатором.", "Связь сущности с событием не доказывает причинность или вывод расследования.");
        response["next_checks"] = timeline.Length == 0 ? new JsonArray("Расширьте период или откройте событие по точному идентификатору.") : new JsonArray("Точная связь объекта с событием не является причинной цепочкой.");
        return response;
    }
    static JsonObject Summary(int count, bool more, string story, string why) => new()
    { ["events_returned"] = count, ["has_more"] = more, ["attention_level"] = "unknown", ["story"] = story, ["why_it_matters"] = why, ["anchor_classification"] = null, ["story_code"] = null, ["why_it_matters_code"] = null };
}
