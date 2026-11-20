using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Workspace;

public sealed class DashboardSnapshotCache
{
    internal readonly object Sync = new();
    internal JsonObject? Payload;
    internal long Created;
    internal Task? Refresh;
    internal Task<JsonObject>? RefreshResult;
    internal string? LastError;
}
public sealed class DashboardSnapshotReader(ILegacyRows rows, OperationsService operations,
    LegacyJobStore jobs, LegacySettings settings, DashboardSnapshotCache cache, IServiceScopeFactory scopes, IHostApplicationLifetime? lifetime = null,
    ILogger<DashboardSnapshotReader>? logger = null,IConfiguration? config = null)
{
    Task<JsonArray> Read(string sql, CancellationToken ct, params object[] parameters) => rows.QueryAsync(sql, parameters, 0, ct);
    static JsonArray A(JsonNode? value) => value as JsonArray ?? [];
    static long N(JsonNode? value) => long.TryParse(value?.ToString(), out long n) ? n : 0;
    static string S(JsonNode? value) => value?.ToString() ?? "";
    double Bounded(string name, double fallback, double minimum, double maximum) => double.TryParse(settings.Get(name), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double value) && double.IsFinite(value) ? Math.Clamp(value, minimum, maximum) : fallback;
    double Ttl => Bounded("ADLOG_DASHBOARD_CACHE_TTL_SECONDS", 5, 1, 60);
    int Sample(string name, int fallback, int maximum) => System.Numerics.BigInteger.TryParse(settings.Get(name),
        System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var value)
        ? (int)System.Numerics.BigInteger.Clamp(value, 1000, maximum) : fallback;
    internal async Task<JsonObject> ReadRoleViewsAsync(CancellationToken ct) {
        bool missing; lock (cache.Sync) missing = cache.Payload is null;
        var snapshot = await ReadAsync(missing, ct);
        return snapshot["role_views"]!.DeepClone().AsObject();
    }
    // The shared build owns its scope and lifetime. A disconnected HTTP caller
    // stops waiting, without starting a second copy of still-running queries.
    Task<JsonObject> Refresh() {
        lock (cache.Sync) {
            if (cache.Refresh?.IsCompleted == false) return cache.RefreshResult!;
            cache.RefreshResult = Task.Run(async () => {
                try {
                    await using var scope = scopes.CreateAsyncScope();
                    var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>();
                    var result = await reader.Build(lifetime?.ApplicationStopping ?? CancellationToken.None);
                    lock (cache.Sync) { cache.Payload = result.DeepClone().AsObject(); cache.Created = Stopwatch.GetTimestamp(); cache.LastError = null; }
                    return result;
                }
                catch (OperationCanceledException) when (lifetime?.ApplicationStopping.IsCancellationRequested == true) { throw; }
                catch (Exception error) {
                    // Keep only the error type: exception messages may contain private source data.
                    lock (cache.Sync) cache.LastError = error.GetType().Name;
                    logger?.LogWarning("snapshot_refresh_failed error_type={ErrorType}", error.GetType().Name);
                    throw;
                }
            }, CancellationToken.None);
            cache.Refresh = ObserveRefresh(cache.RefreshResult);
            return cache.RefreshResult;
        }
    }
    // Observe background failures while forced callers still receive the build error.
    static async Task ObserveRefresh(Task<JsonObject> refresh) {
        try { await refresh; }
        catch (Exception) { /* Refresh records failures without exposing source data. */ }
    }
    public async Task<JsonObject> ReadAsync(bool force, CancellationToken ct) {
        if (force) return (await Refresh().WaitAsync(ct)).DeepClone().AsObject();
        lock (cache.Sync) {
            double age = Stopwatch.GetElapsedTime(cache.Created).TotalMilliseconds;
            bool stale = age >= Ttl * 1000;
            if (cache.Payload is null || stale) _ = Refresh();
            if (cache.Payload is not null) {
                var hit = cache.Payload.DeepClone().AsObject(); var diagnostics = hit["diagnostics"]!;
                diagnostics["cache_hit"] = true; diagnostics["cache_age_ms"] = Math.Max(0, (long)age); diagnostics["cache_ttl_seconds"] = Ttl;
                diagnostics["stale"] = stale; diagnostics["refreshing"] = cache.Refresh?.IsCompleted == false;
                diagnostics["response_model"] = stale ? "stale_while_revalidate" : "fresh_cache"; diagnostics["response_duration_ms"] = 0;
                if (stale && S(hit["status"]) == "ok") hit["status"] = "stale"; return hit;
            }
        }
        return WarmingResponse(await Runtime(ct));
    }
    async Task<JsonObject> Runtime(CancellationToken ct) {
        var status = await operations.ReadAsync("/api/runtime/status", new(), ct);
        return new() { ["status"] = status["status"]?.DeepClone(), ["active_backend"] = status["active_backend"]?.DeepClone(),
            ["scheduler"] = status["scheduler"]?.DeepClone(), ["collection"] = status["collection"]?.DeepClone() };
    }
    internal JsonObject WarmingResponse(JsonNode runtime) {
        return new JsonObject { ["generated_at_utc"] = DateTimeOffset.UtcNow, ["status"] = "warming", ["health"] = new JsonObject { ["status"] = "warming", ["service"] = "ad-log-reports", ["mode"] = "real-readonly-archive-collector", ["runtime"] = runtime },
            ["collector_health"] = new JsonObject { ["summary"] = new JsonObject(), ["items"] = new JsonArray(), ["post_collection"] = new JsonObject { ["summary"] = new JsonObject(), ["items"] = new JsonArray() }, ["status"] = "unavailable" }, ["sources"] = new JsonObject { ["items"] = new JsonArray() },
            ["events_summary"] = new JsonObject { ["total_events"] = 0, ["by_channel"] = new JsonArray(), ["top_event_ids"] = new JsonArray(), ["by_server"] = new JsonArray(), ["by_server_channel"] = new JsonArray(), ["status"] = "unavailable" }, ["entity_summary"] = new JsonObject { ["total_entities"] = 0, ["total_event_entity_links"] = 0, ["by_type"] = new JsonArray(), ["by_role"] = new JsonArray(), ["status"] = "unavailable" },
            ["jobs"] = new JsonObject { ["items"] = new JsonArray() }, ["reports"] = new JsonObject { ["items"] = new JsonArray() }, ["role_views"] = new JsonObject { ["views"] = new JsonArray(), ["summary"] = new JsonObject() },
            ["diagnostics"] = new JsonObject { ["cache_hit"] = false, ["cache_age_ms"] = 0, ["cache_ttl_seconds"] = Ttl, ["stale"] = false, ["refreshing"] = true, ["total_duration_ms"] = 0, ["build_duration_ms"] = 0, ["response_duration_ms"] = 0, ["components_ms"] = new JsonObject(), ["components"] = new JsonObject(), ["failures"] = new JsonArray(), ["request_model"] = "startup_warming_response" } };
    }
    private async Task<JsonObject> Build(CancellationToken ct) {
        var watch = Stopwatch.StartNew(); var diagnostics = new JsonObject();
        async Task<JsonNode> Component(string key, Func<CancellationToken, Task<JsonNode>> run, JsonNode fallback) {
            var clock = Stopwatch.StartNew();
            try { var result = await run(ct); lock (diagnostics) diagnostics[key] = new JsonObject { ["status"] = "ok", ["duration_ms"] = clock.ElapsedMilliseconds, ["error"] = null }; return result; }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { lock (diagnostics) { diagnostics[key] = new JsonObject { ["status"] = "failed", ["duration_ms"] = clock.ElapsedMilliseconds, ["error"] = "dashboard_component_unavailable" }; } return fallback; }
        }
        Task<JsonNode> Ops(string path, CancellationToken token) => operations.ReadAsync(path, new(), token);
        var tasks = new Dictionary<string, Task<JsonNode>> {
            ["events_summary"] = Component("events_summary", async token => await Events(token), new JsonObject { ["total_events"] = 0, ["by_channel"] = new JsonArray(), ["top_event_ids"] = new JsonArray(), ["by_server"] = new JsonArray(), ["by_server_channel"] = new JsonArray(), ["status"] = "unavailable" }),
            ["entity_summary"] = Component("entity_summary", async token => await Entities(token), new JsonObject { ["total_entities"] = 0, ["total_event_entity_links"] = 0, ["by_type"] = new JsonArray(), ["by_role"] = new JsonArray(), ["status"] = "unavailable" }),
            ["collector_health"] = Component("collector_health", token => Ops("/api/collector/health", token), new JsonObject { ["summary"] = new JsonObject(), ["items"] = new JsonArray(), ["post_collection"] = new JsonObject { ["summary"] = new JsonObject(), ["items"] = new JsonArray() }, ["status"] = "unavailable" }),
            ["sources"] = Component("sources", async token => (await Ops("/api/sources", token))["items"]!.DeepClone(), new JsonArray()),
            ["findings"] = Component("findings", async token => await Findings(token), new JsonObject { ["items"] = new JsonArray(), ["summary"] = new JsonArray(), ["status"] = "unavailable" }),
            ["ai_runs"] = Component("ai_runs", _ => Task.FromResult<JsonNode>(new JsonObject { ["status"] = "disabled", ["items"] = new JsonArray() }), new JsonObject()),
            ["jobs"] = Component("jobs", _ => Task.FromResult<JsonNode>(jobs.List()), new JsonArray()),
            ["reports"] = Component("reports", _ => Task.FromResult<JsonNode>(Reports()), new JsonArray()),
            ["archive_status"] = Component("archive_status", async token => await Archive(token), new JsonObject { ["archive_start_utc"] = null, ["channel_states"] = new JsonArray() })
        };
        await Task.WhenAll(tasks.Values);
        return Compose(tasks.ToDictionary(p => p.Key, p => p.Value.Result), await Runtime(ct), diagnostics, watch.ElapsedMilliseconds);
    }
    async Task<JsonObject> Archive(CancellationToken ct) {
        var start = (await Read("select value from archive_settings where key='archive_start_utc'", ct)).FirstOrDefault();
        if (start is null) start = (await Read("""
            insert into archive_settings(key,value,created_at,updated_at)
            select 'archive_start_utc',coalesce((select min(value)::text from (
              select min(run_started_at) as value from collection_runs
              union all select min(time_created_utc) as value from event_hot
              union all select min(time_created_utc) as value from event_cold_facts
              union all select min(first_seen_utc) as value from event_cold_daily
            ) history where value is not null),to_char(current_timestamp at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') || '+00:00'),now(),now()
            on conflict(key) do update set value=archive_settings.value returning value
            """, ct)).FirstOrDefault();
        return new() { ["archive_start_utc"] = start?["value"]?.DeepClone(),
            ["channel_states"] = await Read("select server_hostname,channel,last_successful_collection_utc,last_event_time_utc,last_event_record_id,backfill_completed from collection_channel_state order by server_hostname,channel", ct),
            ["backend"] = "postgres" };
    }
    internal JsonObject Compose(IReadOnlyDictionary<string, JsonNode> components, JsonNode runtime, JsonObject diagnostics, long durationMs) {
        JsonNode R(string key) => components[key];
        var failures = diagnostics.Where(p => S(p.Value?["status"]) != "ok").Select(p => p.Key).ToList();
        var collector = R("collector_health");
        var system = new JsonObject { ["status"] = N(collector["summary"]?["security_high"]) > 0 || N(collector["summary"]?["security_warn"]) > 0 ? "warn" : "ok", ["retention"] = new JsonObject { ["candidates"] = 0, ["source"] = "dashboard_brief" }, ["collector_summary"] = collector["summary"]?.DeepClone(), ["lightweight"] = true };
        var roleClock = Stopwatch.StartNew(); JsonObject roleViews;
        try {
            roleViews = RoleViews(R("events_summary"), R("entity_summary"), collector, system, R("findings"), R("ai_runs"), R("sources"));
            diagnostics["role_views_compose"] = new JsonObject { ["status"] = "ok", ["duration_ms"] = roleClock.ElapsedMilliseconds, ["error"] = null };
        }
        catch {
            roleViews = new JsonObject { ["views"] = new JsonArray(), ["summary"] = new JsonObject(), ["status"] = "unavailable" };
            failures.Add("role_views_compose");
            diagnostics["role_views_compose"] = new JsonObject { ["status"] = "failed", ["duration_ms"] = roleClock.ElapsedMilliseconds, ["error"] = "RuntimeError: dashboard_component_unavailable" };
        }
        var componentsMs = new JsonObject(diagnostics.Select(p => KeyValuePair.Create(p.Key, p.Value?["duration_ms"]?.DeepClone())));
        return new() { ["generated_at_utc"] = DateTimeOffset.UtcNow, ["status"] = failures.Count > 0 ? "partial" : "ok",
            ["health"] = new JsonObject { ["status"] = failures.Count > 0 ? "warn" : "ok", ["service"] = "ad-log-reports", ["mode"] = "real-readonly-archive-collector", ["runtime"] = runtime, ["archive_start_utc"] = R("archive_status")["archive_start_utc"]?.DeepClone(), ["archive_channel_states"] = R("archive_status")["channel_states"]?.DeepClone() ?? new JsonArray(), ["archive_backend"] = S(R("archive_status")["backend"]) is { Length: > 0 } backend ? backend : "postgres" },
            ["collector_health"] = collector, ["sources"] = new JsonObject { ["items"] = R("sources") }, ["events_summary"] = R("events_summary"), ["entity_summary"] = R("entity_summary"),
            ["jobs"] = new JsonObject { ["items"] = R("jobs") }, ["reports"] = new JsonObject { ["items"] = R("reports") }, ["role_views"] = roleViews,
            ["diagnostics"] = new JsonObject { ["cache_hit"] = false, ["cache_age_ms"] = 0, ["cache_ttl_seconds"] = Ttl, ["stale"] = false, ["refreshing"] = false, ["total_duration_ms"] = durationMs, ["build_duration_ms"] = durationMs, ["response_duration_ms"] = durationMs, ["components_ms"] = componentsMs, ["components"] = diagnostics, ["failures"] = new JsonArray(failures.Order().Select(f => (JsonNode)JsonValue.Create(f)!).ToArray()), ["request_model"] = "parallel_bounded_snapshot" } };
    }
    internal async Task<JsonObject> Events(CancellationToken ct) {
        int sample = Sample("ADLOG_DASHBOARD_RECENT_EVENT_SAMPLE", 50000, 250000);
        var boundary = EventReadService.ShortBoundary(config).UtcDateTime;
        var summary = (await Read(WorkspaceOverview.SummarySql, ct, boundary)).FirstOrDefault();
        string cte = "with short_events as (" + EntityShortSql.Source("@p0") + "), admitted as (select e.* from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id) ";
        var channels = await Read(cte + "select channel,sum(event_count)::bigint as count from admitted group by channel order by count desc,channel", ct, boundary);
        var top = await Read(cte + ", recent as (select * from admitted order by time_created_utc desc,id desc nulls last,summary_key desc limit @p1) select event_id,channel,sum(event_count)::bigint as count from recent group by event_id,channel order by count desc,event_id limit 20", ct, boundary, sample);
        var important = WorkspaceJson.Declarations.GetProperty("important_event_ids").EnumerateArray().Select(n => n.GetInt32()).ToHashSet();
        return new() { ["total_events"] = N(summary?["events_total"]) > 0 ? N(summary?["events_total"]) : channels.Sum(r => N(r?["count"])), ["by_channel"] = channels, ["top_event_ids"] = top,
            ["by_server"] = await Read(cte + "select s.hostname,s.fqdn,s.role,s.is_active,s.os_name,s.os_version,d.fqdn as domain_fqdn,si.name as site_name,coalesce(sum(e.event_count),0)::bigint as count from servers s join domains d on d.id=s.domain_id left join sites si on si.id=s.site_id left join admitted e on e.server_id=s.id and e.domain_id=s.domain_id group by s.id,s.hostname,s.fqdn,s.role,s.is_active,s.os_name,s.os_version,d.fqdn,si.name order by s.hostname", ct, boundary),
            ["by_server_channel"] = await Read(cte + "select s.hostname,e.channel,sum(e.event_count)::bigint as count from admitted e join servers s on s.id=e.server_id and s.domain_id=e.domain_id group by s.hostname,e.channel order by s.hostname,e.channel", ct, boundary),
            ["security_24h_summary"] = new JsonObject { ["important_total"] = top.Where(r => important.Contains((int)N(r?["event_id"]))).Sum(r => N(r?["count"])), ["mode"] = "recent_bounded_sample", ["sample_size"] = sample },
            ["dashboard_mode"] = "postgres_v2_bounded_catalog", ["estimated"] = false, ["catalog_event_rows"] = channels.Sum(r => N(r?["count"])), ["recent_sample_size"] = sample,
            ["limitations"] = new JsonArray("top_event_ids is calculated from a bounded recent event sample", "deep event reports keep exact query semantics") };
    }
    internal async Task<JsonObject> Entities(CancellationToken ct) {
        int sample = Sample("ADLOG_DASHBOARD_RECENT_ENTITY_SAMPLE", 20000, 100000);
        var summary = (await Read(WorkspaceOverview.SummarySql, ct, EventReadService.ShortBoundary(config).UtcDateTime)).FirstOrDefault();
        var count = (await Read(ShortLinkCountSql,ct,EventReadService.ShortBoundary(config).UtcDateTime)).FirstOrDefault();
        return new() { ["total_entities"] = N(summary?["entities_total"]), ["total_event_entity_links"] = N(count?["count"]),
            ["by_type"] = await Read("with recent as (select t.value as entity_type from entities_v2_active e join storage_v2_entity_type t on t.id=e.entity_type_id order by e.id desc limit @p0) select entity_type,count(*)::bigint as count from recent group by entity_type order by count desc,entity_type", ct, sample),
            ["by_role"] = await RecentLinkRolesAsync(sample, ct),
            ["dashboard_mode"] = "postgres_v2_statistics_and_sample", ["estimated"] = true, ["recent_sample_size"] = sample, ["limitations"] = new JsonArray("entity/link totals use PostgreSQL statistics estimates", "type/role distribution uses a bounded recent sample", "deep entity reports keep exact query semantics") };
    }
    internal async Task<JsonArray> RecentLinkRolesAsync(int sampleLimit, CancellationToken ct) {
        return await Read("with short_events as ("+EntityShortSql.Source("@p1")+") " + """
            , recent as (select * from short_events order by time_created_utc desc,id desc nulls last,summary_key desc limit @p0)
            select link.link_role,sum(e.event_count)::bigint as count from recent e
            cross join lateral public.short_event_entity_links339(e.event_id,e.actor,e.target,e.source,e.computer,e.method,e.fields) link
            group by link.link_role order by count desc,link.link_role
            """,ct,sampleLimit,EventReadService.ShortBoundary(config).UtcDateTime);
    }
    // Keep the dashboard's statistics estimate: sample each compact layer,
    // weight daily rows by their real event_count, and scale by leaf statistics.
    // An unanalyzed/small layer uses at least the observed sample size.
    internal const string ShortLinkCountSql = """
        with samples as (
            (select 'event_hot' as layer,case when time_created_utc>=@p0 then 1 else 0 end::bigint as weight,
                (select count(*) from public.short_event_entity_links339(event_kind,actor,target,source,computer,method,fields)) as link_count
                from event_hot order by time_created_utc desc,event_id desc limit 1000)
            union all
            (select 'event_cold_facts',case when time_created_utc<@p0 then 1 else 0 end::bigint,
                (select count(*) from public.short_event_entity_links339(event_kind,actor,target,source,computer,method,fields))
                from event_cold_facts order by time_created_utc desc,event_id desc limit 1000)
            union all
            (select 'event_cold_daily',case when day<(@p0 at time zone 'UTC')::date then event_count else 0 end,
                (select count(*) from public.short_event_entity_links339(event_kind,actor,target,source,computer,method,'{}'::jsonb))
                from event_cold_daily order by day desc,grouping_key desc limit 1000)
        ), estimates as (
            select parent.relname as layer,sum(greatest(coalesce(c.reltuples,0),coalesce(s.n_live_tup,0))) as rows
            from pg_inherits i join pg_class c on c.oid=i.inhrelid join pg_class parent on parent.oid=i.inhparent
            left join pg_stat_user_tables s on s.relid=c.oid
            where i.inhparent in ('event_hot'::regclass,'event_cold_facts'::regclass,'event_cold_daily'::regclass) group by parent.relname
        ), totals as (
            select s.layer,avg(s.weight*s.link_count) * greatest(count(*),coalesce(max(e.rows),0)) as links
            from samples s left join estimates e on e.layer=s.layer group by s.layer
        ) select coalesce(sum(links),0)::bigint as count from totals
        """;
    internal async Task<JsonObject> Findings(CancellationToken ct) => new() {
        ["generated_at_utc"] = DateTimeOffset.UtcNow, ["status"] = "ok", ["backend"] = "postgres",
        ["items"] = await Read("select id,fingerprint,rule_code,title,severity,confidence,status,first_seen_utc,last_seen_utc,actor,target,source,summary,evidence_count,repeat_count,assigned_to,status_reason,last_repeat_detected_at,updated_at from findings_active order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,coalesce(last_seen_utc,updated_at::text) desc limit 50", ct),
        ["summary"] = await Read("select severity,status,count(*) as count from findings_active group by severity,status", ct),
        ["filters"] = new JsonObject { ["limit"] = 50 }, ["details_included"] = false, ["dashboard_mode"] = "lightweight_two_query",
        ["limitations"] = new JsonArray("evidence, related entities and status history are available on dedicated findings endpoints")
    };
    internal static JsonObject RoleViews(JsonNode events, JsonNode entities, JsonNode collector, JsonNode system, JsonNode findings, JsonNode ai, JsonNode sources) {
        var security = A(collector["items"]).Where(i => S(i?["channel"]) == "Security").ToArray();
        long[] lags = security.Select(i => long.TryParse(i?["lag_minutes"]?.ToString(), out var lag) ? (long?)lag : null).Where(l => l is not null).Select(l => l!.Value).ToArray();
        long active = A(findings["items"]).Count(f => S(f?["status"]) is not ("closed" or "false_positive"));
        var summary = new JsonObject { ["sources"] = A(sources).Count, ["total_events"] = N(events["total_events"]), ["security_events"] = A(events["by_channel"]).Where(c => S(c?["channel"]) == "Security").Sum(c => N(c?["count"])), ["entities"] = N(entities["total_entities"]), ["active_findings"] = active, ["ai_runs"] = A(ai["items"]).Count, ["security_high"] = N(collector["summary"]?["security_high"]), ["worst_security_lag_minutes"] = lags.Length == 0 ? null : lags.Max(), ["system_status"] = system["status"]?.DeepClone() };
        var views = JsonNode.Parse(WorkspaceJson.ReadResource("role-view-templates.json"))!.AsArray();
        JsonNode?[][] values = [[JsonValue.Create(active), summary["security_events"]?.DeepClone(), JsonValue.Create(lags.Length == 0 ? "—" : lags.Max() + " мин"), JsonValue.Create(A(ai["items"]).Count)], [summary["sources"]?.DeepClone(), summary["security_high"]?.DeepClone(), system["retention"]?["candidates"]?.DeepClone(), system["status"]?.DeepClone()], [summary["total_events"]?.DeepClone(), JsonValue.Create(A(events["by_channel"]).Count), summary["entities"]?.DeepClone(), entities["total_event_entity_links"]?.DeepClone()]];
        for (int i = 0; i < views.Count; i++) { var view = views[i]!; for (int j = 0; j < 4; j++) view["metrics"]![j]!["value"] = values[i][j]; view["status"] = i == 2 ? "ok" : N(summary["security_high"]) > 0 ? "high" : i == 0 && active > 0 || i == 1 && S(system["status"]) == "warn" ? "warn" : "ok"; }
        return new() { ["generated_at_utc"] = DateTimeOffset.UtcNow, ["principle"] = "Ролевые представления не удаляют данные: они только меняют порядок и акценты.", ["summary"] = summary, ["views"] = views };
    }
    private JsonArray Reports() => Reports(Path.Combine(settings.DataDirectory, "reports"));
    internal static JsonArray Reports(string directory) {
        var items = new JsonArray(); var source = JsonNode.Parse(WorkspaceJson.ReadResource("legacy-reports.json"))!; var metadata = source["metadata"]!.AsObject();
        string root = new OperationsFiles(new ConfigurationBuilder().Build()).Root;
        var files = Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*.html").Select(p => new FileInfo(p)).Where(f => metadata.ContainsKey(f.Name) || f.Name.EndsWith("-security-profile.html", StringComparison.Ordinal)).OrderByDescending(f => f.LastWriteTimeUtc).ToArray() : [];
        foreach (var file in files) {
            var item = metadata[file.Name]?.DeepClone().AsObject() ?? new JsonObject { ["kind"] = "html_report", ["server"] = null, ["title"] = file.Name, ["roles"] = new JsonArray("security", "it", "technical"), ["focus_group"] = "shared", ["navigation_priority"] = 1000 };
            if (!metadata.ContainsKey(file.Name) && file.Name.StartsWith("server-", StringComparison.Ordinal)) { string server = file.Name[7..^22]; item["kind"] = "server_security_profile"; item["server"] = server; item["title"] = "Профиль безопасности " + server; }
            item["name"] = file.Name; string relative = Path.GetRelativePath(root, file.FullName); item["path"] = relative.StartsWith("..", StringComparison.Ordinal) ? file.FullName : relative;
            item["size_bytes"] = file.Length; item["updated_at"] = new DateTimeOffset(file.LastWriteTimeUtc).ToUnixTimeMilliseconds() / 1000d; item["url"] = "/reports/" + file.Name; items.Add(item);
        }
        var existing = items.Select(i => S(i?["name"])).ToHashSet();
        foreach (var dynamic in source["dynamic"]!.AsArray().Reverse()) {
            string name = S(dynamic![0]); if (existing.Contains(name)) continue;
            var item = metadata[name]!.DeepClone().AsObject(); item["name"] = name; item["path"] = "dynamic:/reports/" + name; item["size_bytes"] = null; item["updated_at"] = null; item["url"] = "/reports/" + name; item["dynamic"] = true; items.Insert(0, item);
        }
        return items;
    }
}

