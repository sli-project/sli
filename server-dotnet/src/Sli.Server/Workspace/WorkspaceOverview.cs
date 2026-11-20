using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Workspace.WorkspaceJson;
using static Sli.Server.Workspace.AgentCollectionOverview;

namespace Sli.Server.Workspace;

public sealed class WorkspaceOverview(IWorkspaceRows rows, DashboardSnapshotReader snapshots, IConfiguration? config = null)
{
    internal DashboardRiskProjection RiskProjection { get; init; } = DashboardRiskProjection.Bundled;
    internal const string SourcesSql = """
        select s.hostname,coalesce(s.fqdn,inventory.attrs->>'dns_host_name') as fqdn,s.role,s.is_active,
               coalesce(inventory.attrs->>'operating_system',s.os_name) as os_name,
               coalesce(inventory.attrs->>'operating_system_version',s.os_version) as os_version,si.name as site,
               inventory.attrs->'ip_addresses' as ip_addresses,inventory.attrs->'logical_disks' as logical_disks,
               inventory.attrs->>'technical_inventory_status' as technical_inventory_status,
               inventory.observed as inventory_observed_at_utc,
               case when inventory.observed is not null then 'ad_context' end as inventory_source
        from servers s join domains d on d.id=s.domain_id left join sites si on si.id=s.site_id
        left join lateral (
            select case when count(*)=1 then (array_agg(v.attributes_json->'attributes'))[1] end as attrs,
                   case when count(*)=1 then max(v.last_observed_at_utc) end as observed
            from ad_context_entity_versions v join ad_context_runs run on run.run_id=v.source_run_id
            where run.domain_id=s.domain_id and v.valid_to_utc is null and v.source_section='directory_accounts'
              and lower(v.attributes_json->'identity'->>'kind')='ad_computer'
              and (lower(rtrim(v.attributes_json->'attributes'->>'dns_host_name','.'))=lower(rtrim(coalesce(s.fqdn,s.hostname||'.'||d.fqdn),'.'))
                or lower(trim(trailing '$' from v.attributes_json->'attributes'->>'sam_account_name'))=lower(split_part(s.hostname,'.',1)))
        ) inventory on true order by lower(s.hostname),s.id limit 50
        """;
    internal const string CollectorSql = """
        select c.server_hostname as server,c.channel,c.last_successful_collection_utc,c.last_event_time_utc,
               c.last_event_record_id,a.current_limit as adaptive_limit,a.recovery_mode,a.last_action as adaptive_action,
               coalesce(latest.status,a.last_status) as last_status,latest.backend_reason as failure_reason
        from collection_channel_state c
        left join collector_adaptive_state a on a.server=c.server_hostname and a.channel=c.channel
        left join lateral (select status,backend_reason from collector_channel_runs r
            where r.server=c.server_hostname and r.channel=c.channel order by coalesce(r.finished_utc,r.created_at::text) desc,r.id desc limit 1) latest on true
        order by c.server_hostname,c.channel
        """;
    internal static readonly string SummarySql = "with short_events as (" + EntityShortSql.Source("@p0") + ") " + """
        select (select coalesce(sum(e.event_count),0) from short_events e
                   join servers s on s.id=e.server_id and s.domain_id=e.domain_id)::bigint as events_total,
               greatest(0,coalesce(max(estimate) filter(where relname='entities_v2'),0)
                 -coalesce(max(estimate) filter(where relname='entity_identity_merges_v2'),0))::bigint as entities_total
        from (select pc.relname,greatest(coalesce(st.n_live_tup,0),coalesce(pc.reltuples,0)) as estimate
              from pg_class pc join pg_namespace pn on pn.oid=pc.relnamespace
              left join pg_stat_user_tables st on st.relid=pc.oid where pn.nspname=current_schema()
                and pc.relname in ('entities_v2','entity_identity_merges_v2')) estimates
        """;
    internal const string FindingsSql = """
        select id,title,severity,status,actor,target,source,last_seen_utc,evidence_count,assigned_to,updated_at,
               last_evidence_event_id as event_db_id from findings_active
        order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'low' then 4 else 5 end,
                 coalesce(last_seen_utc,updated_at::text) desc limit 12
        """;
    internal const string WorkerSql = """
        select worker_id,status,phase,details_json,heartbeat_at from runtime_worker_heartbeats where worker_name='collection'
        """;

    public async Task<object> ReadAsync(IQueryCollection query, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        DateTimeOffset? Parse(string name) => DateTimeOffset.TryParse(query[name].FirstOrDefault(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var value) ? value.ToUniversalTime() : null;
        var end = Parse("time_to") ?? now;
        var start = Parse("time_from") ?? end.AddHours(-24);
        if (end <= start || end - start > TimeSpan.FromDays(8)) start = end.AddHours(-24);
        string? selected = query["server"].FirstOrDefault()?.Trim();
        if (string.IsNullOrEmpty(selected)) selected = null;
        var failures = new List<string>();
        async Task<IReadOnlyList<JsonElement>> Read(string sql, string section, params NpgsqlParameter[] parameters)
        {
            try { return await rows.ReadAsync(sql, ct, parameters); }
            catch (Exception error) when (!ct.IsCancellationRequested && error is NpgsqlException or TimeoutException)
            { failures.Add(section); return []; }
        }
        // DashboardSnapshotReader owns cache freshness and background refresh. A page
        // refresh adapts that snapshot; it never forces the dashboard to rebuild.
        var snapshot = JsonSerializer.SerializeToElement(await snapshots.ReadAsync(false, ct));
        var diagnostics = snapshot.Get("diagnostics");
        bool warming = diagnostics.Text("request_model") == "startup_warming_response";
        IReadOnlyList<JsonElement> sources = snapshot.Get("sources").Get("items").Items().ToArray();
        if (sources.Count == 0 && warming || sources.Any(s => new[] { "fqdn", "os_name", "os_version", "ip_addresses" }.Any(key => s.Get(key).ValueKind == JsonValueKind.Undefined)))
            sources = MergeInventory(sources, await Read(SourcesSql, "sources"));
        IReadOnlyList<JsonElement> channels = snapshot.Get("collector_health").Get("items").Items().ToArray();
        if (channels.Count == 0 && warming) channels = await Read(CollectorSql, "collector_health");
        var events = snapshot.Get("events_summary");
        var entities = snapshot.Get("entity_summary");
        var summary = JsonSerializer.SerializeToElement(new { events_total = Number(events, "total_events"), entities_total = Number(entities, "total_entities"),
            important_recent = Number(events.Get("security_24h_summary"), "important_total") });
        var findings = snapshot.Get("role_views").Get("findings");
        if (findings.ValueKind != JsonValueKind.Object || !findings.EnumerateObject().Any()) findings = snapshot.Get("findings");
        var alerts = findings.Get("items").Items().Take(12).ToArray();
        var progressChannels = await Read(CollectorSql, "collection_progress");
        var worker = (await Read(WorkerSql, "workers")).FirstOrDefault();
        int buckets = end - start > TimeSpan.FromDays(2) ? 7 : 24;
        var risk = RiskProjection.Get();
        var parameters = new List<NpgsqlParameter> { new("start", start), new("end", end), new("buckets", buckets),
            new("seconds", (end - start).TotalSeconds / buckets), new("server", NpgsqlDbType.Text) { Value = (object?)selected ?? DBNull.Value },
            new("boundary", EventReadService.ShortBoundary(config)) };
        int index = 0;
        foreach (var parameter in risk.Parameters)
            parameters.Add(new("risk" + index++, parameter));
        string activitySql = "with short_events as (" + EntityShortSql.Source("@boundary", daily:false) + ") " + """
            select bucket,final_security_severity,sum(event_count)::bigint as count from (
                select least(@buckets-1,greatest(0,floor(extract(epoch from(e.time_created_utc-@start::timestamptz))/@seconds)::int)) as bucket,
                e.event_count,
            """ + risk.Sql + """
                as final_security_severity from (
                    select core.*,jsonb_build_object('TaskName',native.data->'TaskName','Action',native.data->'Action',
                        'Author',native.data->'Author','RunAs',native.data->'RunAs',
                        'ProcessName',native.data->'ProcessName','Message',native.data->'Message')::text as event_data_json
                    from short_events core cross join lateral (select core.fields || core.method || core.outcome as data) native
                ) e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
                where e.time_created_utc>=@start::timestamptz and e.time_created_utc<@end::timestamptz
                  and (@server::text is null or lower(s.hostname)=lower(@server))
            ) semantic_events group by bucket,final_security_severity order by bucket,final_security_severity
            """;
        var activity = await Read(activitySql, "activity", parameters.ToArray());
        var result = JsonSerializer.SerializeToNode(Compose(sources, channels, summary, alerts, worker, activity, start, end, selected, now, failures, risk.Exact, progressChannels))!.AsObject();
        result["generated_at_utc"] = snapshot.Get("generated_at_utc").ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? null : JsonNode.Parse(snapshot.Get("generated_at_utc").GetRawText());
        result["status"] = snapshot.Text("status", "warming");
        result["data_state"] = new JsonObject { ["cache"] = diagnostics.Text("response_model", "warming"), ["stale"] = Flag(diagnostics, "stale"),
            ["failures"] = JsonSerializer.SerializeToNode(diagnostics.Get("failures").Items().ToArray()) };
        result["metrics"]!["events_estimated"] = Flag(events, "estimated");
        result["metrics"]!["entities_estimated"] = Flag(entities, "estimated");
        return result;
    }

    static IReadOnlyList<JsonElement> MergeInventory(IReadOnlyList<JsonElement> cached, IReadOnlyList<JsonElement> live)
    {
        var merged = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in cached.Concat(live))
        {
            string hostname = item.Text("hostname").Trim();
            if (hostname.Length == 0) continue;
            if (!merged.TryGetValue(hostname, out var current)) merged[hostname] = current = new();
            foreach (var field in item.EnumerateObject())
            {
                if (field.Name == "hostname" && current.ContainsKey(field.Name)) continue;
                bool empty = field.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined || field.Value.ValueKind == JsonValueKind.String && field.Value.GetString() == ""
                    || field.Value.ValueKind == JsonValueKind.Array && field.Value.GetArrayLength() == 0;
                if (!empty || !current.ContainsKey(field.Name)) current[field.Name] = JsonNode.Parse(field.Value.GetRawText());
            }
        }
        return merged.Values.Select(v => JsonSerializer.SerializeToElement(v)).ToArray();
    }

    public static object Compose(IReadOnlyList<JsonElement> sources, IReadOnlyList<JsonElement> channels, JsonElement summary,
        IReadOnlyList<JsonElement> alerts, JsonElement worker, IReadOnlyList<JsonElement> activity,
        DateTimeOffset start, DateTimeOffset end, string? selected, DateTimeOffset now, IReadOnlyList<string> failures, bool exact,
        IReadOnlyList<JsonElement>? progressChannels = null)
    {
        var inventory = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in sources)
        {
            var item = JsonSerializer.SerializeToNode(new { hostname = source.Text("hostname"), fqdn = TextOrNull(source, "fqdn"),
                role = TextOrNull(source, "role"), active = NullableFlag(source, "is_active"), registered = true, site = TextOrNull(source, "site"),
                os_name = TextOrNull(source, "os_name"), os_version = TextOrNull(source, "os_version"),
                ip_addresses = source.Get("ip_addresses").Strings().Where(s => IPAddress.TryParse(s, out _)).ToArray(),
                disks = Disks(source), disk_state = DiskState(source), inventory_observed_at_utc = Iso(Time(source, "inventory_observed_at_utc")),
                inventory_source = TextOrNull(source, "inventory_source"), collection_state = (string?)null, collection_label = (string?)null,
                last_successful_collection_utc = (string?)null, last_event_time_utc = (string?)null, channels_total = 0, channels = Array.Empty<object>() })!.AsObject();
            if (source.Text("hostname").Length > 0) inventory[source.Text("hostname")] = item;
        }
        foreach (var group in channels.GroupBy(c => c.Text("server"), StringComparer.OrdinalIgnoreCase))
        {
            if (group.Key.Length == 0) continue;
            if (!inventory.TryGetValue(group.Key, out var source))
            {
                source = JsonSerializer.SerializeToNode(new { hostname = group.Key, fqdn = (string?)null, role = (string?)null, active = (bool?)null,
                    registered = false, site = (string?)null, os_name = (string?)null, os_version = (string?)null, ip_addresses = Array.Empty<string>(),
                    disk_state = "not_collected", disks = Array.Empty<object>(), inventory_observed_at_utc = (string?)null, inventory_source = (string?)null })!.AsObject();
                inventory[group.Key] = source;
            }
            var freshness = Freshness(group.ToArray(), now);
            source["collection_state"] = freshness["state"]!.DeepClone(); source["collection_label"] = freshness["label"]!.DeepClone();
            source["last_successful_collection_utc"] = freshness["checked_at_utc"]?.DeepClone();
            source["last_event_time_utc"] = freshness["latest_event_utc"]?.DeepClone(); source["channels_total"] = group.Count();
            source["channels"] = JsonSerializer.SerializeToNode(group.Select(c => new { server = TextOrNull(c, "server"), channel = TextOrNull(c, "channel"),
                collection_state = Freshness([c], now)["state"]!.GetValue<string>(), last_status = TextOrNull(c, "last_status"), failure_reason = FailureReason(c),
                last_successful_collection_utc = Iso(Time(c, "last_successful_collection_utc")), last_event_time_utc = Iso(Time(c, "last_event_time_utc")) }));
        }
        var allSources = inventory.Values.OrderBy(s => s["hostname"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).Take(50).ToArray();
        int count = end - start > TimeSpan.FromDays(2) ? 7 : 24;
        var bars = Enumerable.Range(0, count).Select(i => new JsonObject { ["index"] = i,
            ["bucket_start_utc"] = Iso(start.AddTicks((end-start).Ticks * i/count)), ["bucket_end_utc"] = Iso(start.AddTicks((end-start).Ticks*(i+1)/count)),
            ["critical"] = 0L, ["important"] = 0L, ["informational"] = 0L }).ToArray();
        foreach (var row in activity)
        {
            int bucket = (int)Number(row, "bucket"); if (bucket < 0 || bucket >= count) continue;
            string category = row.Text("final_security_severity") is "critical" or "high" ? "critical" : row.Text("final_security_severity") == "medium" ? "important" : "informational";
            bars[bucket][category] = bars[bucket][category]!.GetValue<long>() + Number(row, "count");
        }
        var relevant = channels.Where(c => selected is null || string.Equals(c.Text("server"), selected, StringComparison.OrdinalIgnoreCase)).ToArray();
        return new { api_version = "v1", generated_at_utc = Iso(now), status = failures.Count == 0 ? "ok" : "partial",
            data_state = new { cache = "live", stale = false, failures },
            metrics = new { events_total = Number(summary, "events_total"), events_estimated = true, entities_total = Number(summary, "entities_total"), entities_estimated = true,
                important_recent = Number(summary, "important_recent"), sources_total = allSources.Length },
            alerts = alerts.Where(a => (selected is null || a.Text("source").Contains(selected, StringComparison.OrdinalIgnoreCase))
                && (Time(a, "last_seen_utc") is not { } time || time >= start && time < end)).Take(12).Select(a => new {
                    id = Number(a, "id"), title = a.Text("title"), severity = a.Text("severity", "unknown"), status = a.Text("status", "unknown"),
                    actor = TextOrNull(a, "actor"), target = TextOrNull(a, "target"), source = TextOrNull(a, "source"), last_seen_utc = TextOrNull(a, "last_seen_utc"),
                    evidence_count = Number(a, "evidence_count"), assigned_to = TextOrNull(a, "assigned_to"), updated_at = TextOrNull(a, "updated_at"),
                    event_db_id = a.Get("last_evidence_event_id").ValueKind == JsonValueKind.Number ? (long?)Number(a, "last_evidence_event_id") : null }).ToArray(),
            sources = allSources.Where(s => selected is null || string.Equals(s["hostname"]!.GetValue<string>(), selected, StringComparison.OrdinalIgnoreCase)).ToArray(),
            collection_freshness = Freshness(relevant, now), collection_progress = Progress(progressChannels ?? channels, worker, now),
            activity = new { period_label = count == 7 ? "7 дней" : "24 часа", time_from_utc = Iso(start), time_to_utc = Iso(end), selected_source = selected,
                items = failures.Contains("activity") ? [] : bars, available = !failures.Contains("activity"), exact = !failures.Contains("activity") && exact,
                reason = failures.Contains("activity") ? "read_failed" : exact ? null : "catalog_context_projection_incomplete" },
            limits = new { alerts = 12, sources = 50, full_history = false } };
    }

    private static string? TextOrNull(JsonElement row, string key) => row.Text(key) is { Length: > 0 } value ? value : null;
    private static bool? NullableFlag(JsonElement row, string key) => row.Get(key).ValueKind is JsonValueKind.True or JsonValueKind.False ? Flag(row, key)
        : row.Get(key).ValueKind == JsonValueKind.Number ? Number(row, key) != 0 : null;
    private static object[] Disks(JsonElement source) => source.Get("logical_disks").Items().Take(64).Select(d => d.GetString()?.Split('|'))
        .Where(p => p is { Length: 3 } && System.Text.RegularExpressions.Regex.IsMatch(p[0], @"\A[A-Za-z]:\z")
            && long.TryParse(p[1], out var total) && long.TryParse(p[2], out var free) && total > 0 && free >= 0 && free <= total)
        .Select(p => (object)new { name = p![0].ToUpperInvariant(), total_bytes = long.Parse(p[1]), free_bytes = long.Parse(p[2]),
            free_percent = Math.Round(long.Parse(p[2]) * 100.0 / long.Parse(p[1]), 1) }).ToArray();
    private static string DiskState(JsonElement source) => source.Text("technical_inventory_status") switch {
        "complete" => source.Get("logical_disks").Items().Any(d => { var p=d.GetString()?.Split('|'); return p is { Length:3 } && double.TryParse(p[1],out var total)
            && double.TryParse(p[2],out var free) && total>0 && free>=0 && free<=total && Math.Round(free*100/total,1)<15; }) ? "warning" : "ok",
        "failed" => "failed", "timeout" => "timeout", _ => "not_collected" };
    private static bool Error(JsonElement c) => c.Text("last_status").ToLowerInvariant() is "failed" or "error" or "timeout" or "unavailable" or "blocked" or "access_denied";
    private static string? FailureReason(JsonElement c) => Error(c)
        ? TextOrNull(c, "failure_reason") is { Length: > 0 } reason ? reason : TextOrNull(c, "last_status") : null;
    public static JsonObject Freshness(IReadOnlyList<JsonElement> channels, DateTimeOffset now)
    {
        var lags = channels.Select(c => Age(Time(c, "last_successful_collection_utc"), now) / 60).ToArray();
        var eventLags = channels.Select(c => Age(Time(c, "last_event_time_utc"), now) / 60).ToArray();
        long? worst = lags.Where(l => l is not null).DefaultIfEmpty(null).Max();
        int failed = channels.Count(Error);
        string state = failed > 0 && failed < channels.Count ? "partial" : failed > 0 ? "error" : worst is null || lags.Any(l => l is null) || worst > 20 ? "stale" : worst > 5 ? "lagging" : "current";
        return JsonSerializer.SerializeToNode(new { state, label = state switch { "partial" => "Частичный сбор", "error" => "Ошибка сбора", "stale" => "Данные сильно устарели", "lagging" => "Есть отставание", _ => "Данные актуальны" },
            worst_lag_minutes = worst, checked_at_utc = Iso(channels.Select(c => Time(c,"last_successful_collection_utc")).Where(t=>t is not null).DefaultIfEmpty(null).Min()),
            latest_event_utc = Iso(channels.Select(c => Time(c,"last_event_time_utc")).Where(t=>t is not null).DefaultIfEmpty(null).Max()),
            worst_event_lag_minutes = eventLags.Where(l=>l is not null).DefaultIfEmpty(null).Max(), collection_error = failed > 0,
            channels_failed = failed, channels_total = channels.Count, channels_checked = lags.Count(l=>l is not null), basis = "last_successful_collection" })!.AsObject();
    }
    private static object Progress(IReadOnlyList<JsonElement> channels, JsonElement worker, DateTimeOffset now)
    {
        var items = channels.Select(c => new { server = TextOrNull(c,"server"), channel = TextOrNull(c,"channel"), recovery_mode = Flag(c,"recovery_mode"),
            boundary_reached = !Flag(c,"recovery_mode") && (c.Text("last_status")=="completed" || c.Text("adaptive_action").StartsWith("exit_recovery:source_boundary_reached",StringComparison.Ordinal)),
            boundary_checked_at_utc = !Flag(c,"recovery_mode") && (c.Text("last_status")=="completed" || c.Text("adaptive_action").StartsWith("exit_recovery:source_boundary_reached",StringComparison.Ordinal)) ? Iso(Time(c,"last_successful_collection_utc")) : null,
            check_state = Freshness([c],now)["state"]!.GetValue<string>(), last_status = TextOrNull(c,"last_status"), failure_reason = FailureReason(c),
            current_limit = c.Get("adaptive_limit").ValueKind == JsonValueKind.Number ? (long?)Number(c,"adaptive_limit") : null,
            last_event_record_id = c.Get("last_event_record_id").ValueKind == JsonValueKind.Number ? (long?)Number(c,"last_event_record_id") : null,
            last_event_time_utc = Iso(Time(c,"last_event_time_utc")), last_successful_collection_utc = Iso(Time(c,"last_successful_collection_utc")), last_action = TextOrNull(c,"adaptive_action") }).ToArray();
        string check = Freshness(channels,now)["state"]!.GetValue<string>();
        var job = worker.Get("details_json").Get("active_job");
        string status = items.Any(i=>i.check_state=="error") ? "failed" : worker.Text("status") is "failed" or "error" ? "failed" : worker.Text("status")=="blocked" ? "blocked"
            : worker.Text("status")=="running" || job.Text("status")=="running" ? "running"
            : items.Length>0 && items.All(i=>i.boundary_reached) && check=="current" ? "completed" : items.Any(i=>i.recovery_mode) ? "partial"
            : items.Length>0 && check is "stale" or "lagging" ? check : "unknown";
        return new { status, check_state = check, block_reason = (string?)null, blocked_since_utc = (string?)null, source = "postgres_adaptive_state_and_worker_heartbeat",
            channels_total = items.Length, boundaries_reached = items.Count(i=>i.boundary_reached), channels_in_recovery = items.Count(i=>i.recovery_mode),
            worker_id = TextOrNull(worker,"worker_id"), worker_status = worker.Text("status","unknown"), worker_phase = TextOrNull(worker,"phase"), heartbeat_at = Iso(Time(worker,"heartbeat_at")),
            job_id = job.Get("job_id").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? null : (object)job.Get("job_id"),
            job_status = TextOrNull(job,"status"), job_phase = TextOrNull(job,"phase"), items, recovery_items = items.Where(i=>i.recovery_mode).ToArray() };
    }
}
