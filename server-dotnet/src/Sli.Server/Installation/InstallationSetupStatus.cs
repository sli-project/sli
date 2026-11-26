using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService
{
    static async Task<T?> Safe<T>(Func<Task<T>> read) where T : class?
    {
        try { return await read(); }
        catch (Exception e) when (e is NpgsqlException or InstallationException or InvalidOperationException or IOException or ArgumentException) { return null; }
    }
    static bool? AnyState(IEnumerable<JsonNode?> values)
    {
        var items = values.ToArray(); return items.Any(Bool) ? true : items.Any(v => v is null) ? null : false;
    }
    static JsonArray Instances(JsonObject? source) => source?["instances"] as JsonArray ?? new();
    public async Task<JsonObject> SetupStatusAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var report = await Safe(async () =>
        {
            var setting = (await SettingsAsync(ct)).OfType<JsonObject>().Single(i => Text(i["key"]) == "reports.domain_fqdn");
            if (Text(setting["effective_state"]) == "unavailable") throw new InvalidOperationException("report_domain_metadata_unavailable");
            string value = Text(setting["effective_value"]);
            var result = new JsonObject { ["key"] = "reports.domain_fqdn", ["value"] = value,
                ["source"] = value == Text(setting["value"]) ? Text(setting["source"]) : value.Length > 0 ? "default" : "not_configured" };
            if (Text(setting["value"]).Length > 0 && Text(setting["value"]) != value)
            {
                result["configured_value"] = setting["value"]!.DeepClone();
                result["suggested_value"] = await SuggestedDomainAsync(Text(setting["value"]), ct);
            }
            return result;
        });
        var domains = await Safe(() => DomainsAsync(ct));
        var controllers = await Safe(() => ControllersAsync(ct));
        var health = await SetupCollectionHealth.ReadAsync(database, ct);
        var bindings = health["_setup_bindings"]?.DeepClone().AsArray() ?? new(); health.Remove("_setup_bindings");
        var sources = new JsonArray();
        foreach (string file in new[] { "ad_context", "dc", "file_audit", "radius", "workstations" })
        {
            var pack = InstallationPackages.Contract("source_packs/" + file + ".json");
            if (pack["source_kind"] is null) pack["source_kind"] = "event";
            string id = Text(pack["pack_id"]);
            JsonArray? configured = id is "sli.windows.ad-dc" or "sli.windows.ad-context"
                ? await Safe(() => { using var admission = Admission("sli.ad"); return Task.FromResult(AgentSourceConfiguration(id, controllers, domains, health, bindings)); })
                : id == "sli.windows.vpn-radius" ? await Safe(() => RadiusConfigurationAsync(ct)) : null;
            JsonObject source;
            if (id is "sli.windows.ad-dc" or "sli.windows.ad-context")
            {
                if (id == "sli.windows.ad-context" && configured is { Count: > 0 })
                {
                    var history = await Safe(() => SourceDataAsync(pack, configured, ct));
                    foreach (var instance in configured.OfType<JsonObject>())
                        if (instance["last_data_utc"] is null && history?[Text(instance["source_instance_id"]).ToLowerInvariant()] is { } stamp)
                            instance["last_data_utc"] = stamp.DeepClone();
                }
                source = SourceSummary(pack, configured, null);
                source["collection_basis"] = "agents";
            }
            else source = await LegacySourceStatusAsync(pack, configured, now, ct);
            sources.Add(source);
        }
        var instances = sources.OfType<JsonObject>().SelectMany(s => Instances(s).OfType<JsonObject>()).ToArray();
        var ready = instances.Where(i => Bool(i["configured"]) && Bool(i["enabled"])).ToArray();
        int fresh = ready.Count(i => Bool(i["data_received"]));
        string sourceState = ready.Length > 0 ? "done" : sources.OfType<JsonObject>().Any(s => s["configured"] is null || Text(s["activation_state"]) == "unavailable") ? "unavailable" : "todo";
        string collectionState = health["diagnostics"] is not null || Text(health["state"]) is "unknown" or "unavailable" ? "unavailable" : Text(health["state"]) == "current" ? "done" : "todo";
        int? connectedControllers = health["connected_domain_controllers"]?.GetValue<int>();
        string controllerState = connectedControllers is null ? "unavailable" : connectedControllers > 0 ? "done" : "todo";
        JsonObject? next = null;
        foreach (var source in sources.OfType<JsonObject>())
        {
            var instance = Instances(source).OfType<JsonObject>().FirstOrDefault(i => Text(i["next_action"]).Length > 0);
            if (instance is null) continue;
            next = new() { ["pack_id"] = source["pack_id"]!.DeepClone(), ["source_instance_id"] = instance["source_instance_id"]!.DeepClone(), ["action"] = instance["next_action"]!.DeepClone() }; break;
        }
        if (next is null)
        {
            var source = sources.OfType<JsonObject>().FirstOrDefault(s => Instances(s).Count == 0);
            if (source is not null) next = new() { ["pack_id"] = source["pack_id"]!.DeepClone(), ["source_instance_id"] = null, ["action"] = source["configured"] is not null && !Bool(source["configured"]) ? "configure" : "check_configuration" };
        }
        var checks = health["items"]!.AsArray().OfType<JsonObject>().SelectMany(a => a["modules"]!.AsArray().OfType<JsonObject>()).SelectMany(m => m["channels"]!.AsArray().OfType<JsonObject>()).Where(c => Text(c["state"]) is not ("disabled" or "paused")).ToArray();
        string? lastSuccess = checks.Select(c => Text(c["last_import_at"])).Where(t => t.Length > 0).OrderDescending(StringComparer.Ordinal).FirstOrDefault();
        static JsonObject Step(string id, string title, string state, string summary) => new() { ["id"] = id, ["title"] = title, ["state"] = state, ["summary"] = summary };
        var reportStep = Step("report-domain", "Домен отчётов", report is null ? "unavailable" : Text(report["source"]) != "not_configured" ? "done" : "todo",
            report is null ? "Значение недоступно." : Text(report["source"]) != "not_configured" ? "Домен отчётов: " + Text(report["value"]) + "." : "Домен отчётов не задан: укажите его на странице «Настройки платформы».");
        reportStep["link"] = "/platform-settings";
        var domainsStep = Step("domains", "Домены Active Directory", domains is null ? "unavailable" : domains.Count > 0 ? "done" : "todo",
            domains is null ? "Список доменов недоступен." : domains.Count > 0 ? $"Найдено доменов: {domains.Count}." : "Домены ещё не загружены.");
        domainsStep["manual"] = "Домен можно добавить на этой странице (администратору) или он появится при первой загрузке данных каталога. Удалять домены нельзя: на них ссылаются события."; domainsStep["doc"] = "docs/ADMIN_GUIDE.md";
        var dcStep = Step("domain-controllers", "Контроллеры домена", controllerState, connectedControllers is null ? "Состояние агентов контроллеров недоступно." : $"Контроллеров с работающим агентом: {connectedControllers}.");
        dcStep["link"] = "/agents";
        var sourcesStep = Step("sources", "Источники", sourceState, sourceState == "unavailable" ? "Состояние источников недоступно." : $"Настроено и включено экземпляров источников: {ready.Length}.");
        sourcesStep["manual"] = "Новые пакеты источников подключаются по инструкции разработчика."; sourcesStep["doc"] = "docs/HOW_TO_ADD_A_SOURCE.md";
        string summaryState = health["diagnostics"] is not null ? "unavailable" : Text(health["state"]);
        string summary = summaryState switch { "current" => "Сбор работает.", "error" => "Сбор прерван — проверьте агента.", "partial" => "Сбор ещё не подтверждён — проверьте агентов.", "unknown" => "Проверьте назначение и состояние агентов.", _ => "Не удалось проверить сбор — повторите проверку." };
        var collectionStep = Step("first-collection", "Первый сбор", collectionState, summary); collectionStep["link"] = "/operations";
        return new() { ["api_version"] = "v1", ["generated_at_utc"] = now.ToString("o"), ["read_only"] = true,
            ["steps"] = new JsonArray(reportStep, domainsStep, dcStep, sourcesStep, collectionStep), ["report_domain"] = report,
            ["domains"] = domains ?? new(), ["domain_controllers"] = controllers?["items"]?.DeepClone() ?? new JsonArray(),
            ["domain_controller_source"] = controllers?["source"]?.DeepClone(), ["sources"] = sources, ["next_step"] = next,
            ["collection"] = new JsonObject { ["collection_enabled"] = Text(health["state"]) == "unavailable" ? null : JsonValue.Create(Number(health["active_agents"]) > 0), ["block_reason"] = null,
                ["channels"] = checks.Length, ["last_success_utc"] = lastSuccess }, ["agent_collection"] = health };
    }
    internal async Task<string?> SuggestedDomainAsync(string configured, CancellationToken ct, double? freshnessSeconds = 86430)
    {
        if (configured.Length == 0 || freshnessSeconds is null or <= 0) return null;
        return await database.ReadAsync(async s =>
        {
            var current = First(await s.QueryAsync("select is_archived from domains where lower(fqdn)=@p0", ct, configured));
            if (current is null || !Bool(current["is_archived"])) return null;
            var rows = await s.QueryAsync("""
                select d.id,d.fqdn,d.is_archived,observed.observed_at_utc from domains d left join lateral (
                  select max(observed_at_utc) as observed_at_utc from ad_context_runs where domain_id=d.id and status='completed'
                ) observed on true where not d.is_archived order by d.id
                """, ct);
            var domains = rows.OfType<JsonObject>().Select(row => new DomainItem(Number(row["id"]), Text(row["fqdn"]), Bool(row["is_archived"]),
                new(null, null, null, null, JsonSerializer.SerializeToElement(row["observed_at_utc"]).GetString(), null, null)));
            var now = DateTimeOffset.UtcNow;
            var chosen = ReportV2Metadata.ChooseDomain(domains, null, now);
            if (chosen is null) return null;
            var stamp = DateTimeOffset.Parse(chosen.Freshness.DefaultObservedAtUtc!, CultureInfo.InvariantCulture);
            if ((now - stamp).TotalSeconds > freshnessSeconds) return null;
            return InstallationSettings.Dns(chosen.DisplayName);
        }, ct);
    }
    internal static JsonArray? AgentSourceConfiguration(string pack, JsonObject? controllers, JsonArray? domains, JsonObject health, JsonArray bindings)
    {
        bool dc = pack == "sli.windows.ad-dc"; string moduleId = dc ? "sli.windows.ad-dc" : "sli.ad-snapshot", key = dc ? "source_name" : "domain_dns";
        var own = bindings.OfType<JsonObject>().Where(b => Text(b["module_id"]) == moduleId).ToArray();
        var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var binding in own) if (Text(binding[key]).Trim() is { Length: > 0 } label) labels.TryAdd(label, label);
        var candidates = dc ? (controllers?["items"] as JsonArray ?? new()).Select(c => Text(c?["hostname"])) : (domains ?? new()).Select(d => Text(d?["fqdn"]));
        foreach (string label in candidates) labels.TryAdd(label, label);
        if (labels.Count == 0 && (Text(health["state"]) == "unavailable" || own.Length > 0)) return null;
        var result = new JsonArray();
        foreach (string label in labels.Values)
        {
            var bound = own.Where(b => Text(b[key]).Trim().Equals(label, StringComparison.OrdinalIgnoreCase)).ToArray();
            var checks = new List<JsonObject>(); bool missing = false;
            foreach (var binding in bound)
            {
                var agent = health["items"]!.AsArray().OfType<JsonObject>().FirstOrDefault(a => Text(a["id"]) == Text(binding["agent_id"]));
                var module = (agent?["modules"] as JsonArray ?? new()).OfType<JsonObject>().FirstOrDefault(m => Text(m["module_id"]) == moduleId);
                var channelChecks = module?["channels"] as JsonArray ?? new();
                if (Bool(binding["enabled"]) && channelChecks.Count == 0) missing = true;
                checks.AddRange(channelChecks.OfType<JsonObject>());
            }
            var active = checks.Where(c => Text(c["state"]) is not ("disabled" or "paused")).ToArray();
            bool? enabled = bound.Length > 0 ? bound.Any(b => Bool(b["enabled"])) : null;
            string state = bound.Length == 0 || Text(health["state"]) == "unavailable" || health["diagnostics"] is not null ? "unknown"
                : enabled == false && bound.Any(b => Bool(b["paused"])) ? "paused" : enabled == false ? "disabled"
                : active.Any(c => Text(c["state"]) == "error") ? "error" : !missing && active.Length > 0 && active.All(c => Text(c["state"]) == "current") ? "current"
                : active.Any(c => Text(c["state"]) == "lagging") ? "lagging" : active.Any(c => Text(c["state"]) == "waiting") ? "waiting" : "unknown";
            string? stamp = checks.Select(c => Text(c["last_import_at"])).Where(t => t.Length > 0).OrderDescending(StringComparer.Ordinal).FirstOrDefault();
            bool? received = state == "unknown" ? null : state == "current";
            result.Add(new JsonObject { ["source_instance_id"] = label, ["configured"] = bound.Length > 0 ? JsonValue.Create(true) : null, ["enabled"] = enabled,
                ["data_received"] = received, ["data_state"] = received == true ? "fresh" : received is null ? "unavailable" : stamp is not null ? "stale" : "never",
                ["last_data_utc"] = stamp, ["collection_state"] = state, ["next_action"] = state == "current" ? null : bound.Length == 0 ? "check_configuration" : enabled == false ? "enable" : "check_data" });
        }
        return result;
    }
    internal static JsonObject SourceSummary(JsonObject pack, JsonArray? instances, long? freshness)
    {
        bool? configured = instances is null ? null : AnyState(instances.Select(i => i?["configured"]));
        bool? enabled = instances is null ? null : AnyState(instances.Select(i => i?["enabled"]));
        bool? received = instances is null ? null : AnyState(instances.Select(i => i?["data_received"]));
        return new() { ["pack_id"] = pack["pack_id"]!.DeepClone(), ["display_name"] = pack["display_name"]!.DeepClone(), ["version"] = pack["version"]!.DeepClone(), ["source_kind"] = pack["source_kind"]!.DeepClone(),
            ["installed"] = true, ["configured"] = configured, ["enabled"] = enabled == true, ["activation_state"] = enabled is null ? "unavailable" : enabled.Value ? "enabled" : "disabled",
            ["data_received"] = received, ["data_state"] = received == true ? "fresh" : received is null ? "unavailable" : instances!.Any(i => Text(i?["last_data_utc"]).Length > 0) ? "stale" : "never",
            ["freshness_seconds"] = freshness, ["instances"] = instances ?? new() };
    }
    async Task<JsonArray?> RadiusConfigurationAsync(CancellationToken ct)
    {
        using var admission = Admission("sli.remote-access");
        var route = packages.RadiusRoute();
        var rows = await Safe(() => database.ReadAsync(s => s.QueryAsync("""
            select source_instance_id,bool_or(source_activation='manual_enabled' and subscription_activation='manual_enabled') as enabled
            from radius_vpn_operations_v1 group by source_instance_id order by source_instance_id
            """, ct), ct));
        if ((rows is null || rows.Count == 0) && route is null) return null;
        var items = new JsonArray((rows ?? new()).OfType<JsonObject>().Select(r => (JsonNode)new JsonObject { ["source_instance_id"] = r["source_instance_id"]!.DeepClone(), ["configured"] = true, ["enabled"] = Bool(r["enabled"]) }).ToArray());
        if (route is not null && !items.Any(i => Text(i?["source_instance_id"]).Equals(Text(route["source_instance_id"]), StringComparison.OrdinalIgnoreCase)))
            items.Add(new JsonObject { ["source_instance_id"] = route["source_instance_id"]!.DeepClone(), ["configured"] = true, ["enabled"] = null });
        if (route is not null)
            items.OfType<JsonObject>().First(i => Text(i["source_instance_id"]).Equals(Text(route["source_instance_id"]), StringComparison.OrdinalIgnoreCase))["collection_target"] = route["source_name"]!.DeepClone();
        return items;
    }
    async Task<JsonObject> SourceDataAsync(JsonObject pack, JsonArray configured, CancellationToken ct)
    {
        string id = Text(pack["pack_id"]);
        using var admission = id is "sli.windows.ad-dc" or "sli.windows.ad-context" ? Admission("sli.ad") : id == "sli.windows.vpn-radius" ? Admission("sli.remote-access") : null;
        var result = new JsonObject(); if (configured.Count == 0) return result;
        if (id == "sli.windows.vpn-radius") return await RadiusSourceDataAsync(pack, configured, ct);
        string[] ids = configured.Select(i => Text(i?["source_instance_id"]).ToLowerInvariant()).ToArray();
        string sql = Text(pack["source_kind"]) == "context" ? """
            select lower(domain_dns) as source_instance_id,max(created_at)::text as last_data_utc from ad_snapshot_manifests m
            where lower(domain_dns)=any(@p0) and coverage_state in ('complete','partial') and exists
              (select 1 from ad_snapshot_manifest_sources s where s.manifest_id=m.manifest_id and s.family='ad_context_base' and s.source_state in ('complete','partial')) group by lower(domain_dns)
            """ : Text(pack["pack_id"]) == "sli.windows.vpn-radius" ? Sql("setup-radius-data.sql") : """
            select lower(server) as source_instance_id,max(created_at)::text as last_data_utc from collector_channel_runs
            where lower(server)=any(@p0) and lower(channel)=any(@p1) and inserted>0 group by lower(server)
            """;
        var args = Text(pack["source_kind"]) == "context" || Text(pack["pack_id"]) == "sli.windows.vpn-radius" ? new object?[] { ids } : [ids, (pack["channels"] as JsonArray ?? new()).Select(c => Text(c).ToLowerInvariant()).ToArray()];
        var rows = await database.ReadAsync(s => s.QueryAsync(sql, ct, args), ct);
        foreach (var row in rows.OfType<JsonObject>()) result[Text(row["source_instance_id"]).ToLowerInvariant()] = row["last_data_utc"]?.DeepClone();
        return result;
    }
    async Task<JsonObject> RadiusSourceDataAsync(JsonObject pack, JsonArray instances, CancellationToken ct)
    {
        string[] ids = instances.Select(i => Text(i?["source_instance_id"]).ToLowerInvariant()).ToArray();
        var rows = await Safe(() => database.ReadAsync(s => s.QueryAsync(Sql("setup-radius-data.sql"), ct, (object)ids), ct));
        var arrivals = new JsonObject();
        foreach (var row in rows?.OfType<JsonObject>() ?? []) arrivals[Text(row["source_instance_id"]).ToLowerInvariant()] = row["last_data_utc"]?.DeepClone();
        foreach (var instance in instances.OfType<JsonObject>())
        {
            string key = Text(instance["source_instance_id"]).ToLowerInvariant(), host = Text(instance["collection_target"]).ToLowerInvariant();
            if (host.Length == 0) { if (rows is null) arrivals[key] = "unavailable"; continue; }
            var events = await Safe(() => database.ReadAsync(s => s.QueryAsync("""
                select max(created_at)::text as last_data_utc from collector_channel_runs
                where lower(server)=any(@p0) and lower(channel)=any(@p1) and inserted>0
                """, ct, new[] { host }, (pack["channels"] as JsonArray ?? new()).Select(c => Text(c).ToLowerInvariant()).ToArray()), ct));
            string[] raw = [Text(arrivals[key]), Text(First(events ?? new())?["last_data_utc"])];
            var stamps = raw.Select(r => DateTimeOffset.TryParse(r, out var stamp) ? (DateTimeOffset?)stamp : null).Where(t => t.HasValue).ToArray();
            arrivals[key] = stamps.Length > 0 ? stamps.Max()!.Value.ToString("o") : rows is null || events is null || raw.Any(r => r.Length > 0) ? "unavailable" : null;
        }
        return arrivals;
    }
    async Task<JsonObject> LegacySourceStatusAsync(JsonObject pack, JsonArray? configured, DateTimeOffset now, CancellationToken ct)
    {
        var arrivals = configured is null ? null : await Safe(() => SourceDataAsync(pack, configured, ct));
        long? interval = packages.CollectorInterval();
        long? freshness = Text(pack["source_kind"]) == "context" ? 86430 : interval > 0 ? Math.Max(60, interval.Value * 2 + 30) : null;
        var instances = configured is null ? null : new JsonArray();
        foreach (var item in configured?.OfType<JsonObject>() ?? [])
        {
            string raw = Text(arrivals?[Text(item["source_instance_id"]).ToLowerInvariant()]);
            DateTimeOffset? stamp = DateTimeOffset.TryParse(raw, out var parsed) ? parsed : null;
            string state = arrivals is null || raw.Length > 0 && (stamp is null || freshness is null || stamp > now) ? "unavailable" : stamp is null ? "never" : (now - stamp.Value).TotalSeconds <= freshness ? "fresh" : "stale";
            instances!.Add(new JsonObject { ["source_instance_id"] = item["source_instance_id"]!.DeepClone(), ["configured"] = item["configured"]?.DeepClone(), ["enabled"] = item["enabled"]?.DeepClone(),
                ["data_received"] = state == "unavailable" ? null : JsonValue.Create(state == "fresh"), ["data_state"] = state, ["last_data_utc"] = stamp?.ToString("o"),
                ["next_action"] = item["configured"] is not null && !Bool(item["configured"]) ? "configure" : item["configured"] is null || Bool(item["activation_blocked"]) || item["enabled"] is null ? "check_configuration"
                    : !Bool(item["enabled"]) ? "enable" : state == "fresh" ? null : state == "never" ? "collect" : "check_data" });
        }
        var summary = SourceSummary(pack, instances, freshness);
        if (arrivals is null) { summary["data_received"] = null; summary["data_state"] = "unavailable"; }
        return summary;
    }
}
