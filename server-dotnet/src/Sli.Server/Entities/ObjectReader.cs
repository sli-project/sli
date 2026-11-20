using System.Text.Json.Nodes;
using Sli.Server.Access;

namespace Sli.Server.Entities;

public sealed partial class EntityReader
{
    static readonly Dictionary<string, string[]> Aliases = new()
    {
        ["account"] = ["account", "user", "ad_user", "service_account"], ["user"] = ["account", "user", "ad_user", "service_account"],
        ["computer"] = ["computer", "ad_computer", "server", "domain_controller", "asset"], ["server"] = ["computer", "ad_computer", "server", "domain_controller", "asset"],
        ["ip"] = ["ip", "ip_address"], ["entity"] = []
    };
    public async Task<JsonObject> Objects(IQueryCollection query, CapabilityDecisionSet caps, CancellationToken ct)
    {
        string q = (EntityReadInput.First(query, "q") ?? "").Trim(), type = (EntityReadInput.First(query, "type", EntityReadInput.First(query, "object_type")) ?? "").Trim();
        string raw = EntityReadInput.First(query, "limit", "30")!;
        int limit = Math.Clamp(EntityReadInput.Limit(raw, 30, $"invalid literal for int() with base 10: '{raw}'", emptyDefault: false), 1, 100);
        bool scoped = caps.Policies.Any(p => p.CapabilityKey == "objects.view") || caps.ResourceCapabilities.Contains("objects.view");
        int scan = scoped ? 500 : limit + 1;
        var args = new Dictionary<string, object> { ["limit"] = scan }; var conditions = new List<string>();
        if (q.Length > 0) { conditions.Add("(lower(entity.display_name) like lower(@q) or lower(entity.natural_key) like lower(@q))"); args["q"] = "%" + q + "%"; }
        if (type.Length > 0) { conditions.Add("entity_type.value=any(@types)"); args["types"] = Aliases.GetValueOrDefault(type, []).Append(type).Distinct().Order(StringComparer.Ordinal).ToArray(); }
        string where = conditions.Count == 0 ? "" : "where " + string.Join(" and ", conditions);
        var rows = await Read($"""
            select entity.id,entity_type.value as object_type,entity.display_name,entity.natural_key,entity.domain_id,entity.server_id,entity.first_seen_utc,entity.last_seen_utc
            from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id {where}
            order by entity.last_seen_utc desc nulls last,entity.id desc limit @limit
            """, args, ct, 5);
        var allowed = rows.OfType<JsonObject>().Where(r => Allows(caps, "objects.view", r)).ToArray();
        var items = new JsonArray();
        foreach (var row in allowed.Take(limit))
        {
            string display = Text(row, "display_name"); if (display.Length == 0) display = Text(row, "natural_key"); if (display.Length == 0) display = Text(row, "id");
            items.Add(new JsonObject { ["object_type"] = Text(row, "object_type"), ["object_id"] = Text(row, "id"), ["display_name"] = display,
                ["natural_key"] = Allows(caps, "field.technical", row) ? Text(row, "natural_key") : null,
                ["first_seen_utc"] = row["first_seen_utc"]?.DeepClone(), ["last_seen_utc"] = row["last_seen_utc"]?.DeepClone(), ["source"] = "Storage V2", ["freshness"] = row["last_seen_utc"] is null ? "unknown" : "observed" });
        }
        return new() { ["api_version"] = "v4", ["query"] = q, ["object_type"] = type.Length == 0 ? null : type, ["state"] = items.Count == 0 ? "empty" : "available", ["items"] = items,
            ["has_more"] = allowed.Length > limit || scoped && rows.Count == scan, ["scope_filtered"] = allowed.Length != rows.Count,
            ["limits"] = new JsonObject { ["items"] = limit, ["scanned"] = rows.Count, ["scope_scan_max"] = scan, ["scope_truncated"] = scoped && rows.Count == scan, ["total_count"] = "not_calculated" } };
    }
    public static void ValidateObjectType(string type)
    {
        if (type.Length is 0 or > 64 || !type.All(c => char.IsLetterOrDigit(c) || c is '_' or '-')) throw new EntityInputException("unsupported_object_type");
    }
    public async Task<JsonObject?> Object(JsonObject preflight, string requestedType, int eventLimit, CapabilityDecisionSet caps, CancellationToken ct)
    {
        string actual = Text(preflight, "entity_type", "entity");
        if (requestedType != actual && requestedType != "entity" && !Aliases.GetValueOrDefault(requestedType, []).Contains(actual)) throw new EntityInputException("object_type_mismatch");
        var detail = await Detail(preflight, new(Math.Clamp(eventLimit, 1, 100)), caps, true, ct);
        if (detail is null) return null;
        int id = checked((int)Number(preflight, "id"));
        bool Can(string key) => Allows(caps, key, preflight);
        bool technical = Can("field.technical"), security = Can("field.security"), evidence = Can("evidence.exact"), privilege = Can("field.privilege") && Can("objects.privileges");
        var observed = await Read(EntityShortSql.Cte("@boundary","@id") + """
            select e.domain_id,e.server_id,max(e.last_seen_utc) as storage_v2_observed_at_utc
            from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            group by e.domain_id,e.server_id order by storage_v2_observed_at_utc desc limit 1
            """,new() { ["id"]=id,["boundary"]=Boundary },ct);
        var links = await Read("""
            select source_object_type,source_object_id,target_object_type,target_object_id,relation_type,source_name,match_method,confidence,observed_at,valid_from,valid_until
            from object_identity_links where(source_object_type=@type and source_object_id=@id) or(target_object_type=@type and target_object_id=@id)
            order by observed_at desc,id desc limit 50
            """, new() { ["type"] = actual, ["id"] = id.ToString(System.Globalization.CultureInfo.InvariantCulture) }, ct);
        JsonArray findings = security ? await Read("""
            select distinct finding.id,finding.title,finding.severity,finding.status,finding.summary,finding.last_seen_utc,finding.last_evidence_event_id as evidence_event_id
            from findings_active finding join finding_entities link on link.finding_id=finding.id where link.entity_id=@id
            order by finding.last_seen_utc desc nulls last,finding.id desc limit 20
            """, new() { ["id"] = id }, ct) : new();
        var entity = (JsonObject)detail["entity"]!; var safe = Pick(entity, "display_name", "first_seen_utc", "last_seen_utc");
        safe["object_type"] = actual; safe["object_id"] = id.ToString(System.Globalization.CultureInfo.InvariantCulture);
        safe["natural_key"] = technical ? entity["natural_key"]?.DeepClone() : null; safe["latest_state"] = security ? entity["latest_state"]?.DeepClone() : null;
        var tabs = new JsonArray();
        foreach (var (key, label, available) in new (string, string, bool)[] { ("overview", "Обзор", true), ("groups", "Членство в группах", Can("objects.groups")), ("privileges", "Доступ и привилегии", privilege), ("activity", "Активность", security && evidence), ("states", "Состояние и изменения", security), ("findings", "Находки", security), ("evidence", "Доказательства", evidence), ("technical", "Технические атрибуты", technical) })
            tabs.Add(new JsonObject { ["id"] = key, ["label"] = label, ["available"] = available });
        string state = evidence ? Text(detail, "events_state", "available") : "forbidden";
        var limitations = Strings(["Снимок и событие являются разными типами факта", "Отсутствующее значение не интерпретируется как ложь"]);
        if (state == "temporarily_unavailable") limitations.Add("Лента событий временно недоступна: ограниченный запрос превысил допустимое время выполнения");
        if (!evidence) limitations.Add("Точная лента событий скрыта политикой evidence.exact");
        else if (detail["events_scope_filtered"]!.GetValue<bool>()) limitations.Add("Часть связанных доказательств скрыта политикой их собственного ресурса");
        if (!technical && links.Count > 0) limitations.Add("Связи идентичности и их provenance скрыты политикой технических полей");
        var provenance = new JsonArray();
        if (observed.FirstOrDefault()?["storage_v2_observed_at_utc"] is JsonNode when) provenance.Add(new JsonObject { ["source"] = "Storage V2", ["observed_at_utc"] = when.DeepClone(), ["freshness"] = "observed" });
        if (detail["ad_context"]?["items"] is JsonArray { Count: > 0 } contexts) provenance.Add(new JsonObject { ["source"] = "AD Context", ["observed_at_utc"] = contexts[0]?["observed_at_utc"]?.DeepClone(), ["freshness"] = "observed" });
        if (provenance.Count == 0) limitations.Add("Для объекта не найдено доказательство наблюдения подключённым источником");
        return new() { ["api_version"] = "v4", ["state"] = "available", ["object"] = safe, ["identity_links"] = technical ? links : new JsonArray(),
            ["identity_contract"] = "employee_and_account_are_distinct_objects", ["tabs"] = tabs, ["current_states"] = detail["current_states"]?.DeepClone(),
            ["findings"] = findings, ["directory_context"] = detail["ad_context"]?.DeepClone(), ["events"] = evidence ? detail["events"]?.DeepClone() : new JsonArray(), ["events_state"] = state,
            ["has_more_events"] = evidence && detail["has_more"]!.GetValue<bool>(), ["actions"] = Strings(["copy_link"]), ["provenance"] = provenance, ["limitations"] = limitations };
    }
}
