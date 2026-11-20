using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// Frozen computers_v6_reporting_comparison: one compatible pair per issued domain.
internal static class AdComputerComparison
{
    internal const string Contract = "sli.computers-report.v6";
    internal const string CatalogSql = "select id from domains order by id";
    internal const string PairSql = """
        select pair.* from domains selected_domain
        cross join lateral (
            select snapshot.domain_id,snapshot.scope_sha256,snapshot.contract_id,snapshot.schema_version
            from computers_report_v6_snapshots snapshot where snapshot.domain_id=selected_domain.id
            order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 1
        ) latest
        cross join lateral (
            select snapshot.snapshot_id,snapshot.domain_id,snapshot.bucket_start_utc,
                   snapshot.captured_at_utc,snapshot.source_observed_at_utc,
                   snapshot.source_state,snapshot.object_count,snapshot.payload_json,snapshot.payload_sha256,
                   (select count(*) from computers_report_v6_snapshots history
                    where history.domain_id=snapshot.domain_id) as domain_snapshot_count
            from computers_report_v6_snapshots snapshot
            where snapshot.domain_id=latest.domain_id and snapshot.scope_sha256=latest.scope_sha256
              and snapshot.contract_id=latest.contract_id and snapshot.schema_version=latest.schema_version
            order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 2
        ) pair
        where selected_domain.id=any($1)
        order by selected_domain.id,pair.captured_at_utc desc,pair.snapshot_id desc
        """;

    internal static Task<JsonObject> LoadAsync(NpgsqlConnection db, long[]? domains, CancellationToken ct) =>
        LoadAsync(domains, (sql, scope) => scope is null ? AdJson.ReadAsync(db, sql, ct) : AdJson.ReadAsync(db, sql, ct, (object)scope));

    internal static async Task<JsonObject> LoadAsync(long[]? domains, Func<string, long[]?, Task<List<JsonObject>>> read)
    {
        domains ??= (await read(CatalogSql, null)).Select(r => r.Int("id")).ToArray();
        var rows = domains.Length == 0 ? [] : await read(PairSql, domains);
        var grouped = rows.GroupBy(r => r.Int("domain_id")).ToDictionary(g => g.Key, g => g.ToArray());
        if (domains.Length <= 1) return FromRows(grouped.GetValueOrDefault(domains.FirstOrDefault(), []), domains.FirstOrDefault());
        var results = domains.Select(domain =>
        {
            var result = FromRows(grouped.GetValueOrDefault(domain, []), domain);
            result["domain_id"] = domain;
            return result;
        }).ToArray();
        var items = results.SelectMany(r => r["items"]!.AsArray().OfType<JsonObject>()).ToArray();
        return Obj(new { state = results.All(r => r.Text("state") == "available") ? "available" : "partial",
            domains = results, items, change_count = items.Length, deletion_claim_allowed = false });
    }

    static JsonObject Payload(JsonObject row)
    {
        var payload = row["payload_json"] is JsonObject obj ? obj : JsonNode.Parse(row.Text("payload_json")!)!.AsObject();
        if (AdJobPlugin.Digest(payload) != row.Text("payload_sha256")) throw new InvalidDataException("ad_snapshot_hash_mismatch");
        return payload;
    }
    static JsonObject Context(JsonObject row, JsonObject? payload = null)
    {
        var source = (payload ?? Payload(row))["source_snapshot"] as JsonObject;
        return Obj(new { snapshot_id = row.Int("snapshot_id"), captured_at_utc = row.Text("captured_at_utc"),
            source_observed_at_utc = row.Text("source_observed_at_utc"), collection_status = source.Text("state") ?? row.Text("source_state") ?? "unknown",
            source_state = row.Text("source_state") ?? "unknown", object_count = row.Int("object_count"), query_dc = source?["query_dc"]?.DeepClone() });
    }
    static JsonObject FromRows(JsonObject[] rows, long domain)
    {
        if (rows.Length < 2) return Obj(new { state = "not_collected",
            reason = rows.Length == 0 ? "snapshot_history_not_collected" : rows[0].Int("domain_snapshot_count") > 1 ? "incompatible_snapshot_pair_not_compared" : "previous_compatible_snapshot_not_collected",
            current = rows.Length == 0 ? null : Context(rows[0]), previous = (JsonObject?)null,
            items = new JsonArray(), change_count = 0, deletion_claim_allowed = false });
        var current = Payload(rows[0]); var previous = Payload(rows[1]);
        var result = Compare(current, previous);
        foreach (var item in result["items"]!.AsArray()) item!["domain_id"] = domain;
        foreach (var (key, row, payload) in new[] { ("current", rows[0], current), ("previous", rows[1], previous) })
            foreach (var entry in Context(row, payload)) result[key]![entry.Key] = entry.Value?.DeepClone();
        return result;
    }

    internal static JsonObject Compare(JsonObject current, JsonObject previous)
    {
        if (current.Text("contract_id") != Contract || previous.Text("contract_id") != Contract)
            throw new InvalidDataException("incompatible_computers_v6_snapshots");
        Dictionary<string, JsonObject> Index(JsonObject payload)
        {
            var index = new Dictionary<string, JsonObject>();
            foreach (var item in (payload["items"] as JsonArray ?? []).OfType<JsonObject>())
            {
                string? guid = (item.Text("object_guid") ?? item["identity"].Text("object_guid"))?.ToLowerInvariant();
                if (guid is null) throw new InvalidDataException("snapshot_missing_object_guid");
                if (!index.TryAdd(guid, item)) throw new InvalidDataException("snapshot_duplicate_object_guid");
            }
            return index;
        }
        bool Partial(JsonObject payload) => payload.Text("state") == "partial" || payload["coverage"].Text("state") == "partial";
        var before = Index(previous); var after = Index(current); var rows = new List<JsonObject>();
        bool partial = Partial(current);
        JsonObject Push(string kind, JsonObject item, string old, string value)
        {
            bool missing = kind == "missing_current";
            var row = Obj(new { row_id = $"{kind}:{item.Int("entity_id")}", entity_id = item.Int("entity_id"), display_name = item.Text("display_name") ?? item.Int("entity_id").ToString(System.Globalization.CultureInfo.InvariantCulture),
                change_type = kind, before = old, after = value, @object = item,
                qualification = missing ? partial ? "Объект отсутствует в текущем неполном снимке; причина не установлена." : "Объект отсутствует в текущем снимке; причина не установлена." : "Зафиксировано различие двух совместимых снимков; причина изменения не устанавливается автоматически.",
                limitation = missing ? "Отсутствие в текущем снимке не доказывает удаление: объект мог выпасть из scope или неполного сбора." : "Снимки показывают два наблюдаемых состояния и не доказывают, кто, почему или вследствие чего внёс изменение.",
                next_action = "Проверить объект и связанные evidence; решение принимает человек." });
            rows.Add(row); return row;
        }
        string Enabled(JsonObject item) => AdInventoryRows.Bool(item["enabled"]) switch { true => "True", false => "False", _ => "None" };
        string Os(JsonObject item) => string.Join(" · ", new[] { "operating_system", "operating_system_version", "operating_system_build" }.Select(item.Text).Where(v => v is not null)) is { Length: > 0 } value ? value : "нет данных";
        string Ips(JsonObject item) => string.Join(", ", (item["ip_addresses"] as JsonArray ?? []).Select(n => n!.ToString()).Order(StringComparer.Ordinal)) is { Length: > 0 } value ? value : "нет данных";
        string Semantics(JsonObject item) => item["semantic_findings"] is JsonArray { Count: > 0 } findings ? $"{findings.Count} точных опубликованных связей" : "нет точных опубликованных связей";
        string Quality(JsonObject item) => string.Join(", ", (item["quality_issues"] as JsonArray ?? []).Select(i => i.Text("code")).Where(c => c is not null).Order(StringComparer.Ordinal)) is { Length: > 0 } value ? value : "без отмеченных пробелов";
        foreach (string guid in before.Keys.Union(after.Keys).Order(StringComparer.Ordinal))
        {
            before.TryGetValue(guid, out var old); after.TryGetValue(guid, out var item);
            if (item is null) { Push("missing_current", old!, "Присутствовал в предыдущем снимке", "Отсутствует в текущем снимке"); continue; }
            if (old is null) { Push("new_object", item, "Отсутствовал", "Присутствует в текущем снимке"); continue; }
            var oldStates = old["evidence"]?["attribute_states"] as JsonObject ?? new();
            var states = item["evidence"]?["attribute_states"] as JsonObject ?? new();
            int qualityRows = 0;
            foreach (string field in oldStates.Select(p => p.Key).Union(states.Select(p => p.Key)).Order(StringComparer.Ordinal))
            {
                string a = (oldStates[field].Text("state") ?? "unknown").ToLowerInvariant(), b = (states[field].Text("state") ?? "unknown").ToLowerInvariant();
                if (a == b) continue;
                var row = Push("quality_changed", item, a, b); row["field"] = field; row["row_id"] = $"quality_changed:{item.Int("entity_id")}:{field}"; qualityRows++;
            }
            foreach (var (kind, a, b) in new[] {
                ("enabled_changed", Enabled(old), Enabled(item)), ("ou_changed", old.Text("ou_path") ?? "нет данных", item.Text("ou_path") ?? "нет данных"),
                ("os_changed", Os(old), Os(item)), ("ip_changed", Ips(old), Ips(item)),
                ("site_changed", old["network"]?["ad_site"].Text("value") ?? "нет данных", item["network"]?["ad_site"].Text("value") ?? "нет данных"),
                ("managed_by_changed", old.Text("managed_by") ?? "нет данных", item.Text("managed_by") ?? "нет данных"),
                ("classification_changed", old.Text("computer_type") ?? "unknown", item.Text("computer_type") ?? "unknown"), ("semantic_changed", Semantics(old), Semantics(item)) })
                if (a != b) Push(kind, item, a, b);
            if (qualityRows == 0 && Quality(old) != Quality(item)) Push("quality_changed", item, Quality(old), Quality(item))["field"] = "summary";
        }
        return Obj(new { state = partial || Partial(previous) ? "partial" : "available",
            current = new { captured_at_utc = current["captured_at_utc"]?.DeepClone(), state = current.Text("state") },
            previous = new { captured_at_utc = previous["captured_at_utc"]?.DeepClone(), state = previous.Text("state") }, items = rows, change_count = rows.Count, deletion_claim_allowed = false });
    }

    internal static async Task<JsonObject> ReadReportAsync(NpgsqlConnection db, AdV2Request request, CancellationToken ct)
    {
        var comparison = await LoadAsync(db, request.Domains, ct);
        return Report(comparison, request);
    }
    internal static JsonObject Report(JsonObject comparison, AdV2Request request)
    {
        var changes = comparison["items"]!.AsArray().OfType<JsonObject>().Select(r => r.DeepClone().AsObject()).ToList();
        // Keep the v2 table's presentation fields; the comparison itself retains the frozen contract.
        foreach (var row in changes)
        {
            foreach (string key in new[] { "computer_type", "operating_system", "ou_path" }) row[key] = row["object"]?[key]?.DeepClone();
            var domain = comparison["domains"] is JsonArray domains ? domains.First(d => d.Int("domain_id") == row.Int("domain_id"))! : comparison;
            row["observed_at_utc"] = domain["current"]?["captured_at_utc"]?.DeepClone(); row["actor"] = null;
        }
        string Search(JsonNode? node) => node switch { JsonObject obj => string.Join(' ', obj.Select(p => Search(p.Value))), JsonArray array => string.Join(' ', array.Select(Search)), _ => node?.ToString() ?? "" };
        if (request.Params.Text("q") is {} q) changes = changes.Where(r => Search(r).Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
        if (request.Params.Text("reason_code") is {} reason) changes = changes.Where(r => r.Text("change_type") == reason).ToList();
        changes = changes.OrderBy(r => r.Text("change_type"), StringComparer.Ordinal).ThenBy(r => r.Text("display_name"), StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Int("entity_id")).ToList();
        if (request.Cursor is not null) throw new AdInputException("changes_view_does_not_accept_cursor");
        string state = comparison.Text("state") == "available" ? changes.Count == 0 ? "empty" : "ok" : comparison.Text("state")!;
        var result = AdV2Store.Result(request.Key, state, changes.Take(request.Limit), Obj(new { state = comparison.Text("state"), reason = comparison.Text("reason") }));
        result["snapshot_comparison"] = comparison.DeepClone(); result["filtered_count"] = changes.Count; result["has_more"] = changes.Count > request.Limit;
        result["collections"]!["changes"] = result["items"]!.DeepClone();
        return result;
    }
}
