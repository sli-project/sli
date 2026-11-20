using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;
using Sli.Server.Compatibility;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using System.Numerics;

namespace Sli.Server.Workspace;

public sealed class LegacyInvestigationReader(ILegacyHttpReader events, IProblemRepository problems)
{
    static readonly JsonObject Declaration = JsonNode.Parse(WorkspaceJson.ReadResource("legacy-investigation.json"))!.AsObject();
    static string S(JsonNode? value) => value?.ToString() ?? "";
    static long N(JsonNode? value) => long.TryParse(value?.ToString(), out long n) ? n : 0;
    internal static string Category(int id) => Declaration["_INVESTIGATION_CATEGORY_BY_EVENT_ID"]?[id.ToString(CultureInfo.InvariantCulture)]?.ToString() ?? "other";
    internal static int[] EventIds(string scope) => Declaration["important"]!.AsArray()
        .Where(id => scope != "hide_noise" || !Declaration["noise"]!.AsArray().Any(n => N(n) == N(id))).Select(id => (int)N(id)).ToArray();
    static bool Truth(JsonNode? value) => value switch {
        null => false, JsonArray a => a.Count > 0, JsonObject o => o.Count > 0,
        JsonValue v when v.TryGetValue<bool>(out var b) => b,
        JsonValue v when v.TryGetValue<string>(out var s) => s.Length > 0,
        _ => value.ToJsonString() != "0"
    };
    static JsonNode? Or(JsonNode? value, JsonNode? fallback) => Truth(value) ? value : fallback;
    static string Label(JsonNode? value)
    {
        if (!int.TryParse(S(value), out int id)) return "Event ID —";
        string label = LegacySemantics.Label(id);
        return "Event ID " + id.ToString(CultureInfo.InvariantCulture) + (label == "Событие журнала" ? "" : ": " + label);
    }
    public async Task<JsonObject> ReadAsync(IQueryCollection query, CancellationToken ct) {
        string? First(params string[] names) => LegacyQuery.First(query, names);
        // The source int() precedes the read and is not a TimeRangeError.
        if (!ReportParameters.Integer(PythonText.Strip(First("limit") ?? "300"), out var requestedLimit)) throw new FormatException("invalid_limit");
        int limit = (int)BigInteger.Clamp(requestedLimit.IsZero ? 300 : requestedLimit, 1, 2000);
        string q = PythonText.Strip(First("q", "account", "user") ?? ""), scope = PythonText.Strip(First("scope", "mode") ?? "important").ToLowerInvariant();
        if (scope is not ("important" or "hide_noise" or "all")) scope = "important";
        var search = new JsonObject { ["items"] = new JsonArray(), ["total"] = null, ["returned_count"] = 0, ["has_more"] = false };
        var findings = new JsonObject { ["items"] = new JsonArray(), ["summary"] = new JsonArray() }; var chain = new JsonArray(); var grouped = new JsonObject(); var counts = new JsonObject();
        if (q.Length > 0) {
            var values = new Dictionary<string, StringValues> { ["q"] = q, ["limit"] = Math.Min(limit, 1000).ToString(CultureInfo.InvariantCulture), ["order"] = "desc", ["timezone"] = First("timezone") ?? "UTC" };
            foreach (string key in new[] { "time_from", "time_to" }) if (First(key) is {} value) values[key] = value;
            if (scope != "all") values["event_id"] = string.Join(',', EventIds(scope));
            var input = LegacyQuery.Parse("/api/events/search", new QueryCollection(values)); input.Filters["include_internal_evidence"] = true;
            search = await events.ReadAsync("/api/events/search", input, ct); findings = await problems.LegacyFindingsAsync(q, 50, ct);
            foreach (var (category, _) in Declaration["categories"]!.AsObject()) counts[category] = 0;
            foreach (var item in search["items"] as JsonArray ?? []) {
                string category = Category((int)N(item?["event_id"]));
                var row = new JsonObject();
                foreach (string field in new[] { "server", "channel", "event_id", "severity", "subject", "target", "source", "logon_id", "summary" }) row[field] = item?[field]?.DeepClone();
                row["event_db_id"] = N(Or(item?["id"], item?["event_db_id"])); row["time"] = item?["time_created_utc"]?.DeepClone();
                row["time_display"] = Truth(item?["time_created_utc_display"]) ? item!["time_created_utc_display"]!.DeepClone() : JsonValue.Create(S(item?["time_created_utc"]).Length == 0 ? "—" : LegacySemantics.Display(item?["time_created_utc"]));
                row["label"] = Truth(item?["label"]) ? item!["label"]!.DeepClone() : JsonValue.Create(Label(item?["event_id"])); row["category"] = category; row["category_label"] = Declaration["categories"]![category]!.DeepClone();
                var pairs = new List<KeyValuePair<string, string?>> { new("event_id", S(item?["event_id"])), new("channel", S(item?["channel"])), new("server", S(item?["server"])), new("limit", "50") };
                if (item?["time_created_utc"] is {} time) { pairs.Add(new("time_from", S(time))); pairs.Add(new("time_to", S(time))); }
                row["detail_url"] = "/reports/event-details.html" + QueryString.Create(pairs.Where(p => !string.IsNullOrEmpty(p.Value))).ToString().Replace("%20", "+");
                chain.Add(row); if (grouped[category] is not JsonArray) grouped[category] = new JsonArray(); grouped[category]!.AsArray().Add(row.DeepClone()); counts[category] = N(counts[category]) + 1;
            }
            counts["total"] = chain.Count;
        }
        var pivots = new JsonArray();
        foreach (var item in (search["items"] as JsonArray ?? []).Take(250)) {
            foreach (var (kind, raw) in new[] { ("та же учетка", Or(item?["target_user_name"], item?["target"])), ("тот же инициатор", Or(item?["subject_user_name"], item?["subject"])), ("тот же IP", item?["ip_address"]), ("тот же host", Or(item?["workstation_name"], item?["server"])), ("тот же LogonId", item?["logon_id"]) }) {
                string value = Truth(raw) ? PythonText.Strip(S(raw)) : ""; if (value.Length == 0 || value == "—" || value.ToLowerInvariant() == q.ToLowerInvariant() || pivots.Any(p => S(p?["kind"]) == kind && S(p?["value"]) == value)) continue;
                pivots.Add(new JsonObject { ["kind"] = kind, ["value"] = value, ["label"] = value, ["url"] = "/reports/investigation.html" + QueryString.Create(new Dictionary<string, string?> { ["q"] = value, ["limit"] = limit.ToString(CultureInfo.InvariantCulture), ["scope"] = scope }).ToString().Replace("%20", "+") });
            }
            if (pivots.Count >= 12) break;
        }
        var checks = new JsonArray();
        void Check(bool condition, string text) { if (condition) checks.Add(text); }
        int findingCount = (findings["items"] as JsonArray ?? []).Count;
        Check(N(counts["failed_logons"]) > 0 && N(counts["logons"]) > 0, "Сопоставить ошибки входа с последующими успешными входами по той же учетной записи, IP и LogonId.");
        Check(N(counts["passwords"]) > 0, "Проверить, кто инициировал смену/сброс пароля и был ли после этого успешный вход.");
        Check(N(counts["lockouts"]) > 0, "Определить источник блокировки и повторяемость по IP/host.");
        Check(N(counts["groups"]) > 0, "Проверить изменение групп: кто добавил/удалил, какая группа, является ли она привилегированной.");
        Check(N(counts["privileges"]) > 0, S(Declaration["_INVESTIGATION_CHECKS"]!["privileges"]));
        Check(findingCount > 0, "Открыть связанные находки и сверить каждую гипотезу с первичными событиями.");
        Check(pivots.Count > 0, "Продолжить расследование по связанным объектам: та же учётная запись, IP, компьютер или LogonId.");
        if (checks.Count == 0) checks = Declaration["_starter_checks"]!.DeepClone().AsArray();
        JsonObject summary;
        if (q.Length == 0) summary = Declaration["_empty_summary"]!.DeepClone().AsObject();
        else {
            string why = N(counts["groups"]) > 0 || N(counts["privileges"]) > 0 ? "Есть действия, которые могут менять права или отражать привилегированный вход. Их нужно сверить с первичными событиями, а не только с Event ID." : N(counts["passwords"]) > 0 && N(counts["logons"]) > 0 ? "Парольные события рядом с входами помогают выявить сценарий сброса/смены пароля и последующего доступа." : N(counts["failed_logons"]) > 0 && N(counts["logons"]) > 0 ? "Ошибки входа вместе с успешными входами могут указывать на подбор, ошибку пользователя или легитимный вход после неудачных попыток." : findingCount > 0 ? "Есть связанные находки — они требуют сверки с первичными событиями." : "Сводка помогает быстро отделить важные события от второстепенного шума и выбрать следующий шаг.";
            string story = chain.Count == 0 ? $"По запросу {q} не найдено событий в выбранном режиме." : $"По объекту {q} построена история из {chain.Count} событий: " + string.Join(", ", Declaration["categories"]!.AsObject().Where(p => N(counts[p.Key]) > 0).Take(8).Select(p => S(p.Value).ToLowerInvariant() + ": " + N(counts[p.Key]))) + (findingCount > 0 ? $"; связанных находок: {findingCount}" : "") + ".";
            summary = new() { ["total_events"] = N(search["returned_count"]) is var returned && returned != 0 ? returned : chain.Count, ["total_is_exact"] = Truth(search["total_is_exact"]), ["has_more"] = Truth(search["has_more"]), ["chain_events"] = chain.Count, ["findings"] = findingCount, ["first_event_utc"] = chain.LastOrDefault()?["time"]?.DeepClone(), ["last_event_utc"] = chain.FirstOrDefault()?["time"]?.DeepClone(), ["pivots"] = new JsonArray(pivots.Select(p => p!["value"]!.DeepClone()).ToArray()), ["category_summary"] = counts.DeepClone(), ["attention_level"] = N(counts["groups"]) > 0 || N(counts["privileges"]) > 0 ? "высокий" : N(counts["lockouts"]) > 0 || N(counts["passwords"]) > 0 || N(counts["failed_logons"]) >= 5 ? "внимание" : chain.Count > 0 ? "норма" : "—", ["story"] = story, ["why_it_matters"] = why };
        }
        var limitations = new JsonArray(); bool more = Truth(search["has_more"]);
        if (scope != "all") limitations.Add("Показаны важные для расследования события; включите «Все события», если нужен полный контекст.");
        if (more) limitations.Add($"Показано {chain.Count} событий. Чтобы увидеть остальные, откройте следующую страницу результатов.");
        else if (search["total"] is not null && N(search["total"]) > chain.Count) limitations.Add($"Показано {chain.Count} из {N(search["total"])} событий из-за лимита {limit}.");
        if (First("time_from") is null && First("time_to") is null) limitations.Add("Явный временной диапазон не задан; применяется безопасное ограниченное окно быстрого поиска.");
        if (chain.Count == 0 && findingCount == 0 && q.Length > 0) limitations.Add("Отсутствие результатов не доказывает отсутствие активности: проверьте свежесть каналов, период и полноту импорта.");
        var result = new JsonObject { ["q"] = q, ["limit"] = limit, ["scope"] = scope, ["empty_query"] = q.Length == 0, ["search"] = search, ["timeline"] = new JsonObject { ["chain"] = chain, ["grouped"] = grouped, ["summary"] = counts }, ["findings"] = findings, ["summary"] = summary, ["pivots"] = pivots, ["next_checks"] = checks,
            ["data_quality"] = new JsonObject { ["backend"] = S(findings["backend"]) is { Length: > 0 } backend ? backend : "postgres", ["evidence_policy"] = "evidence-first", ["query"] = q, ["scope"] = scope, ["total_events"] = search["total"] is null ? null : JsonValue.Create(N(search["total"])), ["total_is_exact"] = search["total"] is not null, ["returned_events"] = chain.Count, ["findings_count"] = findingCount, ["truncated"] = more || N(search["total"]) > chain.Count, ["has_more"] = more, ["time_from"] = First("time_from"), ["time_to"] = First("time_to"), ["limitations"] = limitations } };
        if (q.Length > 0) result["no_results"] = chain.Count == 0 && findingCount == 0;
        return result;
    }
}
