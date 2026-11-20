using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Operations;
using Sli.Server.Reporting;
using Sli.Server.Semantic;
using static Sli.Server.Legacy.LegacyReportContext;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Legacy;

internal static class LegacyCollectorHealth
{
    internal static async Task<string> RenderAsync(NpgsqlConnection db, NpgsqlTransaction tx, OperationsService operations, CancellationToken ct)
    {
        var data = await operations.CollectorAsync(ct);
        // Preserve the report's existing heartbeat diagnostics alongside durable history.
        data["workers"] = await new SemanticSession(db, tx).QueryAsync("""
            select worker_name,status,phase,heartbeat_at,expected_interval_seconds,
              heartbeat_at < now()-make_interval(secs=>greatest(expected_interval_seconds*3,60)) as stale
            from runtime_worker_heartbeats where worker_name in('collection','post_collection','semantic') order by worker_name
            """, ct);
        return Render(data);
    }

    internal static string Render(JsonArray channels, JsonArray jobs, JsonArray workers)
        => Render(new JsonObject { ["items"] = channels.DeepClone() }, jobs, workers);

    // Render the same real snapshot used by /api/collector/health.
    internal static string Render(JsonObject data, JsonArray? jobs = null, JsonArray? workers = null)
    {
        var html = new StringBuilder("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Состояние сбора</title><style>body{font:16px system-ui;margin:32px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3de;padding:8px;overflow-wrap:anywhere}section{margin:18px 0;padding:20px;border:1px solid #ccd3de}</style></head><body><a href=\"/\">На главную</a><h1>Состояние сбора по каналам</h1><p>Отсутствие событий не доказывает отсутствие активности. Устаревший heartbeat не подтверждает исправность worker.</p>");
        void P(object? value) => html.Append("<p>").Append(E(value)).Append("</p>");
        P("Сформирован: " + FormatTime(data["generated_at_utc"]));
        var summary = data["summary"] as JsonObject ?? new();
        P($"Каналов: {N(summary["channels_total"])}; Security высокий/внимание: {N(summary["security_high"])} / {N(summary["security_warn"])}; Таймауты 24ч: {N(summary["timeouts_24h"])}; Частичные 24ч: {N(summary["partial_timeouts_24h"])}");

        var slo = data["operations_slo"] as JsonObject ?? new();
        string explanation = S(slo["status"]) switch {
            "breached" => "Хотя бы один канал Security не прошёл проверку или его последняя успешная проверка просрочена. Проверьте доступ к источнику и состояние процесса сбора.",
            "attention" => "Проверка каналов Security задерживается, не подтверждена или есть техническое предупреждение.",
            "met" => "Все наблюдаемые каналы Security укладываются в базовый порог свежести; таймаутов и зависших задач нет.",
            _ => "Недостаточно данных, чтобы оценить свежесть Security-каналов."
        };
        long warning = N(slo["warning_minutes"], 5), breach = N(slo["breach_minutes"], 20);
        html.Append("<section><h2>Работа сбора и свежесть данных</h2>");
        P(S(slo["label"], "Недостаточно данных")); P(explanation);
        P($"{N(slo["freshness_current"])} из {N(slo["security_channels"])} — Security: актуальная проверка (до {warning} мин.)");
        P($"{N(slo["freshness_warning"])} — Security: задержка {warning}–{breach} мин.");
        P($"{N(slo["freshness_breached"])} — Security: ошибка или проверка старше {breach} мин.");
        P($"{N(slo["timeouts_24h"])} / {N(slo["partial_timeouts_24h"])} — таймауты / частичные чтения за 24 ч.");
        P($"{N(slo["stale_post_collection"])} — зависшие задачи анализа");
        if (N(slo["freshness_unknown"]) > 0) P($"Не удалось оценить свежесть каналов: {N(slo["freshness_unknown"])}");
        html.Append("</section>");

        var history = data["runtime_history"] as JsonObject;
        if (history?["items"] is JsonArray { Count: > 0 } runs && runs[0] is JsonObject latest)
        {
            html.Append("<section><h2>Независимый worker сбора</h2>");
            P($"Последний самостоятельный запуск: {S(latest["status"], "unknown")}, этап: {S(latest["phase"], "—")}.");
            P("Время старта: " + FormatTime(latest["started_at"] ?? latest["created_at"]));
            P("Длительность: " + (latest["duration_ms"] is null ? "выполняется" : Math.Round(N(latest["duration_ms"]) / 1000d).ToString(CultureInfo.InvariantCulture) + " сек."));
            P("Лимит на канал: " + S(latest["max_events_per_channel"], "—"));
            P("Контроллеры домена: " + (latest["servers_json"] is JsonArray servers ? string.Join(", ", servers.Select(s => S(s))) : "подготавливаются"));
            if (latest["errors_json"] is JsonArray { Count: > 0 } errors) P("Ошибка: " + S(errors[0]));
            P($"Владелец: {S(latest["worker_id"], "—")}. История хранится в PostgreSQL, поэтому не исчезает при перезапуске веб-сервера.");
            html.Append("</section>");
        }
        else if (S(history?["status"]) == "unavailable") P("История процесса сбора временно недоступна.");

        var outbox = data["storage_v2_outbox"] as JsonObject;
        if (S(outbox?["status"]) == "ok")
        {
            html.Append("<section><h2>Очередь архивирования V2</h2>");
            P((N(outbox?["events"]) == 0 ? "Очередь пуста" : "Публикация продолжается") + ". Она не блокирует успешный сбор с контроллеров домена.");
            P(N(outbox?["events"]).ToString("N0", CultureInfo.InvariantCulture) + " — событий ожидают или обрабатываются");
            P($"{N(outbox?["batches"])} — пакетов в работе");
            P(N(outbox?["states"]?["leased"]?["events"]).ToString("N0", CultureInfo.InvariantCulture) + " — событий сейчас взяты worker");
            html.Append("</section>");
        }
        else if (S(outbox?["status"]) == "unavailable") P("Состояние очереди архивирования временно недоступно.");

        void Table(string title,JsonArray rows) {
            html.Append("<h2>").Append(E(title)).Append("</h2>");
            if (rows.Count==0) { html.Append("<p>Нет данных.</p>"); return; }
            string[] columns=rows.OfType<JsonObject>().SelectMany(row => row.Select(x => x.Key)).Distinct().ToArray(); html.Append("<table><thead><tr>");
            foreach (string col in columns) html.Append("<th>").Append(E(UiLabels.Field(col switch {
                "server_hostname" => "server", "last_status" => "status", "last_successful_collection_utc" => "last_collection",
                "last_event_time_utc" => "last_event", "last_event_record_id" => "record_id", "lag_minutes" => "lag",
                "timeouts_24h" => "timeouts", "partial_timeouts_24h" => "partial", "inserted_skipped_ratio" => "inserted_skipped",
                "recovery_mode" => "recovery", "warnings" => "message",
                "cycle_status_label" => "Последний цикл", "freshness_label" => "Свежесть данных",
                "event_observation_label" => "События", "state_explanation" => "Что происходит",
                "adaptive_action" => "actions", _ => col
            }))).Append("</th>");
            html.Append("</tr></thead><tbody>");
            foreach (var row in rows.OfType<JsonObject>()) {
                html.Append("<tr>");
                foreach (string col in columns) {
                    string? value = row?[col] is {} node ? OpsJson.S(node) : null;
                    string text = col switch {
                        "channel" => UiLabels.Channel(value, withOriginal: true),
                        "last_status" or "status" => UiLabels.Status(value),
                        "severity" => UiLabels.Severity(value),
                        "warnings" => row?[col] is JsonArray warnings && warnings.Count > 0 ? string.Join("; ", warnings.Select(w => UiLabels.TranslateWarning(w is null ? null : OpsJson.S(w)))) : "—",
                        "adaptive_action" => AdaptiveActionLabel(row?[col]),
                        "generated_at_utc" or "last_collection_start_utc" or "last_successful_collection_utc" or "last_event_time_utc" or "archive_start_utc" or "updated_at" or "heartbeat_at" => FormatTime(row?[col]),
                        "recovery_mode" => UiLabels.Status(OpsJson.B(row?[col]) || OpsJson.N(row?[col]) != 0 ? "on" : "off"),
                        _ => value ?? "неизвестно"
                    };
                    html.Append("<td>").Append(E(text)).Append("</td>");
                }
                html.Append("</tr>");
            }
            html.Append("</tbody></table>");
        }
        Table("Каналы и покрытие", data["items"] as JsonArray ?? []);
        Table("Post-collection", jobs ?? data["post_collection"]?["items"] as JsonArray ?? []);
        Table("Workers", workers ?? data["workers"] as JsonArray ?? []);
        return html.Append("</body></html>").ToString();
    }

    static string FormatTime(JsonNode? value) => Time(value) is {} time ? time.ToString("dd.MM.yyyy HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) : "—";

    static string AdaptiveActionLabel(JsonNode? value)
    {
        string raw = S(value).Trim();
        if (raw.Length == 0) return "—";
        string[] parts = raw.Split(';', StringSplitOptions.TrimEntries);
        string[] action = parts[0].Split(':', 2);
        string label = action[0] switch { "keep" => "лимит сохранен", "increase_limit" => "лимит увеличен", "decrease_limit" => "лимит уменьшен", "" => "действие", _ => action[0] };
        if (action.Length > 1 && action[1].Length > 0)
            label += ": " + (action[1] switch { "stable" => "стабильная работа", "completed_streak" => "серия успешных сборов", "partial_timeout" => "частичный таймаут", "timeout" => "таймаут", "failed" => "ошибка сбора", "skipped_gt_inserted_x2" => "много повторно прочитанных событий", _ => action[1] });
        if (parts.Length > 1 && parts[1].Contains("->", StringComparison.Ordinal)) label += "; " + parts[1].Replace("->", " → ");
        if (parts.Length > 2 && parts[2].StartsWith("recovery=", StringComparison.Ordinal)) label += "; восстановление " + (parts[2][9..].Trim() == "on" ? "включено" : "выключено");
        return label;
    }
}
