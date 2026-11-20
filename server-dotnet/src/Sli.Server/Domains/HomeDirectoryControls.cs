using System.Text.Json.Nodes;

namespace Sli.Server.Domains;

internal static class HomeDirectoryControls
{
    private static readonly HashSet<string> Unknown = ["", "unknown", "unavailable", "timeout", "not_collected", "not_evaluated", "partial"];
    private static string Diagnostic(JsonNode? value) => Unknown.Contains(value?.ToString().ToLowerInvariant() ?? "") ? "not_evaluated"
        : value?.ToString().Equals("passed", StringComparison.OrdinalIgnoreCase) == true ? "passed" : "failed";
    internal static List<JsonObject> Build(IEnumerable<JsonObject> rows, bool qualified)
    {
        var controls = new List<JsonObject>();
        foreach (var row in rows)
        {
            var attrs = row["attributes"]?["attributes"] as JsonObject ?? row["attributes"] as JsonObject ?? new();
            var type = row.Text("entity_type");
            if (type == "ad_computer")
            {
                if (row.Text("source_section") != "domain_health" || attrs.Text("infrastructure_role") != "domain_controller") continue;
                type = "domain_controller";
            }
            void Add(string field, string id, string label, string qualification, string expected, string basis, string authority)
            {
                var name = row.Text("display_name") ?? row.Text("natural_key") ?? "—";
                var labelCode = "reports.v2.ad.infrastructure.controls." + id + ".label";
                var translated = HomePresentation.Text(labelCode);
                string Translate(string code, string fallback)
                { var text = HomePresentation.Text("reports.v2.ad.infrastructure." + code); return text == "reports.v2.ad.infrastructure." + code ? fallback : text; }
                var zero = id is "replication.result_code" or "replication.consecutive_failures";
                expected = Translate("controls." + (authority == "not_defined" ? "policy_unset" : zero ? "zero" : id) + ".expected", expected);
                basis = Translate("controls." + (authority == "not_defined" ? "policy_basis" : zero ? "zero.basis" : id is "domain.ldap_signing" or "domain.ldap_channel_binding" ? "ldap_basis" : id + ".basis"), basis);
                var actual = attrs[field]?.ToString();
                var actualCode = attrs.Boolean(field) is { } boolean ? "reports.boolean." + (boolean ? "yes" : "no") : "reports.values." + attrs.Text(field);
                var actualText = HomePresentation.Text(actualCode);
                if (actualText != actualCode) actual = actualText;
                controls.Add(new() { ["row_id"] = row.Number("entity_id") + ":" + id, ["control_id"] = id,
                    ["entity_id"] = row.Number("entity_id"), ["domain_id"] = row.Number("domain_id"),
                    ["entity_name"] = qualified ? row.Text("domain_name") + "\\" + name : name,
                    ["entity_type"] = type, ["qualification"] = qualification,
                    ["label"] = translated == labelCode ? label : translated, ["actual_text"] = actual,
                    ["expected_condition"] = expected, ["basis"] = basis, ["authority"] = authority,
                    ["observed_at_utc"] = row["observed_at_utc"].Copy(), ["source_section"] = row["source_section"].Copy() });
            }
            void Unset(string field, string id, string label)
            {
                if (attrs[field] is not null) Add(field, id, label, "policy_not_defined", "Требование организации не задано",
                    "Фактическое значение показано без квалификации; условие должен определить владелец политики.", "not_defined");
            }
            if (type == "domain_controller")
            {
                foreach (var (field, id, label, test) in new[] {
                    ("advertising_state", "dc.advertising", "Advertising контроллера домена", "Advertising"),
                    ("connectivity_state", "dc.connectivity", "Связность контроллера домена", "Connectivity"),
                    ("services_state", "dc.services", "Обязательные службы контроллера домена", "Services"),
                    ("sysvol_state", "dc.sysvol", "Доступность SYSVOL", "SysVolCheck"),
                    ("netlogon_state", "dc.netlogon", "Доступность NETLOGON", "NetLogons"),
                    ("dns_state", "dc.dns", "DNS контроллера домена", "DNS") })
                    if (attrs.ContainsKey(field)) Add(field, id, label, Diagnostic(attrs[field]), $"DCDiag {test} должен завершиться успешно",
                        $"Результат read-only DCDiag {test} для конкретного контроллера домена.", "collector_diagnostic");
                Unset("operating_system", "dc.operating_system", "Операционная система контроллера");
                Unset("operating_system_version", "dc.operating_system_version", "Версия операционной системы");
            }
            else if (type == "domain")
            {
                foreach (var (field, id, label) in new[] { ("domain_mode", "domain.functional_level", "Функциональный уровень домена"),
                    ("forest_mode", "forest.functional_level", "Функциональный уровень леса"), ("recycle_bin_enabled", "domain.recycle_bin", "Active Directory Recycle Bin"),
                    ("machine_account_quota", "domain.machine_account_quota", "MachineAccountQuota") }) Unset(field, id, label);
                foreach (var (field, id, label, expected) in new[] {
                    ("ldap_signing_requirement", "domain.ldap_signing", "Требование подписывания LDAP", "Правило отчёта v1: подписывание LDAP должно быть обязательным"),
                    ("ldap_channel_binding_requirement", "domain.ldap_channel_binding", "Требование LDAP channel binding", "Правило отчёта v1: значение не должно быть Never") })
                {
                    if (!attrs.ContainsKey(field)) continue;
                    var actual = attrs.Text(field)?.Trim().ToLowerInvariant();
                    var state = field == "ldap_signing_requirement" ? actual switch { "require_signing" => "passed", "not_required" => "failed", _ => "not_evaluated" }
                        : actual switch { "always" or "when_supported" => "passed", "never" => "failed", _ => "not_evaluated" };
                    Add(field, id, label, state, expected, "Неизвестное значение не является доказательством безопасной настройки; правило применяется только к наблюдаемому параметру.", "report_rule_v1");
                }
            }
            else if (type == "replication_link")
            {
                if (attrs.ContainsKey("replication_state")) Add("replication_state", "replication.state", "Состояние репликации", Diagnostic(attrs["replication_state"]),
                    "Проверка репликации должна завершиться успешно", "Результат read-only Get-ADReplicationPartnerMetadata.", "collector_diagnostic");
                foreach (var (field, id, label) in new[] { ("last_replication_result", "replication.result_code", "Код последней репликации"),
                    ("consecutive_failure_count", "replication.consecutive_failures", "Последовательные ошибки репликации") })
                    if (attrs.ContainsKey(field)) Add(field, id, label, attrs.Number(field) == 0 ? "passed" : "failed", "Значение должно быть равно 0",
                        "Фактический счётчик последнего read-only снимка метаданных репликации.", "collector_diagnostic");
                if (attrs.ContainsKey("last_replication_success_utc")) Add("last_replication_success_utc", "replication.last_success_freshness", "Свежесть успешной репликации",
                    attrs.Stamp("last_replication_success_utc") is not { } success || row.Stamp("observed_at_utc") is not { } observed ? "not_evaluated"
                        : observed - success > TimeSpan.FromDays(1) ? "failed" : "passed",
                    "Правило отчёта v1: успешная репликация не старше 24 часов", "Сравниваются время снимка и наблюдаемое время последней успешной репликации.", "report_rule_v1");
            }
            else if (type == "password_policy")
            {
                foreach (var (field, id, label) in new[] { ("password_min_length", "minimum_length", "Минимальная длина пароля"),
                    ("password_history_length", "history_length", "История паролей"), ("password_min_age", "minimum_age", "Минимальный возраст пароля"),
                    ("password_max_age", "maximum_age", "Максимальный возраст пароля"), ("password_properties", "properties", "Свойства парольной политики"),
                    ("lockout_threshold", "lockout_threshold", "Порог блокировки"), ("lockout_duration", "lockout_duration", "Длительность блокировки"),
                    ("lockout_observation_window", "lockout_observation_window", "Окно наблюдения блокировки") }) Unset(field, "password." + id, label);
            }
            else if (type == "domain_trust")
            {
                Unset("trust_direction", "trust.direction", "Направление доверия"); Unset("trust_type", "trust.type", "Тип доверия"); Unset("trust_attributes", "trust.attributes", "Атрибуты доверия");
            }
        }
        return controls;
    }
}
