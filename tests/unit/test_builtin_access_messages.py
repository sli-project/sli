"""Synthetic built-in metadata; no database, assignment or directory operations."""
from copy import deepcopy
import re

import pytest

from server.sli.core.messages import response_messages


PACKAGES = [
    ("security_operator", "ИБ · операторы", "Очередь проблем, влияние, гипотезы и безопасные действия", "InfoSec operators"),
    ("security_analyst", "ИБ · аналитики", "События, evidence, entities и investigations", "InfoSec analysts"),
    ("ad_auditor", "AD · аудит и сопровождение", "AD-отчёты, группы, привилегии и GPO", "AD audit and support"),
    ("project_operations", "Проект · эксплуатация", "Источники, workers, queues, PostgreSQL и readiness", "Platform operations"),
    ("access_admin", "Администраторы доступа", "Назначения, explain, preview и audit без автоматического чтения данных", "Access administrators"),
]
PURPOSE = "Что произошло, влияние, гипотеза и безопасный следующий шаг"
EN_PURPOSE = "What happened, its impact, the hypothesis and a safe next step"


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_subjects_translate_builtin_packages_but_keep_names_reasons_and_assignments(locale):
    payload = {"users": [{"username": "Исходное имя"}], "groups": [{"name": "ИБ · операторы"}],
               "packages": [{"package_key": key, "name": name, "description": description, "capabilities": ["reports.view"]}
                            for key, name, description, _ in PACKAGES],
               "assignments": [{"business_reason": "ИБ · операторы"}],
               "package_assignments": [{"package_key": key, "package_name": name, "effect": "deny", "business_reason": name}
                                       for key, name, _, _ in PACKAGES]}
    original = deepcopy(payload)
    result = response_messages(payload, locale, request_path="/api/v1/access/subjects")
    for package, assignment, (_, name, description, english) in zip(result["packages"], result["package_assignments"], PACKAGES):
        assert package["name"] == (english if locale == "en" else name)
        if locale == "ru":
            assert package["description"] == description
        else:
            assert not re.search("[А-Яа-яЁё]", package["description"])
        assert assignment["package_name"] == package["name"]
        assert assignment["effect"] == "deny" and assignment["business_reason"] == name
        assert package["presentation_messages"]["name"]["code"].endswith(".name")
    assert result["users"] == original["users"] and result["groups"] == original["groups"]
    assert result["assignments"] == original["assignments"]
    assert payload == original


def test_effective_access_keeps_decisions_and_translates_only_builtin_display_metadata():
    payload = {"packages": [{"key": "security_operator", "name": "ИБ · операторы"}],
               "reports": [{"report_key": "security.queue", "version": 1, "name": "Имя пользователя", "purpose": PURPOSE,
                            "allowed": False, "allowed_actions": [], "grants": [], "explanation": "Исходное основание"}],
               "explicit_denies": {"packages": ["security_operator"]}}
    original = deepcopy(payload)
    result = response_messages(payload, "en", request_path="/api/v1/access/effective")
    assert result["packages"][0]["name"] == "InfoSec operators"
    assert result["reports"][0]["purpose"] == EN_PURPOSE
    assert {k: v for k, v in result["reports"][0].items() if k not in {"purpose", "presentation_messages"}} == {
        k: v for k, v in original["reports"][0].items() if k != "purpose"}
    assert result["explicit_denies"] == original["explicit_denies"]
    assert payload == original


@pytest.mark.parametrize("path", ["/api/v1/access/grant-options", "/api/v1/reports/catalog"])
def test_builtin_report_purpose_is_localized_in_grant_options_and_catalog(path):
    payload = {"items": [{"report_key": "security.queue", "version": 1, "name": "Название владельца", "purpose": PURPOSE}],
               "limits": {"reports": 1}}
    result = response_messages(payload, "en", request_path=path)
    assert result["items"][0]["purpose"] == EN_PURPOSE
    assert result["items"][0]["name"] == "Название владельца"
    assert result["items"][0]["presentation_messages"]["purpose"]["text"] == EN_PURPOSE


def test_report_data_localizes_header_without_touching_observed_rows():
    report = {"report_key": "security.queue", "version": 1, "purpose": PURPOSE}
    payload = {"report": report, "items": [report], "fields": [{"label": PURPOSE}]}
    result = response_messages(payload, "en", request_path="/api/v1/reports/security.queue/data")
    assert result["report"]["purpose"] == EN_PURPOSE
    assert result["items"] == payload["items"] and result["fields"] == payload["fields"]
    assert response_messages(payload, "en", request_path="/api/v1/events") == payload


def test_customized_builtin_values_unknown_ids_and_report_versions_stay_verbatim():
    packages = [{"package_key": "security_operator", "name": "Название владельца", "description": "Описание владельца"},
                {"package_key": "custom", "name": "ИБ · операторы", "description": PURPOSE}]
    reports = [{"report_key": "security.queue", "version": 1, "purpose": "Описание владельца"},
               {"report_key": "custom", "version": 1, "purpose": PURPOSE},
               {"report_key": "security.queue", "version": 2, "purpose": PURPOSE}]
    assert response_messages({"packages": packages}, "en", request_path="/api/v1/access/subjects") == {"packages": packages}
    assert response_messages({"items": reports}, "en", request_path="/api/v1/access/grant-options") == {"items": reports}
    assert response_messages({"packages": packages}, "en") == {"packages": packages}


def test_current_ad_purpose_and_english_seed_follow_locale_at_response_time():
    report = {"report_key": "ad.state", "version": 1,
              "purpose": "Работоспособность и защищённость домена, контроллеров, репликации, DNS, политик и доверий"}
    english = response_messages({"items": [report]}, "en", request_path="/api/v1/access/grant-options")
    assert english["items"][0]["purpose"] == "Health and security of the domain, controllers, replication, DNS, policies and trusts"
    station = {"report_key": "workstations.overview", "version": 1, "purpose": "Scoped workstation workspace"}
    russian = response_messages({"items": [station]}, "ru", request_path="/api/v1/reports/catalog")
    assert russian["items"][0]["purpose"] == "Рабочее пространство станций в назначенной области"


@pytest.mark.parametrize("version", [True, False, None, "1", 0, 2])
def test_only_the_exact_builtin_version_is_translated(version):
    report = {"report_key": "security.queue", "version": version, "purpose": PURPOSE}
    assert response_messages({"items": [report]}, "en", request_path="/api/v1/reports/catalog") == {"items": [report]}


REPORT_NAMES = [
    ("security.queue", "Очередь проблем ИБ", "InfoSec problem queue"),
    ("events.explorer", "Технические события", "Technical events"),
    ("investigations.workspace", "Расследования", "Investigations"),
    ("ad.state", "Active Directory", "Active Directory"),
    ("ad.privileged", "Привилегированные учётные записи", "Privileged accounts"),
    ("ad.gpo.review", "GPO — MiXeD.пример.test", "GPO — MiXeD.пример.test"),
    ("operations.readiness", "Готовность и устойчивость проекта", "Platform readiness and resilience"),
    ("access.center", "Доступы пользователей и групп", "User and group access"),
    ("vpn.audit", "VPN-доступ и актуальность владельцев", "VPN access and owner status"),
    ("ad.users", "Пользователи", "Users"),
    ("ad.computers", "Компьютеры", "Computers"),
    ("ad.computers.v2", "Компьютеры v2", "Computers v2"),
    ("ad.computers.v4", "Компьютеры v4", "Computers v4"),
    ("ad.computers.v5", "Компьютеры v5", "Computers v5"),
    ("ad.computers.v6", "Компьютеры — MiXeD.пример.test", "Computers — MiXeD.пример.test"),
    ("ad.users.v2", "Пользователи — MiXeD.пример.test", "Users — MiXeD.пример.test"),
    ("ad.gpo.v2", "Групповые политики — MiXeD.пример.test", "Group policies — MiXeD.пример.test"),
    ("ad.computer-logons", "что где когда", "Computer logons"),
    ("security.events.chains", "Действия безопасности", "Security actions"),
    ("notifications.channels", "Каналы уведомлений", "Notification channels"),
    ("notifications.deliveries", "Журнал уведомлений", "Notification journal"),
    ("decoys.registry", "Decoy registry", "Decoy registry"),
    ("watch.registry", "Account watch", "Account watch"),
    ("workstations.overview", "Workstations", "Workstations"),
    ("file-audit.overview", "file-audit.overview", "Overview"),
    ("file-audit.actions", "file-audit.actions", "File actions"),
    ("file-audit.mass-operations", "file-audit.mass-operations", "Mass operations"),
    ("file-audit.permission-changes", "file-audit.permission-changes", "Permission changes"),
    ("file-audit.access-denials", "file-audit.access-denials", "Access denials"),
    ("file-audit.out-of-hours", "file-audit.out-of-hours", "Out of hours"),
    ("file-audit.permissions", "file-audit.permissions", "Permissions"),
    ("file-audit.audit-state", "file-audit.audit-state", "Audit state"),
]


@pytest.mark.parametrize("key,source,english", REPORT_NAMES)
def test_all_seeded_builtin_report_display_names_are_english(key, source, english):
    report = {"report_key": key, "version": 1, "name": source}
    result = response_messages({"items": [report]}, "en", request_path="/api/v1/reports/catalog")["items"][0]
    assert result["name"] == english
    assert "name" in result["presentation_messages"]
    assert report["name"] == source


@pytest.mark.parametrize("key,source,english", [
    ("ad.state", "Состояние и риски Active Directory", "Active Directory state and risks"),
    ("ad.gpo.review", "GPO — очередь ручной проверки", "GPO manual review queue"),
    ("ad.users.v2", "Пользователи — по референсу", "Users — reference"),
    ("ad.computers.v6", "Компьютеры — по референсу", "Computers — reference"),
])
def test_exact_legacy_titles_are_product_messages(key, source, english):
    result = response_messages({"items": [{"report_key": key, "version": 1, "name": source}]}, "en",
                               request_path="/api/v1/access/grant-options")
    assert result["items"][0]["name"] == english


def test_domain_in_legacy_purpose_is_a_verbatim_message_parameter():
    domain = "MiXeD.пример.test."
    source = f"Приблизительная история успешных входов доменных пользователей на рабочие станции {domain}"
    report = {"report_key": "ad.computer-logons", "version": 1, "purpose": source}
    result = response_messages({"items": [report]}, "en", request_path="/api/v1/reports/catalog")["items"][0]
    assert result["purpose"] == f"Approximate history of successful domain-user logons to workstations in {domain}"
    assert result["presentation_messages"]["purpose"]["params"] == {"domain": domain}
    assert report["purpose"] == source


@pytest.mark.parametrize("path", ["/api/v1/access/effective", "/api/v1/workspace"])
def test_workspace_and_effective_display_names_preserve_observed_data(path):
    report = {"report_key": "access.center", "version": 1, "name": "Доступы пользователей и групп"}
    source = {"reports": [report], "packages": [{"key": "security_operator", "name": "ИБ · операторы"}],
              "recent_objects": [report], "groups": [{"name": report["name"]}]}
    result = response_messages(source, "en", request_path=path)
    assert result["reports"][0]["name"] == "User and group access"
    assert result["packages"][0]["name"] == "InfoSec operators"
    assert result["recent_objects"] == source["recent_objects"] and result["groups"] == source["groups"]


def test_request_and_trace_titles_use_their_declared_version_slots():
    name = "Доступы пользователей и групп"
    item = {"report_key": "access.center", "report_version": 1, "report_name": name, "business_reason": name}
    result = response_messages({"items": [item]}, "en", request_path="/api/v1/access/report-requests")
    assert result["items"][0]["report_name"] == "User and group access"
    assert result["items"][0]["business_reason"] == name
    trace = {"report": {"report_key": "access.center", "version": 1, "name": name}, "grants": [item]}
    actual = response_messages(trace, "en", request_path="/api/v1/reports/access.center/access-trace")
    assert actual["report"]["name"] == "User and group access" and actual["grants"] == trace["grants"]


def test_builder_input_values_stay_raw_but_list_has_separate_display_messages():
    row = {"report_key": "access.center", "version": 1, "name": "Доступы пользователей и групп", "purpose": "Пакеты, grants, scopes, сроки и explain"}
    actual = response_messages({"items": [row]}, "en", request_path="/api/v1/reports/definitions")["items"][0]
    assert actual["name"] == row["name"] and actual["purpose"] == row["purpose"]
    assert actual["presentation_messages"]["name"]["text"] == "User and group access"
    detail = {"versions": [row]}
    assert response_messages(detail, "en", request_path="/api/v1/reports/definitions/access.center") == detail


@pytest.mark.parametrize("name", ["Отчёт владельца", "Групповые политики — мой отдельный отчёт", "Групповые политики — <img.test>"])
def test_custom_titles_and_unknown_ids_are_never_parsed_as_system_metadata(name):
    reports = [{"report_key": "ad.gpo.v2", "version": 1, "name": name},
               {"report_key": "custom", "version": 1, "name": "Групповые политики — fixture.test"},
               {"report_key": "access.center", "version": 2, "name": "Доступы пользователей и групп"}]
    assert response_messages({"items": reports}, "en", request_path="/api/v1/reports/catalog") == {"items": reports}


@pytest.mark.parametrize("key,source,english", [
    ("ad.state", "Домен, DC, accounts, computers и контекст AD", "Domain, DCs, accounts, computers and AD context"),
    ("ad.gpo.review", "Приоритеты governance без прямого изменения GPO", "Governance priorities without direct GPO changes"),
    ("notifications.deliveries", "Тестовая очередь: dry_run не означает доставку", "Test queue: dry_run does not mean delivery"),
    ("notifications.deliveries", "Тестовые проблемы: dry_run — без отправки; accepted — приём SMTP, не подтверждение получения",
     "Test problems: dry_run does not send; accepted means SMTP acceptance, not confirmed receipt"),
    ("notifications.deliveries", "Тестовые проблемы: dry_run — без отправки; accepted — приём SMTP или Telegram, не подтверждение прочтения",
     "Test problems: dry_run does not send; accepted means SMTP or Telegram acceptance, not confirmed reading"),
])
def test_registered_legacy_purposes_are_system_text_not_unknown_data(key, source, english):
    actual = response_messages({"items": [{"report_key": key, "version": 1, "purpose": source}]}, "en",
                               request_path="/api/v1/reports/catalog")["items"][0]
    assert actual["purpose"] == english
    assert ".alias." in actual["presentation_messages"]["purpose"]["code"]


@pytest.mark.parametrize("path,identity", [("/api/v1/ui/bootstrap", "key"),
                                          ("/api/v1/reports/access.center/access-summary", "package_key")])
def test_builtin_package_names_in_bootstrap_and_studio_summary(path, identity):
    payload = {"packages": [{identity: "security_operator", "name": "ИБ · операторы"}],
               "assignments": [{"name": "ИБ · операторы", "business_reason": "Основание владельца"}]}
    actual = response_messages(payload, "en", request_path=path)
    assert actual["packages"][0]["name"] == "InfoSec operators"
    assert actual["assignments"] == payload["assignments"]


def test_request_mutation_response_translates_metadata_without_changing_decision():
    request = {"report_key": "access.center", "report_version": 1, "report_name": "Доступы пользователей и групп",
               "status": "rejected", "decision_reason": "Решение владельца"}
    result = response_messages({"item": request}, "en", request_path="/api/v1/access/report-requests/51/decision")
    assert result["item"]["report_name"] == "User and group access"
    assert result["item"]["status"] == "rejected" and result["item"]["decision_reason"] == "Решение владельца"
    assert request["report_name"] == "Доступы пользователей и групп"


def test_unknown_file_audit_ids_and_changed_titles_do_not_use_identifier_fallback():
    reports = [{"report_key": "file-audit.future", "version": 1, "name": "file-audit.future"},
               {"report_key": "file-audit.actions", "version": 1, "name": "file-audit.overview"},
               {"report_key": "access.center", "version": 1, "name": "Доступы пользователей и групп (мой отчёт)"}]
    assert response_messages({"items": reports}, "en", request_path="/api/v1/reports/catalog") == {"items": reports}
