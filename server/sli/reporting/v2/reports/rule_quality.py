"""L09: rule quality on the investigation v2 report framework."""

from datetime import timedelta

from server.sli.core.messages import message
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.reporting.v2.definition import AccessRule, Column, Detail, Param, QueryContext, ReportDefinition, ReportIntent, result, sort_rows
from server.sli.reports import rule_quality as engine

LIMITATIONS = {
    "basis": "Когорта — находки, созданные за период. Решения учитываются до конца периода; подавление, повторы, evidence и допуск policy — текущий снимок. Проценты рассчитаны по сохранённым данным, полнота сбора не доказана.",
    "classification": "Доля ложных срабатываний: FP / (FP + confirmed) по последней классификации каждой находки. Закрытие сохраняет классификацию; принятый риск исключён из знаменателя. Нет классификаций — нет оценки.",
    "policy_context": "Счётчики относятся к rule_code. Список policy и их допуск — текущий контекст, а не доказанная атрибуция находок конкретной версии policy.",
    "evidence": "Полные evidence здесь означают: все заявленные связи ведут к сохранённым фактам с кодом, временем, record ID и каналом. Полнота источника и наличие полного исходного текста этим не доказаны.",
    "accepted_risk_unavailable": "Статус принятого риска не поддерживается текущим lifecycle; метрика недоступна.",
    "truncated": "Достигнут предел чтения 10 000 находок. Метрики и порядок частичные; сузьте период.",
    "history_missing": "Для части находок нет сохранённой истории за выбранное окно. Решения и время до решения неполны.",
    "unavailable": "Сохранённые данные качества правил недоступны. Оценка качества не выполнена.",
}


# Exact built-in scenario IDs from the canonical semantic producers. These are
# rule display names, not retained finding titles or policy-version attribution.
RULE_NAMES = {
    "semantic.qw.password-spray": "password_spray",
    "semantic.qw.password-brute-force": "password_brute",
    "semantic.qw.disabled-account-logon": "disabled_logon",
    "semantic.qw.account-decoy": "account_decoy",
    "semantic.qw.account-watch": "account_watch",
    "semantic.qw.file-decoy": "file_decoy",
    "semantic.qw.file-ransom": "file_ransom",
    "semantic.qw.file-acl-broad-write": "file_acl",
    "semantic.qw.nps-denials": "nps_denials",
    # Both audit-policy changes and cleared security logs use this scenario.
    "semantic.security.audit_controls_changed": "audit_controls_changed",
    "semantic.security.privileged_group_member_added": "privileged_group_member_added",
    "semantic.security.scheduled_task_created": "scheduled_task_created",
}


def _presentation(row):
    suffix = RULE_NAMES.get(row['rule_code'])
    if suffix is None:
        kind = row.get("rule_result_class")
        suffix = "metadata." + kind if kind in engine.RULE_RESULT_CLASSES else "unknown"
    name = message(f"reports.v2.security.rule-quality.names.{suffix}")
    technical = {key: row.get(key) for key in (
        "rule_code", "policies", "admitted_policies", "managed_policies",
        "closed", "accepted_risk", "suppressed", "classified", "median_decision_seconds", "decided", "repeat_rate",
    )}
    return {**row, "rule_name": name["text"], "presentation_messages": {"rule_name": name}, "technical_details": [technical]}


def _query(context: QueryContext):
    domains = context.scope.domain_ids()
    if domains == []:
        raise PermissionError("report_scope_not_executable")
    period = context.params["period"]
    binding = {"scope": context.scope.fingerprint, "period": period["preset"], "sort": context.sort, "direction": context.direction}
    if period["preset"] == "custom":
        binding.update(start=period["from_utc"], end=period["to_utc"])
    after = decode_cursor(context.cursor, binding) if context.cursor else None
    try:
        start, end = (engine.utc(after[key] if after else period[param]) for key, param in (("start", "from_utc"), ("end", "to_utc")))
        if after and period["preset"] == "custom" and (start != engine.utc(period["from_utc"]) or end != engine.utc(period["to_utc"])):
            raise ValueError("invalid_cursor")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid_cursor") from exc
    if not start < end or end - start > timedelta(days=90):
        raise ValueError("invalid_cursor")
    window = {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()}
    try:
        raw = engine.load_quality(start, end, domain_ids=domains, authorization=context.runtime.get("storage_route_authorization"))
    except PermissionError:
        raise
    except Exception:
        return result(REPORT, state="error", window=window, limitations=[{"code": "unavailable", "text": LIMITATIONS["unavailable"]}])
    rows = sort_rows(REPORT, raw["items"], context.sort or "false_positive_rate", context.direction if context.sort else "desc")
    offset = after.get("offset", 0) if after else 0
    if type(offset) is not int or offset < 0:
        raise ValueError("invalid_cursor")
    page = [dict(_presentation(row), cohort_from=start.isoformat(), cohort_to=end.isoformat()) for row in rows[offset:offset + context.limit]]
    more = offset + context.limit < len(rows)
    cursor = encode_cursor(binding, {"start": start.isoformat(), "end": end.isoformat(), "offset": offset + context.limit}) if more else None
    codes = ["basis", "classification", "policy_context", "evidence"]
    if not raw["accepted_risk_supported"]:
        codes.append("accepted_risk_unavailable")
    if raw["truncated"]:
        codes.append("truncated")
    if any(row["missing_history"] for row in rows):
        codes.append("history_missing")
    partial = raw["truncated"] or "history_missing" in codes
    return result(REPORT, state="partial" if partial else "ok" if rows else "empty", items=page,
        window=window, filtered_count=len(rows), has_more=more, next_cursor=cursor,
        limitations=[{"code": code, "text": LIMITATIONS[code]} for code in codes],
        coverage={"completeness": "not_proven", "truncated": raw["truncated"], "accepted_risk_supported": raw["accepted_risk_supported"]})


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security analyst and semantic rule reviewer",
        question="Каково качество опубликованных семантических правил по сохранённым находкам выбранного периода?",
        action="Inspect per-rule classifications and evidence, then drill into the exact finding cohort for review.",
        scope="Server-resolved granted domains and findings created within the selected period, bounded to 90 days and 10,000 findings.",
        exclusions="No source-completeness proof, policy-version attribution or automatic rule changes; unclassified findings have no false-positive estimate.",
        sources=(
            "Canonical: published semantic findings, retained lifecycle decisions before the period end and linked retained facts.",
            "Supplemental: current suppression, repeat observations, evidence availability and policy admission context.",
        ),
        freshness_expectation="Решения учитываются до конца периода; подавление, повторы, evidence и допуск policy отражают текущий снимок и проверяются отдельно.",
        rights="security.queue view grant with security fields and semantic.review capability; server resolves domain scope before reading; export is unavailable.",
        field_classes=("security",),
        coverage="Retained creation cohort and decision history; truncation and missing history are separate limitations, and collection completeness is not proven.",
        completeness="Source-confirmed retained findings divided by the expected finding population for the granted scope and window; the expected population is unknown. Currently not_proven.",
        denominator="Для доли FP — FP + confirmed в когорте созданных за период находок; для полноты — ожидаемые находки разрешённого среза, число которых неизвестно.",
        retention="Findings, lifecycle history and derived evidence follow their storage policies; full source text may expire independently.",
        provenance="Rule code, exact creation window, retained finding and decision history, and links to retained source facts.",
        primary_archetype="summary",
        product_archetype="monitoring-operations",
        deterministic_policy="FP rate is FP / (FP + confirmed) from each finding's latest classification before period end; accepted risk is excluded.",
        result_limits="Creation cohort is at most 90 days and 10,000 findings; current policy context does not attribute a finding to a policy version.",
        fallback="No classified findings means no FP estimate; truncation or missing history stays partial, reader failure stays unavailable.",
        acceptance_lanes={
            "product_user": "Per-rule measurements answer the retained-cohort quality question.",
            "authorization": "security.queue grant, security fields, semantic.review and server domain scope are mandatory; export is absent.",
            "deterministic_interpretation": "FP denominator, latest classification and exclusion of accepted risk are checked independently.",
            "api_view_model": "Sealed cohort cursors preserve the window and bounded per-rule metrics.",
            "ui_honest_states": "Unknown estimates, unsupported accepted risk and partial history are visible without zero substitution.",
            "evidence_audit": "Rule code and cohort link back to retained findings, decision history and evidence.",
        },
    ),
    key="security.rule-quality", section="investigation", title="Качество правил",
    description="Качество опубликованных семантических правил по находкам, решениям аналитиков и сохранённым доказательствам.",
    archetype="investigation-evidence",
    access=AccessRule("security.queue", required_fields=frozenset({"security"}), required_capabilities=frozenset({"semantic.review"})),
    params=(Param.period(default="30d", max_days=90),),
    columns=(
        Column("rule_name", "Правило", link="/app/report/security.problems?rule_code={rule_code}&created_from={cohort_from}&created_to={cohort_to}&show_suppressed=true"),
        Column("findings_produced", "Создано находок", "number"),
        Column("confirmed", "Подтверждено", "number"),
        Column("false_positive", "Ложные срабатывания", "number"),
        Column("closed", "Закрыто", "number"),
        Column("accepted_risk", "Принят риск", "number"),
        Column("suppressed", "Подавлено сейчас", "number"),
        Column("false_positive_rate", "Ложные срабатывания, %", "number", sortable=True),
        Column("classified", "Классифицировано (FP + confirmed)", "number"),
        Column("median_decision_seconds", "Медиана до первого решения, с", "number"),
        Column("decided", "С первым решением", "number", optional=True),
        Column("repeat_rate", "Повторные находки, %", "number"),
        Column("complete_evidence_share", "Полные evidence, %", "number"),
    ), query=_query, row_key="rule_code", default_limit=50, max_limit=200,
    detail=Detail(title="Технические сведения", key="rule_code", inline="technical_details", columns=(
        Column("closed", "Закрыто", "number"),
        Column("accepted_risk", "Принят риск", "number"),
        Column("suppressed", "Подавлено сейчас", "number"),
        Column("classified", "Классифицировано (FP + confirmed)", "number"),
        Column("median_decision_seconds", "Медиана до первого решения, с", "number"),
        Column("decided", "С первым решением", "number"),
        Column("repeat_rate", "Повторные находки, %", "number"),
        Column("rule_code", "Код правила"),
        Column("policies", "Текущие версии политик (контекст)", "list"),
        Column("admitted_policies", "Допущенные версии политик сейчас", "list"),
        Column("managed_policies", "Версии политик с явным допуском", "list"),
    )),
)

