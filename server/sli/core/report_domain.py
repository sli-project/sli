"""Домен, по которому строятся отчёты каталога (пользователи, компьютеры, AD).

Единственная точка выбора домена отчётов. Встроенного имени домена нет.
Сохранённая настройка ``reports.domain_fqdn`` имеет приоритет, если домен
не помечен архивным. Для архивного/незаданного предпочтения используется
зарегистрированный неархивный домен с последним подтверждённым наблюдением.
Настройка при этом не переписывается. Установка может однократно заполнить его из
``SLI_INSTALL_DOMAIN``; рантайм окружение не читает. Если допустимый домен не найден,
выбрасывается ``ReportDomainNotConfiguredError``; вызывающий код
показывает честное состояние «домен отчётов не задан» вместо трассировки.

Значение подставляется в SQL литералом, поэтому принимается только имя DNS.
"""

from __future__ import annotations

NOT_CONFIGURED_CODE = "report_domain_not_configured"


class ReportDomainNotConfiguredError(RuntimeError):
    """Домен отчётов не задан в настройке БД.

    Намеренно не ``ValueError``: маршруты отчётов превращают ``ValueError`` в
    ответ 400 «неверный запрос», а здесь отказ — состояние установки (HTTP 503).
    """

    code = NOT_CONFIGURED_CODE

    def __init__(self) -> None:
        super().__init__(NOT_CONFIGURED_CODE)


def report_domain_fqdn() -> str:
    """FQDN домена отчётов в нижнем регистре.

    Не задан — ``ReportDomainNotConfiguredError``; некорректное значение — ``ValueError``.
    """
    from server.sli.core.platform_settings import get_setting

    try:
        configured = get_setting("reports.domain_fqdn")
    except ReportDomainNotConfiguredError:
        configured = None
    try:
        return effective_domain_fqdn(configured)
    except ReportDomainNotConfiguredError:
        raise
    except Exception as exc:
        raise ReportDomainNotConfiguredError() from exc


def preferred_domain(rows, preferred):
    """Choose only within caller-authorized rows; age never declares an archive.

    A saved non-archived preference wins, even without current evidence. An
    automatic choice requires a real, timezone-aware observation, not publication
    or event-ingestion time. Missing/invalid/future dates remain unknown.
    """
    from datetime import datetime, timezone

    eligible = [row for row in rows if not row.get("is_archived", False)]
    for row in eligible:
        if preferred and str(row["display_name"]).casefold() == preferred.casefold():
            return row
    observed = []
    now = datetime.now(timezone.utc)
    for row in eligible:
        evidence = row.get("freshness") or row
        raw = evidence.get("default_observed_at_utc") if "default_observed_at_utc" in evidence else evidence.get("observed_at_utc")
        try:
            stamp = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if stamp.tzinfo is None or stamp > now:
            continue
        observed.append((stamp, row))
    if not observed:
        return None
    return min(observed, key=lambda item: (-item[0].timestamp(), int(item[1]["id"])))[1]


def effective_domain_fqdn(configured: str | None) -> str:
    """Read-only effective default; explicit archive marking is a prerequisite."""
    from server.sli.core import database

    if configured:
        current = database.query_rows("select is_archived from domains where lower(fqdn) = ?", (configured,))
        if current and not current[0].get("is_archived", False):
            return configured
    chosen = preferred_domain(_observed_domains(), configured)
    if chosen is None:
        raise ReportDomainNotConfiguredError()
    from server.sli.core.platform_settings import _dns_name

    return _dns_name(str(chosen["display_name"]))


def _observed_domains():
    from server.sli.core import database

    return database.query_rows("""
        select d.id, d.fqdn as display_name, d.is_archived,
               observed.observed_at_utc
        from domains d
        left join lateral (
            select max(run.observed_at_utc) as observed_at_utc
            from ad_context_runs run
            where run.domain_id = d.id and run.status = 'completed'
        ) observed on true
        where not d.is_archived
        order by d.id
    """)


def suggested_domain_fqdn(configured: str | None, freshness_seconds: float | None) -> str | None:
    """Offer a change, never persist it or classify lifecycle from snapshot age."""
    from datetime import datetime, timezone

    from server.sli.core import database
    from server.sli.core.platform_settings import _dns_name

    if not configured or freshness_seconds is None or freshness_seconds <= 0:
        return None
    current = database.query_rows("select is_archived from domains where lower(fqdn) = ?", (configured,))
    if not current or current[0].get("is_archived") is not True:
        return None
    chosen = preferred_domain(_observed_domains(), None)
    if chosen is None:
        return None
    raw = chosen["observed_at_utc"]
    stamp = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    if not 0 <= age <= freshness_seconds:
        return None
    return _dns_name(str(chosen["display_name"]))
