"""N01 minimal QW journal using the standard v2 table."""

from server.sli.core import notification_channels as channels
from server.sli.reporting.v2.definition import Column, ReportDefinition, ReportIntent, result


def _query(context):
    channels.require_access(context.access)
    if context.cursor not in {None, "smtp", "telegram"}:
        raise ValueError("invalid_cursor")
    try:
        rows = channels.list_channels(context.access)
    except PermissionError:
        raise
    except Exception:
        return result(REPORT, state="error")
    remaining = [row for row in rows if context.cursor is None or row["kind"] > context.cursor]
    page = remaining[:context.limit]
    more = len(remaining) > len(page)
    return result(REPORT, state="ok" if rows else "empty", items=page, filtered_count=len(rows),
                  has_more=more, next_cursor=page[-1]["kind"] if more else None)


REPORT = ReportDefinition(
    key="notifications.channels", section="admin", title="Каналы уведомлений",
    description="Реестр каналов почты и Telegram. Доставка ещё не настроена.",
    archetype="monitoring-operations", access=channels.ACCESS, params=(),
    columns=(
        Column("kind", "Канал", "state", labels={"smtp": "Почта", "telegram": "Telegram"}),
        Column("state", "Состояние", "state", labels={"not_configured": "Не настроен"}),
        Column("enabled", "Включён", "state", labels={"true": "Да", "false": "Нет"}),
        Column("tls_mode", "TLS"),
        Column("secret_ref", "Ссылка на секрет"),
        Column("revision", "Ревизия", "number"),
        Column("updated_at", "Изменён", "datetime"),
    ), query=_query, row_key="kind", default_limit=2, max_limit=2, detail="none",
    intent=ReportIntent(
        version=1, user_role="Platform administrator",
        question="Какие каналы уведомлений зарегистрированы и настроены?",
        action="Inspect channel metadata and use the admin metadata API to change it.",
        scope="Two installation-wide channels: SMTP and Telegram.",
        exclusions="No credential access, secret availability checks, recipients or delivery in N01.",
        sources=("Canonical: PostgreSQL notification_channels metadata registry.",),
        freshness_expectation="Текущие метаданные и сохранённая ревизия; актуальность доставки не подтверждается.",
        rights="Admin role, global access.manage and global notifications.channels grant with technical fields.",
        field_classes=("technical",), coverage="Exactly two registered channel kinds.",
        completeness="Registry completeness only; transport and secret availability are not proven.",
        denominator="Два канала; not_configured не означает приём сообщения провайдером.",
        retention="Current configuration is retained; safe changes enter the existing access audit.",
        provenance="Channel kind, revision and metadata update timestamp.", primary_archetype="list",
        product_archetype="monitoring-operations", deterministic_policy="Both channels remain not_configured in N01.",
        result_limits="Two metadata rows, no export or detail endpoint.",
        fallback="Read failure is an error, access failure is denied; neither becomes an empty registry.",
        acceptance_lanes={
            "product_user": "Both channel rows show not_configured.",
            "authorization": "Wrong role, missing capability or restricted grant denies before database access.",
            "deterministic_interpretation": "Metadata enablement does not claim configured delivery.",
            "api_view_model": "Only allowlisted metadata fields leave the repository.",
            "ui_honest_states": "Standard v2 table; error and denied remain explicit.",
            "evidence_audit": "Metadata revision and safe audit are committed atomically.",
        },
    ),
)
