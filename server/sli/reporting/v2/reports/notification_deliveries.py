"""Administrative delivery journal; simulation and provider acceptance stay distinct."""

from dataclasses import replace

from server.sli.core import notification_channels as channels, notification_outbox as outbox
from server.sli.core.messages import message
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import Column, ReportDefinition, result
from server.sli.reporting.v2.reports.notification_channels import REPORT as CHANNEL_REPORT

ACCESS = replace(channels.ACCESS, access_key="notifications.deliveries")


def _query(context):
    resolve_access_scope(context.access, ACCESS)
    # This journal has its own report grant, while subscription administration
    # remains tied to the existing channel configuration grant.
    if context.cursor is not None:
        try:
            outbox.identifier(context.cursor)
        except ValueError:
            raise ValueError("invalid_cursor") from None
    try:
        items, more = outbox.journal_rows(before=context.cursor, limit=context.limit)
    except Exception:
        return result(REPORT, state="error")
    return result(REPORT, state="ok" if items else "empty", items=items,
                  has_more=more, next_cursor=str(items[-1]["id"]) if more else None)


REPORT = ReportDefinition(
    key="notifications.deliveries", section="admin", title="Журнал уведомлений",
    description="Тестовые задания и выпуски отчётов. dry_run — без отправки; accepted — приём SMTP или Telegram, не подтверждение прочтения.",
    archetype="monitoring-operations", access=ACCESS, params=(),
    columns=(
        Column("id", "Задание"), Column("subscription_id", "Подписка"), Column("object_id", "Проблема / выпуск отчёта"),
        Column("period_from", "Начало периода", "datetime"), Column("period_to", "Конец периода (не включён)", "datetime"),
        Column("quality", "Качество данных"),
        Column("channel", "Канал", "state", labels={"smtp": "Почта", "telegram": "Telegram"}),
        Column("state", "Состояние", "state", labels={
            "pending": "В очереди", "sending": "Обрабатывается", "dry_run": "Тест без отправки",
            "accepted": "Принято провайдером",
            "delivery_unknown": "Исход отправки неизвестен",
            "retry": "Ожидает повтора", "failed": "Ошибка", "blocked": "Заблокировано", "cancelled": "Отменено",
        }),
        Column("attempts", "Попытки", "number"),
        Column("delivery_reason", message("reports.v2.notifications.deliveries.columns.delivery_reason.label")["text"], "state", labels={
            code: message(f"reports.v2.notifications.deliveries.columns.delivery_reason.labels.{code}")["text"]
            for code in ("live", "pipeline_delay", "historical_replay", "history_import")
        }),
        Column("delay_minutes", message("reports.v2.notifications.deliveries.columns.delay_minutes.label")["text"], "number"),
        Column("result_code", "Результат", "state", labels={
            **{code: message(f"reports.v2.notifications.deliveries.columns.result_code.labels.{code}")["text"]
               for code in ("historical_replay", "history_import")},
            "simulated": "Симуляция", "subscription_changed": "Подписка изменена",
            "recipient_denied": "Нет доступа", "access_unavailable": "Проверка доступа недоступна",
            "transport_unavailable": "Транспорт недоступен",
            "accepted": "Принято провайдером",
            "smtp_not_configured": "SMTP отключён или не настроен",
            "smtp_auth_failed": "Ошибка аутентификации SMTP",
            "smtp_rejected": "Отклонено SMTP-сервером",
            "smtp_unavailable": "SMTP временно недоступен",
            "smtp_outcome_unknown": "Исход отправки неизвестен; проверьте ящик перед повтором",
            "telegram_not_configured": "Telegram отключён или не настроен",
            "telegram_auth_failed": "Ошибка аутентификации Telegram",
            "telegram_chat_denied": "Чат Telegram недоступен для отправки",
            "telegram_rejected": "Отклонено Telegram",
            "telegram_rate_limited": "Ожидает снятия ограничения Telegram",
            "telegram_unavailable": "Telegram временно недоступен",
            "telegram_outcome_unknown": "Исход отправки неизвестен; проверьте чат перед повтором",
        }),
        Column("created_at", "Создано", "datetime"), Column("updated_at", "Изменено", "datetime"),
    ), query=_query, row_key="id", default_limit=50, max_limit=200, detail="none",
    intent=replace(
        CHANNEL_REPORT.intent,
        question="Как завершилась доставка проблемы или выпуска отчёта?",
        action="Inspect durable jobs; manage approved subscriptions through the administrative API.",
        scope="Installation-wide notification jobs and report releases, visible only to globally authorized administrators.",
        exclusions="No message bodies, addresses, credentials, semantic publication or proof of inbox receipt.",
        sources=("Canonical: PostgreSQL notification_outbox, notification_attempts and report_schedule_runs.",),
        freshness_expectation="Сохранённое состояние последней попытки; обработчик запускается отдельным процессом.",
        rights="Admin role, global access.manage and global notifications.deliveries grant with technical fields.",
        coverage="Durable test jobs and report releases, simulated attempts and opt-in SMTP/Telegram acceptance.",
        completeness="dry_run sends nothing; accepted means provider acceptance, not reading by a person.",
        denominator="Одна строка на проблему или выпуск отчёта, получателя и канал; повторы сохраняют ID задания.",
        retention="Pending jobs persist until terminal result; no deletion or retention worker is enabled by N03.",
        provenance="Stable job and subscription IDs, attempt count and safe result code.",
        deterministic_policy="A fake transport finishes as dry_run; Provider acceptance is recorded per job/channel. Replay reuses the job.",
        result_limits="At most 200 metadata rows per page; no export or detail endpoint.",
        acceptance_lanes={
            "product_user": "One problem or report slot yields one job per approved recipient/channel; provider acceptance is explicit.",
            "authorization": "Global admin journal grant; current owner and recipient report access rechecked before each attempt.",
            "deterministic_interpretation": "dry_run is simulated; accepted never claims inbox receipt. Uncertain provider outcomes require inspection.",
            "api_view_model": "Allowlisted metadata only, bounded cursor pagination.",
            "ui_honest_states": "Pending, blocked, retry, failed, cancelled, dry_run, accepted and delivery_unknown are distinct.",
            "evidence_audit": "Stable job identity, fenced leases and safe immutable attempt rows.",
        },
    ),
)
