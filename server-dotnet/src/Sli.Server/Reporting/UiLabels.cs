using System.Globalization;
using Sli.Server.Entities;

namespace Sli.Server.Reporting;

// Frozen reporting/ui_labels.py dictionaries; raw values are escaped by the renderer.
internal static class UiLabels
{
    static bool English(string? lang) => string.Equals(lang?.Trim(), "en", StringComparison.OrdinalIgnoreCase);
    static string Key(string? value) => string.IsNullOrEmpty(value) ? "unknown" : value;
    internal static string Status(string? value, string? lang = null) => Key(value) switch
    {
        "completed" => English(lang) ? "completed" : "завершено",
        "partial_timeout" => English(lang) ? "partial timeout" : "частичный сбор по таймауту",
        "timeout" => English(lang) ? "timeout" : "таймаут",
        "failed" => English(lang) ? "failed" : "ошибка",
        "running" => English(lang) ? "running" : "выполняется",
        "queued" => English(lang) ? "queued" : "в очереди",
        "stale" => English(lang) ? "stale" : "устарело",
        "unknown" => English(lang) ? "unknown" : "неизвестно",
        "ok" => English(lang) ? "ok" : "норма",
        "warn" => English(lang) ? "warning" : "внимание",
        "high" => English(lang) ? "high" : "высокий риск",
        "critical" => English(lang) ? "critical" : "критично",
        "info" => English(lang) ? "info" : "информация",
        "low" => English(lang) ? "low" : "низкий риск",
        "medium" => English(lang) ? "medium" : "средний риск",
        "on" => English(lang) ? "on" : "включен",
        "off" => English(lang) ? "off" : "выключен",
        "new" => English(lang) ? "new" : "новый",
        "active" => English(lang) ? "active" : "активный",
        "repeated" => English(lang) ? "repeated" : "повторяется",
        "review" => English(lang) ? "in review" : "проверяется",
        "confirmed" => English(lang) ? "confirmed" : "подтвержден",
        "false_positive" => English(lang) ? "false positive" : "ложное срабатывание",
        "closed" => English(lang) ? "closed" : "закрыт",
        _ => Key(value)
    };
    internal static string Severity(string? value, string? lang = null) => Key(value) switch
    {
        "critical" => English(lang) ? "critical" : "критично",
        "high" => English(lang) ? "high" : "высокий",
        "medium" => English(lang) ? "medium" : "средний",
        "warn" => English(lang) ? "warning" : "внимание",
        "low" => English(lang) ? "low" : "низкий",
        "info" => English(lang) ? "info" : "информация",
        "ok" => English(lang) ? "ok" : "норма",
        "unknown" => English(lang) ? "unknown" : "неизвестно",
        _ => Key(value)
    };
    internal static string EntityRole(string? value, string? lang = null) => Key(value) switch
    {
        "recorder" => English(lang) ? "recorder" : "источник записи",
        "actor" => English(lang) ? "actor" : "кто выполнил действие",
        "target" => English(lang) ? "target" : "над кем/чем выполнено действие",
        "affected" => English(lang) ? "affected" : "затронутый объект",
        "source" => English(lang) ? "source" : "откуда пришло действие",
        "context" => English(lang) ? "context" : "контекст",
        "executor" => English(lang) ? "executor" : "исполнитель",
        "unknown" => English(lang) ? "unknown role" : "роль не определена",
        _ => Key(value)
    };
    internal static string EntityType(string? value, string? lang = null) => Key(value) switch
    {
        "user" => English(lang) ? "user account" : "учетная запись",
        "group" => English(lang) ? "group" : "группа",
        "computer" => English(lang) ? "computer" : "компьютер",
        "server" => English(lang) ? "server" : "сервер",
        "domain_controller" => English(lang) ? "domain controller" : "контроллер домена",
        "ip" => English(lang) ? "IP address" : "IP-адрес",
        "session" => English(lang) ? "session / LogonId" : "сеанс / LogonId",
        "task" => English(lang) ? "scheduled task" : "задание планировщика",
        "service" => English(lang) ? "service" : "служба",
        "process" => English(lang) ? "process" : "процесс",
        "unknown" => English(lang) ? "object" : "объект",
        _ => Key(value)
    };
    internal static string Field(string? value, string? lang = null) => Key(value) switch
    {
        "server" => English(lang) ? "Server" : "Сервер",
        "channel" => English(lang) ? "Channel" : "Журнал",
        "status" => English(lang) ? "Status" : "Статус",
        "severity" => English(lang) ? "Severity" : "Важность",
        "last_collection" => English(lang) ? "Last collection" : "Последний сбор",
        "last_event" => English(lang) ? "Last event" : "Последнее событие",
        "record_id" => "Record ID",
        "lag" => English(lang) ? "Lag" : "Отставание",
        "timeouts" => English(lang) ? "Timeouts" : "Таймауты",
        "partial" => English(lang) ? "Partial" : "Частичные",
        "inserted_skipped" => English(lang) ? "Inserted / skipped" : "Добавлено / пропущено",
        "adaptive_limit" => English(lang) ? "Adaptive limit" : "Адаптивный лимит",
        "recovery" => English(lang) ? "Recovery" : "Режим восстановления",
        "actions" => English(lang) ? "Actions" : "Действия",
        "time" => English(lang) ? "Time" : "Время",
        "utc" => "UTC",
        "local_time" => English(lang) ? "Local time" : "Локальное время",
        "event_id" => "Event ID",
        "event_name" => English(lang) ? "Meaning" : "Что это значит",
        "subject" => English(lang) ? "Subject" : "Инициатор",
        "target" => English(lang) ? "Target" : "Цель",
        "source" => English(lang) ? "Source" : "Источник",
        "details" => English(lang) ? "Details" : "Детали",
        "role" => English(lang) ? "Role" : "Роль",
        "confidence" => English(lang) ? "Confidence" : "Уверенность",
        "user" => English(lang) ? "User" : "Учетная запись",
        "ip" => English(lang) ? "IP address" : "IP-адрес",
        "logon_id" => "LogonId",
        "message" => English(lang) ? "Message" : "Сообщение",
        _ => Key(value)
    };
    internal static string Channel(string? value, string? lang = null, bool withOriginal = false)
    {
        string label = Key(value) switch
        {
            "Security" => English(lang) ? "Security" : "Безопасность",
            "System" => English(lang) ? "System" : "Система",
            "Directory Service" => English(lang) ? "Directory Service" : "Служба каталогов",
            "DNS Server" => English(lang) ? "DNS Server" : "DNS-сервер",
            "Microsoft-Windows-PowerShell/Operational" => English(lang) ? "PowerShell" : "PowerShell",
            "Microsoft-Windows-TaskScheduler/Operational" => English(lang) ? "Task Scheduler" : "Планировщик заданий",
            _ => Key(value)
        };
        return withOriginal && !string.IsNullOrEmpty(value) && label != value ? $"{label} ({value})" : label;
    }
    internal static string TranslateWarning(string? value, string? lang = null)
    {
        if (string.IsNullOrEmpty(value)) return "—";
        if (English(lang)) return value;
        return value switch
        {
            "channel timeout" => "таймаут канала",
            "Security lag > 2h" => "отставание Security больше 2 часов",
            "Security lag > 30m" => "отставание Security больше 30 минут",
            "possible repeated backlog read" => "возможно повторное чтение backlog",
            "channel data stale" => "данные канала давно не обновлялись",
            _ => value
        };
    }
    // No explicit source identity: Python defaults to the bundled AD/DC normalizer.
    internal static string EventId(string? value, string? lang = null, bool prefix = true)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int id)) return prefix ? "Event ID —" : "—";
        string? text = English(lang) ? id switch
        {
            4624 => "Successful logon",
            4625 => "Failed logon",
            4634 => "Logoff",
            4647 => "User initiated logoff",
            4648 => "Explicit credentials logon",
            4672 => "Special privileges assigned",
            4720 => "User account created",
            4722 => "User account enabled",
            4723 => "Password change attempt",
            4724 => "Password reset attempt",
            4725 => "User account disabled",
            4726 => "User account deleted",
            4728 => "Added to privileged group",
            4729 => "Removed from privileged group",
            4732 => "Added to local group",
            4733 => "Removed from local group",
            4740 => "Account locked out",
            4767 => "Account unlocked",
            4781 => "Account renamed",
            4768 => "Kerberos TGT requested",
            4769 => "Kerberos service ticket requested",
            4771 => "Kerberos pre-authentication failed",
            4776 => "Credential validation",
            5504 => "DNS invalid query/response",
            7045 => "New service installed",
            _ => null
        } : EntityEventLabels.Label(id);
        if (text == $"Event ID {id}") text = null;
        return text is null ? prefix ? $"Event ID {id}" : English(lang) ? "Unknown event type" : "неизвестный тип события"
            : prefix ? $"Event ID {id}: {text}" : text;
    }
}
