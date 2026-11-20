using System.Text.Json.Nodes;

namespace Sli.Server.Compatibility;

internal static partial class LegacySemantics
{
    internal static int[] AnalysisFamily(string key) => Declarations["analysis_families"]?[key.Trim()]?.AsArray().Select(n => int.Parse(n!.ToString())).ToArray() ?? [];
    internal static string? EventLabel(int id, string lang) => Declarations["labels"]?[id.ToString()] is JsonObject labels
        ? (labels[lang.Trim().ToLowerInvariant()] ?? labels["ru"])?.ToString() : null;
    internal static JsonObject FindingRules => Declarations["finding_rules"]!.DeepClone().AsObject();
    internal static int[] MonitorPrivilegedEventIds => Declarations["monitor_privileged_event_ids"]!.AsArray().Select(n => int.Parse(n!.ToString())).ToArray();

    // Frozen contextual classifier, separate from the catalogue card assessment.
    internal static JsonObject ClassifyContextual(JsonObject row)
    {
        int id = (int)Number(row, "event_id"); string channel = Text(row, "channel");
        string server = Text(row, "server", Text(row, "hostname"));
        var data = Object(row["event_data_json"]);
        string target = Text(row, "target_user_name"); if (target.Length == 0) target = Text(data, "TargetUserName");
        string subject = Text(row, "subject_user_name"); if (subject.Length == 0) subject = Text(data, "SubjectUserName");
        string group = Text(data, "TargetUserName", Text(data, "GroupName", target));
        bool dc = Text(row, "server_role") == "domain_controller" || server.StartsWith("dc", StringComparison.OrdinalIgnoreCase);
        string logon = Text(data, "LogonType", Text(data, "Logon Type")).Trim();
        JsonObject Result(string severity, string title, string reason) => new() { ["severity"] = severity, ["title"] = title, ["reason"] = reason };
        if (channel == "Security" && id == 4624)
        {
            string name = target.Trim().ToLowerInvariant().Split('\\')[^1];
            bool service = name.StartsWith("svc") || name.StartsWith("service") || name.EndsWith('$') || name.Contains("service");
            if (dc && service && logon is "2" or "10" or "11")
                return Result("critical", "Интерактивный вход сервисной учеткой на DC", $"Успешный вход 4624: account={target}, LogonType={logon}, server={server}.");
            return Result("info", "Успешный вход", "Базовый факт входа; критичность зависит от account/source/LogonType.");
        }
        if (channel == "Security" && id is 4728 or 4732 or 4756)
        {
            string name = group.Trim().ToLowerInvariant();
            if (new[] { "domain admins", "enterprise admins", "schema admins", "administrators", "администраторы домена", "администраторы предприятия", "администраторы схемы" }.Any(name.Contains))
                return Result("critical", "Изменение привилегированной группы", $"Затронута привилегированная группа {group}; actor={(subject.Length == 0 ? "—" : subject)}.");
            return Result("important", "Изменение группы", "Изменение группы требует проверки actor/member/target group.");
        }
        if (channel.Contains("taskscheduler", StringComparison.OrdinalIgnoreCase) && dc && id is 100 or 106 or 129 or 140 or 200 or 201)
            return Result("high", "Активность Scheduled Task на DC", $"Task Scheduler Event ID {id} на контроллере домена требует проверки task/action/run-as.");
        return Result("info", $"Event ID {id}", "Нет контекстного правила; используется базовая классификация.");
    }
}
