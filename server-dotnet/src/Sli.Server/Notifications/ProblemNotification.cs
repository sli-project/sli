namespace Sli.Server.Notifications;

internal static class ProblemNotification
{
    internal const string AdmissionAvailable = "to_regprocedure('public.enqueue_problem_notification419(uuid,uuid)') is not null";

    internal static bool IsTransition(bool created, bool reopened, string status, string previousSeverity, string severity) =>
        created || reopened || status is not ("closed" or "false_positive") && Rank(severity) > Rank(previousSeverity);

    private static int Rank(string severity) => severity switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };
}
