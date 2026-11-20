namespace Sli.Agent.Service;

public static class Backoff
{
    /// <summary>The Python loop's wait: <c>min(interval, 60)</c> when healthy, otherwise <c>min(60, 2^n + jitter)</c> seconds.</summary>
    public static TimeSpan Delay(int intervalSeconds, int failures, Func<double>? jitter = null, string? errorCode = null)
    {
        if (errorCode == "agent_identity_missing_reenroll_required") return TimeSpan.FromMinutes(15);
        if (failures <= 0) return TimeSpan.FromSeconds(Math.Min(intervalSeconds, 60));
        return TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, failures) + (jitter ?? Random.Shared.NextDouble)()));
    }
}
