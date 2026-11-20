using System.Globalization;
using System.Numerics;

namespace Sli.Server.Auth.Lifecycle.Security;

// Exact rolling reservations (including successful/in-flight requests), not fixed/segmented windows.
public sealed class LoginSourceAdmission : ISourceAdmission
{
    private readonly object sync = new();
    private readonly Dictionary<string, List<long>> attempts = new(StringComparer.Ordinal);
    private readonly TimeProvider clock;
    private readonly int windowSeconds;
    private readonly int limit;

    public LoginSourceAdmission(IConfiguration configuration, TimeProvider? clock = null)
        : this(Parse(configuration["ADLOG_LOGIN_FAILURE_WINDOW_SECONDS"], 900),
            Parse(configuration["ADLOG_MAX_LOGIN_FAILURES"], 8), clock) { }

    public LoginSourceAdmission(int windowSeconds = 900, int limit = 8, TimeProvider? clock = null)
    {
        this.windowSeconds = Math.Clamp(windowSeconds, 60, 3600);
        this.limit = Math.Clamp(limit, 3, 30);
        this.clock = clock ?? TimeProvider.System;
    }

    private static int Parse(string? value, int fallback)
    {
        if (value is null) return fallback;
        // Python's configuration integers are unbounded; clamp before narrowing to the CLR type.
        var parsed = BigInteger.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
        return (int)BigInteger.Clamp(parsed, int.MinValue, int.MaxValue);
    }

    public AdmissionResult TryReserve(string address)
    {
        ArgumentNullException.ThrowIfNull(address);
        // Match the baseline sampling order: monotonic time is sampled before acquiring the lock.
        long now = clock.GetTimestamp();
        lock (sync)
        {
            foreach (string key in attempts.Keys.ToArray())
            {
                attempts[key].RemoveAll(t => clock.GetElapsedTime(t, now).TotalSeconds >= windowSeconds);
                if (attempts[key].Count == 0) attempts.Remove(key);
            }
            if (!attempts.TryGetValue(address, out var recent))
                attempts[address] = recent = [];
            if (recent.Count >= limit)
                return new(false, Math.Max(1, (int)(windowSeconds - clock.GetElapsedTime(recent[0], now).TotalSeconds)));
            recent.Add(now);
            return new(true, 0);
        }
    }
}
