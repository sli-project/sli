using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Auth.Recovery;

// Recovery's additional process-local budget; ordinary source admission still runs first.
public sealed class OwnerRecoveryAdmission(TimeProvider time)
{
    private sealed class Budget
    {
        public readonly List<long> Failures = [];
        public int Pending;
        public long? BlockedAt;
    }

    private readonly object sync = new();
    private readonly Dictionary<string, (Budget State, LinkedListNode<string> Node)> addresses = new(StringComparer.Ordinal);
    private readonly LinkedList<string> order = [];

    public async Task<Principal?> VerifyAsync(string address, Func<Task<Principal?>> authenticate)
    {
        Budget state;
        lock (sync)
        {
            long now = time.GetTimestamp();
            for (int i = 0; i < 64 && order.First is { } first; i++)
            {
                Budget oldest = addresses[first.Value].State;
                if (oldest.Pending != 0 || BlockRemaining(oldest, now) > 0
                    || oldest.Failures.Count != 0 && Age(oldest.Failures[^1], now) < 900) break;
                Remove(first.Value);
            }
            if (!addresses.TryGetValue(address, out var entry))
            {
                if (addresses.Count >= 4096) throw new LoginThrottledException(900);
                state = new();
                addresses.Add(address, (state, order.AddLast(address)));
            }
            else state = entry.State;
            double remaining = BlockRemaining(state, now);
            if (remaining > 0) throw new LoginThrottledException((int)Math.Ceiling(remaining));
            state.Failures.RemoveAll(stamp => Age(stamp, now) >= 900);
            if (state.Failures.Count + state.Pending >= 5) throw new LoginThrottledException(1);
            state.Pending++;
            Touch(address);
        }
        bool completed = false;
        Principal? principal = null;
        try
        {
            principal = await authenticate();
            completed = true;
            return principal;
        }
        finally
        {
            lock (sync)
            {
                state.Pending--;
                long now = time.GetTimestamp();
                state.Failures.RemoveAll(stamp => Age(stamp, now) >= 900);
                if (completed && principal is null)
                {
                    state.Failures.Add(now);
                    if (state.Failures.Count >= 5) state.BlockedAt = now;
                }
                Touch(address);
                if (state.Failures.Count == 0 && state.Pending == 0) Remove(address);
            }
        }
    }

    private double Age(long stamp, long now) => time.GetElapsedTime(stamp, now).TotalSeconds;
    private double BlockRemaining(Budget state, long now) => state.BlockedAt is { } stamp ? 900 - Age(stamp, now) : 0;
    private void Touch(string address) { var node = addresses[address].Node; order.Remove(node); order.AddLast(node); }
    private void Remove(string address) { order.Remove(addresses[address].Node); addresses.Remove(address); }
}
