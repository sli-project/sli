namespace Sli.Server.Agents.Registry;

/// <summary>One hour of server-observed contact gaps. No packets or host identities are retained.</summary>
public sealed class AgentLinkHistory
{
    private sealed record Gap(DateTimeOffset From, DateTimeOffset To, long Interval);
    private sealed class AgentState
    {
        public DateTimeOffset Last;
        public long Interval;
        public bool Enabled;
        public List<Gap> Gaps { get; } = [];
    }
    private readonly object sync = new();
    private readonly Dictionary<Guid, AgentState> agents = [];
    private DateTimeOffset nextPrune;

    private void Prune(DateTimeOffset now)
    {
        // Housekeeping runs once per minute, rather than scanning every agent
        // on every transport request or every row of the home projection.
        if (now < nextPrune) return;
        nextPrune = now.AddMinutes(1);
        var start = now.AddHours(-1);
        foreach (var (id, state) in agents.ToArray())
        {
            state.Gaps.RemoveAll(g => g.To <= start);
            if (state.Last < start && state.Gaps.Count == 0) agents.Remove(id);
        }
    }

    // Called only after certificate, registry and revocation checks succeed.
    // The locked PG row seeds the previous contact even after a server restart.
    public void Contact(Guid id, DateTimeOffset? previous, DateTimeOffset now, long interval, bool enabled)
    {
        if (interval <= 0) interval = 60;
        lock (sync)
        {
            Prune(now);
            if (!agents.TryGetValue(id, out var state)) agents[id] = state = new() { Last = previous ?? now, Interval = interval, Enabled = enabled };
            if (now < state.Last) return;
            if (!enabled || !state.Enabled || state.Interval != interval) state.Gaps.Clear();
            else
            {
                var before = previous > state.Last ? previous.Value : state.Last;
                if ((now - before).TotalSeconds > 3d * interval) state.Gaps.Add(new(before, now, interval));
            }
            state.Last = now;
            state.Interval = interval;
            state.Enabled = enabled;
        }
    }

    public DateTimeOffset? Check(Guid id, DateTimeOffset lastSeen, long interval, DateTimeOffset since, DateTimeOffset now)
    {
        lock (sync)
        {
            Prune(now);
            long missed = 0;
            DateTimeOffset? latest = null;
            void Count(Gap gap)
            {
                var overdue = gap.From.AddSeconds(3d * gap.Interval);
                var start = overdue > since ? overdue : since;
                var end = gap.To < now ? gap.To : now;
                if (end <= start) return;
                missed += (long)Math.Ceiling((end - start).TotalSeconds / gap.Interval);
                latest = end;
            }
            if (agents.TryGetValue(id, out var state))
            {
                foreach (var gap in state.Gaps.Where(g => g.Interval == interval)) Count(gap);
                if (state.Last > lastSeen) lastSeen = state.Last;
            }
            if (lastSeen < now) Count(new(lastSeen, now, interval));
            return missed >= 3 ? latest : null;
        }
    }
}
