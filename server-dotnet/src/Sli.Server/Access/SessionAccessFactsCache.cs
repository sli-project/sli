using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access;

// Frozen session_access_cache.py: recheck the audit revision and the next grant
// boundary on every request. Authentication and plugin admission are never cached.
public sealed class SessionAccessFactsCache(IPostgresConnectionFactory connections, TimeProvider clock)
{
    internal const string StampSql = """
        select (select coalesce(max(id),0) from access_audit_v4) as revision,
            (select count(*) from access_audit_v4) as revision_count,
            (select min(boundary) from (
                select valid_from as boundary from access_group_members where valid_from>now() union all
                select valid_until from access_group_members where valid_until>now() union all
                select valid_from from access_subject_packages where valid_from>now() union all
                select valid_until from access_subject_packages where valid_until>now() union all
                select valid_from from access_capability_assignments where valid_from>now() union all
                select valid_until from access_capability_assignments where valid_until>now() union all
                select valid_from from access_report_assignments where valid_from>now() union all
                select valid_until from access_report_assignments where valid_until>now()
            ) changes) as next_change
        """;
    sealed record Entry(Principal Principal, long Revision, long Count, long Captured, TimeSpan Lifetime, AccessFacts Facts);
    readonly object gate = new();
    readonly Dictionary<string, LinkedListNode<(string Key, Entry Value)>> cache = new(StringComparer.Ordinal);
    readonly LinkedList<(string Key, Entry Value)> order = new();

    public void Invalidate(string? token = null, long? userId = null)
    {
        lock (gate)
        {
            if (!string.IsNullOrEmpty(token))
            {
                string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
                if (cache.Remove(key, out var node)) order.Remove(node);
            }
            else if (userId.HasValue)
            {
                foreach (var key in order.Where(item => item.Value.Principal.Id == userId.Value).Select(item => item.Key).ToArray())
                {
                    order.Remove(cache[key]); cache.Remove(key);
                }
            }
            else { cache.Clear(); order.Clear(); }
        }
    }
    internal async Task<AccessFacts> LoadAsync(Principal principal, string? token, Func<Task<AccessFacts>> loader, CancellationToken ct)
    {
        if (principal.Type != "session" || string.IsNullOrEmpty(token)) return await loader();
        long revision, count; DateTimeOffset? next;
        await using (var db = await connections.OpenAsync(ct))
        await using (var command = new NpgsqlCommand(StampSql, db) { CommandTimeout = 0 })
        await using (var row = await command.ExecuteReaderAsync(ct))
        {
            if (!await row.ReadAsync(ct)) throw new InvalidOperationException("access_policy_stamp_unavailable");
            revision = row.GetInt64(0); count = row.GetInt64(1); next = row.IsDBNull(2) ? null : new DateTimeOffset(row.GetDateTime(2));
        }
        string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        var now = clock.GetUtcNow(); long captured = clock.GetTimestamp();
        lock (gate)
        {
            if (cache.Remove(key, out var node))
            {
                order.Remove(node); var entry = node.Value.Value;
                if (entry.Principal == principal && entry.Revision == revision && entry.Count == count && clock.GetElapsedTime(entry.Captured, captured) < entry.Lifetime)
                { order.AddLast(node); cache.Add(key, node); return Copy(entry.Facts); }
            }
        }
        var facts = await loader(); var lifetime = TimeSpan.FromSeconds(60); if (next is {} boundary && boundary - now < lifetime) lifetime = boundary > now ? boundary - now : TimeSpan.Zero;
        lock (gate)
        {
            if (cache.Remove(key, out var existing)) order.Remove(existing);
            cache[key] = order.AddLast((key, new Entry(principal, revision, count, captured, lifetime, Copy(facts))));
            while (cache.Count > 256 && order.First is {} first) { cache.Remove(first.Value.Key); order.RemoveFirst(); }
        }
        return facts;
    }
    static AccessFacts Copy(AccessFacts f) => f with { Packages = f.Packages.Select(v => v.Clone()).ToArray(), PackageCapabilities = f.PackageCapabilities.Select(v => v.Clone()).ToArray(), DirectCapabilities = f.DirectCapabilities.Select(v => v.Clone()).ToArray(), AllCapabilities = f.AllCapabilities.Select(v => v.Clone()).ToArray(), PackageReports = f.PackageReports.Select(v => v.Clone()).ToArray(), ReportAssignments = f.ReportAssignments.Select(v => v.Clone()).ToArray(), Definitions = f.Definitions.Select(v => v.Clone()).ToArray(), Groups = f.Groups.Select(v => v.Clone()).ToArray(), Requests = f.Requests.Select(v => v.Clone()).ToArray(), Preferences = f.Preferences.Select(v => v.Clone()).ToArray(), ReportCatalog = null };
}
