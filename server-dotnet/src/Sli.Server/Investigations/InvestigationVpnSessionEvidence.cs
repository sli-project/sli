using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Infrastructure;

namespace Sli.Server.Investigations;

public sealed class InvestigationVpnSessionEvidence(IPostgresConnectionFactory connections, IInvestigationVpnEvidence rights) : IInvestigationVpnSessionEvidence
{
    public async Task<bool> AvailableAsync(AccessDecision access, BigInteger domain, string reference, CancellationToken ct)
    {
        if (domain <= 0 || !Regex.IsMatch(reference, @"\Aradius-session-row:[0-9a-f]{64}\z"))
            throw new InvestigationException("invalid_evidence_ref", "invalid_evidence_ref");
        if (domain > long.MaxValue || !rights.Allowed(access, (long)domain)) return false;
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await InvestigationLinksRepository.Execute(db, tx, "set transaction read only", _ => { }, ct);
        var rows = await InvestigationLinksRepository.Rows(db, tx, """
            select observation_id,lifecycle_event,identity_state,timestamp_state,session_identity_key,
                   exact_principal_key,observed_at_utc,canonical_record_sha256
            from radius_vpn_session_evidence_observations_v1
            where domain_id=@domain and session_row_id=@reference
            order by observed_at_utc,observation_id limit 10001
            """, c => { c.Parameters.AddWithValue("domain", (long)domain); c.Parameters.AddWithValue("reference", reference); }, ct);
        if (rows.Count > 10000) throw new InvestigationException("unavailable", "unavailable", 503);
        bool present = ContainsSession(rows, reference);
        await tx.CommitAsync(ct);
        if (!present) throw new InvestigationException("not_found", "not_found", 404);
        return true;
    }
    // Same (session key, generation, first observation) identity as fold_radius_sessions.
    // Only the protected candidate view is read; a stored row alone is insufficient.
    internal static bool ContainsSession(IEnumerable<JsonObject> rows, string reference)
    {
        var seen = new HashSet<string>(); var exact = new List<JsonObject>();
        foreach (var row in rows)
        {
            string id = Text(row, "observation_id"), lifecycle = Text(row, "lifecycle_event"), identity = Text(row, "identity_state"), timestamp = Text(row, "timestamp_state");
            if (id.Length is 0 or > 256 || !seen.Add(id) || lifecycle is not ("start" or "stop" or "interim_update") || identity is not ("exact" or "unresolved") || timestamp is not ("ready" or "unresolved")) throw Invalid();
            string key = Text(row, "session_identity_key"), principal = Text(row, "exact_principal_key");
            if (identity == "unresolved") { if (key.Length > 0 || principal.Length > 0) throw Invalid(); continue; }
            if (!key.StartsWith("radius-session:", StringComparison.Ordinal) || principal.Length == 0 || !Regex.IsMatch(Text(row, "canonical_record_sha256"), @"\A[0-9a-fA-F]{64}\z")) throw Invalid();
            if (timestamp == "unresolved") { if (row["observed_at_utc"] is not null) throw Invalid(); continue; }
            if (!DateTimeOffset.TryParse(Text(row, "observed_at_utc"), CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) throw Invalid();
            exact.Add(row);
        }
        bool found = false;
        foreach (var group in exact.GroupBy(r => Text(r, "session_identity_key")))
        {
            if (group.Select(r => Text(r, "exact_principal_key")).Distinct().Count() != 1) throw Invalid();
            int generation = 0; bool current = false;
            foreach (var row in group.OrderBy(r => DateTimeOffset.Parse(Text(r, "observed_at_utc"), CultureInfo.InvariantCulture)).ThenBy(r => Text(r, "observation_id"), StringComparer.Ordinal))
            {
                string lifecycle = Text(row, "lifecycle_event");
                if (lifecycle == "start" || !current)
                {
                    generation++; current = true;
                    string material = group.Key + "\0" + generation.ToString(CultureInfo.InvariantCulture) + "\0" + Text(row, "observation_id");
                    found |= reference == "radius-session-row:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
                }
                if (lifecycle == "stop") current = false;
            }
        }
        return found;
    }
    static string Text(JsonObject row, string key) => row[key]?.ToString().Trim() ?? "";
    static InvestigationException Invalid() => new("unavailable", "unavailable", 503);
}
