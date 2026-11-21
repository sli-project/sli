using System.Globalization;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Problems;

public sealed partial class ProblemRepository
{
    private static readonly HashSet<string> PasswordDiagnostics = [
        "source_error", "password_v2_native_unavailable", "password_v2_window_truncated",
        "password_v2_xml_budget_exceeded", "xml_invalid", "state_bound", "clock_regression",
        "too_late", "coverage_gap", "gap_native_unavailable", "prequalification_native_unavailable",
        "episode_evidence_budget_exhausted", "prequalification_proof_budget_exhausted",
        "missing_target", "unclassified_failure", "ambiguous_failure", "conflicting_client", "missing_client"
    ];
    internal static JsonObject PasswordCoverageUnavailable() => new() {
        ["availability"] = "unavailable", ["as_of"] = null, ["rows"] = new JsonArray(), ["has_more"] = false
    };
    private static JsonObject CoverageShape(JsonNode? node, params string[] keys)
    {
        if (node is not JsonObject value || !keys.ToHashSet().SetEquals(value.Select(p => p.Key))) throw new FormatException();
        return value;
    }
    private static string CoverageText(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : throw new FormatException();
    private static bool CoverageBool(JsonNode? node) => node is JsonValue value && value.TryGetValue<bool>(out bool flag) ? flag : throw new FormatException();
    private static DateTimeOffset? CoverageTime(JsonNode? node, bool nullable = false)
    {
        if (nullable && node is null) return null;
        string text = CoverageText(node);
        if (!Regex.IsMatch(text, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)\z") ||
            !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp)) throw new FormatException();
        return stamp;
    }
    private static string CoverageCount(JsonNode? node)
    {
        string raw = node?.ToJsonString() ?? "";
        if (!Regex.IsMatch(raw, @"\A[0-9]+\z") || !BigInteger.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ||
            number > (BigInteger)25 * long.MaxValue) throw new FormatException();
        return number.ToString(CultureInfo.InvariantCulture);
    }
    // This is the sanitized SQL boundary, not a substitute for SQL source authority.
    internal static JsonObject ProjectPasswordCoverage(JsonNode? node, IReadOnlySet<long> domains)
    {
        try {
            var page = CoverageShape(node, "as_of", "rows", "has_more");
            var asOf = CoverageTime(page["as_of"])!.Value;
            bool more = CoverageBool(page["has_more"]);
            if (page["rows"] is not JsonArray source || source.Count > 256) throw new FormatException();
            var rows = new JsonArray(); var seen = new HashSet<(long, string, string)>();
            foreach (var value in source) {
                var row = CoverageShape(value, "domain_id", "rule_id", "scope_ref", "policy_state", "status", "reason",
                    "last_attempt_at", "last_completed_at", "last_successful_cutoff", "loss", "frozen_episode_count", "evidence_snapshot_as_of");
                string domainText = CoverageCount(row["domain_id"]);
                if (!long.TryParse(domainText, out long domain) || domain <= 0 || !domains.Contains(domain)) throw new FormatException();
                string rule = CoverageText(row["rule_id"]), scope = CoverageText(row["scope_ref"]);
                if (rule is not ("qw.password-brute-force" or "qw.password-spray") || !Regex.IsMatch(scope, @"\A[a-f0-9]{64}\z") ||
                    !seen.Add((domain, rule, scope))) throw new FormatException();
                string policy = CoverageText(row["policy_state"]), status = CoverageText(row["status"]);
                string? reason = row["reason"] is null ? null : CoverageText(row["reason"]);
                if (policy is not ("enabled" or "disabled" or "disabled_last_known" or "unknown") ||
                    status is not ("healthy" or "partial" or "error" or "stale" or "unknown" or "frozen") ||
                    reason is not null && !PasswordDiagnostics.Contains(reason) && reason is not ("attempt_stale" or "recent_loss" or "checkpoint_absent" or "policy_unconfirmed")) throw new FormatException();
                var times = new[] { "last_attempt_at", "last_completed_at", "last_successful_cutoff", "evidence_snapshot_as_of" }
                    .ToDictionary(k => k, k => CoverageTime(row[k], true));
                if (times.Values.Any(t => t > asOf)) throw new FormatException();
                if (row["loss"] is not JsonObject loss) throw new FormatException();
                var projectedLoss = new JsonObject();
                foreach (var (code, item) in loss) {
                    if (!PasswordDiagnostics.Contains(code)) throw new FormatException();
                    var summary = CoverageShape(item, "count_lower_bound", "count_exact", "from", "to", "observation_window_from", "as_of");
                    string count = CoverageCount(summary["count_lower_bound"]);
                    var from = CoverageTime(summary["from"], true); var to = CoverageTime(summary["to"], true);
                    var observed = CoverageTime(summary["observation_window_from"])!.Value;
                    _ = CoverageBool(summary["count_exact"]);
                    if (count == "0" || (from is null) != (to is null) || from > to ||
                        observed < asOf.AddHours(-24) || observed > asOf || CoverageTime(summary["as_of"]) != asOf) throw new FormatException();
                    var copy = summary.DeepClone().AsObject(); copy["count_lower_bound"] = count; projectedLoss[code] = copy;
                }
                string frozen = CoverageCount(row["frozen_episode_count"]);
                if (frozen != "0") status = "frozen";
                else if (status == "healthy") {
                    var completed = times["last_completed_at"];
                    if (completed is null) { status = "unknown"; reason = "checkpoint_absent"; }
                    else if ((asOf - completed.Value).TotalSeconds >= 300) { status = "stale"; reason = "attempt_stale"; }
                    else if (projectedLoss.Count > 0) { status = "partial"; reason = "recent_loss"; }
                }
                var projected = row.DeepClone().AsObject(); projected["domain_id"] = domainText; projected["loss"] = projectedLoss;
                projected["frozen_episode_count"] = frozen; projected["status"] = status; projected["reason"] = reason; rows.Add(projected);
            }
            return new() { ["availability"] = "observed", ["as_of"] = page["as_of"]!.DeepClone(), ["rows"] = rows, ["has_more"] = more };
        }
        catch (Exception error) when (error is FormatException or ArgumentException or InvalidOperationException or OverflowException) {
            return PasswordCoverageUnavailable();
        }
    }
    public async Task<JsonObject?> ReadQueuePasswordCoverageAsync(long[]? domains, CancellationToken ct)
    {
        if (domains?.Any(d => d <= 0) == true) throw new ArgumentException("password_coverage_domain", nameof(domains));
        if (domains is { Length: 0 }) return null;
        try {
            await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
            // The coverage function's checkpoint validation maintains private bookkeeping.
            await Execute(tx, "set local jit=off", new(), ct);
            await DirectRuntimeAuthorization.LoadAsync(db, tx, clock.GetUtcNow().UtcDateTime, ct);
            if (domains is null) {
                var catalog = await Rows(tx, "select id from public.domains order by id", null, ct);
                domains = catalog.Select(r => long.Parse(CoverageCount(CoverageShape(r, "id")["id"]), CultureInfo.InvariantCulture)).Distinct().Order().ToArray();
                if (domains.Any(d => d <= 0)) throw new FormatException();
                if (domains.Length == 0) return PasswordCoverageUnavailable();
            }
            var row = await One(tx, "select public.read_password_detection_coverage(@coverage_domains::bigint[]) as coverage",
                new() { ["coverage_domains"] = domains.Distinct().Order().ToArray() }, ct);
            await tx.CommitAsync(ct);
            return ProjectPasswordCoverage(row?["coverage"], domains.ToHashSet());
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return PasswordCoverageUnavailable(); } // Owned context is disposed before this catch.
    }
}
