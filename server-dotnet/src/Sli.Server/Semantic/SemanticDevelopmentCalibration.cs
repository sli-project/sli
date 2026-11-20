using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

// Synthetic labels establish the development contract without writing analyst reviews.
internal static class SemanticDevelopmentCalibration
{
    internal const string EvidenceClass = "development_fixture";

    internal static JsonObject EvaluateDevelopmentFixture(IEnumerable<string?> verdicts, int minimumSample = 10)
    {
        string[] normalized = verdicts.Select(value => (value ?? "").Trim().ToLowerInvariant()).ToArray();
        if (normalized.Length is < 1 or > 100)
            throw new ArgumentException("development calibration requires 1..100 fixture labels");
        string[] allowed = ["confirmed_security", "false_positive", "benign_expected", "insufficient_evidence"];
        var unsupported = normalized.Except(allowed).Order(StringComparer.Ordinal).ToArray();
        if (unsupported.Length > 0)
            throw new ArgumentException("unsupported development fixture verdicts: " + string.Join(", ", unsupported));
        var counts = new JsonArray(normalized.GroupBy(value => value).OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => (JsonNode)new JsonObject { ["verdict"] = group.Key, ["item_count"] = group.Count() }).ToArray());
        var summary = SemanticWorkspace.ReviewSummary(counts, ready: true, minimumSample);
        bool measured = summary.Text("state") == "measured";
        summary["reason"] = measured ? "development_decisive_fixture_available" : "development_fixture_" + summary.Text("reason");
        summary["evidence_class"] = EvidenceClass;
        summary["fixture_fingerprint_sha256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(normalized))));
        summary["writes_runtime_data"] = false;
        summary["counts_as_analyst_sample"] = false;
        summary["production_accuracy_claim"] = false;
        summary["development_contract_ready"] = measured;
        return summary;
    }

    internal static void AssertDevelopmentOnly(JsonObject payload)
    {
        if (payload.Text("evidence_class") != EvidenceClass)
            throw new ArgumentException("development calibration evidence class mismatch");
        static bool IsFalse(JsonNode? node) => node is JsonValue value && value.TryGetValue<bool>(out bool flag) && !flag;
        if (!IsFalse(payload["counts_as_analyst_sample"]))
            throw new ArgumentException("development fixture cannot count as an analyst sample");
        if (!IsFalse(payload["production_accuracy_claim"]))
            throw new ArgumentException("development fixture cannot claim production accuracy");
    }
}
