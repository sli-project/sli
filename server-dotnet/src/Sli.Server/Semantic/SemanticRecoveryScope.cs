using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    // Native releases have no Python source tree. Bind admission to the actual
    // server binary instead of a Python source fingerprint or a version label.
    private static readonly Lazy<string> ReleaseFingerprint = new(() =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(typeof(SemanticProduction).Assembly.Location))));

    private static JsonObject RepairScope(string digest) => new() {
        ["job_kind"] = "semantic_v2_quarantine_repair", ["repair_plan_digest"] = digest
    };

    private static void ValidateRepairMode(string mode, string? digest)
    {
        if (digest is null) return;
        if (mode != SemanticRuntimeSettings.InvestigationMode)
            throw new InvalidOperationException("semantic v2 quarantine recovery requires investigation mode");
        if (digest.Length != 64 || digest.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9')))
            throw new InvalidOperationException("semantic_repair_digest_invalid");
    }

    // Controller admission: freshness, deployed release, managed investigation
    // contract and the entire exact scope must agree before repair is admitted.
    internal static async Task RequireRepairWorkerAsync(ISemanticSession session, string repairDigest, CancellationToken ct)
    {
        ValidateRepairMode(SemanticRuntimeSettings.InvestigationMode, repairDigest);
        var row = (await session.QueryAsync("""
            select details_json from runtime_worker_heartbeats where worker_name='semantic'
                and status in ('running','idle') and heartbeat_at >= now() -
                    (greatest(180,expected_interval_seconds*3) * interval '1 second') for share
            """, ct)).SingleOrDefault();
        var details = row?["details_json"];
        var contract = details?["processing_contract"];
        if (contract.Text("release_fingerprint") != ReleaseFingerprint.Value)
            throw new InvalidOperationException("semantic_repair_worker_release_mismatch");
        var expected = HeartbeatDetails(SemanticRuntimeSettings.InvestigationMode);
        if (details.Text("runtime_mode") != SemanticRuntimeSettings.InvestigationMode
            || details?["manual_runtime"]?.ToJsonString() != "false"
            || !JsonNode.DeepEquals(contract, expected["processing_contract"]))
            throw new InvalidOperationException("semantic_repair_worker_contract_mismatch");
        if (!JsonNode.DeepEquals(details?["repair_scope"], RepairScope(repairDigest)))
            throw new InvalidOperationException("semantic_repair_worker_scope_mismatch");
    }
}
