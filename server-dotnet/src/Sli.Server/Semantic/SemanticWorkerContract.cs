using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal static class SemanticWorkerContract
{
    // The compiled server contains the worker, processing contract and embedded semantic rules.
    // A deployed .NET release must attest its binary, rather than the frozen Python sources.
    private static readonly Lazy<string> DeployedFingerprint = new(() => HashRelease(typeof(SemanticWorkerContract).Assembly.Location));
    internal static string ReleaseFingerprint(string? assemblyPath = null) => assemblyPath is null ? DeployedFingerprint.Value : HashRelease(assemblyPath);
    private static string HashRelease(string assemblyPath)
    {
        using var source = File.OpenRead(assemblyPath);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        // Bind the loaded code as well: replacing a DLL on disk cannot make an old process attest a new release.
        digest.AppendData(typeof(SemanticWorkerContract).Module.ModuleVersionId.ToByteArray());
        digest.AppendData(SHA256.HashData(source));
        return Convert.ToHexStringLower(digest.GetHashAndReset());
    }
    internal static JsonObject Normalizer => new() { ["id"] = SemanticEvent.Normalizer, ["version"] = SemanticEvent.Version };
    internal static JsonObject Assembler => new() { ["id"] = "semantic-action-assembler", ["version"] = "1.1" };
    internal static JsonObject Details(string mode, bool manual, string? repairDigest = null) => new() {
        ["runtime_mode"] = mode, ["manual_runtime"] = manual, ["production"] = !manual,
        ["processing_contract"] = new JsonObject { ["claim_protocol_version"] = 1, ["semantic_contract_version"] = 1,
            ["processor_id"] = "semantic-shadow", ["processor_version"] = SemanticEvent.Version,
            ["normalizer"] = Normalizer, ["assembler"] = Assembler, ["release_fingerprint"] = ReleaseFingerprint() },
        ["repair_scope"] = repairDigest is null ? null : new JsonObject { ["job_kind"] = SemanticQuarantineRepairController.JobKind, ["repair_plan_digest"] = repairDigest }
    };
    internal static async Task LockSourcesAsync(ISemanticSession session, IEnumerable<long> sources, CancellationToken ct)
    {
        foreach (long id in sources.Distinct().Order())
            await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, "semantic_source:" + id.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }
}
