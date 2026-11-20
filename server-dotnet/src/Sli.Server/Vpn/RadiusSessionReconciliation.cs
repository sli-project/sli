using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Vpn;

public sealed record RadiusUnresolvedCandidate(string ObservationId, string EvidenceUid, string OriginalOutcome);
public sealed record RadiusExactResolutionProposal(string ObservationId, string SessionIdentityKey, string ExactPrincipalKey, string ResolutionInputSha256)
{
    public override string ToString() => $"RadiusExactResolutionProposal {{ ObservationId = {ObservationId}, ResolutionInputSha256 = {ResolutionInputSha256} }}";
}
public sealed record RadiusReconciliationAttempt(string AttemptKey, string ObservationId, string EvidenceUid, string Outcome,
    string EvidenceCorpusSha256, string ResolverContractId, string? ResolutionInputSha256);

// Pure append-only reconciliation plan, matching radius/session_reconciliation.py.
// Persistence and source discovery remain separate from this contract.
public static class RadiusSessionReconciliation
{
    public static IReadOnlyList<RadiusReconciliationAttempt> BuildAttempts(
        IEnumerable<RadiusUnresolvedCandidate> candidates,
        IReadOnlyDictionary<string, RadiusExactResolutionProposal> proposals,
        string evidenceCorpusSha256,
        string resolverContractId,
        IEnumerable<string>? priorAttemptKeys = null)
    {
        string corpus = RequiredHex(evidenceCorpusSha256, "corpus_hash");
        string resolver = resolverContractId?.Trim() ?? "";
        if (resolver.Length is < 1 or > 160) throw new VpnInputException("reconciliation_resolver_contract_invalid");
        var prior = (priorAttemptKeys ?? []).Select(key => RequiredHex(key, "attempt_key")).ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var attempts = new List<RadiusReconciliationAttempt>();
        // Q500: process every candidate; do not impose the Python run-size ceiling.
        foreach (var candidate in candidates.OrderBy(c => c.ObservationId, StringComparer.Ordinal))
        {
            string observation = candidate.ObservationId?.Trim() ?? "";
            string evidence = candidate.EvidenceUid?.Trim() ?? "";
            if (observation.Length == 0 || evidence.Length == 0) throw new VpnInputException("reconciliation_candidate_identity_invalid");
            if (!seen.Add(observation)) throw new VpnInputException("reconciliation_candidate_duplicate");
            if (candidate.OriginalOutcome != "identity_unresolved") throw new VpnInputException("reconciliation_candidate_outcome_invalid");
            string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(observation + "\0" + corpus + "\0" + resolver)));
            if (prior.Contains(key)) continue;
            string outcome = "still_unresolved";
            string? resolutionHash = null;
            if (proposals.TryGetValue(observation, out var proposal))
            {
                ValidateProposal(proposal, observation);
                outcome = "projected";
                resolutionHash = proposal.ResolutionInputSha256;
            }
            attempts.Add(new(key, observation, evidence, outcome, corpus, resolver, resolutionHash));
        }
        if (proposals.Keys.Any(key => !seen.Contains(key))) throw new VpnInputException("reconciliation_proposal_without_candidate");
        return attempts.ToArray();
    }

    public static JsonObject ApplyExactResolution(JsonObject original, RadiusExactResolutionProposal proposal)
    {
        if (original.Text("identity_state") != "unresolved") throw new VpnInputException("reconciliation_exact_observation_override_forbidden");
        ValidateProposal(proposal, original.Text("observation_id"));
        var resolved = (JsonObject)original.DeepClone();
        resolved["identity_state"] = "exact";
        resolved["session_identity_key"] = proposal.SessionIdentityKey;
        resolved["exact_principal_key"] = proposal.ExactPrincipalKey;
        return resolved;
    }

    static void ValidateProposal(RadiusExactResolutionProposal proposal, string observation)
    {
        if (proposal.ObservationId != observation) throw new VpnInputException("reconciliation_proposal_observation_mismatch");
        if (!Regex.IsMatch(proposal.SessionIdentityKey ?? "", @"\Aradius-session:[0-9a-f]{64}\z")) throw new VpnInputException("reconciliation_session_key_invalid");
        if (!Regex.IsMatch(proposal.ExactPrincipalKey ?? "", @"\Aentity:[1-9][0-9]*\z")) throw new VpnInputException("reconciliation_principal_key_invalid");
        RequiredHex(proposal.ResolutionInputSha256, "resolution_input_hash");
    }

    static string RequiredHex(string? value, string label)
    {
        string clean = value?.Trim().ToLowerInvariant() ?? "";
        if (!Regex.IsMatch(clean, @"\A[0-9a-f]{64}\z")) throw new VpnInputException($"reconciliation_{label}_invalid");
        return clean;
    }
}
