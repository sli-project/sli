using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal sealed record VerifiedEvidenceRecord(string EvidenceUid, string CanonicalRecord)
{ public override string ToString() => nameof(VerifiedEvidenceRecord); }
internal sealed record ImmutableTerminalObservation(string ObservationId, string EvidenceUid, string LifecycleEvent,
    string TimestampState, DateTimeOffset? ObservedAtUtc);
internal sealed record UnresolvedCandidate(string ObservationId, string EvidenceUid, string OriginalOutcome);
internal sealed record ExactResolutionProposal(string ObservationId, string SessionIdentityKey, string ExactPrincipalKey, string ResolutionInputSha256)
{ public override string ToString() => nameof(ExactResolutionProposal); }
internal sealed record ReconciliationAttempt(string AttemptKey, string ObservationId, string EvidenceUid, string Outcome,
    string EvidenceCorpusSha256, string ResolverContractId, string? ResolutionInputSha256);
internal sealed record ExactReconciliationBatch(string EvidenceCorpusSha256, IReadOnlyList<UnresolvedCandidate> Candidates,
    IReadOnlyDictionary<string, ExactResolutionProposal> Proposals, int EvidenceRecordCount, int AccessAcceptCount,
    int UnresolvedAccessAcceptCount, int ReconciledCount)
{ public override string ToString() => nameof(ExactReconciliationBatch); }

// Pure counterpart of session_reconciliation_production.py: verified local records in,
// evidence IDs and derived keys out. No observation updates or source/DB access.
internal static class RadiusSessionReconciliationProduction
{
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false, true).GetBytes(value)));
    private static string Value(IReadOnlyList<string> fields, int index) => PythonText.Strip(fields[index]);
    private static ArgumentException Error(string suffix) => new("production_reconciliation_" + suffix);
    private static string Uuid(string value, string label) => Guid.TryParse(value, out var id) ? id.ToString("D") : throw Error(label + "_invalid");

    public static async Task<ExactReconciliationBatch> BuildAsync(IEnumerable<VerifiedEvidenceRecord> evidenceRecords,
        IEnumerable<ImmutableTerminalObservation> terminalObservations, string sourceInstanceId, string organizationFqdn,
        string sourceTimezoneId, int sourceUtcOffsetMinutes, Func<string, string, Task<string?>> exactLookup)
    {
        var records = evidenceRecords.ToArray();
        var observations = terminalObservations.ToArray();
        // Q500: no arbitrary per-run record or observation ceilings.
        if (records.Length == 0) throw Error("evidence_count_invalid");
        if (observations.Length == 0) throw Error("observation_count_invalid");
        string source = PythonText.Strip(sourceInstanceId), organization = UnicodeCaseFold.Fold(PythonText.Strip(organizationFqdn));
        if (source.Length == 0 || organization.Length == 0) throw Error("source_scope_invalid");

        var parsed = new Dictionary<string, (string Hash, IReadOnlyList<string> Fields)>(StringComparer.Ordinal);
        foreach (var record in records)
        {
            string id = Uuid(record.EvidenceUid, "evidence_uid");
            if (parsed.ContainsKey(id)) throw Error("evidence_duplicate");
            parsed.Add(id, (Hash(record.CanonicalRecord), RadiusAccountingRecord.ParseFields(record.CanonicalRecord)));
        }

        var bindings = new Dictionary<string, (string Principal, string Hash)>(StringComparer.Ordinal);
        int accepts = 0, unresolvedAccepts = 0;
        foreach (var record in parsed.Values)
        {
            if (!PythonInt.TryParse(Value(record.Fields, 4), out var packet) || packet != 2) continue;
            accepts++;
            string? principal = await RadiusIdentity.ResolveAsync(Value(record.Fields, 6), organization, exactLookup);
            if (!Regex.IsMatch(source, @"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z")) throw new ArgumentException("source_instance_id_invalid");
            string classValue = Value(record.Fields, 26);
            if (classValue.Length == 0) throw new ArgumentException("access_accept_class_required");
            if (Value(record.Fields, 6).Length == 0) throw new ArgumentException("access_accept_distinguished_name_required");
            principal = principal is null ? null : PythonText.Strip(principal);
            if (string.IsNullOrEmpty(principal)) { unresolvedAccepts++; continue; }
            if (bindings.TryGetValue(classValue, out var prior))
            {
                if (prior.Principal != principal) throw Error("class_identity_conflict");
                if (string.CompareOrdinal(prior.Hash, record.Hash) <= 0) continue;
            }
            bindings[classValue] = (principal, record.Hash);
        }

        var candidates = new List<UnresolvedCandidate>();
        var proposals = new Dictionary<string, ExactResolutionProposal>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var observation in observations.OrderBy(o => o.ObservationId, StringComparer.Ordinal))
        {
            string id = Uuid(observation.ObservationId, "observation_id"), evidence = Uuid(observation.EvidenceUid, "observation_evidence_uid");
            if (!seen.Add(id)) throw Error("observation_duplicate");
            if (!parsed.TryGetValue(evidence, out var record)) throw Error("observation_evidence_missing");
            candidates.Add(new(id, evidence, "identity_unresolved"));
            if (!bindings.TryGetValue(Value(record.Fields, 26), out var binding)) continue;
            if (!Regex.IsMatch(source, @"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z")) throw new ArgumentException("source_instance_id_invalid");
            if (PythonText.Strip(sourceTimezoneId).Length == 0) throw new ArgumentException("source_timezone_context_incomplete");
            if (sourceUtcOffsetMinutes is < -840 or > 840) throw new ArgumentException("source_timezone_offset_invalid");
            var rebuilt = RadiusPlanner.BuildObservation(record.Fields, record.Hash, source, sourceUtcOffsetMinutes, binding.Principal);
            if (rebuilt?.SessionIdentityKey is null) throw Error("session_identity_required");
            if (rebuilt.Lifecycle != observation.LifecycleEvent) throw Error("lifecycle_mismatch");
            if (observation.TimestampState != "ready") throw Error("timestamp_ready_required");
            if (observation.ObservedAtUtc is null) throw Error("timestamp_invalid");
            if (rebuilt.ObservedAt != observation.ObservedAtUtc) throw Error("timestamp_mismatch");
            string resolutionHash = Hash(CanonicalJson.Serialize(new JsonObject
            {
                ["access_accept_record_sha256"] = binding.Hash, ["accounting_record_sha256"] = record.Hash,
                ["evidence_uid"] = evidence, ["exact_principal_key"] = rebuilt.Principal, ["observation_id"] = id,
                ["session_identity_key"] = rebuilt.SessionIdentityKey, ["source_instance_id"] = source
            }));
            proposals.Add(id, new(id, rebuilt.SessionIdentityKey, binding.Principal, resolutionHash));
        }
        string corpus = Hash(string.Join('\n', parsed.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "\0" + p.Value.Hash)));
        return new(corpus, candidates.AsReadOnly(), new ReadOnlyDictionary<string, ExactResolutionProposal>(proposals),
            records.Length, accepts, unresolvedAccepts, proposals.Count);
    }

    // The retry identity is scoped to an evidence corpus and a resolver version.
    public static IReadOnlyList<ReconciliationAttempt> BuildAttempts(ExactReconciliationBatch batch, string resolverContractId,
        IEnumerable<string>? priorAttemptKeys = null)
    {
        string resolver = PythonText.Strip(resolverContractId);
        if (resolver.Length == 0 || resolver.Length > 160) throw new ArgumentException("reconciliation_resolver_contract_invalid");
        var prior = new HashSet<string>(priorAttemptKeys ?? [], StringComparer.Ordinal);
        var attempts = new List<ReconciliationAttempt>();
        foreach (var candidate in batch.Candidates)
        {
            string key = Hash(candidate.ObservationId + "\0" + batch.EvidenceCorpusSha256 + "\0" + resolver);
            if (prior.Contains(key)) continue;
            batch.Proposals.TryGetValue(candidate.ObservationId, out var proposal);
            if (proposal is not null && !Regex.IsMatch(proposal.ExactPrincipalKey, @"\Aentity:[1-9][0-9]*\z"))
                throw new ArgumentException("reconciliation_principal_key_invalid");
            attempts.Add(new(key, candidate.ObservationId, candidate.EvidenceUid, proposal is null ? "still_unresolved" : "projected",
                batch.EvidenceCorpusSha256, resolver, proposal?.ResolutionInputSha256));
        }
        return attempts.AsReadOnly();
    }
}
