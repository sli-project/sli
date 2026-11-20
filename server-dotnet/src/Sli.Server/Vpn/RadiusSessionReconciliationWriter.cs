using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Vpn;

public sealed record ReconciliationAttempt(string AttemptKey, string ObservationId, string EvidenceUid,
    string Outcome, string EvidenceCorpusSha256, string ResolverContractId, string? ResolutionInputSha256);
public sealed record ExactResolutionProposal(string ObservationId, string SessionIdentityKey,
    string ExactPrincipalKey, string ResolutionInputSha256);
public sealed record ReconciliationWriteReceipt(string AttemptKey, string ObservationId, string Outcome,
    string PersistenceState, bool OverlayCreated);

// Source-free append-only writer, matching source_packs/radius/session_reconciliation_postgres.py.
// No scheduler or autostart: the prepared contract does not activate reconciliation.
public static class RadiusSessionReconciliationWriter
{
    public const string ContractId = "sli.radius-session-reconciliation-writer.v1";
    public const string WriterRole = "adlog_radius_session_reconciliation_writer";
    static VpnInputException Error(string code) => new(code);

    public static JsonObject LoadContract(string? json = null)
    {
        JsonNode? value;
        try {
            if (json is null) {
                using var stream = typeof(RadiusSessionReconciliationWriter).Assembly.GetManifestResourceStream("Sli.Server.Vpn.reconciliation-writer.json")!;
                value = JsonNode.Parse(stream);
            } else value = JsonNode.Parse(json);
        }
        catch (JsonException) { throw Error("writer_contract_invalid"); }
        if (value is not JsonObject contract) throw Error("writer_contract_object_required");
        ValidateContract(contract);
        foreach (var (key, expected) in new[] {
            ("immutable_inputs", new[] {"radius_accounting_session_observations", "radius_session_projection_receipts", "core_evidence_manifests"}),
            ("append_only_outputs", new[] {"radius_session_reconciliation_attempts", "radius_session_identity_overlays"})
        }) {
            if (contract[key] is not JsonArray values || !expected.ToHashSet(StringComparer.Ordinal).SetEquals(values.Select(v => v?.ToString() ?? "")))
                throw Error($"writer_contract_{key}_invalid");
        }
        return contract;
    }

    static void ValidateContract(JsonObject contract)
    {
        var expected = new JsonObject {
            ["schema_version"] = 1, ["contract_id"] = ContractId, ["status"] = "prepared_disabled_only",
            ["required_migration"] = 65, ["writer_role"] = WriterRole, ["maximum_attempts_per_transaction"] = 50,
            ["source_contact_allowed"] = false, ["production_migration_applied"] = false,
            ["runtime_enabled"] = false, ["autostart_enabled"] = false
        };
        foreach (var item in expected)
            if (!JsonNode.DeepEquals(contract[item.Key], item.Value)) throw Error($"writer_contract_{item.Key}_invalid");
    }

    sealed record Normalized(ReconciliationAttempt Attempt, Guid Observation, Guid Evidence, string Corpus,
        string Resolver, string? Resolution, ExactResolutionProposal? Proposal);

    static string Hex(string? value, string label)
    {
        string clean = (value ?? "").Trim().ToLowerInvariant();
        if (!Regex.IsMatch(clean, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant)) throw Error($"writer_{label}_invalid");
        return clean;
    }

    static Normalized Normalize(ReconciliationAttempt attempt, ExactResolutionProposal? proposal)
    {
        if (!Guid.TryParse(attempt.ObservationId, out var observation) || !Guid.TryParse(attempt.EvidenceUid, out var evidence))
            throw Error("writer_uuid_invalid");
        string corpus = Hex(attempt.EvidenceCorpusSha256, "corpus_hash"), resolver = (attempt.ResolverContractId ?? "").Trim();
        if (resolver.Length is < 1 or > 160) throw Error("writer_resolver_contract_invalid");
        string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(observation.ToString("D") + "\0" + corpus + "\0" + resolver)));
        if (attempt.AttemptKey != key) throw Error("writer_attempt_key_invalid");
        if (attempt.Outcome is not ("projected" or "still_unresolved")) throw Error("writer_outcome_invalid");
        string? resolution = attempt.ResolutionInputSha256;
        if (attempt.Outcome == "projected") {
            if (proposal is null || proposal.ObservationId != observation.ToString("D")) throw Error("writer_projected_proposal_required");
            if (!Regex.IsMatch(proposal.SessionIdentityKey, "\\Aradius-session:[0-9a-f]{64}\\z", RegexOptions.CultureInvariant)) throw Error("writer_session_key_invalid");
            if (!Regex.IsMatch(proposal.ExactPrincipalKey, "\\Aentity:[1-9][0-9]*\\z", RegexOptions.CultureInvariant)) throw Error("writer_principal_key_invalid");
            resolution = Hex(resolution, "resolution_hash");
            if (proposal.ResolutionInputSha256 != resolution) throw Error("writer_resolution_hash_mismatch");
        } else if (proposal is not null || resolution is not null) throw Error("writer_unresolved_proposal_forbidden");
        return new(attempt, observation, evidence, corpus, resolver, resolution, proposal);
    }

    public static async Task<IReadOnlyList<ReconciliationWriteReceipt>> WriteAsync(NpgsqlConnection db,
        IReadOnlyList<ReconciliationAttempt> attempts, IReadOnlyDictionary<string, ExactResolutionProposal> proposals,
        CancellationToken ct, JsonObject? contract = null)
    {
        ValidateContract(contract ?? LoadContract());
        if (attempts.Count == 0) throw Error("writer_attempt_count_invalid");
        // The legacy maximum remains contract metadata. Owner decision Q500: no arbitrary process limits.
        var normalized = attempts.Select(a => Normalize(a, proposals.GetValueOrDefault(a.ObservationId))).ToArray();
        if (normalized.Select(a => a.Observation).Distinct().Count() != normalized.Length) throw Error("writer_duplicate_observation_in_batch");
        if (!proposals.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(normalized.Where(a => a.Attempt.Outcome == "projected").Select(a => a.Observation.ToString("D"))))
            throw Error("writer_proposal_set_mismatch");

        await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(db, tx, $"set local role {WriterRole}", ct);
        var receipts = new List<ReconciliationWriteReceipt>();
        foreach (var item in normalized) receipts.Add(await WriteOne(db, tx, item, ct));
        await tx.CommitAsync(ct);
        return receipts;
    }

    static async Task<ReconciliationWriteReceipt> WriteOne(NpgsqlConnection db, NpgsqlTransaction tx, Normalized item, CancellationToken ct)
    {
        var a = item.Attempt;
        var original = await Read(db, tx, """
            select observation.evidence_uid::text, observation.identity_state,
                exists(select 1 from radius_session_projection_receipts receipt
                    where receipt.observation_id=observation.observation_id and receipt.outcome='identity_unresolved')
            from radius_accounting_session_observations observation where observation.observation_id=$1
            """, ct, item.Observation);
        if (original is null) throw Error("writer_observation_not_found");
        if ((string)original[0]! != item.Evidence.ToString("D")) throw Error("writer_evidence_uid_mismatch");
        if ((string)original[1]! != "unresolved" || original[2] is not true) throw Error("writer_terminal_unresolved_receipt_required");

        var prior = await Read(db, tx, """
            select observation_id::text,evidence_uid::text,outcome,evidence_corpus_sha256,
                resolver_contract_id,resolution_input_sha256,writer_contract_id
            from radius_session_reconciliation_attempts where attempt_key=$1
            """, ct, a.AttemptKey);
        object?[] expected = [item.Observation.ToString("D"), item.Evidence.ToString("D"), a.Outcome, item.Corpus, item.Resolver, item.Resolution, ContractId];
        if (prior is not null) {
            if (!prior.SequenceEqual(expected)) throw Error("writer_attempt_replay_conflict");
            await VerifyOverlay(db, tx, item, ct);
            return new(a.AttemptKey, item.Observation.ToString("D"), a.Outcome, "already_persisted", false);
        }
        if (await Read(db, tx, "select attempt_key from radius_session_identity_overlays where observation_id=$1", ct, item.Observation) is not null)
            throw Error("writer_observation_already_resolved");
        if (item.Proposal is not null) {
            // entities_v2.id is a PostgreSQL integer. A syntactically valid larger key cannot name an entity.
            if (!long.TryParse(item.Proposal.ExactPrincipalKey[7..], out long entity) ||
                (await Read(db, tx, "select exists(select 1 from entities_v2 where id=$1)", ct, entity))![0] is not true)
                throw Error("writer_exact_entity_not_found");
        }
        await Execute(db, tx, """
            insert into radius_session_reconciliation_attempts(attempt_key,observation_id,evidence_uid,outcome,
                evidence_corpus_sha256,resolver_contract_id,resolution_input_sha256,writer_contract_id)
            values($1,$2,$3,$4,$5,$6,$7,$8)
            """, ct, a.AttemptKey, item.Observation, item.Evidence, a.Outcome, item.Corpus, item.Resolver, item.Resolution, ContractId);
        if (item.Proposal is not null)
            await Execute(db, tx, """
                insert into radius_session_identity_overlays(observation_id,attempt_key,evidence_uid,
                    session_identity_key,exact_principal_key,resolution_input_sha256,resolver_contract_id)
                values($1,$2,$3,$4,$5,$6,$7)
                """, ct, item.Observation, a.AttemptKey, item.Evidence, item.Proposal.SessionIdentityKey, item.Proposal.ExactPrincipalKey, item.Resolution, item.Resolver);
        return new(a.AttemptKey, item.Observation.ToString("D"), a.Outcome, "created", item.Proposal is not null);
    }

    static async Task VerifyOverlay(NpgsqlConnection db, NpgsqlTransaction tx, Normalized item, CancellationToken ct)
    {
        var overlay = await Read(db, tx, """
            select attempt_key,evidence_uid::text,session_identity_key,exact_principal_key,
                resolution_input_sha256,resolver_contract_id from radius_session_identity_overlays where observation_id=$1
            """, ct, item.Observation);
        if (item.Attempt.Outcome == "still_unresolved") {
            if (overlay is not null) throw Error("writer_unresolved_replay_has_overlay");
            return;
        }
        if (item.Proposal is null || overlay is null) throw Error("writer_projected_replay_overlay_missing");
        object?[] expected = [item.Attempt.AttemptKey, item.Evidence.ToString("D"), item.Proposal.SessionIdentityKey,
            item.Proposal.ExactPrincipalKey, item.Resolution, item.Resolver];
        if (!overlay.SequenceEqual(expected)) throw Error("writer_overlay_replay_conflict");
    }

    static NpgsqlCommand Command(NpgsqlConnection db, NpgsqlTransaction tx, string sql, object?[] values)
    {
        var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
        foreach (var value in values)
            command.Parameters.Add(value is null ? new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Text, Value = DBNull.Value } : new NpgsqlParameter { Value = value });
        return command;
    }
    static async Task Execute(NpgsqlConnection db, NpgsqlTransaction tx, string sql, CancellationToken ct, params object?[] values)
    {
        await using var command = Command(db, tx, sql, values);
        await command.ExecuteNonQueryAsync(ct);
    }
    static async Task<object?[]?> Read(NpgsqlConnection db, NpgsqlTransaction tx, string sql, CancellationToken ct, params object?[] values)
    {
        await using var command = Command(db, tx, sql, values);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? null : reader.GetValue(i)).ToArray();
    }
}
