using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticQuarantineRepairController
{
    private const string ManifestType = "retained_security_events_vocabulary_v2";
    private static readonly int[] Vocabulary = [4740,4767,4723,4724,4720,4722,4725,4726,4738,4781,4728,4729,4732,4733,4756,4757,4727,4730,4737,4731,4734,4735,4754,4755,4758,4764,4624,4625,4771,4776,4719,1102];
    private static JsonObject Selection(int batch) => new() { ["source"] = "semantic_event_rows", ["runtime_mode"] = "investigation-v1", ["semantic_contract_version"] = 1,
        ["normalizer"] = SemanticWorkerContract.Normalizer, ["assembler"] = SemanticWorkerContract.Assembler,
        ["vocabulary"] = new JsonArray(Vocabulary.Select(id => JsonValue.Create(id)).ToArray()), ["batch_limit"] = batch,
        ["moves_collection_cursors"] = false, ["contacts_sources"] = false };
    private static void ValidateManifest(JsonObject manifest, JsonObject identity)
    {
        if (manifest.Text("manifest_type") != ManifestType) throw new InvalidOperationException("security history v2 repair requires the v2 manifest");
        int batch = (int)manifest.Number("batch_limit");
        if (batch is < 1 or > SemanticProducer.MaxBatch) throw new InvalidOperationException("security history manifest batch limit is invalid");
        var expected = Selection(batch); expected["database_identity"] = identity.DeepClone();
        expected["selection_fingerprint"] = SemanticJson.Hash(new JsonObject { ["v1_selection_fingerprint"] = SemanticJson.Hash(Selection(batch)),
            ["manifest_type"] = ManifestType, ["logon_semantic_scope"] = "successful_password_reset_same_domain_sid_within_1h" });
        if (expected.Any(pair => !JsonNode.DeepEquals(manifest[pair.Key], pair.Value))) throw new InvalidOperationException("security history manifest immutable contract changed");
        if (manifest.Text("plan_digest") is not { Length: 64 }) throw new InvalidOperationException("security history manifest plan digest is invalid");
        if (manifest["supersedes"] is { } predecessor && (predecessor.Text("manifest_type") != "retained_security_events_vocabulary_v1" ||
            predecessor.Text("reason") != "routine_logons_are_exact_context_only" || !Regex.IsMatch((predecessor.Text("plan_digest") ?? "").ToLowerInvariant(), "\\A[0-9a-f]{64}\\z")))
            throw new InvalidOperationException("security history v2 supersedes contract is invalid");
        if (manifest.Text("semantic_context_strategy") != "successful_password_reset_same_domain_sid_within_1h") throw new InvalidOperationException("security history v2 context strategy is invalid");
        if (manifest["events"] is not JsonObject events || !events.Select(x => x.Key).ToHashSet().SetEquals(Vocabulary.Select(x => x.ToString(CultureInfo.InvariantCulture))))
            throw new InvalidOperationException("security history manifest vocabulary is invalid");
        foreach (int id in Vocabulary) {
            if (events[id.ToString(CultureInfo.InvariantCulture)] is not JsonObject entry) throw new InvalidOperationException("security history manifest cohort is invalid");
            if (!JsonNode.DeepEquals(entry["predicate"], new JsonObject { ["channel"] = "Security", ["provider"] = Provider(id), ["event_id"] = id }))
                throw new InvalidOperationException("security history manifest predicate is invalid");
            if (entry.Number("cursor") < 0 || entry.Number("cursor") > entry.Number("high_watermark")) throw new InvalidOperationException("security history manifest cursor is invalid");
            string? state = entry.Text("state"), reason = entry.Text("terminal_reason");
            string? exactReason = state switch { "no_retained_events" => "no_retained_events", "complete" => "current_version_normalized_hash_reconciled",
                "incomplete_original" => "frozen_original_integrity_mismatch", "incomplete_normalization" => "current_version_non_unknown_normalization_missing",
                "blocked" => "operator_blocked_after_evidence", "failed" => "failed_current_version_work", "quarantined" => "quarantined_current_version_work", _ => null };
            if (exactReason is null ? state is not ("planned" or "publishing" or "queued" or "processing") || reason is not null : reason != exactReason)
                throw new InvalidOperationException("security history state reason is invalid");
            if ((entry.Number("count") == 0) != (state == "no_retained_events")) throw new InvalidOperationException("security history empty cohort state is invalid");
            long raw = entry.Number("raw_retained_count"), semantic = entry.Number("semantic_expected_count");
            if (raw < 0 || semantic < 0 || semantic > raw) throw new InvalidOperationException("security history v2 semantic coverage is invalid");
            if (id == 4624) {
                if (entry.Text("semantic_scope") != "password_reset_context_only" || entry.Text("semantic_context_digest") is not { Length:64 } ||
                    entry.Number("semantic_context_reset_high_watermark") < 0 || entry.Number("count") != semantic ||
                    entry.Number("semantic_context_reset_high_watermark") != events["4724"].Number("high_watermark"))
                    throw new InvalidOperationException("security history v2 logon context coverage is invalid");
            }
            else if (entry.Text("semantic_scope") != "all_retained" || semantic != raw || entry.Number("count") != raw || entry["semantic_context_digest"] is not null)
                throw new InvalidOperationException("security history v2 event semantic coverage is invalid");
        }
    }
    private static string Provider(int id) => id == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing";
    private static void Append(IncrementalHash digest, long id, string hash) => digest.AppendData(Encoding.ASCII.GetBytes(id.ToString(CultureInfo.InvariantCulture) + ":" + hash + "\n"));
    private static string CheckedHash(string? value)
    {
        string hash = (value ?? "").ToLowerInvariant();
        if (!Regex.IsMatch(hash, "\\A[0-9a-f]{64}\\z")) throw new InvalidOperationException("security history normalized hash is invalid");
        return hash;
    }
    private async Task<(IReadOnlyList<(long Id,string Hash)> Pairs,JsonObject Context)> Snapshot(ISemanticSession session, JsonObject manifest, CancellationToken ct)
    {
        var identities = await session.QueryAsync("select coalesce(inet_server_addr()::text,'') as host, current_database() as database, session_user as role", ct);
        var identity = identities.FirstOrDefault() as JsonObject;
        if (identity is null || new[] { "host", "database", "role" }.Any(key => string.IsNullOrEmpty(identity.Text(key)))) throw new InvalidOperationException("security history database identity is unavailable");
        ValidateManifest(manifest, identity);
        var events = manifest["events"]!.AsObject();
        foreach (int eventId in Vocabulary) {
            var entry = events[eventId.ToString(CultureInfo.InvariantCulture)]!;
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long after = 0, count = 0; long? min = null, max = null;
            while (true) {
                var page = await new SemanticHistorySession(session,configuration).QueryAsync("""
                    select core.id,encode(core.normalized_hash,'hex') as normalized_hash from semantic_event_rows core
                    join storage_v2_channel channel on channel.id=core.channel_id join storage_v2_provider provider on provider.id=core.provider_id
                    where channel.value='Security' and provider.value=$1 and core.event_id=$2 and core.id>$3 and core.id<=$4
                    order by core.id limit 256
                    """, ct, Provider(eventId), eventId, after, entry.Number("high_watermark"));
                if (page.Count == 0) break;
                foreach (var row in page) {
                    long id = row.Number("id"); if (id <= after) throw new InvalidOperationException("security history cohort order is invalid");
                    Append(digest, id, CheckedHash(row.Text("normalized_hash"))); count++; min ??= id; max = after = id;
                }
            }
            string observedHash = Convert.ToHexStringLower(digest.GetHashAndReset());
            if (entry.Number("raw_retained_count") != count || entry.Text("raw_cohort_digest") != observedHash || entry.Number("high_watermark") != (max ?? 0) ||
                !JsonNode.DeepEquals(entry["min_id"], JsonValue.Create(min)) || !JsonNode.DeepEquals(entry["max_id"], JsonValue.Create(max)))
                throw new InvalidOperationException("security history frozen raw cohort changed");
        }
        var logon = events["4624"]!;
        var candidates = await new SemanticHistorySession(session,configuration).QueryAsync("""
            select login.id as source_event_id,encode(login.normalized_hash,'hex') as normalized_hash,
              login.target_user_sid as login_target_user_sid,reset_event.target_user_sid as reset_target_user_sid,reset_keywords.value as reset_keywords
            from semantic_event_rows login
            join storage_v2_channel login_channel on login_channel.id=login.channel_id and login_channel.value='Security'
            join storage_v2_provider login_provider on login_provider.id=login.provider_id and login_provider.value='Microsoft-Windows-Security-Auditing'
            join semantic_event_rows reset_event on reset_event.domain_id=login.domain_id
              and lower(nullif(btrim(reset_event.target_user_sid),''))=lower(nullif(btrim(login.target_user_sid),''))
              and reset_event.event_id=4724 and reset_event.id<=$2
              and login.time_created_utc>reset_event.time_created_utc and login.time_created_utc<=reset_event.time_created_utc+interval '1 hour'
            join storage_v2_channel reset_channel on reset_channel.id=reset_event.channel_id and reset_channel.value='Security'
            join storage_v2_provider reset_provider on reset_provider.id=reset_event.provider_id and reset_provider.value='Microsoft-Windows-Security-Auditing'
            left join storage_v2_keywords reset_keywords on reset_keywords.id=reset_event.keywords_id
            where login.event_id=4624 and login.id>0 and login.id<=$1 order by login.id,reset_event.time_created_utc,reset_event.id
            """, ct, logon.Number("high_watermark"), logon.Number("semantic_context_reset_high_watermark"));
        var pairs = new List<(long Id,string Hash)>();
        using var contextDigest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var group in candidates.GroupBy(row => row.Number("source_event_id"))) {
            var first = group.First(); long id = group.Key;
            string hash = CheckedHash(first.Text("normalized_hash"));
            if (group.Any(row => row.Text("login_target_user_sid") is { Length: <=184 } sid && Regex.IsMatch(sid, "\\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\\z") &&
                sid == row.Text("reset_target_user_sid") && SemanticProducer.AuditOutcome(row.Text("reset_keywords")) == "success")) {
                if (pairs.Count > 0 && id <= pairs[^1].Id) throw new InvalidOperationException("security history context cohort order is invalid");
                pairs.Add((id, hash)); Append(contextDigest, id, hash);
            }
        }
        string contextHash = Convert.ToHexStringLower(contextDigest.GetHashAndReset());
        var context = new JsonObject { ["count"] = pairs.Count, ["cohort_digest"] = contextHash, ["reset_high_watermark"] = logon.Number("semantic_context_reset_high_watermark") };
        if (pairs.Count != logon.Number("semantic_expected_count") || contextHash != logon.Text("semantic_context_digest"))
            throw new InvalidOperationException("security history frozen v2 context cohort changed");
        if (pairs.Count != 260) throw new InvalidOperationException("security history v2 repair selection is not exact");
        return (pairs, context);
    }
}
