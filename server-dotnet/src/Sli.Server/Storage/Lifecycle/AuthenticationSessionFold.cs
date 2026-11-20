using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Storage.Lifecycle;

internal sealed record AuthenticationEvidence(long SourceEventId, long SourceRecordId, int EventKey,
    string DescriptorSource, string DescriptorStream, long ServerId, long ChannelId, string ProviderName,
    string? LogonId, DateTimeOffset At, string Hash, string? Principal = null, string? Host = null,
    string? LogonType = null, string? PrivilegeMarker = null);

internal sealed record AuthenticationContinuity(string ScopeIdentity, string DescriptorSource,
    string DescriptorStream, long ServerId, long ChannelId, string ProviderName, string ChannelGenerationIdentity,
    IReadOnlyList<long> SourceEventIds, IReadOnlyList<string> SourceHashes, long FirstRecordId, long LastRecordId,
    string Completeness);

// Pure counterpart of warm_session_lifecycle.assemble_authentication_sessions.
// Pairing alone never proves coverage: the immutable source ids AND hashes must be declared.
internal static class AuthenticationSessionFold
{
    internal const string Provider = "Microsoft-Windows-Security-Auditing";
    const string Contract = "sli.warm-authentication-session-lifecycle.v1";
    static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    static bool Digest(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    static void Require(bool valid, string code) { if (!valid) throw new LifecycleBlocked(code); }
    static (long, long, string, string, string) Scope(AuthenticationEvidence e) => (e.ServerId, e.ChannelId, e.ProviderName, e.DescriptorSource, e.DescriptorStream);
    static bool SameScope(AuthenticationContinuity p, AuthenticationEvidence e) =>
        (p.ServerId, p.ChannelId, p.ProviderName, p.DescriptorSource, p.DescriptorStream) == Scope(e);
    static IEnumerable<AuthenticationEvidence> Ordered(IEnumerable<AuthenticationEvidence> source) => source.OrderBy(e => e.SourceRecordId).ThenBy(e => e.SourceEventId);

    internal static AuthenticationEvidence FromNormalized(SemanticEvent e, long sourceRecordId,
        string descriptorSource = "sli.windows.ad-dc", string descriptorStream = "Security", long channelId = 1,
        string providerName = Provider)
    {
        string host = Clean(e.Roles["source_host"]?.ToString()) ?? "";
        Require(long.TryParse(host, NumberStyles.Integer, CultureInfo.InvariantCulture, out long server) &&
            int.TryParse(e.Facts["windows_event_id"]?.ToString(), out _), "warm_session_normalized_source_identity_invalid");
        string session = Clean(e.Roles["session_principal"]?.ToString()) ?? "";
        return new(e.Source, sourceRecordId, int.Parse(e.Facts["windows_event_id"]!.ToString(), CultureInfo.InvariantCulture),
            descriptorSource, descriptorStream, server, channelId, providerName,
            session.StartsWith(host + ":", StringComparison.Ordinal) ? session[(host.Length + 1)..] : null,
            e.At, e.Sha, Clean(e.Roles["affected_entity"]?.ToString()) ?? Clean(e.Roles["actor"]?.ToString()),
            host, e.Facts["logon_type"]?.ToString(), e.Facts["privileges"]?.ToString());
    }

    static AuthenticationEvidence Validate(AuthenticationEvidence e)
    {
        Require(e.EventKey is 4608 or 4624 or 4634 or 4672 or 4647 or 4648, "warm_session_authentication_event_key_invalid");
        Require(e.SourceEventId > 0 && e.SourceRecordId > 0 && e.ServerId > 0 && e.ChannelId > 0, "warm_session_authentication_identity_invalid");
        Require(Digest(e.Hash), "warm_session_authentication_hash_invalid");
        Require(Clean(e.DescriptorSource) is not null && Clean(e.DescriptorStream) is not null && Clean(e.ProviderName) is not null, "warm_session_authentication_descriptor_invalid");
        Require(Clean(e.DescriptorStream) == "Security" && Clean(e.ProviderName) == Provider, "warm_session_authentication_source_scope_invalid");
        Require(e.EventKey == 4608 || Clean(e.LogonId) is not null, "warm_session_authentication_logon_id_required");
        return e with { DescriptorSource = e.DescriptorSource.Trim(), DescriptorStream = e.DescriptorStream.Trim(), ProviderName = e.ProviderName.Trim(), LogonId = Clean(e.LogonId), Hash = e.Hash.ToLowerInvariant(), At = e.At.ToUniversalTime() };
    }

    static AuthenticationContinuity Validate(AuthenticationContinuity p)
    {
        Require(new[] { p.ScopeIdentity, p.DescriptorSource, p.DescriptorStream, p.ProviderName, p.ChannelGenerationIdentity }.All(s => Clean(s) is not null) &&
            p.ServerId > 0 && p.ChannelId > 0 && p.FirstRecordId > 0 && p.LastRecordId >= p.FirstRecordId &&
            p.Completeness is "complete" or "gap" or "partial" or "failed" or "truncated" &&
            p.SourceEventIds.Count == p.SourceHashes.Count && p.SourceEventIds.Distinct().Count() == p.SourceEventIds.Count &&
            p.SourceEventIds.All(id => id > 0) && p.SourceHashes.All(Digest), "warm_session_continuity_declaration_invalid");
        return p with { ScopeIdentity = p.ScopeIdentity.Trim(), DescriptorSource = p.DescriptorSource.Trim(), DescriptorStream = p.DescriptorStream.Trim(), ProviderName = p.ProviderName.Trim(), ChannelGenerationIdentity = p.ChannelGenerationIdentity.Trim(), SourceHashes = p.SourceHashes.Select(s => s.ToLowerInvariant()).ToArray() };
    }

    internal static IReadOnlyList<JsonObject> Assemble(IEnumerable<AuthenticationEvidence> evidence, IEnumerable<AuthenticationContinuity> declarations)
    {
        var facts = evidence.Select(Validate).ToArray(); var proofs = declarations.Select(Validate).ToArray();
        var boots = facts.Where(e => e.EventKey == 4608).ToArray();
        AuthenticationEvidence? Boot(AuthenticationEvidence e)
        {
            var candidates = boots.Where(b => Scope(b) == Scope(e) && b.SourceRecordId < e.SourceRecordId).ToArray();
            if (candidates.Length == 0) return null;
            var latest = candidates.Where(b => b.SourceRecordId == candidates.Max(b => b.SourceRecordId)).ToArray();
            return latest.Length == 1 ? latest[0] : null;
        }
        var boundaries = facts.Where(e => e.EventKey is 4624 or 4634).ToArray();
        var rebooted = new HashSet<long>(); var result = new List<JsonObject>();
        foreach (var group in boundaries.GroupBy(e => (Scope(e), e.LogonId)))
        {
            var items = Ordered(group).ToArray(); var scopes = items.Select(Boot).Distinct().ToArray();
            if (items.Length == 2 && items.Count(e => e.EventKey == 4624) == 1 && scopes.Length == 2)
            {
                result.Add(Observation(items, null, "incomplete_reboot_boundary", extra: Ordered(scopes.OfType<AuthenticationEvidence>()).ToArray()));
                rebooted.UnionWith(items.Select(e => e.SourceEventId));
            }
        }
        foreach (var group in boundaries.Where(e => !rebooted.Contains(e.SourceEventId)).GroupBy(e => (Scope(e), Boot(e), e.LogonId)))
        {
            var items = Ordered(group).ToArray(); var boot = group.Key.Item2;
            if (boot is null) { result.Add(Observation(items, null, "incomplete_boot_scope_missing")); continue; }
            var (chain, reason) = Proof(boot, items, proofs);
            var covered = (chain ?? []).SelectMany(p => p.SourceEventIds.Zip(p.SourceHashes)).ToHashSet();
            var opened = items.FirstOrDefault(e => e.EventKey == 4624); var closed = items.FirstOrDefault(e => e.EventKey == 4634);
            var supplements = Ordered(facts.Where(e => e.EventKey is 4647 or 4648 && opened is not null &&
                Scope(e) == Scope(opened) && e.LogonId == opened.LogonId && boot.SourceRecordId < opened.SourceRecordId &&
                opened.SourceRecordId < e.SourceRecordId && (closed is null || e.SourceRecordId < closed.SourceRecordId) &&
                Boot(e) == boot && covered.Contains((e.SourceEventId, e.Hash)))).ToArray();
            var anchor = opened ?? items[0];
            var privileges = Ordered(facts.Where(e => e.EventKey == 4672 && Scope(e) == Scope(anchor) && e.LogonId == anchor.LogonId &&
                (opened ?? boot).SourceRecordId < e.SourceRecordId && (!items.Any(b => b.EventKey == 4634) || e.SourceRecordId < items.Where(b => b.EventKey == 4634).Max(b => b.SourceRecordId)) &&
                (opened ?? boot).At <= e.At && Boot(e) == boot)).ToArray();
            string privilegeState = privileges.Length == 0 ? "missing" : privileges.Length > 1 ? "ambiguous" : covered.Contains((privileges[0].SourceEventId, privileges[0].Hash)) ? "exact" : "provenance_unverified";
            int opens = items.Count(e => e.EventKey == 4624), closes = items.Length - opens;
            string? failure = opens != 1 || closes != 1 ? opens > 1 || closes > 1 ? "incomplete_duplicate_boundary" : opens > 0 ? "incomplete_missing_close" : "incomplete_missing_open" :
                opened!.SourceRecordId >= closed!.SourceRecordId || opened.At > closed.At ? "incomplete_out_of_order" : reason;
            // The reference does not attach supplements to an out-of-order or unproven pair.
            result.Add(Observation(items, boot, failure, chain, privilegeState, privileges,
                failure is null or "incomplete_duplicate_boundary" or "incomplete_missing_close" or "incomplete_missing_open" ? supplements : []));
        }
        return result.OrderBy(r => r["source_event_ids"]![0]!.GetValue<long>()).ThenBy(r => r["session_uid"]!.ToString(), StringComparer.Ordinal).ToArray();
    }

    static (AuthenticationContinuity[]? Chain, string? Reason) Proof(AuthenticationEvidence boot, AuthenticationEvidence[] boundaries, AuthenticationContinuity[] proofs)
    {
        var relevant = proofs.Where(p => SameScope(p, boot)).ToArray();
        if (relevant.Length == 0) return (null, "incomplete_coverage_unproven");
        var expected = new[] { boot }.Concat(boundaries).Select(e => (e.SourceEventId, e.Hash)).ToArray();
        long last = boundaries.Append(boot).Max(e => e.SourceRecordId);
        var complete = relevant.Where(p => p.Completeness == "complete").OrderBy(p => p.FirstRecordId).ThenBy(p => p.LastRecordId).ThenBy(p => p.ScopeIdentity, StringComparer.Ordinal).ToArray();
        var accepted = new List<AuthenticationContinuity[]>();
        for (int i = 0; i < complete.Length; i++)
        {
            var first = complete[i];
            if (first.FirstRecordId > boot.SourceRecordId || first.LastRecordId < boot.SourceRecordId || !first.SourceEventIds.Zip(first.SourceHashes).Contains(expected[0])) continue;
            var chain = new List<AuthenticationContinuity> { first };
            foreach (var next in complete.Skip(i + 1))
            {
                if (chain[^1].LastRecordId >= last || next.FirstRecordId != chain[^1].LastRecordId + 1 || next.ChannelGenerationIdentity != chain[^1].ChannelGenerationIdentity) break;
                chain.Add(next);
            }
            var covered = chain.SelectMany(p => p.SourceEventIds.Zip(p.SourceHashes)).ToHashSet();
            if (chain[^1].LastRecordId >= last && expected.All(covered.Contains)) accepted.Add(chain.ToArray());
        }
        return accepted.Count == 1 ? (accepted[0], null) : (null, "incomplete_coverage_gap");
    }

    static JsonObject Observation(AuthenticationEvidence[] boundaries, AuthenticationEvidence? boot, string? reason,
        AuthenticationContinuity[]? chain = null, string privilegeState = "missing", AuthenticationEvidence[]? privileges = null,
        AuthenticationEvidence[]? supplements = null, AuthenticationEvidence[]? extra = null)
    {
        bool complete = reason is null; var opened = boundaries.FirstOrDefault(e => e.EventKey == 4624);
        var closed = complete ? boundaries.First(e => e.EventKey == 4634) : null;
        var source = complete ? new[] { boot!, opened!, closed! } : Ordered((extra ?? []).Concat(boot is null ? [] : [boot]).Concat(boundaries).Distinct()).ToArray();
        var privilege = privilegeState == "exact" ? privileges![0] : null;
        string material = string.Join('\0', new[] { Contract, complete ? "closed" : reason! }.Concat(source.Select(e => $"{e.SourceEventId}:{e.Hash}")));
        static JsonArray Ids(IEnumerable<AuthenticationEvidence> events) => new(events.Select(e => (JsonNode)JsonValue.Create(e.SourceEventId)).ToArray());
        static JsonArray Hashes(IEnumerable<AuthenticationEvidence> events) => new(events.Select(e => (JsonNode)JsonValue.Create(e.Hash)).ToArray());
        static string? Stamp(AuthenticationEvidence? e) => e is null ? null : SemanticJson.Stamp(e.At);
        var logout = (supplements ?? []).Where(e => e.EventKey == 4647).ToArray(); var credentials = (supplements ?? []).Where(e => e.EventKey == 4648).ToArray();
        return new JsonObject {
            ["session_uid"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(material)))[..32],
            ["state"] = complete ? "closed" : "incomplete", ["completeness"] = complete ? "complete" : reason == "incomplete_missing_open" ? "missing_start" : reason == "incomplete_missing_close" ? "missing_stop" : "conflict",
            ["quality_reason"] = reason ?? "complete", ["coverage_state"] = complete || chain is { Length: > 0 } ? "accepted" : "unavailable", ["promotion_eligible"] = complete || chain is { Length: > 0 },
            ["boot_source_event_id"] = boot?.SourceEventId, ["boot_normalized_hash"] = boot?.Hash,
            ["logon_source_event_id"] = opened?.SourceEventId, ["logon_normalized_hash"] = opened?.Hash,
            ["logoff_source_event_id"] = closed?.SourceEventId, ["logoff_normalized_hash"] = closed?.Hash,
            ["source_event_ids"] = Ids(source), ["source_hashes"] = Hashes(source), ["logon_time_utc"] = Stamp(opened), ["logoff_time_utc"] = Stamp(closed),
            ["duration_seconds"] = complete ? (long?)(closed!.At - opened!.At).TotalSeconds : null,
            ["principal"] = opened?.Principal, ["host"] = opened?.Host, ["logon_type"] = opened?.LogonType,
            ["privilege_marker"] = privilege?.PrivilegeMarker, ["privilege_source_event_id"] = privilege?.SourceEventId, ["privilege_normalized_hash"] = privilege?.Hash,
            ["privilege_attachment_state"] = privilegeState, ["privilege_evidence_source_event_ids"] = Ids(privileges ?? []), ["privilege_evidence_normalized_hashes"] = Hashes(privileges ?? []),
            ["supplemental_logout_source_event_ids"] = Ids(logout), ["supplemental_logout_normalized_hashes"] = Hashes(logout),
            ["explicit_credentials_source_event_ids"] = Ids(credentials), ["explicit_credentials_normalized_hashes"] = Hashes(credentials)
        };
    }
}
