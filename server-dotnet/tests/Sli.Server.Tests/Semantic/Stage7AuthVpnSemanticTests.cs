using System.Text.Json.Nodes;
using Sli.Server.Agents.Radius;
using Sli.Server.Semantic;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_stage7_auth_vpn_semantic.py.
public sealed class Stage7AuthVpnSemanticTests
{
    static JsonObject Data(params (string Key, string Value)[] values) => new(values.Select(p => new KeyValuePair<string, JsonNode?>(p.Key, JsonValue.Create(p.Value))));
    static SemanticEvent Event(long source, int eventId, JsonObject? data = null, int minute = 0, string provider = AuthenticationSessionFold.Provider, long host = 17) =>
        SemanticNormalization.Normalize(new JsonObject {
            ["id"] = source, ["event_id"] = eventId, ["channel"] = "Security", ["provider_name"] = provider,
            ["computer"] = host == 17 ? "DC1" : "NPS01", ["server_id"] = host, ["source_host_id"] = host,
            ["time_created_utc"] = new DateTimeOffset(2026, 8, 25, 1, minute, 0, TimeSpan.Zero).ToString("O"),
            ["event_data_json"] = data ?? new JsonObject()
        });
    static AuthenticationEvidence[] Evidence(long firstRecord, params SemanticEvent[] events) =>
        events.Select((e, i) => AuthenticationSessionFold.FromNormalized(e, firstRecord + i)).ToArray();
    static AuthenticationContinuity Proof(AuthenticationEvidence[] evidence) => new("stage7-fixture", "sli.windows.ad-dc", "Security", 17, 1,
        AuthenticationSessionFold.Provider, "boot-generation-1", evidence.Select(e => e.SourceEventId).ToArray(), evidence.Select(e => e.Hash).ToArray(),
        evidence.Min(e => e.SourceRecordId), evidence.Max(e => e.SourceRecordId), "complete");
    static long[] Ids(JsonObject session, string name) => session[name]!.AsArray().Select(n => n!.GetValue<long>()).ToArray();
    static string[] Strings(JsonObject session, string name) => session[name]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();

    [Theory]
    [InlineData(4634)] [InlineData(4647)] [InlineData(4768)] [InlineData(4769)]
    [InlineData(4770)] [InlineData(4771)] [InlineData(4773)] [InlineData(4776)]
    public void Authentication_requires_the_exact_provider_descriptor(int eventId)
    {
        var wrong = Event(eventId + 100_000, eventId, Data(("TargetUserName", "alice"), ("TargetDomainName", "EXAMPLE"), ("TargetLogonId", "0xabc"), ("Status", "0x0")), provider: "Wrong-Provider");
        Assert.Equal("event.unknown", wrong.Type);
        Assert.Empty(SemanticAssembly.Assemble([wrong]));
    }

    [Theory] [InlineData(4771, "authentication.kerberos.preauthentication.failed")] [InlineData(4773, "authentication.kerberos.service_ticket.failed")]
    public void Kerberos_failure_status_is_observed(int id, string semantic)
    {
        var e = Event(id, id, Data(("TargetUserName", "alice"), ("TargetLogonId", "0xabc"), ("Status", "0x18")));
        Assert.Equal(semantic, e.Type); Assert.Equal("0x18", e.Facts["result_code"]!.ToString());
        Assert.Equal("observed", e.Facts["result_code_state"]!.ToString()); Assert.Equal("failure", e.Facts["result"]!.ToString());
    }

    [Theory] [InlineData(4625)] [InlineData(4771)] [InlineData(4776)]
    public void Missing_result_codes_stay_unknown(int eventId)
    {
        var e = Event(eventId, eventId);
        Assert.Equal("unknown", e.Facts["result_code_state"]!.ToString());
        Assert.Equal("unknown", e.Facts["result"]!.ToString()); Assert.False(e.Facts.ContainsKey("result_code"));
    }

    [Fact]
    public void Authentication_and_Nps_are_independent_evidence_bearing_actions()
    {
        int[] ids = [4634, 4647, 4625, 4648, 4672, 4768, 4769, 4770, 4771, 4773, 4776];
        var windows = ids.Select(id => Event(2000 + id, id, Data(("TargetUserName", "alice"), ("TargetLogonId", "0xabc"), ("SubjectLogonId", "0xabc")), minute: 1));
        var nps = new[] { 6272, 6273 }.Select(id => Event(9000 + id, id, Data(("AccountSessionIdentifier", "same-native-value")), minute: 1, host: 32));
        var actions = SemanticAssembly.Assemble(windows.Concat(nps));
        Assert.Equal(ids.Length + 2, actions.Count);
        Assert.All(actions, a => {
            var e = Assert.Single(a.Evidence); var reference = Assert.Single(a.Attributes["source_evidence"]!.AsArray())!;
            Assert.Equal(e.Source, reference["source_event_id"]!.GetValue<long>()); Assert.Equal(e.Sha, reference["semantic_sha256"]!.ToString());
        });
        var privileged = Assert.Single(actions, a => a.Kind == "authentication.privileged_session.created");
        Assert.Equal("privileged_session_observed_not_privilege_escalation", privileged.Attributes["observed_facts"]![0]!["security_assertion"]!.ToString());
        Assert.DoesNotContain(actions, a => a.Kind == "privilege.escalation");
        var remote = actions.Where(a => a.Kind.StartsWith("remote_access.", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, remote.Length); Assert.All(remote, a => Assert.True(a.Attributes["session_independent"]!.GetValue<bool>()));
    }

    [Fact]
    public void Boot_scoped_path_has_complete_exact_session_and_separate_privilege_evidence()
    {
        SemanticEvent[] events = [Event(10, 4608), Event(11, 4624, Data(("TargetUserName", "alice"), ("TargetLogonId", "0xabc"), ("LogonType", "3")), 1),
            Event(12, 4672, Data(("SubjectUserName", "alice"), ("SubjectLogonId", "0xabc"), ("PrivilegeList", "SeBackupPrivilege")), 2), Event(13, 4634, Data(("TargetLogonId", "0xabc")), 6)];
        var evidence = Evidence(100, events);
        Assert.Equal(new[] { "authentication.privileged_session.created", "authentication.session.created", "authentication.session.ended" }, SemanticAssembly.Assemble(events).Select(a => a.Kind).Order(StringComparer.Ordinal));
        var s = Assert.Single(AuthenticationSessionFold.Assemble(evidence, [Proof(evidence)]));
        Assert.Equal("complete", s["completeness"]!.ToString()); Assert.Equal(300, s["duration_seconds"]!.GetValue<long>());
        Assert.Equal(new long[] { 10, 11, 13 }, Ids(s, "source_event_ids")); Assert.Equal(new[] { events[0].Sha, events[1].Sha, events[3].Sha }, Strings(s, "source_hashes"));
        Assert.Equal(12, s["privilege_source_event_id"]!.GetValue<long>()); Assert.Equal(events[2].Sha, s["privilege_normalized_hash"]!.ToString());
        Assert.Equal("exact", s["privilege_attachment_state"]!.ToString()); Assert.Equal("accepted", s["coverage_state"]!.ToString()); Assert.True(s["promotion_eligible"]!.GetValue<bool>());
        Assert.Equal("SeBackupPrivilege", s["privilege_marker"]!.ToString()); Assert.Equal("3", s["logon_type"]!.ToString());
    }

    [Fact]
    public void Incomplete_path_preserves_missing_stop_without_duration()
    {
        var e = Evidence(200, Event(20, 4608), Event(21, 4624, Data(("TargetLogonId", "0xdef")), 1));
        var s = Assert.Single(AuthenticationSessionFold.Assemble(e, [Proof(e)]));
        Assert.Equal("missing_stop", s["completeness"]!.ToString()); Assert.Null(s["duration_seconds"]);
        Assert.Equal(new long[] { 20, 21 }, Ids(s, "source_event_ids"));
    }

    [Fact]
    public void Logout_is_supplemental_and_explicit_credentials_require_exact_native_key()
    {
        var e = Evidence(300, Event(30, 4608), Event(31, 4624, Data(("TargetLogonId", "0xaaa")), 1),
            Event(32, 4648, Data(("SubjectLogonId", "0xaaa")), 2), Event(33, 4647, Data(("TargetLogonId", "0xaaa")), 3), Event(34, 4648, Data(("SubjectLogonId", "0xbbb")), 4));
        var s = Assert.Single(AuthenticationSessionFold.Assemble(e, [Proof(e)]));
        Assert.Equal(31, s["logon_source_event_id"]!.GetValue<long>()); Assert.Equal("missing_stop", s["completeness"]!.ToString()); Assert.Null(s["duration_seconds"]);
        Assert.Equal(new long[] { 33 }, Ids(s, "supplemental_logout_source_event_ids")); Assert.Equal(new long[] { 32 }, Ids(s, "explicit_credentials_source_event_ids"));
        Assert.Equal(new[] { e[2].Hash }, Strings(s, "explicit_credentials_normalized_hashes")); Assert.Equal(new[] { e[3].Hash }, Strings(s, "supplemental_logout_normalized_hashes"));
    }

    [Fact]
    public void Supplemental_fact_after_reboot_never_attaches_to_prior_logon()
    {
        var e = Evidence(400, Event(40, 4608), Event(41, 4624, Data(("TargetLogonId", "0xaaa")), 1), Event(42, 4608, minute: 2), Event(43, 4648, Data(("SubjectLogonId", "0xaaa")), 3));
        var s = Assert.Single(AuthenticationSessionFold.Assemble(e, [Proof(e)]));
        Assert.Equal(41, s["logon_source_event_id"]!.GetValue<long>()); Assert.Empty(Ids(s, "explicit_credentials_source_event_ids"));
    }

    [Theory] [InlineData("missing")] [InlineData("hash")] [InlineData("gap")]
    public void Pair_without_exact_continuity_never_claims_complete(string variant)
    {
        var e = Evidence(100, Event(10, 4608), Event(11, 4624, Data(("TargetLogonId", "0xabc")), 1), Event(13, 4634, Data(("TargetLogonId", "0xabc")), 6));
        var p = Proof(e); if (variant == "hash") p = p with { SourceHashes = [e[0].Hash, e[1].Hash, new string('a', 64)] };
        if (variant == "gap") p = p with { Completeness = "gap" };
        var s = Assert.Single(AuthenticationSessionFold.Assemble(e, variant == "missing" ? [] : [p]));
        Assert.Equal("conflict", s["completeness"]!.ToString()); Assert.Null(s["duration_seconds"]); Assert.False(s["promotion_eligible"]!.GetValue<bool>());
    }

    static string RadiusLine(string status, string clock)
    {
        var row = Enumerable.Repeat("", 66).ToArray(); row[0] = "NPS01"; row[1] = "IAS"; row[2] = "08/25/2026"; row[3] = clock; row[4] = "4";
        row[5] = "EXAMPLE\\alice"; row[11] = "VPN-GW-01"; row[31] = status; row[35] = "opaque-session-7";
        return string.Join(',', row);
    }
    static JsonObject Input(RadiusObservation o) => new() { ["observation_id"] = o.RecordHash, ["lifecycle_event"] = o.Lifecycle,
        ["identity_state"] = o.Principal is null ? "unresolved" : "exact", ["timestamp_state"] = "ready", ["session_identity_key"] = o.SessionIdentityKey,
        ["exact_principal_key"] = o.Principal, ["observed_at_utc"] = o.ObservedAt.ToString("O"), ["canonical_record_sha256"] = o.RecordHash };

    [Fact]
    public void Radius_pipeline_folds_exact_evidence_and_preserves_honest_variants()
    {
        const string principal = "sid:S-1-5-21-100000001-200000002-300000003-1101";
        var observations = new[] { ("1", "09:00:00"), ("3", "09:05:00"), ("2", "09:10:00") }.Select(p =>
            RadiusPlanner.BuildSessionObservation(RadiusLine(p.Item1, p.Item2), "radius-stage7-fixture", "N. Central Asia Standard Time", 420, principal)).ToArray();
        Assert.All(observations, o => Assert.NotNull(o)); var inputs = observations.Select(o => Input(o!)).ToArray();
        // Executed Python reference, with the queue's reserved synthetic SID.
        Assert.Equal(new[] { "0b92e8521986c24189475d757dfb21eec3a64386a8660d04f5f04fdd5b740c26", "ff8d8536432c15563abad2cd3216b8538bbed085f5d2ce1857ff7dcae98a0488", "9283f429e7ffbe1d6ca4b9b37318486612f3de8692c4d6253fac6afbcf641962" }, observations.Select(o => o!.RecordHash));
        Assert.All(observations, o => Assert.Equal("radius-session:9346a736f38b2736b07c548870f9b8eddfb1ffd27768eccfe60e886e996b3676", o!.SessionIdentityKey));
        Assert.Equal(new DateTimeOffset(2026, 8, 25, 2, 0, 0, TimeSpan.Zero), observations[0]!.ObservedAt);
        Assert.Single(observations.Select(o => o!.SessionIdentityKey).Distinct());
        var complete = Assert.Single(RadiusSessionFold.Fold(inputs)); var partial = Assert.Single(RadiusSessionFold.Fold(inputs.Take(2)));
        Assert.Equal("complete", complete["completeness"]!.ToString()); Assert.Equal(600, complete["duration_seconds"]!.GetValue<long>());
        Assert.Equal(observations.Select(o => o!.RecordHash), Strings(complete, "observation_ids")); Assert.Equal(observations.Select(o => o!.RecordHash), Strings(complete, "evidence_sha256s"));
        Assert.Equal("missing_stop", partial["completeness"]!.ToString()); Assert.Null(partial["duration_seconds"]);
        var unresolved = RadiusSessionFold.FoldWithCoverage([Input(RadiusPlanner.BuildSessionObservation(RadiusLine("1", "09:00:00"), "radius-stage7-fixture", "N. Central Asia Standard Time", 420, null)!)]);
        Assert.Empty(unresolved.Sessions); Assert.Equal(1, unresolved.UnresolvedIdentityObservations); Assert.Equal(1, unresolved.InputObservations); Assert.Equal(0, unresolved.ExactReadyObservations);
    }
}
