using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Behavioral vectors from tests/semantic/test_semantic_dispatch1.py.
public sealed class SemanticDispatchTests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-400";
    private const string OtherSid = "S-1-5-21-100000001-200000002-300000003-401";
    private const string GroupSid = "S-1-5-21-100000001-200000002-300000003-512";
    private const string Failed = "authentication.session.failed", Locked = "authentication.account.locked";
    private const string Created = "authentication.session.created", Privileged = "authentication.privileged_session.created";
    private const string Reset = "account.password.reset.succeeded";
    private static readonly DateTimeOffset Start = new(2026, 7, 19, 0, 0, 0, TimeSpan.Zero);

    private static SemanticEvent Event(long id, string type, int seconds = 0, string host = "dc-1", string session = "session-1") =>
        new(id, type, Start.AddSeconds(seconds), new() { ["source_host"] = host, ["session_principal"] = session }, new(), new(), id.ToString("x64"));

    private static SemanticEvent Identity(long id, string type, int seconds = 0, int domain = 7, string account = Sid, string? member = null, string? group = null)
    {
        var ev = Event(id, type, seconds, host: $"dc-{id}");
        ev.Facts["domain_id"] = domain;
        if (account.Length > 0)
        {
            ev.Facts["relation_account_sid"] = account;
            ev.Quality["relation_account_identity"] = new JsonObject { ["state"] = "exact" };
            ev.Roles["affected_entity"] = "sid:" + account;
        }
        if (member is not null && group is not null)
        {
            ev.Facts["relation_member_sid"] = member;
            ev.Facts["relation_group_sid"] = group;
            ev.Quality["relation_membership_identity"] = new JsonObject { ["state"] = "exact" };
        }
        return ev;
    }

    private static SemanticCorrelation Compile(string kind, JsonObject? overrides = null, bool crossDc = false)
    {
        JsonObject definition = new()
        {
            ["type"] = kind,
            ["inputs"] = crossDc ? new JsonArray(Failed, Locked) : new JsonArray(Created, Privileged),
            ["window_seconds"] = 900,
            ["output_relation_kind"] = crossDc ? "authentication.account.lockout_preceded_by_failures_observed" : "authentication.session.has_special_privileges",
            ["confidence"] = crossDc ? "medium" : "high",
            ["explanation"] = crossDc ? "Observed exact domain and SID sequence; this makes no causal claim." : "same source host and session principal"
        };
        if (crossDc) { definition["partition_kind"] = "domain_account_sid"; definition["minimum_count"] = 2; definition["strict_time_order"] = true; }
        else definition["join_roles"] = new JsonArray("source_host", "session_principal");
        if (overrides is not null) foreach (var item in overrides) definition[item.Key] = item.Value?.DeepClone();
        return SemanticCorrelation.Compile(new JsonObject { ["rule_id"] = (crossDc ? "cross-dc-" : "dispatch-") + kind, ["rule_version"] = 1, ["rule_kind"] = kind, ["definition_json"] = definition });
    }

    private static SemanticCorrelation ResetRule(bool all = false) => Compile("sequence", new()
    {
        ["inputs"] = new JsonArray(Reset, Created), ["window_seconds"] = 3600,
        ["output_relation_kind"] = "authentication.password_reset_followed_by_logon_observed",
        ["continuation_policy"] = all ? "anchor_all_admissible" : "first_admissible"
    }, crossDc: true);

    private static void Evidence(SemanticRelation relation, params long[] ids) => Assert.Equal(ids, relation.Evidence.Select(x => x.Source));

    [Fact]
    public void Count_then_requires_same_domain_exact_sid_and_strictly_preceding_failures()
    {
        var rule = Compile("count_then", crossDc: true);
        var relation = Assert.Single(rule.Match([
            Identity(1, Failed), Identity(2, Failed, 120), Identity(3, Locked, 180),
            Identity(4, Locked, 240, account: OtherSid), Identity(5, Locked, 300, domain: 8)]));
        Evidence(relation, 1, 2, 3);
        Assert.Equal($"domain:7|account_sid:{Sid}", relation.Partition);
        Assert.Equal("authentication.account.lockout_preceded_by_failures_observed", relation.Kind);
        Assert.Equal("medium", relation.Confidence);
        Assert.Contains("causal", relation.Explanation);
        Assert.Empty(rule.Match([Identity(1, Failed), Identity(2, Failed), Identity(3, Locked)]));
        Assert.Empty(rule.Match([Identity(1, Failed), Identity(2, Locked, 180)]));
    }

    [Fact]
    public void Cross_dc_partition_rejects_non_numeric_sid()
    {
        Assert.Null(Compile("count_then", crossDc: true).Partition(Identity(1, Failed, account: "S-1-5-21-not-numeric")));
    }

    [Fact]
    public void Membership_sequence_requires_exact_member_and_group_sids()
    {
        var rule = Compile("sequence", new()
        {
            ["inputs"] = new JsonArray("group.member.added", "group.member.removed"),
            ["partition_kind"] = "domain_member_group_sid", ["window_seconds"] = 86400,
            ["output_relation_kind"] = "directory.group.membership_reverted_observed"
        }, crossDc: true);
        var added = Identity(1, "group.member.added", account: "", member: Sid, group: GroupSid);
        var removed = Identity(2, "group.member.removed", 1, account: "", member: Sid, group: GroupSid);
        var relation = Assert.Single(rule.Match([added, removed,
            Identity(3, "group.member.removed", 2, account: "", member: OtherSid, group: GroupSid)]));
        Evidence(relation, 1, 2);
        Assert.Equal($"domain:7|member_sid:{Sid}|group_sid:{GroupSid}", relation.Partition);
        Assert.Empty(rule.Match([added, Identity(4, "group.member.removed", 1, account: "", member: Sid, group: OtherSid)]));
        Assert.Null(rule.Partition(removed with { Quality = new() }));
    }

    [Fact]
    public void Strict_sequence_rejects_equal_timestamps()
    {
        var rule = Compile("sequence", new() { ["inputs"] = new JsonArray(Locked, "authentication.account.unlocked"), ["window_seconds"] = 86400,
            ["output_relation_kind"] = "authentication.account.unlock_after_lock_observed" }, crossDc: true);
        Assert.Empty(rule.Match([Identity(1, Locked), Identity(2, "authentication.account.unlocked")]));
    }

    [Fact]
    public void Reset_then_logon_requires_success_exact_identity_and_time()
    {
        var rule = ResetRule();
        var reset = Identity(1, Reset);
        var logon = Identity(2, Created, 1800);
        var relation = Assert.Single(rule.Match([reset, logon]));
        Evidence(relation, 1, 2);
        Assert.Equal($"domain:7|account_sid:{Sid}", relation.Partition);
        Assert.Contains("causal", relation.Explanation);
        Assert.Empty(rule.Match([Identity(3, "account.password.reset.attempted"), logon]));
        Assert.Empty(rule.Match([reset, Identity(4, Created, 1800, account: OtherSid)]));
        Assert.Empty(rule.Match([reset, Identity(5, Created)]));
        Assert.Empty(rule.Match([reset, Identity(6, Created, 3601)]));
        Evidence(Assert.Single(rule.Match([reset, Identity(7, Created, 3600)])), 1, 7);
    }

    [Fact]
    public void Anchor_sequence_replay_adds_late_evidence_without_changing_independent_keys()
    {
        var rule = ResetRule(all: true);
        SemanticEvent[] initial = [Identity(1, Reset), Identity(2, Created, 600), Identity(10, Reset, 7200), Identity(11, Created, 7800)];
        var before = rule.Match(initial);
        // Deliberately unsorted input, as in replay with newly discovered evidence.
        var after = rule.Match([.. initial, Identity(3, Created, 1200)]);
        Assert.Equal(2, before.Count); Assert.Equal(2, after.Count);
        Evidence(before[0], 1, 2); Evidence(before[1], 10, 11);
        Evidence(after[0], 1, 2, 3); Evidence(after[1], 10, 11);
        Assert.StartsWith("dispatch:", after[0].Key);
        Assert.Equal(before.Select(x => x.Key), after.Select(x => x.Key));
        Assert.NotEqual(after[0].Key, after[1].Key);
    }

    [Fact]
    public void Count_then_keeps_lockout_anchor_key_for_late_failure_evidence()
    {
        var rule = Compile("count_then", crossDc: true);
        SemanticEvent[] initial = [Identity(2, Failed, 60), Identity(3, Failed, 120), Identity(4, Locked, 180)];
        var before = Assert.Single(rule.Match(initial));
        var after = Assert.Single(rule.Match([Identity(1, Failed), .. initial]));
        Evidence(before, 2, 3, 4); Evidence(after, 1, 2, 3, 4);
        Assert.Equal(before.Key, after.Key);
    }

    [Fact]
    public void Account_member_partition_rejects_member_without_exact_quality()
    {
        var rule = Compile("sequence", new()
        {
            ["inputs"] = new JsonArray("directory.account.created", "group.member.added"), ["partition_kind"] = "domain_account_member_sid",
            ["window_seconds"] = 86400, ["output_relation_kind"] = "directory.account.group_membership_added_observed"
        }, crossDc: true);
        var account = Identity(1, "directory.account.created");
        var member = Identity(2, "group.member.added", 1, account: "", member: Sid, group: GroupSid);
        var relation = Assert.Single(rule.Match([account, member]));
        Evidence(relation, 1, 2);
        Assert.Equal($"domain:7|account_member_sid:{Sid}", relation.Partition);
        Assert.Empty(rule.Match([account, member with { Quality = new() }]));
    }

    [Fact]
    public void All_of_requires_exact_roles_and_window()
    {
        var rule = Compile("all_of");
        var relation = Assert.Single(rule.Match([Event(1, Created), Event(2, Privileged, 1), Event(3, Privileged, 2, host: "dc-2")]));
        Evidence(relation, 1, 2); Assert.StartsWith("dispatch:", relation.Key);
        Assert.Equal("authentication.session.has_special_privileges", relation.Kind);
        Assert.Equal("high", relation.Confidence); Assert.Null(relation.Partition);
        Assert.Empty(rule.Match([Event(1, Created), Event(2, Privileged, 960)]));
        Assert.Empty(rule.Match([Event(1, Created), Event(2, Privileged, 1, session: "session-2")]));
        Evidence(Assert.Single(rule.Match([Event(1, Created), Event(2, Privileged, 900)])), 1, 2);
    }

    [Fact]
    public void Count_uses_one_input_type_and_keeps_all_evidence_without_process_cap()
    {
        JsonObject definition = new() { ["inputs"] = new JsonArray(Failed), ["minimum_count"] = 3, ["output_relation_kind"] = "authentication.session.failure_burst" };
        var rule = Compile("count", definition);
        Evidence(Assert.Single(rule.Match([Event(0, Failed), Event(1, Failed, 1), Event(2, Failed, 2), Event(3, Created)])), 0, 1, 2);
        Assert.Empty(rule.Match([Event(0, Failed), Event(1, Failed, 1)]));
        var events = Enumerable.Range(0, 5001).Select(i => Event(i, Failed)).ToArray();
        Evidence(Assert.Single(rule.Match(events)), events.Select(x => x.Source).ToArray());
        definition["inputs"] = new JsonArray(Failed, Locked);
        Assert.Throws<InvalidDataException>(() => Compile("count", definition));
    }

    [Fact]
    public void All_of_returns_independent_relations_from_one_group()
    {
        var relations = Compile("all_of", new() { ["window_seconds"] = 30 }).Match([
            Event(1, Created), Event(2, Privileged, 1), Event(3, Created, 120), Event(4, Privileged, 121)]);
        Assert.Equal(2, relations.Count);
        Evidence(relations[0], 1, 2); Evidence(relations[1], 3, 4);
    }

    [Theory]
    [InlineData("{\"join_roles\":[\"session_principal\"]}", "correlation_partition_invalid")]
    [InlineData("{\"window_seconds\":86401}", "correlation_definition_invalid")]
    [InlineData("{\"minimum_count\":1}", "correlation_definition_invalid")]
    [InlineData("{\"join_roles\":[\"source_host\",\"arbitrary\"]}", "correlation_partition_invalid")]
    public void All_of_compiler_rejects_invalid_definitions(string json, string code)
    {
        Assert.Equal(code, Assert.Throws<InvalidDataException>(() => Compile("all_of", JsonNode.Parse(json)!.AsObject())).Message);
    }

    [Fact]
    public void Sequence_requires_declared_event_order()
    {
        var rule = Compile("sequence", new() { ["output_relation_kind"] = "authentication.session.privileged_context_observed" });
        Evidence(Assert.Single(rule.Match([Event(1, Created), Event(2, Privileged, 1)])), 1, 2);
        Assert.Empty(rule.Match([Event(1, Privileged), Event(2, Created, 1)]));
    }

    private static JsonObject Pack()
    {
        using var stream = typeof(SemanticCorrelation).Assembly.GetManifestResourceStream("Sli.Server.Semantic.chain_pack.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }

    [Fact]
    public void Chain_training_pack_dispatch_rules_stay_draft_and_compile()
    {
        var pack = Pack();
        Assert.Equal("semantic_worker", pack["owner"]!.GetValue<string>());
        Assert.True(pack["execution_policy"]!["no_implicit_close"]!.GetValue<bool>());
        var rules = pack["rules"]!.AsArray().Where(x => x!["rule_kind"]!.GetValue<string>() != "worker_assembler").ToArray();
        Assert.NotEmpty(rules);
        foreach (var item in rules)
        {
            Assert.Equal("draft", item!["lifecycle_status"]!.GetValue<string>());
            var compiled = SemanticCorrelation.Compile(new JsonObject
            {
                ["rule_id"] = item["rule_id"]!.DeepClone(), ["rule_version"] = item["rule_version"]!.DeepClone(),
                ["rule_kind"] = item["rule_kind"]!.DeepClone(), ["definition_json"] = item["definition"]!.DeepClone()
            });
            Assert.Contains(compiled.Kind, new[] { "sequence", "count_then" });
        }
    }

    [Fact]
    public void Investigation_pack_preserves_approved_sid_rule_contracts()
    {
        (string Id, string Kind, string Partition, string First, string Second, int Seconds)[] approved = [
            ("investigation.account.lockout.preceded-by-failures", "count_then", "domain_account_sid", Failed, Locked, 900),
            ("investigation.account.unlock.after-lock", "sequence", "domain_account_sid", Locked, "authentication.account.unlocked", 86400),
            ("investigation.group.membership.removed-after-add", "sequence", "domain_member_group_sid", "group.member.added", "group.member.removed", 86400),
            ("investigation.account.created-then-group-add", "sequence", "domain_account_member_sid", "directory.account.created", "group.member.added", 86400),
            ("investigation.password.reset-then-logon", "sequence", "domain_account_sid", Reset, Created, 3600)
        ];
        var rules = Pack()["rules"]!.AsArray();
        foreach (var expected in approved)
        {
            var item = rules.Last(x => x!["rule_id"]!.GetValue<string>() == expected.Id)!;
            var definition = item["definition"]!;
            Assert.Equal(expected.Kind, item["rule_kind"]!.GetValue<string>());
            Assert.Equal("draft", item["lifecycle_status"]!.GetValue<string>());
            Assert.Equal(expected.Partition, definition["partition_kind"]!.GetValue<string>());
            Assert.Equal(new[] { expected.First, expected.Second }, definition["inputs"]!.AsArray().Select(x => x!.GetValue<string>()));
            Assert.Equal(expected.Seconds, definition["window_seconds"]!.GetValue<int>());
            Assert.True(definition["strict_time_order"]!.GetValue<bool>());
            Assert.Contains("causal", definition["explanation"]!.GetValue<string>().ToLowerInvariant());
        }
        Assert.All(rules, item => Assert.DoesNotContain("account.password.reset.attempted",
            item?["definition"]?["inputs"]?.AsArray().Select(x => x!.GetValue<string>()) ?? []));
    }
}
