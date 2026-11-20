using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_semantic_l1_shadow_control.py and control.POLICIES.
public sealed class SemanticL1ShadowControlTests
{
    private const string Actor = "sid:S-1-5-21-100000001-200000002-300000003-1001";
    private const string Host = "dc-1.example.test";
    private const string ActionId = "11111111-1111-1111-1111-111111111111";
    private const string EvidenceId = "22222222-2222-2222-2222-222222222222";
    private static readonly DateTime Now = new(2026, 7, 30, 0, 0, 0, DateTimeKind.Utc);

    private static JsonObject Policy(string id, string action, string scenario, string[] roles, string title, string explanation, int points) => new()
    {
        ["policy_id"] = id, ["policy_version"] = 2, ["source_kind"] = "canonical_action",
        ["definition_json"] = new JsonObject
        {
            ["type"] = "scenario_policy", ["source_selector"] = new JsonObject { ["action_kind"] = action },
            ["scenario_kind"] = scenario, ["result_class"] = "security_incident",
            ["strict_roles"] = new JsonArray(roles.Select(x => JsonValue.Create(x)).ToArray()),
            ["merge_window_seconds"] = 300, ["title"] = title, ["explanation"] = explanation,
            ["expected_evidence_count"] = 1, ["required_controls"] = new JsonArray(), ["allowed_lateness_seconds"] = 60,
            ["risk"] = new JsonObject
            {
                ["class"] = points >= 70 ? "high" : "medium", ["raw_score"] = points.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["display_points"] = points, ["hard_critical"] = false, ["rationale"] = "Bounded Stage-8 L1 SHADOW policy match"
            }
        }
    };
    private static JsonObject[] Policies() =>
    [
        Policy("l1-eventlog-cleared", "eventlog.cleared", "security.audit_controls_changed", ["source_host"],
            "Security event log was cleared", "Exact provider-aware Event 1102 action was observed", 85),
        Policy("l1-audit-policy-changed", "audit.policy.changed", "security.audit_controls_changed", ["source_host", "actor"],
            "Audit policy was changed", "Exact named EventData from Event 4719 was observed", 75),
        Policy("l1-privileged-group-member-added", "group.member.added", "security.privileged_group_member_added", ["source_host", "container_entity", "target_entity"],
            "Member was added to a privileged group", "Exact group and member identities were observed", 85),
        Policy("l1-scheduled-task-created", "scheduled_task.created", "security.scheduled_task_created", ["source_host", "target_entity"],
            "Scheduled task was registered", "Exact Task Scheduler Event 106 action was observed", 65)
    ];

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Four_l1_policies_compile_to_three_canonical_action_scenario_families(int version)
    {
        var inputs = Policies();
        foreach (var row in inputs) row["policy_version"] = version;
        var compiled = inputs.Select(SemanticPolicy.Compile).ToArray();
        Assert.Equal(4, compiled.Length);
        Assert.Equal(new[] { "audit.policy.changed", "eventlog.cleared", "group.member.added", "scheduled_task.created" }, compiled.Select(x => x.Selector).Order().ToArray());
        Assert.Equal(new[] { "security.audit_controls_changed", "security.privileged_group_member_added", "security.scheduled_task_created" }, compiled.Select(x => x.Kind).Distinct().Order().ToArray());
        for (int i = 0; i < compiled.Length; i++)
        {
            var policy = compiled[i];
            Assert.Equal("canonical_action", policy.Source);
            Assert.Equal("security_incident", policy.Result);
            Assert.Equal(300, policy.Window);
            Assert.Equal(1, policy.Expected);
            Assert.Equal(60, policy.Lateness);
            Assert.Empty(policy.Controls);
            Assert.Equal(new[] { 85, 75, 85, 65 }[i], policy.Points);
            Assert.Equal(policy.Points, policy.Raw);
            Assert.False(policy.Hard);
            Assert.Equal(i == 3 ? "medium" : "high", policy.Risk);
        }
    }

    [Fact]
    public async Task Canonical_action_is_step_evidence_and_does_not_split_scenario_merge_identity()
    {
        var policy = SemanticPolicy.Compile(Policies()[1]);
        await using var session = new Session();
        var first = await SemanticProduction.Proposal(session, policy, ActionId, "shadow", TestContext.Current.CancellationToken);
        const string nextId = "33333333-3333-3333-3333-333333333333";
        session.Action["canonical_action_id"] = nextId;
        var second = await SemanticProduction.Proposal(session, policy, nextId, "shadow", TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["source_host"] = Host, ["actor"] = Actor }, first.Strict));
        Assert.Equal(Host, first.Partition);
        Assert.Equal(ActionId, first.SourceId);
        Assert.Equal(Guid.Parse(ActionId), first.SourceValues[0]);
        Assert.Equal(new[] { Guid.Parse(EvidenceId) }, first.Evidence);
        Assert.Equal(first.Identity, second.Identity);
        Assert.NotEqual(first.Step, second.Step);
        Assert.NotEqual(first.Contribution, second.Contribution);
        session.Evidence[0]!["roles_json"]!["actor"] = Actor + "0";
        session.Evidence[0]!["quality_json"]!["identity_roles"]!["actor"]!["key"] = Actor + "0";
        var differentActor = await SemanticProduction.Proposal(session, policy, nextId, "shadow", TestContext.Current.CancellationToken);
        Assert.NotEqual(first.Identity, differentActor.Identity);
    }

    [Fact]
    public async Task Canonical_material_host_must_agree_with_normalized_evidence()
    {
        await using var session = new Session();
        session.Action["attributes_json"]!["material_identity"]!["source_host"] = "dc-2.example.test";
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.Proposal(session, SemanticPolicy.Compile(Policies()[1]), ActionId, "shadow", TestContext.Current.CancellationToken));
        Assert.Equal("semantic_risk_source_host_not_exact", error.Message);
    }

    [Theory]
    [InlineData("schema_missing", "semantic_archive_authorization_schema_not_ready")]
    [InlineData("permission_missing", "semantic_archive_authorization_schema_not_ready")]
    [InlineData("authorization_missing", "storage_v2_admission_required")]
    [InlineData("expired", "storage_v2_admission_required")]
    [InlineData("revoked", "storage_v2_admission_required")]
    [InlineData("tampered", "storage_v2_admission_required")]
    public async Task Semantic_archive_reader_requires_active_persisted_storage_authorization(string state, string code)
    {
        await using var session = new Session();
        session.Ready = state is not ("schema_missing" or "permission_missing");
        session.Authorization = state == "authorization_missing" ? null : Authorization(state);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.AuthorizedArchiveRoot(session, Now, TestContext.Current.CancellationToken));
        Assert.Equal(code, error.Message);
        if (!session.Ready) Assert.Equal(1, session.Queries);
    }

    [Fact]
    public async Task Semantic_archive_root_comes_from_the_verified_persisted_authorization()
    {
        await using var session = new Session { Authorization = Authorization("active") };
        Assert.Equal("/synthetic/archive", await SemanticProduction.AuthorizedArchiveRoot(session, Now, TestContext.Current.CancellationToken));
        Assert.Equal(2, session.Queries);
    }

    private static JsonObject Authorization(string state)
    {
        var record = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a', 64), "/synthetic/archive",
            new JsonObject { ["kind"] = "fresh-event-store", ["version"] = 1 }, "synthetic-operator", Now.AddDays(-1),
            state == "expired" ? Now : Now.AddDays(1), state == "revoked" ? Now : null, "");
        return new JsonObject
        {
            ["route"] = record.Route, ["authority"] = record.Authority, ["preflight_digest"] = record.PreflightDigest,
            ["archive_root"] = record.ArchiveRoot, ["evidence"] = record.Evidence.DeepClone(), ["authorized_by"] = record.AuthorizedBy,
            ["authorized_at"] = SemanticJson.Stamp(record.AuthorizedAt), ["expires_at"] = SemanticJson.Stamp(record.ExpiresAt),
            ["revoked_at"] = record.RevokedAt is { } revoked ? SemanticJson.Stamp(revoked) : null,
            ["authorization_digest"] = state == "tampered" ? new string('b', 64) : DirectRuntimeAuthorization.Digest(record)
        };
    }

    private sealed class Session : ISemanticSession
    {
        internal bool Ready = true;
        internal JsonObject? Authorization;
        internal int Queries;
        internal JsonObject Action { get; } = new()
        {
            ["canonical_action_id"] = ActionId, ["action_kind"] = "audit.policy.changed", ["action_status"] = "observed",
            ["occurred_at_utc"] = SemanticJson.Stamp(Now),
            ["attributes_json"] = new JsonObject { ["material_identity"] = new JsonObject { ["source_host"] = Host } }
        };
        internal JsonArray Evidence { get; } = new(new JsonObject
        {
            ["normalized_event_id"] = EvidenceId, ["semantic_type"] = "audit.policy.changed",
            ["roles_json"] = new JsonObject { ["source_host"] = Host, ["actor"] = Actor },
            ["quality_json"] = new JsonObject { ["event_data_encoding"] = "named",
                ["identity_roles"] = new JsonObject { ["actor"] = new JsonObject { ["key"] = Actor, ["state"] = "resolved" } } }
        });
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            ct.ThrowIfCancellationRequested(); Queries++;
            if (sql.Contains("has_table_privilege")) return Task.FromResult(new JsonArray(new JsonObject { ["available"] = Ready }));
            if (sql.Contains("from public.storage_v2_runtime_authorizations")) return Task.FromResult(Authorization is null ? new JsonArray() : new JsonArray(Authorization.DeepClone()));
            Assert.Equal(Guid.Parse(Action.Text("canonical_action_id")!), Assert.Single(values));
            if (sql.StartsWith("select * from canonical_actions")) return Task.FromResult(new JsonArray(Action.DeepClone()));
            if (sql.Contains("from canonical_action_evidence")) return Task.FromResult((JsonArray)Evidence.DeepClone());
            throw new InvalidOperationException("Unexpected query: " + sql);
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
