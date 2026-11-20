using System.Text.Json.Nodes;
using Sli.Server.Auth;
using Sli.Server.Hosting;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Parity vectors from tests/semantic/test_semantic_governance.py. No runtime database.
public sealed class SemanticGovernanceTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly Principal Owner = new("session", 1, "admin", " test-owner ");
    private const string Id = "11111111-1111-1111-1111-111111111111";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    private static JsonObject Rule() => new()
    {
        ["semantic_type"] = "semantic.audit.policy.changed", ["domain_id"] = 1L,
        ["scope_kind"] = "subject_sid", ["scope_value"] = "S-1-5-21-100000001-200000002-300000003-1001",
        ["reason"] = "Approved maintenance", ["expires_at"] = Now.AddDays(1).ToString("O")
    };

    [Theory]
    [InlineData("{}", "unknown")]
    [InlineData("{\"subject_sid\":\"S-1-5-18\"}", "system_account")]
    [InlineData("{\"subject_sid\":\"S-1-5-21-100000001-200000002-300000003-1001\",\"machine_account\":true}", "machine_account")]
    [InlineData("{\"machine_account\":true,\"gpo_correlated\":true}", "known_gpo_refresh")]
    [InlineData("{\"logon_type\":\"10\",\"privileged_session\":true}", "interactive_admin")]
    [InlineData("{\"logon_type\":\"10\"}", "unknown")]
    [InlineData("{\"process_name\":\"gpupdate.exe\"}", "unknown")]
    [InlineData("{\"gpo_correlated\":true,\"process_name\":\"gpupdate.exe\"}", "known_gpo_refresh")]
    [InlineData("{\"gpo_correlated\":true,\"process_name\":\"auditpol.exe\"}", "unknown")]
    [InlineData("{\"subject_sid\":\"S-1-5-18\",\"mixed\":true}", "unknown")]
    [InlineData("{\"subject_sid\":\"S-1-5-18\",\"has_audit_change\":false}", "unknown")]
    public void Classification_is_only_a_hint(string json, string bucket)
    {
        var facts = O(json); var original = facts.DeepClone();
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["bucket"] = bucket, ["kind"] = "hint", ["verdict"] = false }, ProblemPresentation.ClassifyAuditChange(facts)));
        Assert.True(JsonNode.DeepEquals(original, facts));
    }

    [Theory]
    [InlineData("reason", "\" \"")]
    [InlineData("domain_id", "0")]
    [InlineData("scope_value", "\"*\"")]
    [InlineData("semantic_type", "\"*\"")]
    [InlineData("scope_kind", "\"all\"")]
    [InlineData("expires_at", "\"2026-10-06T00:00:00Z\"")]
    [InlineData("expires_at", "\"2027-01-04T00:00:01Z\"")]
    [InlineData("expires_at", "\"2026-10-07T00:00:00\"")]
    public void Suppression_requires_exact_scope_reason_and_bounded_expiry(string key, string json)
    {
        var body = Rule(); body[key] = JsonNode.Parse(json);
        Assert.Equal("invalid_suppression", Assert.Throws<SemanticInputException>(() => SemanticGovernance.ValidateSuppression(body, Now)).Message);
    }
    [Fact]
    public void Suppression_accepts_known_bucket_at_exact_maximum_but_rejects_unknown_bucket()
    {
        var body = Rule(); body["scope_kind"] = "bucket"; body["scope_value"] = "machine_account";
        body["expires_at"] = Now.AddDays(90).ToString("O");
        Assert.Equal("machine_account", SemanticGovernance.ValidateSuppression(body, Now).Text("scope_value"));
        body["scope_value"] = "anything";
        Assert.Equal("invalid_suppression", Assert.Throws<SemanticInputException>(() => SemanticGovernance.ValidateSuppression(body, Now)).Message);
    }

    private sealed class Database : ISemanticDatabase, ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Calls = [];
        internal Func<string, JsonArray> Reply = _ => new();
        internal int Opened, Committed;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opened++; return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values)); return Task.FromResult(Reply(sql));
        }
        public Task CommitAsync(CancellationToken ct) { Committed++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private static JsonArray Policy(string state) => new(new JsonObject
    {
        ["policy_id"] = "test-policy", ["policy_version"] = 2, ["source_kind"] = "canonical_action",
        ["definition_json"] = new JsonObject(), ["definition_sha256"] = "fixture", ["lifecycle_status"] = state
    });
    private static JsonObject Admission() => new()
    {
        ["action"] = "policy_admission", ["policy_id"] = "test-policy", ["policy_version"] = 2,
        ["enabled"] = true, ["reason"] = " Test admission "
    };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Revocation_only_changes_active_unexpired_suppressions_and_audits_once(bool active)
    {
        var db = new Database { Reply = sql => sql.StartsWith("with changed as(update semantic_suppressions") && active ? new(new JsonObject { ["id"] = 1 }) : new() };
        var body = new JsonObject { ["action"] = "revoke_suppression", ["id"] = 1L, ["reason"] = " Test revocation " };
        var service = new SemanticGovernance(db);
        if (active) Assert.Equal("ok", (await service.ChangeAsync(body, Owner, "192.0.2.1", Ct)).Text("status"));
        else Assert.Equal("suppression_not_active", (await Assert.ThrowsAsync<SemanticInputException>(() => service.ChangeAsync(body, Owner, "192.0.2.1", Ct))).Message);
        var update = Assert.Single(db.Calls, x => x.Sql.StartsWith("with changed as(update"));
        Assert.Contains("kind='suppression'", update.Sql); Assert.Contains("state='active'", update.Sql);
        Assert.Contains("expires_at>clock_timestamp()", update.Sql); Assert.Equal(new object?[] { "test-owner", 1L }, update.Values);
        var audits = db.Calls.Where(x => x.Sql.StartsWith("with audit as")).ToArray();
        if (active)
        {
            var audit = Assert.Single(audits); Assert.Equal("semantic_suppression_revoke", audit.Values[2]); Assert.Equal("1", audit.Values[3]);
            Assert.True(JsonNode.DeepEquals(O("""{"actor":"test-owner","reason":"Test revocation"}"""), (JsonObject)audit.Values[5]!));
        }
        else Assert.Empty(audits);
        Assert.Equal(active ? 1 : 0, db.Committed);
    }

    [Theory]
    [InlineData("draft")]
    [InlineData("validated")]
    [InlineData("test")]
    [InlineData("disabled")]
    [InlineData("deprecated")]
    public async Task Admission_does_not_bypass_policy_readiness(string state)
    {
        var db = new Database { Reply = sql => sql.StartsWith("select policy_id,policy_version,source_kind") ? Policy(state) : new() };
        Assert.Equal("policy_not_ready", (await Assert.ThrowsAsync<SemanticInputException>(() => new SemanticGovernance(db).ChangeAsync(Admission(), Owner, "192.0.2.1", Ct))).Message);
        Assert.DoesNotContain(db.Calls, x => x.Sql.Contains("insert into semantic_policy_admission") || x.Sql.StartsWith("with audit as"));
        Assert.Equal(0, db.Committed);
    }
    [Theory] [InlineData("shadow")] [InlineData("enabled")]
    public async Task Admission_is_versioned_and_audited_under_policy_lock(string state)
    {
        var db = new Database { Reply = sql => sql.StartsWith("select policy_id,policy_version,source_kind") ? Policy(state) : new() };
        await new SemanticGovernance(db).ChangeAsync(Admission(), Owner, "192.0.2.1", Ct);
        var locked = db.Calls.FindIndex(x => x.Sql.EndsWith("for update"));
        var insert = Assert.Single(db.Calls, x => x.Sql.Contains("insert into semantic_policy_admission"));
        Assert.Equal(new object?[] { "test-policy", 2, true, "test-owner" }, insert.Values);
        Assert.InRange(locked, 0, db.Calls.IndexOf(insert) - 1);
        var audit = Assert.Single(db.Calls, x => x.Sql.StartsWith("with audit as"));
        Assert.Equal("semantic_policy_admission", audit.Values[2]); Assert.Equal("test-policy:2", audit.Values[3]);
        Assert.True(JsonNode.DeepEquals(O("""{"enabled":true,"actor":"test-owner","reason":"Test admission"}"""), (JsonObject)audit.Values[5]!));
        Assert.Equal(1, db.Committed);
    }
    [Theory] [InlineData("policy_admission")] [InlineData("revoke_suppression")]
    public async Task Human_decisions_require_reason_before_any_database_access(string action)
    {
        var db = new Database(); var body = Admission(); body["action"] = action; body.Remove("reason");
        Assert.Equal("reason_required", (await Assert.ThrowsAsync<SemanticInputException>(() => new SemanticGovernance(db).ChangeAsync(body, Owner, "192.0.2.1", Ct))).Message);
        Assert.Equal(0, db.Opened); Assert.Empty(db.Calls);
    }
    [Fact]
    public async Task Controls_list_separates_suppressions_from_risk_decisions_and_projects_only_public_policy_metadata()
    {
        var db = new Database(); var result = await new SemanticGovernance(db).ListAsync(Ct);
        Assert.Equal(200, result.Number("limit")); Assert.Equal(3, db.Calls.Count);
        string policies = db.Calls[0].Sql;
        Assert.Contains("definition_json->>'title' as title", policies); Assert.Contains("created_at::text as version_created_at", policies);
        Assert.DoesNotContain("updated_at", policies); Assert.DoesNotContain("definition_sha256", policies);
        Assert.Contains("kind='suppression'", db.Calls[1].Sql);
        Assert.Equal(0, db.Committed);
    }

    [Theory] [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)] [InlineData(true, true)]
    public void Suppression_filter_applies_to_both_population_and_summary(bool showSuppressed, bool groupQueue)
    {
        var query = new FindingQuery(null, null, null, null, null, null, null, null, 30, showSuppressed) { GroupQueue = groupQueue };
        var (page, summary, _) = ProblemRepository.FindingsQueries(query);
        string filter = "not (" + ProblemRepository.Suppressed + ")";
        foreach (string sql in new[] { page, summary })
            Assert.Equal(!showSuppressed, sql.Contains(filter, StringComparison.Ordinal));
    }
    [Fact]
    public void Queue_projects_classification_without_metadata_or_lifecycle_changes()
    {
        var hint = O("""{"bucket":"machine_account","kind":"hint","verdict":false,"event_db_id":900001,"unknown_field":"fixture-marker"}""");
        var finding = new JsonObject { ["id"] = 1, ["status"] = "confirmed", ["review_hint"] = hint, ["suppressed"] = true };
        var original = finding.DeepClone();
        var row = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), "ru");
        Assert.Equal("Учётная запись компьютера", row.Text("review_hint_text")); Assert.Equal("confirmed", row.Text("status"));
        Assert.True(row.Flag("suppressed")); Assert.True(JsonNode.DeepEquals(O("""{"bucket":"machine_account"}"""), row["review_hint"]));
        Assert.True(JsonNode.DeepEquals(original, finding));
    }
    [Fact]
    public async Task Runtime_applies_admission_before_enqueueing_and_claiming()
    {
        var db = new Database { Reply = sql => sql.StartsWith("select action_kind as selector") ? new(new JsonObject { ["selector"] = "audit.policy.changed" }) : new() };
        Assert.Equal(0, await SemanticProduction.EnqueueRiskSource(db, "canonical_action", Id, Ct));
        Assert.Equal(2, db.Calls.Count); Assert.Contains("semantic_policy_mode_v160", db.Calls[1].Sql);
        Assert.Contains("a.enabled is true", db.Calls[1].Sql);
        Assert.Contains("semantic_policy_mode_v160", SemanticProductionSql.RiskClaim0);
        Assert.Contains("admission.enabled is true", SemanticProductionSql.RiskClaim0);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Managed_policies_allow_both_extended_and_empty_enabled_sets(bool empty)
    {
        var guard = O("""
            {"facts_schema_ready":true,"processor_version_gate_schema_ready":true,"facts_capability_ready":true,
             "investigation_rule_lock_schema_ready":true,"investigation_rule_lock_capability_ready":true,
             "schema_ready":true,"test_policy_exists":false,"admission_configured":true}
            """);
        guard["enabled_policies"] = empty ? new JsonArray() : new JsonArray("l1-audit-policy-changed:2", "test-policy:3");
        guard["unmanaged_enabled_policies"] = empty ? new JsonArray() : new JsonArray("l1-audit-policy-changed:2");
        var db = new Database { Reply = _ => new JsonArray(guard.DeepClone()) };
        await SemanticProduction.GuardAsync(db, "findings-v1", Ct);
        Assert.Equal(2, db.Calls.Count); Assert.Equal(0, db.Committed);
        if (empty)
        {
            guard["admission_configured"] = false;
            var error = await Assert.ThrowsAsync<WorkerFailure>(() => SemanticProduction.GuardAsync(db, "findings-v1", Ct));
            Assert.Contains("enabled_policy_set_differs", error.Message);
        }
    }
    [Fact]
    public async Task Publication_rechecks_admission_under_policy_lock_before_any_write()
    {
        var db = new Database();
        Assert.Equal("finding_requires_enabled_observed_result", (await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.PublishFinding(db, null!, new() { ["scenario_id"] = Id }, Guid.Parse(Id), Ct))).Message);
        var query = Assert.Single(db.Calls); Assert.Contains("semantic_policy_mode_v160", query.Sql); Assert.Contains("for share of policy", query.Sql);
        Assert.Equal(0, db.Committed);
    }
    [Fact]
    public void Heartbeat_reports_observed_policies_and_never_invents_enabled_policy()
    {
        Assert.False(SemanticProduction.HeartbeatDetails("findings-v1").ContainsKey("enabled_policy"));
        var result = O("""{"enabled_policies":["test-policy:2","test-policy:3"]}""");
        var details = SemanticProduction.HeartbeatDetails("findings-v1", result);
        Assert.True(JsonNode.DeepEquals(result["enabled_policies"], details["enabled_policies"])); Assert.False(details.ContainsKey("enabled_policy"));
        result["enabled_policies"] = new JsonArray("test-policy:2");
        Assert.Equal(2, details["enabled_policies"]!.AsArray().Count);
        Assert.Equal("test-policy:2", SemanticProduction.HeartbeatDetails("findings-v1", result).Text("enabled_policy"));
        Assert.False(SemanticProduction.HeartbeatDetails("facts-v1", result).ContainsKey("enabled_policy"));
    }
}
