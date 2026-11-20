using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticDispatchPartitionRecoveryTests
{
    private const string Boundary = "2026-09-20T10:00:00+00:00";
    private static JsonObject Relation(long trigger, long first, string key) => new()
    {
        ["trigger_source_event_id"] = trigger, ["source_event_ids"] = new JsonArray(first, trigger), ["contribution_key"] = "dispatch:" + key
    };
    private static JsonArray ExpectedRelations() => new(
        Relation(6487797, 6442170, "2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"),
        Relation(6486534, 6436767, "9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"),
        Relation(6943209, 6923513, "5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"),
        Relation(6943209, 6874055, "b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb"));
    private static List<JsonObject> Rows()
    {
        (string Id, long Trigger, string Suffix, char Hash)[] jobs = [
            ("e24572a7-159d-517c-a284-a0eff96ac007", 6487797, "6295", 'a'),
            ("75280b7d-4573-5bc9-9e0e-c1d3f6e897e3", 6486534, "6682", 'b'),
            ("10eac730-5285-5740-b605-577d3ef9f4c2", 6943209, "7291", 'c')];
        return jobs.Select(job => new JsonObject
        {
            ["job_id"] = job.Id, ["dispatch_status"] = "quarantined", ["source_event_id"] = job.Trigger,
            ["partition_key"] = "sid:S-1-5-21-100000001-200000002-300000003-" + job.Suffix,
            ["trigger_identity"] = job.Suffix, ["normalized_at"] = Boundary, ["source_hash"] = new string(job.Hash, 64),
            ["semantic_contract_version"] = 1, ["normalizer_id"] = "windows.named-eventdata", ["normalizer_version"] = "1.4+identity-1.0",
            ["rule_id"] = "investigation.account.unlock.after-lock", ["rule_version"] = 2,
            ["definition_sha256"] = "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e",
            ["last_error_code"] = "UniqueViolation",
            ["last_error_detail"] = "duplicate key value violates unique constraint \"semantic_correlation_candidate__candidate_id_evidence_order_key\"",
            ["lease_token"] = null, ["lease_until"] = null, ["heartbeat_at"] = null, ["attempt_count"] = 5, ["max_attempts"] = 5,
            ["accepted_relations"] = new JsonArray(), ["blocking_relations"] = new JsonArray(),
            ["repairable_relations"] = SemanticJson.Array(ExpectedRelations().Where(x => x.Number("trigger_source_event_id") == job.Trigger))
        }).ToList();
    }
    private static JsonObject Plan(IReadOnlyList<JsonObject>? rows = null) => SemanticDispatchPartitionRecovery.BuildSealedPlan(rows ?? Rows(), Boundary);
    private static JsonObject Apply(SemanticDispatchPartitionRecoveryController controller, JsonObject plan) =>
        controller.Apply(plan.Text("plan_digest")!, plan.Text("confirmation")!, plan);
    private static void Complete(JsonObject row)
    {
        row["dispatch_status"] = "completed";
        row["accepted_relations"] = SemanticJson.Array(ExpectedRelations().Where(x => x.Number("trigger_source_event_id") == row.Number("source_event_id")));
        row["repairable_relations"] = new JsonArray();
    }
    private static JsonObject Verified() => new()
    {
        ["completed"] = true, ["relations_exact"] = true, ["scenario_evidence_added"] = 0, ["unrelated_status_unchanged"] = true
    };

    [Fact]
    public void Exact_three_plan_is_canonical_sealed_secret_free_and_matches_python_digest()
    {
        var first = Plan(); var rows = Rows(); rows.Reverse();
        Assert.True(JsonNode.DeepEquals(first, Plan(rows)));
        Assert.Equal(3, first.Number("job_count"));
        // Frozen Python output for the same vectors with the approved synthetic SID prefix.
        Assert.Equal("f1a9ee6f348117687c1978093d1c5f89918df24a003e58eee42769f1995e646f", first.Text("plan_digest"));
        Assert.Equal("REPAIR-SEMANTIC-DISPATCH-PARTITION:" + first.Text("plan_digest"), first.Text("confirmation"));
        Assert.DoesNotContain("last_error_detail", first.ToJsonString());
        Assert.DoesNotContain("password", first.ToJsonString().ToLowerInvariant());
        Assert.True(JsonNode.DeepEquals(ExpectedRelations(), first["expected_relations"]));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"semantic_contract_version":1,"normalizer_id":"windows.named-eventdata","normalizer_version":"1.4+identity-1.0"}"""), first["jobs"]![0]!["normalized_contract"]));
    }

    [Theory]
    [InlineData("job_id", "\"00000000-0000-0000-0000-000000000000\"")]
    [InlineData("dispatch_status", "\"failed\"")]
    [InlineData("last_error_code", "\"IntegrityError\"")]
    [InlineData("source_hash", "\"not-a-hash\"")]
    [InlineData("rule_version", "3")]
    [InlineData("normalizer_version", "\"1.5-drifted\"")]
    [InlineData("source_event_id", "1")]
    [InlineData("rule_id", "\"other\"")]
    [InlineData("definition_sha256", "\"bad\"")]
    [InlineData("partition_key", "\"sid:other\"")]
    [InlineData("trigger_identity", "\"other\"")]
    [InlineData("semantic_contract_version", "2")]
    [InlineData("normalizer_id", "\"other\"")]
    public void Plan_fails_closed_for_job_contract_drift(string field, string value)
    {
        var rows = Rows(); rows[0][field] = JsonNode.Parse(value);
        Assert.Throws<InvalidOperationException>(() => Plan(rows));
    }

    [Fact]
    public void Plan_rejects_wrong_count_duplicate_identity_and_constraint()
    {
        Assert.Throws<InvalidOperationException>(() => Plan(Rows().Take(2).ToList()));
        var rows = Rows(); rows[1] = (JsonObject)rows[0].DeepClone();
        Assert.Throws<InvalidOperationException>(() => Plan(rows));
        rows = Rows(); rows[0]["last_error_detail"] = "violates unique constraint \"other\"";
        Assert.Throws<InvalidOperationException>(() => Plan(rows));
    }

    [Fact]
    public void Plan_accepts_exact_queued_recovery_state_and_binds_jobs()
    {
        var rows = Rows(); foreach (var row in rows) row["dispatch_status"] = "queued";
        var plan = Plan(rows);
        Assert.Equal(rows.Select(x => x.Text("job_id")).Order(StringComparer.Ordinal), plan["jobs"]!.AsArray().Select(x => x.Text("job_id")));
        Assert.Equal(Plan().Text("plan_digest"), plan.Text("plan_digest"));
    }

    [Fact]
    public void Plan_accepts_only_expired_recovery_lease_for_crash_resume()
    {
        var rows = Rows();
        foreach (var row in rows)
        {
            row["dispatch_status"] = "leased"; row["lease_token"] = "recovery-lease";
            row["lease_until"] = "2026-09-21T03:00:00+00:00"; row["lease_expired"] = true;
            row["heartbeat_at"] = "2026-09-21T02:59:00+00:00";
        }
        Assert.Equal(3, Plan(rows).Number("job_count"));
        rows[0]["lease_expired"] = false;
        Assert.Contains("leased", Assert.Throws<InvalidOperationException>(() => Plan(rows)).Message);
    }

    [Fact]
    public void Plan_accepts_exact_controller_completion_constraint_failure()
    {
        var rows = Rows();
        foreach (var row in rows)
        {
            row["heartbeat_at"] = "2026-09-21T04:04:26+00:00"; row["last_error_code"] = "CheckViolation";
            row["last_error_detail"] = "violates check constraint \"semantic_correlation_dispatch_terminal\"";
        }
        Assert.Equal(3, Plan(rows).Number("job_count"));
        rows[0]["last_error_detail"] = "violates check constraint \"other\"";
        Assert.Contains("contract", Assert.Throws<InvalidOperationException>(() => Plan(rows)).Message);
    }

    [Theory]
    [InlineData("lease_token", "\"still-leased\"")]
    [InlineData("lease_until", "\"2026-09-21T00:00:00+00:00\"")]
    [InlineData("heartbeat_at", "\"2026-09-21T00:00:00+00:00\"")]
    [InlineData("attempt_count", "4")]
    [InlineData("max_attempts", "7")]
    [InlineData("accepted_relations", "[{\"unexpected\":true}]")]
    public void Plan_rejects_queued_state_drift(string field, string value)
    {
        var rows = Rows(); foreach (var row in rows) row["dispatch_status"] = "queued";
        rows[0][field] = JsonNode.Parse(value);
        Assert.Throws<InvalidOperationException>(() => Plan(rows));
    }

    [Theory]
    [InlineData("repairable_relations", "[]")]
    [InlineData("blocking_relations", "[{\"unexpected\":true}]")]
    [InlineData("accepted_relations", "null")]
    [InlineData("repairable_relations", "[1]")]
    public void Plan_rejects_missing_legacy_or_blocking_or_malformed_relations(string field, string value)
    {
        var rows = Rows(); rows[0][field] = JsonNode.Parse(value);
        Assert.Contains("relation", Assert.Throws<InvalidOperationException>(() => Plan(rows)).Message);
    }

    [Fact]
    public void Apply_revalidates_everything_before_requeue_dispatch_and_audit()
    {
        var plan = Plan(); var changed = Rows(); changed[1]["source_hash"] = new string('d', 64);
        var calls = new List<string>();
        var controller = new SemanticDispatchPartitionRecoveryController(() => changed, () => false, () => true)
        {
            Requeue = _ => calls.Add("requeue"), Dispatch = _ => { calls.Add("dispatch"); return new(); },
            Audit = _ => calls.Add("audit")
        };
        Assert.Contains("changed", Assert.Throws<InvalidOperationException>(() => Apply(controller, plan)).Message);
        Assert.Empty(calls);
    }

    [Theory]
    [InlineData(2, 1)]
    [InlineData(2, 0)]
    [InlineData(3, 1)]
    public void Apply_passes_only_plan_ids_boundary_and_rule_and_failure_is_not_success(int completed, int failed)
    {
        var plan = Plan(); JsonObject? observed = null;
        var controller = new SemanticDispatchPartitionRecoveryController(Rows, () => false, () => true)
        {
            Requeue = _ => { }, Dispatch = scope => { observed = scope; return new() { ["completed"] = completed, ["failed"] = failed, ["relations"] = 3 }; },
            Verify = _ => throw new Exception("failed processing must not verify success"),
            Audit = _ => throw new Exception("failed processing must not audit success")
        };
        Assert.Contains("failed", Assert.Throws<InvalidOperationException>(() => Apply(controller, plan)).Message);
        Assert.Equal(plan["jobs"]!.AsArray().Select(x => x.Text("job_id")), observed!["allowed_job_ids"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal(Boundary, observed.Text("normalized_before"));
        Assert.True(JsonNode.DeepEquals(new JsonArray("investigation.account.unlock.after-lock", 2, "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e"), observed["allowed_rule_identity"]));
        Assert.Equal(3, observed.Count);
    }

    [Theory]
    [InlineData(true, true, "live")]
    [InlineData(false, false, "busy")]
    public void Apply_refuses_competing_worker_or_lock_before_snapshot(bool live, bool locks, string error)
    {
        var controller = new SemanticDispatchPartitionRecoveryController(() => throw new Exception("snapshot must not run"), () => live, () => locks);
        Assert.Contains(error, Assert.Throws<InvalidOperationException>(() => Apply(controller, Plan())).Message);
    }

    [Fact]
    public void Completed_acceptance_is_noop_and_audited()
    {
        var rows = Rows(); foreach (var row in rows) Complete(row);
        JsonObject? audited = null;
        var controller = new SemanticDispatchPartitionRecoveryController(() => rows, () => false, () => true) { Audit = x => audited = x };
        var result = Apply(controller, Plan());
        Assert.Equal("already_complete", result.Text("status")); Assert.False(result.Flag("production_changed"));
        Assert.Same(result, audited);
    }

    [Theory]
    [InlineData("quarantined")]
    [InlineData("queued")]
    public void Apply_resumes_only_remaining_jobs_after_exact_completed_readback(string status)
    {
        var rows = Rows(); foreach (var row in rows) row["dispatch_status"] = status;
        var plan = Plan(rows); Complete(rows[0]);
        JsonObject? requeued = null, dispatched = null, verified = null, audited = null;
        var controller = new SemanticDispatchPartitionRecoveryController(() => rows, () => false, () => true)
        {
            Requeue = x => requeued = x,
            Dispatch = x => { dispatched = x; return new() { ["completed"] = 2, ["failed"] = 0, ["relations"] = 3 }; },
            Verify = x => { verified = x; return Verified(); }, Audit = x => audited = x
        };
        var result = Apply(controller, plan);
        Assert.Equal("complete", result.Text("status")); Assert.True(result.Flag("production_changed"));
        var remaining = plan["jobs"]!.AsArray().Where(x => x.Text("job_id") != rows[0].Text("job_id")).Select(x => x.Text("job_id")).ToArray();
        Assert.Equal(remaining, dispatched!["allowed_job_ids"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal(remaining, requeued!["jobs"]!.AsArray().Select(x => x.Text("job_id")));
        Assert.True(JsonNode.DeepEquals(plan, verified)); Assert.Same(result, audited);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Apply_rejects_completed_job_without_exact_relation_readback(bool extra)
    {
        var rows = Rows(); var plan = Plan(rows);
        if (extra)
        {
            Complete(rows[0]);
            rows[0]["accepted_relations"]!.AsArray().Add(Relation(6487797, 1, new string('0', 64)));
        }
        else rows[0]["dispatch_status"] = "completed";
        var controller = new SemanticDispatchPartitionRecoveryController(() => rows, () => false, () => true);
        Assert.Contains("completed", Assert.Throws<InvalidOperationException>(() => Apply(controller, plan)).Message);
    }

    [Fact]
    public void Apply_revalidates_frozen_baseline_before_any_requeue()
    {
        var calls = new List<string>();
        var controller = new SemanticDispatchPartitionRecoveryController(Rows, () => false, () => true)
        {
            Preflight = _ => false, Requeue = _ => calls.Add("requeue"),
            Dispatch = _ => { calls.Add("dispatch"); return new(); }
        };
        Assert.Contains("preflight", Assert.Throws<InvalidOperationException>(() => Apply(controller, Plan())).Message);
        Assert.Empty(calls);
    }

    [Theory]
    [InlineData("completed", "false")]
    [InlineData("relations_exact", "false")]
    [InlineData("scenario_evidence_added", "1")]
    [InlineData("scenario_evidence_added", "null")]
    [InlineData("scenario_evidence_added", "\"invalid\"")]
    [InlineData("scenario_evidence_added", "\"0\"")]
    [InlineData("unrelated_status_unchanged", "false")]
    public void Apply_requires_full_acceptance_before_success_audit(string field, string value)
    {
        var verification = Verified(); verification[field] = JsonNode.Parse(value);
        var controller = new SemanticDispatchPartitionRecoveryController(Rows, () => false, () => true)
        {
            Requeue = _ => { }, Dispatch = _ => new() { ["completed"] = 3, ["failed"] = 0, ["relations"] = 4 },
            Verify = _ => verification, Audit = _ => throw new Exception("verification failure must not audit success")
        };
        Assert.Contains("verification failed", Assert.Throws<InvalidOperationException>(() => Apply(controller, Plan())).Message);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Apply_requires_exact_confirmation_before_worker_or_locks(bool changeDigest)
    {
        var plan = Plan();
        var controller = new SemanticDispatchPartitionRecoveryController(Rows, () => throw new Exception("worker must not be checked"), () => throw new Exception("locks must not run"));
        Assert.Contains("confirmation", Assert.Throws<InvalidOperationException>(() => controller.Apply(
            changeDigest ? "bad" : plan.Text("plan_digest")!, changeDigest ? plan.Text("confirmation")! : "bad", plan)).Message);
    }

    [Fact]
    public void Apply_freezes_caller_plan_before_callbacks()
    {
        var plan = Plan(); var original = (JsonObject)plan.DeepClone();
        var controller = new SemanticDispatchPartitionRecoveryController(Rows, () => { plan["normalized_before"] = "changed"; plan["jobs"] = new JsonArray(); return false; }, () => true)
        {
            Requeue = x => Assert.True(JsonNode.DeepEquals(original, x)),
            Dispatch = x => { Assert.Equal(Boundary, x.Text("normalized_before")); return new() { ["completed"] = 3, ["failed"] = 0, ["relations"] = 4 }; },
            Verify = _ => Verified()
        };
        Assert.Equal("complete", Apply(controller, plan).Text("status"));
    }
}
