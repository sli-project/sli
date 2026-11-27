using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;
using Sli.Server.Semantic.Password;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Agents.FileAudit;

namespace Sli.Server.Tests.Semantic;

public sealed class RemainingDetectorTests
{
    public static IEnumerable<object[]> Vectors()
    {
        using var stream = typeof(RemainingDetectorTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.remaining-reference.json")!;
        var rows = JsonNode.Parse(stream)!.AsArray().Select(v => new object[] { v!.Text("kind")!, v.Text("case")!, v!.ToJsonString() }).ToList();
        using var accounts = typeof(RemainingDetectorTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.detection-reference.json")!;
        foreach (var vector in JsonNode.Parse(accounts)!.AsArray())
        {
            var copy = vector!.DeepClone().AsObject(); string kind = copy.Flag("watch") ? "account-watch" : "account-decoy";
            copy["kind"] = kind; copy["rule"] = new JsonObject { ["scope"] = copy["scope"]!.DeepClone(), ["evaluation_mode"] = "enabled" };
            rows.Add([kind,copy.Text("case")!,copy.ToJsonString()]);
        }
        return rows;
    }
    internal sealed class NativeSession(JsonObject vector, DetectorRule rule) : ISemanticSession
    {
        public JsonArray Signals = []; public JsonObject? Checkpoint; public bool DenyEvidence, NoPolicy; public int Checks, Jobs, Members, Advances;
        public JsonObject? AclPortion, AclBundle, AclDefinition; public Exception? RansomFailure; public List<string> Statements = [];
        private JsonObject? stored; private Guid job;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Statements.Add(sql);
            JsonArray One(string key, JsonNode? value) => new(new JsonObject { [key] = value?.DeepClone() });
            if (sql.StartsWith("savepoint ") || sql.StartsWith("release savepoint ") || sql.StartsWith("rollback to savepoint ")) return Task.FromResult(new JsonArray());
            if (sql.Contains("to_regprocedure('public.complete_account_batch460")) return Task.FromResult(One("compact",JsonValue.Create(false)));
            if (sql.Contains("ensure_default_qw_policy")) return Task.FromResult(One("admitted",JsonValue.Create(true)));
            if (sql.Contains("read_pending_file_acl_portions")) return Task.FromResult(One("portions",new JsonArray(AclPortion!.DeepClone())));
            if (sql.Contains("read_file_acl_portion_v265")) return Task.FromResult(One("portion",AclPortion));
            if (sql.Contains("read_file_acl_result_by_id")) return Task.FromResult(One("bundle",AclBundle));
            if (sql.Contains("advance_file_acl_checkpoint")) { Advances++; return Task.FromResult(One("advanced",JsonValue.Create(true))); }
            if (sql.Contains("resolve_finding_evidence_ref")) return Task.FromResult(One("verified", JsonValue.Create(!DenyEvidence)));
            if (sql.Contains("read_file_decoy_observations")) return Task.FromResult(new JsonArray(vector["row"]!.DeepClone()));
            if (sql.Contains("read_account_decoy_events") || sql.Contains("read_account_watch_events")) return Task.FromResult(new JsonArray(vector["row"]!.DeepClone()));
            if (sql.Contains("read_file_ransom_results")) { if (RansomFailure is not null) throw RansomFailure; return Task.FromResult(new JsonArray(vector["row"]!.DeepClone())); }
            if (sql.StartsWith("select 1 from semantic_file_ransom_members")) return Task.FromResult(vector.Text("case") == "replay" ? new JsonArray(new JsonObject { ["exists"] = true }) : new JsonArray());
            if (sql.StartsWith("select * from semantic_file_ransom_episodes")) return Task.FromResult(new JsonArray());
            if (sql.StartsWith("insert into semantic_file_ransom_episodes")) return Task.FromResult(new JsonArray());
            if (sql.StartsWith("insert into semantic_file_ransom_members")) { Members++; return Task.FromResult(new JsonArray()); }
            if (sql.StartsWith("insert into semantic_file_decoy_checks")) { Checks++; return Task.FromResult(new JsonArray()); }
            if (sql.StartsWith("insert into semantic_account_decoy_checks") || sql.StartsWith("insert into semantic_account_watch_checks")) { Checks++; return Task.FromResult(new JsonArray()); }
            if (sql.Contains("select checkpoint_json")) return Task.FromResult(One("checkpoint_json",new JsonObject()));
            if (sql.Contains("nps_threshold_watermark")) return Task.FromResult(One("watermark",vector["now"]));
            if (sql.Contains("read_nps_threshold_events")) return Task.FromResult(vector["rows"]!.DeepClone().AsArray());
            if (sql.Contains("nps_threshold_window_quality")) return Task.FromResult(One("quality",vector["quality"]));
            if (sql.StartsWith("update semantic_nps_threshold_state")) { Checkpoint = ((JsonObject)values[0]!).DeepClone().AsObject(); return Task.FromResult(new JsonArray()); }
            if (sql.StartsWith("insert into semantic_qw_signals")) { stored = ((JsonObject)values[2]!).DeepClone().AsObject(); Signals.Add(stored.DeepClone()); return Task.FromResult(new JsonArray()); }
            if (sql.StartsWith("select document_json from semantic_qw_signals")) return Task.FromResult(One("document_json",stored));
            if (sql.StartsWith("select document_json->>")) return Task.FromResult(new JsonArray(new JsonObject { ["selector"] = stored!["rule_id"]!.DeepClone(), ["evaluation_mode"] = rule.Mode, ["document_json"] = stored.DeepClone() }));
            if (sql.Contains("from semantic_risk_policy_subscriptions"))
            {
                var definition = AclDefinition?.DeepClone().AsObject() ?? rule.Definition(); return Task.FromResult(NoPolicy ? new JsonArray() : new JsonArray(new JsonObject { ["policy_id"] = "synthetic-policy", ["policy_version"] = rule.Revision, ["source_kind"] = "qw_signal", ["effective_mode"] = rule.Mode, ["definition_json"] = definition, ["definition_sha256"] = SemanticJson.Hash(definition) }));
            }
            if (sql.StartsWith("insert into semantic_risk_evaluation_jobs")) { job = (Guid)values[0]!; Jobs++; return Task.FromResult(new JsonArray()); }
            if (sql.StartsWith("select job_id from semantic_risk_evaluation_jobs")) return Task.FromResult(One("job_id",JsonValue.Create(job.ToString())));
            if (sql.Contains("pg_advisory_xact_lock") || sql.StartsWith("insert into semantic_nps_threshold_state")) return Task.FromResult(new JsonArray());
            throw new InvalidOperationException("unexpected_query: " + sql);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Fact] public void Runtime_static_pack_selection_matches_python_last_version_per_id()
    {
        var rules = SemanticProduction.ReadInvestigationRules(); Assert.Equal(5,rules.Count);
        Assert.Equal(1,rules["investigation.account.lockout.preceded-by-failures"].Item1);
        Assert.Equal(2,rules["investigation.account.unlock.after-lock"].Item1);
    }
    [Theory] [InlineData("account-watch")] [InlineData("account-decoy")] [InlineData("file-decoy")] [InlineData("file-ransom")] [InlineData("nps-threshold")]
    public async Task Manual_commands_reject_missing_rule_file_with_nonzero_exit(string kind)
    {
        Assert.Equal(1,await DetectorCommand.RunAsync(kind,["--rule-file",Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N")+".json")]));
    }
    private static (JsonObject Resource, NativeSession Session) AclFixture()
    {
        var resource = Scope("sli.file-audit"); resource.Remove("source_generation"); resource["agent_id"] = resource["installation_id"]!.DeepClone(); resource["collection_scope_id"] = "root";
        var config = JsonNode.Parse("""{"source_kind":"server","roots":[{"collection_scope_id":"root","path":"C:\\share","important":false}],"service_account_exclusions":[]}""")!.AsObject();
        var snapshot = JsonNode.Parse("""{"agent_id":"11111111-1111-1111-1111-111111111111","source_instance_id":"synthetic","collection_scope_id":"root","snapshot_id":"22222222-2222-2222-2222-222222222222","snapshot_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at_utc":"2026-01-01T00:00:00+00:00","completeness":"complete","share":{"path":"C:\\share","dacl":"D:(A;;FR;;;WD)","complete":true},"local_groups":{"complete":true,"groups":[]},"objects":[{"path":"C:\\share\\file","dacl":"D:(A;;FW;;;WD)"}]}""")!.AsObject();
        var native = FileAuditPermissionRules.Evaluate(snapshot,config,new JsonObject())[0]!.AsObject();
        var members = new JsonArray(new JsonObject { ["result_id"] = native["result_id"]!.DeepClone(), ["result_sha256"] = new string('b',64), ["snapshot_id"] = snapshot["snapshot_id"]!.DeepClone(), ["snapshot_sha256"] = snapshot["snapshot_sha256"]!.DeepClone(), ["command_id"] = "synthetic", ["domain_id"] = 1 });
        string key = SemanticProduction.FileAclResourceKey(resource); var definition = DefaultDetectionDefinitions.Read()["qw.file-acl-broad-write"]!.DeepClone().AsObject(); definition["source_selector"]!["execution"]!["resource"] = resource.DeepClone();
        var scope = Scope("sli.file-audit"); scope["source_generation"] = "audit-command:synthetic"; scope["collection_scope_id"] = "root";
        var refs = new JsonArray(new JsonObject { ["scope"] = scope, ["storage_kind"] = "file_audit_snapshot", ["native_id"] = snapshot["snapshot_id"]!.DeepClone(), ["sha256"] = snapshot["snapshot_sha256"]!.DeepClone() });
        var now = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var document = SemanticProduction.Signal(definition,key,PasswordJson.Hash(new JsonArray("file-acl-episode.v1",key,"qw.file-acl-broad-write")),now,now,refs,"medium",total:1);
        document["processing_mode"] = "historical_replay"; document["acl_context"] = new JsonObject { ["version"] = "sli.file-acl-context.v1", ["resource"] = resource.DeepClone(), ["resource_key"] = key, ["members"] = members, ["portion_id"] = PasswordJson.Hash(new JsonArray("file-acl-portion.v1",key,members.DeepClone())), ["proof_sha256"] = PasswordJson.Hash(new JsonArray("file-acl-proof.v1",key,members.DeepClone())) };
        var material = document.DeepClone().AsObject(); material.Remove("received_at_utc");
        var rule = DetectorRule.Read("account-decoy",new JsonObject { ["scope"] = Scope("sli.windows.ad-dc"), ["evaluation_mode"] = "enabled" });
        var session = new NativeSession(new JsonObject(),rule) { AclDefinition = definition, AclPortion = new JsonObject { ["document"] = document, ["signal_id"] = PasswordJson.Hash(material), ["portion_id"] = document["acl_context"]!["portion_id"]!.DeepClone() }, AclBundle = new JsonObject { ["status"] = "verified", ["result"] = native.DeepClone(), ["config"] = config, ["snapshot"] = snapshot } };
        return (resource,session);
    }
    [Fact] public async Task Acl_native_recomputation_admits_job_before_checkpoint()
    {
        var (resource,session) = AclFixture(); var result = await SemanticProduction.RunFileAclResource(session,resource,TestContext.Current.CancellationToken);
        Assert.Equal(1,result.Number("jobs")); Assert.Equal(1,session.Advances); Assert.Equal("historical_replay",session.Signals[0].Text("processing_mode"));
        Assert.True(session.Statements.FindIndex(s => s.StartsWith("insert into semantic_risk_evaluation_jobs")) < session.Statements.FindIndex(s => s.Contains("advance_file_acl_checkpoint")));
    }
    [Theory] [InlineData("receipt")] [InlineData("verdict")] [InlineData("policy")] [InlineData("hash")]
    public async Task Acl_denied_or_modified_proof_never_advances_checkpoint(string failure)
    {
        var (resource,session) = AclFixture();
        if (failure == "receipt") session.DenyEvidence = true;
        if (failure == "verdict") session.AclBundle!["status"] = "owner_denied";
        if (failure == "policy") session.NoPolicy = true;
        if (failure == "hash") session.AclPortion!["signal_id"] = new string('0',64);
        await Assert.ThrowsAnyAsync<Exception>(() => SemanticProduction.RunFileAclResource(session,resource,TestContext.Current.CancellationToken)); Assert.Equal(0,session.Advances);
    }
    [Theory] [InlineData("proof_sha256")] [InlineData("resource_key")] [InlineData("portion_id")]
    public void Acl_context_hashes_are_independently_validated(string key)
    {
        var (_,session) = AclFixture(); var document = session.AclPortion!["document"]!.AsObject(); SemanticProduction.ValidateAclDocument(document);
        document["acl_context"]![key] = new string('0',64); Assert.Throws<InvalidDataException>(() => SemanticProduction.ValidateAclDocument(document));
    }
    [Theory] [InlineData("P0001","file_ransom_source_policy_mismatch",1)] [InlineData("42501","file_ransom_source_policy_mismatch",0)] [InlineData("P0001","other",0)]
    public async Task Ransom_failure_rolls_back_only_savepoint_and_preserves_decoy_job(string state, string message, int waiting)
    {
        var json = Vectors().First(v => (string)v[0] == "file-decoy" && (string)v[1] == "read")[2]; var vector = JsonNode.Parse((string)json)!.AsObject(); var rule = DetectorRule.Read("file-decoy",vector["rule"]!.AsObject());
        var session = new NativeSession(vector,rule) { RansomFailure = new Npgsql.PostgresException(message,"ERROR","ERROR",state) };
        var source = new JsonObject { ["scope"] = rule.Scope.DeepClone(), ["agent_id"] = rule.Agent, ["config"] = new JsonObject { ["policy_revision"] = "1" } };
        var decoy = await SemanticProduction.RunDetector(session,rule,SigmaProjection.At(vector,"now"),TestContext.Current.CancellationToken); Assert.Equal(1,decoy.Number("jobs"));
        // A unique root keeps the process-local wait state independent between cases.
        source["scope"]!["collection_scope_id"] = "root-" + state + "-" + message;
        // Exercise the savepoint directly; the preceding durable work stays in the caller transaction.
        var result = await SemanticProduction.ManagedRansom(session,source,DateTimeOffset.Parse("2026-01-01T00:10:00Z"),TestContext.Current.CancellationToken);
        Assert.True(session.Statements.Any(s => s.Contains("read_file_ransom_results")),string.Join("\n",session.Statements));
        Assert.Equal(1,session.Jobs); Assert.Equal(1,session.Checks); Assert.Equal(1,result.Failed); Assert.Equal(waiting,result.Waiting); Assert.Contains("rollback to savepoint default_file_ransom",session.Statements); Assert.Equal("release savepoint default_file_ransom",session.Statements[^1]);
    }
    [Theory] [MemberData(nameof(Vectors))]
    public async Task File_decoy_and_nps_outputs_match_frozen_python(string kind, string name, string json)
    {
        _ = name; var vector = JsonNode.Parse(json)!.AsObject(); var rule = DetectorRule.Read(kind,vector["rule"]!.AsObject()); var session = new NativeSession(vector,rule); var now = SigmaProjection.At(vector,"now");
        if (kind == "nps-threshold") {
            var disabled=await SemanticProduction.RunDetector(session,rule,now,TestContext.Current.CancellationToken);
            Assert.Equal("disabled",disabled.Text("state")); Assert.Equal(0,disabled.Number("jobs"));
            Assert.Empty(session.Statements); Assert.Empty(session.Signals); Assert.Null(session.Checkpoint); return;
        }
        if (kind == "file-decoy")
        {
            var (signals,state) = SemanticProduction.EvaluateFileDecoy(rule.Definition(),rule.Agent!,vector["row"]!,now);
            foreach (var signal in signals) rule.Apply(signal!.AsObject()); Assert.Equal(vector.Text("state"),state); Assert.True(JsonNode.DeepEquals(vector["expected"],signals),signals.ToJsonString());
        }
        var result = await SemanticProduction.RunDetector(session,rule,now,TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(vector["expected"],session.Signals),session.Signals.ToJsonString());
        Assert.Equal(vector["expected"]!.AsArray().Count,result.Number("jobs"));
        if (kind == "file-ransom") Assert.Equal(vector.Text("case") == "replay" ? 0 : 1,session.Members);
    }
    [Theory] [InlineData("account-watch")] [InlineData("account-decoy")] [InlineData("file-decoy")] [InlineData("file-ransom")] [InlineData("nps-threshold")]
    public void Manual_rule_metadata_rejects_wrong_scope_unknown_fields_and_invalid_revision(string kind)
    {
        var scope = Scope(kind.StartsWith("file-") ? "sli.file-audit" : kind == "nps-threshold" ? "sli.vpn-nps" : "sli.windows.ad-dc"); if (kind.StartsWith("file-")) scope["collection_scope_id"] = "root";
        var input = new JsonObject { ["scope"] = scope, ["evaluation_mode"] = "enabled" }; if (kind.StartsWith("file-")) input["agent_id"] = "11111111-1111-1111-1111-111111111111"; if (kind == "file-ransom") input["source_policy_revision"] = "1";
        Assert.Equal("enabled",DetectorRule.Read(kind,input).Mode);
        input["policy_revision"] = 0; Assert.Throws<InvalidDataException>(() => DetectorRule.Read(kind,input)); input.Remove("policy_revision");
        scope["plugin_id"] = "other"; Assert.Throws<InvalidDataException>(() => DetectorRule.Read(kind,input));
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task Denied_receipt_or_missing_policy_cannot_consume_file_checkpoint(bool evidenceDenied)
    {
        var json = Vectors().First(v => (string)v[0] == "file-decoy" && (string)v[1] == "read")[2]; var vector = JsonNode.Parse((string)json)!.AsObject(); var rule = DetectorRule.Read("file-decoy",vector["rule"]!.AsObject());
        var session = new NativeSession(vector,rule) { DenyEvidence = evidenceDenied, NoPolicy = !evidenceDenied };
        await Assert.ThrowsAnyAsync<Exception>(() => SemanticProduction.RunDetector(session,rule,SigmaProjection.At(vector,"now"),TestContext.Current.CancellationToken)); Assert.Equal(0,session.Checks); Assert.Equal(0,session.Jobs);
    }
    internal static JsonObject Scope(string plugin = "sli.vpn-nps") => new() { ["installation_id"] = "11111111-1111-1111-1111-111111111111", ["plugin_id"] = plugin, ["source_instance_id"] = "synthetic", ["source_generation"] = "1", ["collection_scope_id"] = "" };
    internal sealed class Session : ISemanticSession
    {
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) => throw new InvalidOperationException("unexpected_query");
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    [Theory] [InlineData("current_quality", "invented")] [InlineData("identity_state", "resolved")] [InlineData("comparison", "invalid")] [InlineData("count", "20")]
    public async Task Threshold_publication_rejects_invalid_diagnostics(string key, string value)
    {
        var scope = Scope(); var definition = SemanticProduction.Definition("qw.nps-denials", scope); var end = DateTimeOffset.Parse("2026-01-01T00:05:00Z");
        var context = new JsonObject { ["count"] = 20, ["previous_count"] = 1, ["threshold"] = 20, ["window_seconds"] = 300, ["surge_factor"] = 3, ["dimension"] = "account", ["comparison"] = "threshold", ["current_quality"] = "partial", ["previous_quality"] = "partial", ["from_utc"] = "2026-01-01T00:00:00+00:00", ["to_utc"] = "2026-01-01T00:05:00+00:00", ["identity_state"] = "observed" }; context[key] = value;
        var refs = new JsonArray(new JsonObject { ["scope"] = scope.DeepClone(), ["storage_kind"] = "core_event", ["native_id"] = "1", ["sha256"] = new string('a',64) });
        var document = SemanticProduction.Signal(definition, new string('b',64), new string('c',64), end, end, refs, "medium", "nps_threshold", "degraded", "threshold_context", context, 20);
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.VerifyQWContext(new Session(), document, TestContext.Current.CancellationToken));
    }
}
