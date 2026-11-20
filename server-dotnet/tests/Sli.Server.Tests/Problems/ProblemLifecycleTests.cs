using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Problems;
using Xunit;

namespace Sli.Server.Tests.Problems;

public sealed class ProblemLifecycleTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 18, 0, 0, 0, TimeSpan.Zero);
    static JsonObject O(string s) => JsonNode.Parse(s)!.AsObject();
    static JsonElement E(string s) => JsonDocument.Parse(s).RootElement.Clone();
    static readonly string[] Fields = ["security", "identity_basic", "technical", "raw_evidence"];
    static readonly Principal Admin = new("session", 1, "admin", "alice");
    internal static ProblemAccess Access(string report, string scope = "{\"kind\":\"all\"}", string[]? fields = null, string[]? caps = null, IReadOnlyList<CapabilityPolicy>? policies = null, IReadOnlyList<AtomicReportGrant>? grants = null)
    {
        string[] keys = caps ?? ["objects.view", "watch.manage", "decoys.manage", "investigations.view", "investigations.manage"];
        var capabilities = new CapabilityDecisionSet(false, keys.ToHashSet(), new HashSet<string>(), policies ?? [], new Dictionary<string, JsonElement>());
        return new(new("admin", capabilities, [new(report, true, grants ?? [new(E(scope), (fields ?? Fields).ToHashSet(), new HashSet<string> { "view", "manage_watch", "manage_decoy" }, 1, 1)])]));
    }
    [Theory]
    [InlineData("new", "repeated", false)]
    [InlineData("new", "closed", true)]
    [InlineData("confirmed", "review", false)]
    [InlineData("false_positive", "new", false)]
    [InlineData("closed", "active", true)]
    [InlineData("closed", "review", false)]
    [InlineData("repeated", "confirmed", true)]
    [InlineData("active", "repeated", true)]
    public void LifecycleHasExactSourceTransitions(string old, string target, bool allowed)
    {
        var input = FindingStatusInput.Parse(new() { ["status"] = target, ["note"] = "reason" }, "alice");
        var row = new JsonObject { ["status"] = old };
        if (allowed) { var result = input.Apply(row); Assert.True(result.Changed); Assert.True(result.Audit); }
        else { var error = Assert.Throws<ProblemException>(() => input.Apply(row)); Assert.Equal("invalid_transition", error.Code); Assert.Equal(409, error.Status); }
    }
    [Fact] public void AllFortyNineStatusPairsMatchTheFrozenTransitionTable()
    {
        foreach (string old in FindingStatusInput.Statuses) foreach (string target in FindingStatusInput.Statuses)
        {
            var input = FindingStatusInput.Parse(new() { ["status"] = target, ["note"] = "fixture reason" }, "alice");
            if (old == target || FindingStatusInput.Transitions[old].Contains(target)) Assert.Equal(old != target, input.Apply(new() { ["status"] = old }).Changed);
            else Assert.Equal("invalid_transition", Assert.Throws<ProblemException>(() => input.Apply(new() { ["status"] = old })).Code);
        }
    }
    [Fact] public void IdempotentStatusDoesNotAuditButExplicitAssignmentDoes()
    {
        var row = O("""{"status":"new","assigned_to":"bob","status_reason":"original"}""");
        var same = FindingStatusInput.Parse(O("""{"status":"new"}"""), "alice").Apply(row);
        Assert.False(same.Changed); Assert.False(same.Audit); Assert.Equal("bob", same.Assignee); Assert.Equal("original", same.Reason);
        var clear = FindingStatusInput.Parse(O("""{"status":"new","assigned_to":null,"note":"clear"}"""), "alice").Apply(row);
        Assert.Null(clear.Assignee); Assert.True(clear.Audit); Assert.False(clear.Changed); Assert.Equal("clear", clear.Reason); Assert.Equal("original", row["status_reason"]!.GetValue<string>());
    }
    [Theory]
    [InlineData("new")]
    [InlineData("review")]
    [InlineData("confirmed")]
    [InlineData("repeated")]
    public void ResolveWithoutCommentKeepsOwnerAndReasonAndRequiresAudit(string status)
    {
        var row = new JsonObject { ["status"] = status, ["assigned_to"] = "bob", ["status_reason"] = "original" };
        var input = FindingStatusInput.Parse(O("""{"status":"closed","note":null}"""), "alice");
        var result = input.Apply(row);

        Assert.True(result.Changed);
        Assert.True(result.Audit);
        Assert.Null(input.Note);
        Assert.Equal("bob", result.Assignee);
        Assert.Equal("original", result.Reason);
    }
    [Theory]
    [InlineData("{\"status\":\"active\"}")]
    [InlineData("{\"status\":\"new\",\"assigned_to\":null}")]
    [InlineData("{\"status\":\"new\",\"status_reason\":\"\"}")]
    public void HumanDecisionsRequireReasons(string body)
    { var row = O("""{"status":"new","status_reason":"old"}"""); Assert.Equal("reason_required", Assert.Throws<ProblemException>(() => FindingStatusInput.Parse(O(body), "alice").Apply(row)).Code); }
    [Fact] public void StatusBoundsUseCodePointsAndPythonStrings()
    {
        var body = O("""{"status":" ACTIVE ","assigned_to":true,"note":true}"""); var input = FindingStatusInput.Parse(body, " alice ");
        Assert.Equal("active", input.Status); Assert.Equal("True", input.Note); Assert.Equal("True", input.Assignee);
        body["note"] = string.Concat(Enumerable.Repeat("😀", 2001)); Assert.Equal(2000, FindingStatusInput.Parse(body, "alice").Note!.EnumerateRunes().Count());
        Assert.Equal("actor_required", Assert.Throws<ProblemException>(() => FindingStatusInput.Parse(body, " ")).Code);
    }
    static JsonObject RiskBody() => new() { ["action"] = "create", ["reason"] = "reason", ["responsible_user_id"] = 1, ["expires_at"] = Now.AddDays(7).ToString("O") };
    [Fact] public void RiskAcceptanceValidatesNinetyDayBoundaryAndRevokeIdentity()
    {
        var body = RiskBody(); body["expires_at"] = Now.AddDays(90).ToString("O"); var input = RiskInput.Parse(body, " alice ", Now);
        Assert.Equal("alice", input.Actor); Assert.Equal(Now.AddDays(90), input.Expires);
        body["expires_at"] = Now.AddDays(90).AddSeconds(1).ToString("O"); Assert.Equal("invalid_expiry", Assert.Throws<ProblemException>(() => RiskInput.Parse(body, "alice", Now)).Code);
        var revoke = RiskInput.Parse(O("""{"action":"revoke","id":1}"""), "alice", Now); Assert.Equal(1, revoke.Id); Assert.Null(revoke.Expires);
    }
    [Theory]
    [InlineData("reason", "null", "reason_required")]
    [InlineData("reason", "\"   \"", "reason_required")]
    [InlineData("responsible_user_id", "true", "invalid_responsible")]
    [InlineData("responsible_user_id", "1.0", "invalid_responsible")]
    [InlineData("responsible_user_id", "9223372036854775808", "invalid_responsible")]
    [InlineData("expires_at", "\"2026-10-18T00:00:00Z\"", "invalid_expiry")]
    [InlineData("expires_at", "\"2026-10-19T00:00:00\"", "invalid_expiry")]
    [InlineData("action", "\"delete\"", "invalid_action")]
    public void InvalidRiskInputHasSpecificSourceError(string field, string json, string expected)
    { var body = RiskBody(); body[field] = JsonNode.Parse(json); Assert.Equal(expected, Assert.Throws<ProblemException>(() => RiskInput.Parse(body, "alice", Now)).Code); }
    static JsonObject WatchBody() { var body = O(ProblemEndpointTests.WatchBody); body["expires_at"] = Now.AddDays(7).ToString("O"); return body; }
    static JsonObject Identity() => O("""{"entity_id":12,"domain_id":1,"sid":"S-1-5-21-1-2-3-1001","guid":"00000000-0000-4000-8000-000000000001"}""");
    [Fact] public void WatchRevisionAndIdentityCannotBeOverwritten()
    {
        var body = WatchBody(); var input = WatchInput.Parse(body, Now); var identity = Identity();
        Assert.Equal(Now, input.CheckPrevious(null, null, identity, Now));
        Assert.Equal("watch_revision_conflict", Assert.Throws<ProblemException>(() => input.CheckPrevious(null, ProblemEndpointTests.Uuid, identity, Now)).Code);
        var previous = new JsonObject { ["id"] = ProblemEndpointTests.Uuid, ["revision"] = 1, ["identity"] = identity.DeepClone(), ["active"] = true,
            ["active_from"] = Now.AddDays(-1).ToString("O"), ["expires_at"] = Now.AddDays(1).ToString("O") };
        Assert.Equal("watch_revision_conflict", Assert.Throws<ProblemException>(() => input.CheckPrevious(previous, ProblemEndpointTests.Uuid, identity, Now)).Code);
        body["revision"] = 1; input = WatchInput.Parse(body, Now); Assert.Equal(Now.AddDays(-1), input.CheckPrevious(previous, ProblemEndpointTests.Uuid, identity, Now));
        identity["guid"] = "00000000-0000-4000-8000-000000000002";
        Assert.Equal("watch_revision_conflict", Assert.Throws<ProblemException>(() => input.CheckPrevious(previous, ProblemEndpointTests.Uuid, identity, Now)).Code);
        body["active"] = false; input = WatchInput.Parse(body, Now); Assert.Equal(Now, input.CheckPrevious(previous, ProblemEndpointTests.Uuid, Identity(), Now));
    }
    [Fact] public void ExpiredWatchRestartsAndInactiveWatchCanKeepPastExpiry()
    {
        var body = WatchBody(); body["revision"] = 1;
        var old = new JsonObject { ["id"] = ProblemEndpointTests.Uuid, ["revision"] = 1, ["identity"] = Identity(), ["active"] = true, ["active_from"] = Now.AddDays(-1).ToString("O"), ["expires_at"] = Now.ToString("O") };
        Assert.Equal(Now, WatchInput.Parse(body, Now).CheckPrevious(old, ProblemEndpointTests.Uuid, Identity(), Now));
        body["expires_at"] = Now.ToString("O"); Assert.Throws<ProblemException>(() => WatchInput.Parse(body, Now)); body["active"] = false; Assert.False(WatchInput.Parse(body, Now).Active);
    }
    [Theory]
    [InlineData("entity_id", "true")]
    [InlineData("entity_id", "9007199254740992")]
    [InlineData("entity_id", "1.0")]
    [InlineData("revision", "true")]
    [InlineData("revision", "9007199254740991")]
    [InlineData("active", "1")]
    [InlineData("reason", "\"reason\\nformula\"")]
    [InlineData("owner", "\" trailing \"")]
    [InlineData("extra", "null")]
    public void WatchRejectsInvalidShapesBeforeSourceRead(string key, string value)
    { var body = WatchBody(); body[key] = JsonNode.Parse(value); Assert.Equal("watch_invalid", Assert.Throws<ProblemException>(() => WatchInput.Parse(body, Now)).Code); }
    [Fact] public void RegistryStringsAreDataAndRemainExactJsonForReact()
    {
        var body = WatchBody(); body["reason"] = "=HYPERLINK(\"https://untrusted.invalid\")"; body["owner"] = "<script>fixture</script>";
        var input = WatchInput.Parse(body, Now); Assert.Equal(body["reason"]!.GetValue<string>(), input.Reason); Assert.Equal(body["owner"]!.GetValue<string>(), input.Owner);
        // These JSON routes never interpolate data into SQL or CSV. CSV export
        // escaping remains the export writer's boundary, as in the reference.
    }
    [Fact] public void RegistryFieldsAndScopeAreCheckedInTheSameGrant()
    {
        var identity = Identity(); var access = Access("watch.registry", "{\"kind\":\"domain\",\"ids\":[1]}");
        access.Registry("watch.registry", identity, true, Admin);
        Assert.Equal(403, Assert.Throws<ProblemException>(() => Access("watch.registry", "{\"kind\":\"domain\",\"ids\":[2]}").Registry("watch.registry", identity, true, Admin)).Status);
        Assert.False(Access("watch.registry", caps: ["watch.manage"]).CanManage("watch.registry", identity, Admin));
        Assert.False(access.CanManage("watch.registry", identity, Admin with { Type = "local" }));
        Assert.False(access.CanManage("watch.registry", identity, Admin with { Role = "viewer" }));
        Assert.False(access.CanManage("watch.registry", identity, Admin with { Id = 0 }));
        var grants = new[] { new AtomicReportGrant(E("{\"kind\":\"domain\",\"ids\":[1]}"), new HashSet<string> { "security" }, new HashSet<string> { "view" }, 1, 1),
            new AtomicReportGrant(E("{\"kind\":\"domain\",\"ids\":[2]}"), new HashSet<string> { "identity_basic" }, new HashSet<string> { "view" }, 1, 1) };
        Assert.Equal("report_field_categories_not_allowed", Assert.Throws<ProblemException>(() => Access("watch.registry", grants: grants).Scope("watch.registry")).Code);
    }
    [Fact] public void ResourceDeniesWinOverGlobalWatchAllows()
    {
        var deny = new CapabilityPolicy("watch.manage", "deny", true, false, E("{\"kind\":\"domain\",\"ids\":[1]}"));
        Assert.False(Access("watch.registry", policies: [deny]).CanManage("watch.registry", Identity(), Admin));
    }
    [Fact] public void GenericScopeNeverMultipliesDimensionsAcrossClauses()
    {
        string scope = """{"mode":"restricted","clauses":[{"source_instance_ids":["source:a"],"device_ids":["agent:b"]},{"source_instance_ids":["source:b"],"device_ids":["agent:a"]}]}""";
        var identity = O("""{"agent_id":"agent:a","source_instance_id":"source:a","collection_scope_id":"scope:a"}""");
        Assert.Throws<ProblemException>(() => Access("decoys.registry", scope).Registry("decoys.registry", identity, true, Admin, "file"));
        var args = new Dictionary<string, object?>(); string predicate = Access("decoys.registry", scope).Scope("decoys.registry").Predicate(args, false);
        Assert.Contains(" or ", predicate); Assert.Equal(4, args.Count);
        Assert.Throws<ProblemException>(() => Access("watch.registry", scope).Scope("watch.registry").Predicate(new(), true));
    }
    [Fact] public void FindingFieldProjectionMustCoverTheWholeAuthorizedScope()
    {
        var grants = new[] { new AtomicReportGrant(E("{\"kind\":\"all\"}"), new HashSet<string> { "security" }, new HashSet<string> { "view" }, 1, 1),
            new AtomicReportGrant(E("{\"kind\":\"domain\",\"ids\":[1]}"), Fields.ToHashSet(), new HashSet<string> { "view" }, 1, 1) };
        var access = Access("security.queue", grants: grants); Assert.False(access.Fields("identity_basic")); Assert.False(access.Fields("raw_evidence"));
        var finding = O("""{"id":1,"rule_code":"semantic.qw.account-decoy","status":"new","severity":"high","actor":"secret identity","target":"secret target","assigned_to":"analyst","status_reason":"secret reason","source":"secret host","evidence":[{"event_id":4624,"hostname":"secret host"}],"identity_context":{"actor":{"label":"secret label"},"snapshot_state":"lookup_complete"},"risk_acceptance":{"id":3,"reason":"secret reason","responsible_user_id":1},"risk_audit":[],"decoy_id":"secret id","entities":[],"status_history":[]}""");
        var row = ProblemPresentation.Finding(finding, access, "en");
        foreach (string field in new[] { "actor", "target", "assigned_to", "status_reason", "evidence", "identity_context", "source", "risk_audit", "decoy_id" }) Assert.False(row.ContainsKey(field), field);
        Assert.False(row["risk_acceptance"]!.AsObject().ContainsKey("reason")); Assert.False(row["presentation_messages"]!.AsObject().ContainsKey("actor_text"));
        Assert.Equal("account_decoy_used", row["presentation_code"]!.GetValue<string>());
        var context = new DefaultHttpContext(); context.Request.QueryString = new("?q=identity");
        Assert.Equal("report_field_categories_not_allowed", Assert.Throws<ProblemException>(() => FindingQuery.Parse(context.Request.Query, access)).Code);
    }
    [Fact] public void DomainAdapterAndRequestIntersectionNeverBroadenScope()
    {
        var access = Access("security.queue", "{\"kind\":\"domain\",\"ids\":[1,2]}"); var context = new DefaultHttpContext();
        context.Request.QueryString = new("?domain=2&limit=999"); var query = FindingQuery.Parse(context.Request.Query, access); Assert.Equal([2L], query.Domains!); Assert.Equal(200, query.Limit);
        context.Request.QueryString = new("?domain=3"); Assert.Equal(403, Assert.Throws<ProblemException>(() => FindingQuery.Parse(context.Request.Query, access)).Status);
        Assert.Throws<ProblemException>(() => Access("security.queue", "{\"mode\":\"restricted\",\"clauses\":[{\"entity_ids\":[1]}]}").Scope("security.queue").Domains());
    }
    [Fact] public void RuntimeFreshnessDistinguishesMissingInactiveAndStaleFindings()
    {
        Assert.Equal("unknown", ProblemPresentation.Runtime(new(), Now)["state"]!.GetValue<string>());
        var heartbeat = new JsonObject { ["status"] = "idle", ["heartbeat_at"] = Now.ToString("O"), ["expected_interval_seconds"] = 30,
            ["details_json"] = new JsonObject { ["runtime_mode"] = "investigation-v1", ["manual_runtime"] = false } };
        Assert.Equal("inactive", ProblemPresentation.Runtime(heartbeat, Now)["state"]!.GetValue<string>());
        heartbeat["details_json"]!["runtime_mode"] = "findings-v1"; Assert.Equal("active", ProblemPresentation.Runtime(heartbeat, Now)["state"]!.GetValue<string>());
        Assert.Equal("stale", ProblemPresentation.Runtime(heartbeat, Now.AddMinutes(5))["state"]!.GetValue<string>());
        heartbeat["details_json"]!["manual_runtime"] = true; Assert.Equal("inactive", ProblemPresentation.Runtime(heartbeat, Now)["state"]!.GetValue<string>());
    }
    [Fact] public void RawRegistryTimestampsAndActorFallbackMatchTheSource()
    {
        var row = O("""{"active_from":"2026-10-18T01:02:03.123456+00:00","valid_to":null}"""); ProblemJson.RawTimes(row, "active_from", "valid_to");
        Assert.Equal("2026-10-18 01:02:03.123456+00:00", row["active_from"]!.GetValue<string>()); Assert.Null(row["valid_to"]);
        Assert.Equal("key label", ProblemJson.Actor(new("api_key", 1, "admin", "", "key label")));
        Assert.Equal("api_key", ProblemJson.Actor(new("api_key", 1, "admin", "", ""), true));
        Assert.Equal("", ProblemJson.Actor(new("api_key", 1, "admin", "", "")));
    }
    [Fact] public void EmptyFindingTextUsesCatalogFallbackAndNeverPublishesStorageColumns()
    {
        var row = ProblemPresentation.Finding(O("""{"id":1,"title":"","summary":"","status":"new","severity":"info","private_storage_column":"private"}"""), Access("security.queue"), "en");
        Assert.Equal("", row["title_code"]!.GetValue<string>());
        Assert.Null(row["severity_message"]); Assert.False(row.ContainsKey("private_storage_column"));
    }
}
