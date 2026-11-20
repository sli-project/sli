using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Auth;
using Sli.Server.Problems;
using Xunit;

namespace Sli.Server.Tests.Problems;

public sealed class DecoyRegistryTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 18, 0, 0, 0, TimeSpan.Zero);
    const string Agent = "00000000-0000-4000-8000-000000000001";
    const string Source = "00000000-0000-4000-8000-000000000002";
    static JsonObject O(string s) => JsonNode.Parse(s)!.AsObject();
    static JsonObject Body() => new() { ["kind"] = "file", ["identity"] = new JsonObject { ["agent_id"] = Agent, ["source_instance_id"] = Source,
        ["collection_scope_id"] = "scope:one", ["path"] = "C:/Decoys/BAIT.txt" }, ["owner"] = "fixture-owner", ["reason"] = "reason", ["active"] = true, ["revision"] = 0 };
    static JsonObject AgentRecord()
    {
        var config = O("""{"policy_revision":"4","roots":[{"collection_scope_id":"scope:one","path":"c:\\decoys","important":true,"sacl":{"trustee_sids":["S-1-1-0"],"inherit_files":true,"inherit_directories":true}}],"service_account_exclusions":[]}""");
        return new() { ["host_id"] = Source, ["status"] = "active", ["policy_revision"] = 4, ["applied_policy_revision"] = 4, ["last_seen"] = Now.ToString("O"),
            ["collection_policy"] = new JsonObject { ["state"] = "active" }, ["assigned_modules"] = new JsonArray(new JsonObject { ["module_id"] = "sli.file-audit", ["enabled"] = true, ["config"] = config.DeepClone() }),
            ["file_audit"] = new JsonObject { ["reported_at"] = Now.ToString("O"), ["request"] = new JsonObject { ["config"] = config, ["command"] = new JsonObject { ["action"] = "check", ["policy_revision"] = "4" } },
                ["scopes"] = new JsonObject { ["scope:one"] = new JsonObject { ["state"] = "verified", ["reason_code"] = "ok" } } } };
    }
    static JsonObject Coverage() => new() { ["state"] = "complete", ["read_audit_enabled"] = true, ["lost_count"] = 0, ["window_end"] = Now.ToString("O") };
    static JsonObject Check(JsonObject agent, JsonObject? coverage = null, bool present = true, JsonObject? identity = null, bool active = true) => DecoyReadiness.Evaluate("file", identity ?? Body()["identity"]!.AsObject(), active, [], agent, present, coverage ?? Coverage(), Now);
    [Fact] public void FileIdentityIsNormalizedWithoutPrefixMatching()
    {
        var input = DecoyInput.Parse(Body()); Assert.Equal("c:\\decoys\\bait.txt", input.Identity["path"]!.GetValue<string>());
        Assert.Equal("ready", Check(AgentRecord())["state"]!.GetValue<string>());
        input.Identity["path"] = "c:\\decoys-other\\bait.txt"; Assert.Contains("root_not_covered", Reasons(Check(AgentRecord(), identity: input.Identity)));
    }
    static string[] Reasons(JsonObject value) => value["reasons"]!.AsArray().Select(r => r!.GetValue<string>()).ToArray();
    [Theory]
    [InlineData("status", "source_not_ready")]
    [InlineData("host", "source_not_ready")]
    [InlineData("paused", "source_not_ready")]
    [InlineData("unapplied", "source_not_ready")]
    [InlineData("modules", "source_not_ready")]
    [InlineData("mismatch", "source_not_ready")]
    [InlineData("old_audit", "audit_stale")]
    [InlineData("old_agent", "audit_stale")]
    [InlineData("future_agent", "audit_stale")]
    [InlineData("workstation", "server_profile_required")]
    [InlineData("root", "root_not_covered")]
    [InlineData("important", "read_audit_missing")]
    [InlineData("inherit", "read_audit_missing")]
    [InlineData("trustee", "read_audit_missing")]
    [InlineData("exclusions", "exclusions_conflict")]
    [InlineData("receipt", "audit_missing")]
    [InlineData("command", "audit_missing")]
    [InlineData("revision", "audit_missing")]
    public void EachMissingReceiptIsVisibleAndNeverReady(string field, string reason)
    {
        var agent = AgentRecord(); var audit = agent["file_audit"]!.AsObject(); var config = audit["request"]!["config"]!.AsObject(); var root = config["roots"]![0]!.AsObject();
        switch (field)
        {
            case "status": agent["status"] = "revoked"; break; case "host": agent["host_id"] = Agent; break;
            case "paused": agent["collection_policy"]!["state"] = "paused"; break; case "unapplied": agent["applied_policy_revision"] = 3; break;
            case "modules": agent["assigned_modules"] = new JsonArray(); break; case "mismatch": agent["assigned_modules"]![0]!["config"]!["source_kind"] = "workstation"; break;
            case "old_audit": audit["reported_at"] = Now.AddDays(-2).ToString("O"); break; case "old_agent": agent["last_seen"] = Now.AddDays(-2).ToString("O"); break;
            case "future_agent": agent["last_seen"] = Now.AddSeconds(1).ToString("O"); break; case "workstation": config["source_kind"] = "workstation"; break;
            case "root": root["path"] = "c:\\other"; break; case "important": root["important"] = false; break;
            case "inherit": root["sacl"]!["inherit_files"] = false; break; case "trustee": root["sacl"]!["trustee_sids"] = new JsonArray("S-1-5-11"); break;
            case "exclusions": config["service_account_exclusions"] = new JsonArray("S-1-5-18"); break;
            case "receipt": audit["scopes"]!["scope:one"]!["reason_code"] = "sacl_missing"; break;
            case "command": audit["request"]!["command"]!["action"] = "restore"; break; case "revision": audit["request"]!["command"]!["policy_revision"] = "3"; break;
        }
        var result = Check(agent); Assert.Equal("not_ready", result["state"]!.GetValue<string>()); Assert.Contains(reason, Reasons(result));
    }
    [Theory]
    [InlineData("missing")]
    [InlineData("lost")]
    [InlineData("stale")]
    [InlineData("read_disabled")]
    public void CompleteSaclDoesNotHideCollectionGaps(string kind)
    {
        var coverage = Coverage(); if (kind == "missing") coverage.Clear(); if (kind == "lost") coverage["lost_count"] = 1;
        if (kind == "stale") coverage["window_end"] = Now.AddDays(-2).ToString("O"); if (kind == "read_disabled") coverage["read_audit_enabled"] = false;
        Assert.Contains("collection_gap", Reasons(Check(AgentRecord(), coverage)));
    }
    [Fact] public void MissingFileAndDisabledLabelNeverClaimReadiness()
    {
        var result = Check(AgentRecord(), present: false, active: false); Assert.Contains("file_unverified", Reasons(result)); Assert.Contains("label_disabled", Reasons(result));
        result = Check(new()); Assert.Equal("not_ready", result["state"]!.GetValue<string>()); Assert.Contains("audit_missing", Reasons(result));
    }
    [Fact] public void ExactAccountSnapshotNeverProvesAuthenticationCoverage()
    {
        var identity = O(ProblemEndpointTests.DecoyBody)["identity"]!.AsObject();
        var records = new JsonArray(new JsonObject { ["attributes_json"] = new JsonObject { ["identity"] = new JsonObject { ["kind"] = "ad_user", ["object_sid"] = identity["sid"]!.DeepClone(), ["object_guid"] = identity["guid"]!.DeepClone() } }, ["last_observed_at_utc"] = Now.ToString("O") });
        var result = DecoyReadiness.Evaluate("account", identity, true, records, new(), false, new(), Now); Assert.Equal(["authentication_audit_unverified"], Reasons(result));
        records[0]!["attributes_json"]!["identity"]!["object_guid"] = Source;
        Assert.Contains("identity_unverified", Reasons(DecoyReadiness.Evaluate("account", identity, true, records, new(), false, new(), Now)));
        Assert.Contains("identity_stale", Reasons(DecoyReadiness.Evaluate("account", identity, true, [], new(), false, new(), Now)));
    }
    [Theory]
    [InlineData("c:\\decoys\\..\\bait.txt")]
    [InlineData("c:\\decoys\\name.\\bait.txt")]
    [InlineData("c:\\decoys\\bait.txt:stream")]
    [InlineData("\\\\server\\share\\bait.txt")]
    [InlineData("c:relative")]
    [InlineData("c:\\decoys\\*.txt")]
    [InlineData("c:\\decoys\\line\nbreak")]
    public void AmbiguousPathsAreRejectedBeforeAnySourceReads(string path)
    { var body = Body(); body["identity"]!["path"] = path; Assert.Equal("decoy_invalid", Assert.Throws<ProblemException>(() => DecoyInput.Parse(body)).Code); }
    [Fact] public void DecoyUpdatesRequireExpectedRevisionAndAdminIdentity()
    {
        var input = DecoyInput.Parse(Body()); input.CheckPrevious(null, false);
        Assert.Equal("decoy_revision_conflict", Assert.Throws<ProblemException>(() => input.CheckPrevious(null, true)).Code);
        Assert.Throws<ProblemException>(() => input.CheckPrevious(new() { ["revision"] = 1 }, true));
        var body = Body(); body["revision"] = 1; DecoyInput.Parse(body).CheckPrevious(new() { ["revision"] = 1 }, true);
        var access = ProblemLifecycleTests.Access("decoys.registry"); Assert.True(access.CanManage("decoys.registry", input.Identity, new("session", 1, "admin"), "file"));
        Assert.False(access.CanManage("decoys.registry", input.Identity, new("session", 1, "operator"), "file"));
        Assert.False(access.CanManage("decoys.registry", input.Identity, new("local", 1, "admin"), "file"));
    }
    [Theory]
    [InlineData("?touches=00000000-0000-4000-8000-000000000001", false)]
    [InlineData("?touches=00000000-0000-4000-8000-000000000001&revision=0", false)]
    [InlineData("?touches=00000000-0000-4000-8000-000000000001&revision=1&cursor=deadbeef", false)]
    [InlineData("?id=00000000-0000-4000-8000-000000000001&revision=1&cursor=2", false)]
    [InlineData("?id=00000000-0000-4000-8000-000000000001&cursor=2", true)]
    [InlineData("?id=00000000-0000-4000-8000-000000000001&revision=1", true)]
    [InlineData("?cursor=00000000-0000-4000-8000-000000000001", true)]
    public void HistoryAndTouchesHaveDistinctCursorTypes(string query, bool valid)
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new(query);
        if (valid) RegistryQuery.Parse(context.Request.Query, false); else Assert.Equal("decoy_invalid", Assert.Throws<ProblemException>(() => RegistryQuery.Parse(context.Request.Query, false)).Code);
    }
    [Fact] public void TouchesHashCursorIsBoundedAndCaseSensitive()
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new("?touches=" + Agent + "&revision=1&cursor=" + new string('a', 64));
        var input = RegistryQuery.Parse(context.Request.Query, false); Assert.True(input.Touches); Assert.Equal(1, input.Revision);
        context.Request.QueryString = new("?touches=" + Agent + "&revision=1&cursor=" + new string('A', 64)); Assert.Throws<ProblemException>(() => RegistryQuery.Parse(context.Request.Query, false));
    }
}
