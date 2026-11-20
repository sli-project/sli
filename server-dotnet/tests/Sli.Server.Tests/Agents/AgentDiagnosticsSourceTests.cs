using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using Xunit;
namespace Sli.Server.Tests.Agents;

public sealed class AgentDiagnosticsSourceTests
{
    [Fact]
    public void RootAuditConsentIsTypedAndSentThroughExistingPolicy()
    {
        var value = System.Text.Json.JsonSerializer.SerializeToElement(new { manage_windows_audit = true, manage_domain_root_sacl = true });
        var normalized = AgentPolicyStore.NormalizeCollectionPolicy(value);
        Assert.True(normalized.GetProperty("manage_domain_root_sacl").GetBoolean());
        var agent = new JsonObject { ["id"] = "00000000-0000-4000-8000-000000000001", ["policy_revision"] = 3,
            ["assigned_modules"] = new JsonArray(), ["collection_policy"] = JsonNode.Parse(normalized.GetRawText()) };
        Assert.True(Sli.Server.Agents.ClientControl.AgentClientPolicy.CheckIn(agent, false)["collection_policy"]!["manage_domain_root_sacl"]!.GetValue<bool>());
        Assert.Throws<AgentControlException>(() => AgentPolicyStore.NormalizeCollectionPolicy(
            System.Text.Json.JsonSerializer.SerializeToElement(new { manage_domain_root_sacl = "true" })));
    }
    [Fact]
    public void DcAuditReportKeepsDetectionDependenciesAndPerSettingResults()
    {
        var now = DateTimeOffset.Parse("2026-11-15T01:19:00Z");
        var agent = JsonNode.Parse("""{"policy_revision":3,"assigned_modules":[{"module_id":"sli.windows.ad-dc","enabled":true,"config":{}}],"collection_policy":{"manage_windows_audit":true}}""")!.AsObject();
        var rows = new JsonArray();
        foreach (var spec in Sli.Agent.Core.WindowsAuditManager.Families["domain_controller"].Append(Sli.Agent.Core.WindowsAuditManager.DomainRootRequirement))
            rows.Add(new JsonObject { ["subcategory"] = spec.Name, ["guid"] = spec.Guid,
                ["success"] = (spec.Mask & 1) != 0, ["failure"] = (spec.Mask & 2) != 0,
                ["actual_success"] = true, ["actual_failure"] = spec.Name != "domain_root_sacl", ["state"] = "ok",
                ["enabled_at"] = "2026-11-15T01:18:00Z", ["policy_name"] = null,
                ["detections"] = new JsonArray((spec.Detections ?? []).Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()), ["domain_changes"] = spec.DomainChanges });
        var body = new JsonObject { ["windows_audit"] = new JsonObject { ["policy_revision"] = 3, ["management_state"] = "applied",
            ["command_line_enabled"] = null, ["checked_at"] = "2026-11-15T01:19:00Z", ["families"] = new JsonObject {
                ["domain_controller"] = new JsonObject { ["state"] = "ok", ["required"] = rows, ["non_security_channels"] = new JsonArray() } } } };
        var change = AgentWindowsAuditReport.Prepare(agent, body, now);
        Assert.True(change.Write);
        var root = change.State["families"]!["domain_controller"]!["required"]!.AsArray().Single(r => r!["subcategory"]!.ToString() == "domain_root_sacl")!;
        Assert.Equal("ok", root["state"]!.ToString());
        Assert.True(root["domain_changes"]!.GetValue<bool>());
        // A server update must still accept observations from the preceding agent package.
        var previous = body.DeepClone().AsObject();
        var previousRows = previous["windows_audit"]!["families"]!["domain_controller"]!["required"]!.AsArray();
        foreach (var row in previousRows.Where(r => Sli.Agent.Core.WindowsAuditManager.AdditionalDcRequirements.Any(s => s.Name == r!["subcategory"]!.ToString())).ToArray())
            previousRows.Remove(row);
        Assert.True(AgentWindowsAuditReport.Prepare(agent, previous, now).Write);
        previousRows.Insert(previousRows.Count - 1, rows.First(r => r!["subcategory"]!.ToString() == "directory_service_access")!.DeepClone());
        Assert.Throws<AgentControlException>(() => AgentWindowsAuditReport.Prepare(agent, previous, now));
        var rootInput = rows.Single(r => r!["subcategory"]!.ToString() == "domain_root_sacl")!;
        rootInput["actual_success"] = false; rootInput["state"] = "restored"; rootInput["enabled_at"] = null;
        body["windows_audit"]!["management_state"] = "restored";
        body["windows_audit"]!["families"]!["domain_controller"]!["state"] = "missing";
        Assert.Equal("restored", AgentWindowsAuditReport.Prepare(agent, body, now).State["families"]!["domain_controller"]!["required"]!.AsArray()
            .Single(r => r!["subcategory"]!.ToString() == "domain_root_sacl")!["state"]!.ToString());
        rootInput["actual_success"] = true; rootInput["state"] = "ok"; rootInput["enabled_at"] = "2026-11-15T01:18:00Z";
        body["windows_audit"]!["management_state"] = "applied";
        body["windows_audit"]!["families"]!["domain_controller"]!["state"] = "ok";
        Assert.Equal("2026-11-15T01:18:00Z", change.State["families"]!["domain_controller"]!["required"]![0]!["enabled_at"]!.ToString());
        agent["windows_audit"] = change.State.DeepClone();
        body["windows_audit"]!["checked_at"] = "2026-11-15T01:18:30Z";
        Assert.False(AgentWindowsAuditReport.Prepare(agent, body, now).Write);
        body["windows_audit"]!["checked_at"] = "2026-11-15T01:19:00Z";
        rows[0]!["actual_failure"] = false; rows[0]!["state"] = "managed_by_gpo";
        rows[0]!["policy_name"] = "LAB Audit"; rows[0]!["enabled_at"] = null;
        body["windows_audit"]!["management_state"] = "blocked";
        body["windows_audit"]!["families"]!["domain_controller"]!["state"] = "managed_by_gpo";
        Assert.Equal("LAB Audit", AgentWindowsAuditReport.Prepare(agent, body, now).State["families"]!["domain_controller"]!["required"]![0]!["policy_name"]!.ToString());
        rows[0]!["detections"] = new JsonArray(99);
        Assert.Throws<AgentControlException>(() => AgentWindowsAuditReport.Prepare(agent, body, now));
    }
    [Fact]
    public void FrozenAuditReportTypesFamiliesMonotonicStateAndWireMatch()
    {
        var vector=Read();Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",vector["source_commit"]!.GetValue<string>());
        var now=new DateTimeOffset(2026,11,4,1,2,3,TimeSpan.Zero).AddTicks(4567890);
        foreach(var row in vector["audit"]!.AsArray())
        {
            if(row!["error"] is not null)Assert.Equal(row["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentWindowsAuditReport.Prepare(row["agent"]!.AsObject(),row["body"],now)).Message);
            else {var change=AgentWindowsAuditReport.Prepare(row["agent"]!.AsObject(),row["body"],now);Assert.Equal(row["write"]!.GetValue<bool>(),change.Write);Assert.True(JsonNode.DeepEquals(row["output"]!["windows_audit"],change.State),row["name"]!.GetValue<string>());}
        }
    }
    [Fact]
    public void FrozenRemovalResultAndRevocationCursorRulesMatch()
    {
        var vector=Read();
        foreach(var row in vector["removals"]!.AsArray())
        {
            if(row!["error"] is not null)Assert.Equal(row["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentDiagnosticRules.RemovalResult(row["body"])).Message);
            else Assert.Equal(row["output"]!["state"]!.GetValue<string>(),AgentDiagnosticRules.RemovalResult(row["body"]).State);
        }
        foreach(var row in vector["cursors"]!.AsArray())
        {
            if(row!["error"] is not null)Assert.Equal(row["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentDiagnosticRules.RevocationCursor(row["query"]!.GetValue<string>())).Message);
            else Assert.Equal(row["value"]!.GetValue<long>(),AgentDiagnosticRules.RevocationCursor(row["query"]!.GetValue<string>()));
        }
    }
    private static JsonObject Read([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-diagnostics.json");if(File.Exists(f))return JsonNode.Parse(File.ReadAllBytes(f))!.AsObject();}throw new IOException();}
}
