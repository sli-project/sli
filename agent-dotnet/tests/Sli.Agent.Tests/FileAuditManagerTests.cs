using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class FileAuditManagerTests : IDisposable
{
    private readonly string _dir = Helpers.TempDirectory();
    private readonly PhysicalDurableFiles _files = new();
    public void Dispose() => Directory.Delete(_dir,true);
    internal static JsonObject Config() => new() { ["roots"]=new JsonArray(new JsonObject { ["collection_scope_id"]="scope:one",["share_name"]="synthetic",["path"]=@"C:\synthetic",["important"]=false,
        ["sacl"]=new JsonObject { ["trustee_sids"]=new JsonArray("S-1-1-0"),["inherit_files"]=true,["inherit_directories"]=true } }) };
    internal static JsonObject Request(string action = "apply", string id = "one", JsonObject? config = null) => new() { ["config"]=config ?? Config(),["command"]=new JsonObject
    { ["contract_id"]="sli.file-audit.audit-command.v1",["command_id"]=id,["action"]=action,["policy_revision"]="1",["collection_scope_ids"]=new JsonArray("scope:one") } };
    private AgentPolicy Policy(JsonObject? request, bool manage = true) => new(1,new CollectionControl("active",60,32,120,10000000,manage,false),new JsonArray(),null,null,null) { FileAuditRequest = request };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ACheckWithoutNativeSupportStopsAfterItsDurableReceipt(bool missingEntryPoint)
    {
        var api = new FakeFileApi(_dir) {
            Owner = missingEntryPoint ? "ok" : "native_unavailable",
            FailedRead = missingEntryPoint ? "native_unavailable" : null
        };
        var request = Policy(Request("check"));
        var manager = new FileAuditManager(_dir, _files, api);
        var report = manager.Reconcile(request, new FakeAudit(), Helpers.Now).Report!;
        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("failed", scope["state"]!.ToString());
        Assert.Equal("native_unavailable", scope["reason_code"]!.ToString());
        var restarted = new FileAuditManager(_dir, _files, api);
        Assert.True(JsonNode.DeepEquals(report, restarted.Reconcile(request, new FakeAudit(), Helpers.Now).Report));
        restarted.Acknowledge(report);
        Assert.Null(restarted.Reconcile(request, new FakeAudit(), Helpers.Now.AddDays(2)).Report);
        Assert.Equal(1, api.CheckPreflightCalls);
        Assert.NotNull(restarted.Reconcile(Policy(Request("check", "new-check")), new FakeAudit(), Helpers.Now.AddDays(2)).Report);
        Assert.Equal(2, api.CheckPreflightCalls);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void AnUpgradeRetriesADurableTerminalCheckOnce(bool recordedVersion, bool pendingReceipt)
    {
        var api = new FakeFileApi(_dir) { Owner = "native_unavailable" };
        var oldPolicy = Policy(Request("check"));
        var manager = new FileAuditManager(_dir, _files, api);
        var oldReport = manager.Reconcile(oldPolicy, new FakeAudit(), Helpers.Now).Report!;
        if (!pendingReceipt) manager.Acknowledge(oldReport);
        var statePath = Path.Combine(_dir, "state.json");
        var state = JsonNode.Parse(File.ReadAllBytes(statePath))!.AsObject();
        var walk = state["walks"]!["scope:one"]!.AsObject();
        if (recordedVersion) walk["terminal_check_version"] = "26.0.136";
        else walk.Remove("terminal_check_version");
        File.WriteAllBytes(statePath, CanonicalJson.ToBytes(state));

        var newPolicy = AgentPolicy.Parse(new JsonObject {
            ["agent_id"] = "synthetic-agent", ["policy_revision"] = 1,
            ["collection_policy"] = new JsonObject(), ["assigned_modules"] = new JsonArray(),
            ["file_audit"] = Request("check"), ["file_audit_retry_version"] = oldPolicy.Report("active")["agent_version"]!.DeepClone()
        }, "synthetic-agent", EventCatalog.Load());
        api.Owner = "ok";
        var now = Helpers.Now.AddMinutes(1);
        var restarted = new FileAuditManager(_dir, _files, api);
        var retry = Assert.IsType<JsonObject>(restarted.Reconcile(newPolicy, new FakeAudit(), now).Report);
        Assert.NotEmpty(retry["snapshots"]!.AsArray());
        Assert.Equal(oldReport["command_id"]!.ToString(), retry["command_id"]!.ToString());
        Assert.Equal(Iso8601.Format(now), retry["observed_at_utc"]!.ToString());
        Assert.Equal(2, api.CheckPreflightCalls);
        restarted.Acknowledge(retry);
        var restartedAgain = new FileAuditManager(_dir, _files, api);
        Assert.Null(restartedAgain.Reconcile(newPolicy, new FakeAudit(), now.AddDays(2)).Report);
        Assert.Equal(2, api.CheckPreflightCalls);
        Assert.Equal(0, api.Writes);
    }

    [Theory]
    [InlineData("audit_policy", "audit_policy_read_unavailable:5")]
    [InlineData("share", "share_read_unavailable:5")]
    [InlineData("directory", "directory_read_unavailable:5")]
    [InlineData("acl", "acl_read_unavailable:5")]
    public void AFailedServerCheckReportsOnlyItsReadStageAndWindowsCode(string stage, string reason)
    {
        var api = new FakeFileApi(_dir) { FailedRead = stage };
        var manager = new FileAuditManager(_dir, _files, api);
        var report = manager.Reconcile(Policy(Request("check")), new FakeAudit(), Helpers.Now, readDiagnostics: true).Report!;
        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("failed", scope["state"]!.ToString());
        Assert.Equal(reason, scope["reason_code"]!.ToString());
        Assert.Equal(stage, scope["read_error"]!["stage"]!.ToString());
        Assert.Equal("win32", scope["read_error"]!["code_kind"]!.ToString());
        Assert.Equal(5u, scope["read_error"]!["code"]!.GetValue<uint>());
        Assert.Empty(report["snapshots"]!.AsArray());
        Assert.Equal(0, api.Writes);
        Assert.DoesNotContain("synthetic private path or ACL", report.ToJsonString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DomainControllerGroupFailureKeepsTheShareMasksAndFileInventory(bool readDiagnostics)
    {
        var api = new FakeFileApi(_dir) { FailedRead = "local_groups", GroupError = 2221 };
        var manager = new FileAuditManager(_dir, _files, api);

        var report = manager.Reconcile(Policy(Request("check")), new FakeAudit(), Helpers.Now, readDiagnostics).Report!;

        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("partial", scope["state"]!.ToString());
        Assert.Equal("local_groups_unavailable:2221", scope["reason_code"]!.ToString());
        Assert.NotEmpty(scope["required_masks"]!.AsObject());
        Assert.NotEmpty(scope["actual_masks"]!.AsObject());
        var snapshot = Assert.Single(report["snapshots"]!.AsArray())!;
        Assert.Equal("partial", snapshot["completeness"]!.ToString());
        Assert.False(snapshot["local_groups"]!["complete"]!.GetValue<bool>());
        Assert.Empty(snapshot["local_groups"]!["groups"]!.AsArray());
        Assert.True(snapshot["share"]!["complete"]!.GetValue<bool>());
        Assert.Single(snapshot["objects"]!.AsArray());
        Assert.Equal(0, snapshot["unread_objects"]!.GetValue<int>());
        Assert.Equal(0, api.Writes);
    }

    [Theory]
    [InlineData("share_path_mismatch", "share_path_mismatch")]
    [InlineData("security_privilege_missing", "security_privilege_missing:1300")]
    [InlineData("preflight_privilege_missing", "security_privilege_missing:1300")]
    public void NativeChecksReportSharePathMismatchOrMissingPrivilegeWithoutDiagnosticCapability(string failure, string reason)
    {
        var api = new FakeFileApi(_dir) { FailedRead = failure };
        var report = new FileAuditManager(_dir, _files, api).Reconcile(Policy(Request("check")), new FakeAudit(), Helpers.Now).Report!;

        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("failed", scope["state"]!.ToString());
        Assert.Equal(reason, scope["reason_code"]!.ToString());
        Assert.Empty(report["snapshots"]!.AsArray());
        Assert.Equal(0, api.Writes);
    }

    [Fact]
    public void IncompleteLocalGroupResolutionAllowsOnlyReadOnlyInventory()
    {
        var api = new FakeFileApi(_dir) { UnresolvedGroupSid = true };
        var manager = new FileAuditManager(_dir, _files, api);
        var check = manager.Reconcile(Policy(Request("check")), new FakeAudit(), Helpers.Now).Report!;
        var scope = Assert.Single(check["scopes"]!.AsArray())!;
        Assert.Equal("coverage_incomplete", scope["reason_code"]!.ToString());
        var snapshot = Assert.Single(check["snapshots"]!.AsArray())!;
        Assert.False(snapshot["local_groups"]!["complete"]!.GetValue<bool>());
        Assert.NotEmpty(snapshot["objects"]!.AsArray());

        manager.Acknowledge(check);
        var apply = manager.Reconcile(Policy(Request("apply", "apply")), new FakeAudit(), Helpers.Now).Report!;
        Assert.Equal("local_group_identity_unavailable", Assert.Single(apply["scopes"]!.AsArray())!["reason_code"]!.ToString());
        Assert.Empty(apply["snapshots"]!.AsArray());
        Assert.Equal(0, api.Writes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void LocalGroupReadFailureLeavesApplyOwnershipAndNativePolicyUntouched(bool unresolvedSid)
    {
        var fileApi = new FakeFileApi(_dir)
        {
            UnresolvedGroupSid = unresolvedSid,
            FailedRead = unresolvedSid ? null : "local_groups"
        };
        var audit = AuditForFilePolicy(out var windowsApi);
        var manager = new FileAuditManager(_dir, _files, fileApi);

        var result = manager.Reconcile(Policy(Request()), audit, Helpers.Now, readDiagnostics: true);

        var report = result.Report!;
        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("failed", scope["state"]!.ToString());
        Assert.Equal(unresolvedSid ? "local_group_identity_unavailable" : "local_groups_unavailable:5", scope["reason_code"]!.ToString());
        Assert.Null(scope["read_error"]);
        Assert.Empty(report["snapshots"]!.AsArray());
        Assert.False(report["ownership_remaining"]!.GetValue<bool>());
        Assert.Null(result.Audit);
        Assert.Equal(1, fileApi.LocalGroupReads);
        Assert.Equal(0, windowsApi.Reads);
        Assert.Equal(0, windowsApi.Writes);
        Assert.Equal(0, fileApi.Writes);

        var state = JsonNode.Parse(File.ReadAllBytes(Path.Combine(_dir, "state.json")))!;
        Assert.Null(state["active"]);
        Assert.Empty(state["masks"]!.AsObject());
        Assert.Empty(state["objects"]!.AsObject());
        Assert.True(JsonNode.DeepEquals(report, state["pending_report"]));
    }

    [Fact]
    public void ApplyReusesTheStrictGroupReadAndKeepsIncompletePageSemantics()
    {
        var fileApi = new FakeFileApi(_dir) { IncompleteGroupPage = true };
        var audit = AuditForFilePolicy(out var windowsApi);
        var manager = new FileAuditManager(_dir, _files, fileApi);

        var report = manager.Reconcile(Policy(Request()), audit, Helpers.Now).Report!;

        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("partial", scope["state"]!.ToString());
        Assert.Equal("coverage_incomplete", scope["reason_code"]!.ToString());
        var snapshot = Assert.Single(report["snapshots"]!.AsArray())!;
        Assert.False(snapshot["local_groups"]!["complete"]!.GetValue<bool>());
        Assert.True(report["ownership_remaining"]!.GetValue<bool>());
        Assert.Equal(1, fileApi.LocalGroupReads);
        Assert.Equal(1, windowsApi.Writes);
        Assert.Equal(1, fileApi.Writes);
    }

    private WindowsAuditManager AuditForFilePolicy(out WindowsAuditTests.Api windowsApi)
    {
        windowsApi = new WindowsAuditTests.Api();
        foreach (var guid in FileAuditPolicy.Parse(Config()).RequiredMasks().Keys)
            windowsApi.Values.TryAdd(guid, 0);
        return new WindowsAuditManager(Path.Combine(_dir, "windows-audit"), _files, windowsApi);
    }

    [Theory]
    [InlineData("S-1-5-32-544", null, "S-1-5-32-544")]
    [InlineData(null, "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001")]
    [InlineData("S-1-5-32-544", "S-1-5-21-1-2-3-1001", null)]
    [InlineData(null, "S-1-5-21-4-5-6-1001", null)]
    [InlineData(null, null, null)]
    public void GroupSidMustBeUniqueAndFromAnAuthoritativeLocalDomain(
        string? builtin, string? account, string? expected)
    {
        if (!OperatingSystem.IsWindows()) return;

        var resolved = NativeFileAuditApi.SelectLocalGroupSid(
            builtin is null ? null : new(builtin), new("S-1-5-32"),
            account is null ? null : new(account), new("S-1-5-21-1-2-3"));
        Assert.Equal(expected, resolved?.Value);
    }

    [Fact]
    public void NativeGroupReadsKeepNetApiStatusAndAcceptPartialPages()
    {
        if (!OperatingSystem.IsWindows()) return;

        NativeFileAuditApi.EnsureLocalGroupRead(0);
        NativeFileAuditApi.EnsureLocalGroupRead(234);
        try
        {
            NativeFileAuditApi.EnsureLocalGroupRead(5);
            Assert.Fail("NetAPI access denied should be reported as a native read failure.");
        }
        catch (FileAuditNativeReadException error)
        {
            Assert.Equal(5u, error.NativeStatus);
        }
    }

    [Fact]
    public void NativeLocalGroupInventoryResolvesTheBuiltinAdministratorsAlias()
    {
        if (!OperatingSystem.IsWindows()) return;

        var groups = new NativeFileAuditApi().LocalGroups(100);
        Assert.Contains(groups["groups"]!.AsArray(), group => group!["group_sid"]!.ToString() == "S-1-5-32-544");
    }

    [Theory]
    [InlineData(false, 0, 2, true, null)]
    [InlineData(false, 0, 2, false, "global_sacl_unknown")]
    [InlineData(true, 0, 0, true, null)]
    [InlineData(true, 0, 0, false, null)]
    [InlineData(true, 1, 0, true, "global_sacl_present")]
    [InlineData(true, 1, 0, false, "global_sacl_present")]
    [InlineData(false, 0, 5, true, "global_sacl_unknown")]
    [InlineData(false, 0, 87, true, "global_sacl_unknown")]
    [InlineData(false, 0, 0, true, "global_sacl_unknown")]
    public void GlobalFileSaclReadKeepsInventoryAndPolicyChangesSeparate(
        bool readSucceeded, int aceCount, int status, bool readOnlyCheck, string? reason)
    {
        Assert.Equal(reason, GlobalFileSaclPreflight.BlockReason(readSucceeded, aceCount, (uint)status, readOnlyCheck));
    }

    [Theory]
    [InlineData("check", "global_sacl_present", "global_sacl_present", 1)]
    [InlineData("check", "managed_by_gpo", "managed_by_gpo", 1)]
    [InlineData("apply", "global_sacl_unknown", "global_sacl_unknown", 0)]
    [InlineData("restore", "global_sacl_unknown", "global_sacl_unknown", 0)]
    public void OnlyChecksUseTheReadOnlyPreflightAndPolicyCanStillBlock(string action, string owner, string reason, int checkCalls)
    {
        var api = new FakeFileApi(_dir) { Owner = owner };
        var manager = new FileAuditManager(_dir, _files, api);
        var report = manager.Reconcile(Policy(Request(action)), new FakeAudit(), Helpers.Now, readDiagnostics: true).Report!;
        var scope = Assert.Single(report["scopes"]!.AsArray())!;
        Assert.Equal("blocked", scope["state"]!.ToString());
        Assert.Equal(reason, scope["reason_code"]!.ToString());
        Assert.Equal(checkCalls, api.CheckPreflightCalls);
        Assert.Equal(0, api.Writes);
    }

    [Theory]
    [InlineData("check")]
    [InlineData("apply")]
    [InlineData("restore")]
    public void InventoryAndAuditReportMatchPythonByteForByte(string name)
    {
        var vector=Vectors.Load("file-audit-inventory.json").AsArray().Single(x => x!["name"]!.ToString() == name)!;
        var api=new FakeFileApi(_dir);
        foreach (var step in vector["steps"]!.AsArray())
        {
            var manager=new FileAuditManager(_dir,_files,api);
            var report=manager.Reconcile(Policy(step!["request"]!.AsObject()),new FakeAudit(),Iso8601.ParseUtc(vector["now"]!.ToString())).Report!;
            Assert.Equal(step["report_canonical"]!.ToString(),CanonicalJson.Serialize(report));
            if (Environment.GetEnvironmentVariable("SLI_DOTNET_INTEROP_DIR") is { Length: > 0 } target)
            {
                Directory.CreateDirectory(target);
                File.WriteAllText(Path.Combine(target,"file-inventory-"+name+"-"+report["action"]+".json"),new JsonObject { ["request"]=step["request"]!.DeepClone(),["report"]=report.DeepClone() }.ToJsonString());
            }
            manager.Acknowledge(report);
        }
    }

    [Fact]
    public void DefaultCheckIsReadOnlyAndPendingReportSurvivesRestartUntilExactAck()
    {
        var api = new FakeFileApi(_dir); var policy = Policy(Request("check"));
        var manager = new FileAuditManager(_dir,_files,api);
        var report = manager.Reconcile(policy,new FakeAudit(),Helpers.Now).Report!;
        Assert.Equal(0,api.Writes);
        Assert.Equal("sacl_missing",report["scopes"]![0]!["reason_code"]!.ToString());
        var restarted = new FileAuditManager(_dir,_files,api);
        Assert.Equal(CanonicalJson.Serialize(report),CanonicalJson.Serialize(restarted.Reconcile(policy,new FakeAudit(),Helpers.Now.AddMinutes(1)).Report));
        restarted.Acknowledge(new JsonObject());
        Assert.NotNull(restarted.Reconcile(policy,new FakeAudit(),Helpers.Now).Report);
        restarted.Acknowledge(report);
        Assert.Null(restarted.Reconcile(policy,new FakeAudit(),Helpers.Now).Report);
    }

    [Fact]
    public void ApplyUsesExactInheritancePlanAndVerifiesOwnerDaclAndSaclAfterWrite()
    {
        var api = new FakeFileApi(_dir);
        var manager = new FileAuditManager(_dir,_files,api);
        var report = manager.Reconcile(Policy(Request()),new FakeAudit(),Helpers.Now).Report!;
        Assert.Equal("verified",report["scopes"]![0]!["state"]!.ToString());
        Assert.Equal("S:exact-inheritance",api.Object.Row["sacl"]!.ToString());
        Assert.Equal(1,api.Writes);
        Assert.Equal("confirmed",JsonNode.Parse(File.ReadAllBytes(Path.Combine(_dir,"state.json")))!["objects"]![@"C:\synthetic"]!["phase"]!.ToString());
        manager.Acknowledge(report);
        var restored = manager.Reconcile(Policy(Request("restore","two")),new FakeAudit(),Helpers.Now).Report!;
        Assert.False(restored["ownership_remaining"]!.GetValue<bool>());
        Assert.Equal("S:old",api.Object.Row["sacl"]!.ToString());
    }

    [Fact]
    public void AddingAndRestoringSecondSharePreservesFirstShareOwnership()
    {
        var api = new FakeFileApi(_dir);
        var secondPath = @"C:\projects";
        var second = new FakeFileApi.FakeObject(api, secondPath);
        api.AdditionalRoots.Add(secondPath, second);
        var manager = new FileAuditManager(_dir, _files, api);
        var audit = new FakeAudit();
        var first = manager.Reconcile(Policy(Request()), audit, Helpers.Now).Report!;
        manager.Acknowledge(first);

        var config = Config();
        var addedRoot = config["roots"]![0]!.DeepClone().AsObject();
        addedRoot["collection_scope_id"] = "scope:two";
        addedRoot["path"] = secondPath;
        addedRoot["share_name"] = "Projects";
        config["roots"]!.AsArray().Add(addedRoot);
        var applyBoth = Request("apply", "both", config);
        applyBoth["command"]!["collection_scope_ids"] = new JsonArray("scope:one", "scope:two");
        for (int i = 0; i < 2; i++)
        {
            var applied = manager.Reconcile(Policy(applyBoth), audit, Helpers.Now.AddSeconds(i + 1)).Report!;
            Assert.Equal("verified", applied["scopes"]![0]!["state"]!.ToString());
            manager.Acknowledge(applied);
        }
        Assert.Equal("S:exact-inheritance", api.Object.Row["sacl"]!.ToString());
        Assert.Equal("S:exact-inheritance", second.Row["sacl"]!.ToString());

        var restoreSecond = Request("restore", "second-only", config.DeepClone().AsObject());
        restoreSecond["command"]!["collection_scope_ids"] = new JsonArray("scope:two");
        var restored = manager.Reconcile(Policy(restoreSecond), audit, Helpers.Now.AddSeconds(3)).Report!;
        Assert.Equal("verified", restored["scopes"]![0]!["state"]!.ToString());
        Assert.False(restored["ownership_remaining"]!.GetValue<bool>());
        Assert.Equal("S:old", second.Row["sacl"]!.ToString());
        Assert.Equal("S:exact-inheritance", api.Object.Row["sacl"]!.ToString());
        manager.Acknowledge(restored);

        var restoreFirst = manager.Reconcile(Policy(Request("restore", "first-only")), audit, Helpers.Now.AddSeconds(4)).Report!;
        Assert.Equal("verified", restoreFirst["scopes"]![0]!["state"]!.ToString());
        Assert.Equal("S:old", api.Object.Row["sacl"]!.ToString());
    }

    [Fact]
    public void ForeignReadbackNeverBecomesOwnedAndRestoreDoesNotOverwriteIt()
    {
        var api = new FakeFileApi(_dir) { ForeignReadback = true };
        var manager = new FileAuditManager(_dir,_files,api);
        var report = manager.Reconcile(Policy(Request()),new FakeAudit(),Helpers.Now).Report!;
        Assert.NotEqual("verified",report["scopes"]![0]!["state"]!.ToString());
        manager.Acknowledge(report);
        manager.Reconcile(Policy(Request("restore","two")),new FakeAudit(),Helpers.Now);
        Assert.Equal(1,api.Writes);
        Assert.Equal("S:foreign",api.Object.Row["sacl"]!.ToString());
    }

    [Fact]
    public void GpoAuditMasksMaySupplyPolicyWhileLocalFileSaclRemainsUnmanagedByGpo()
    {
        var api=new FakeFileApi(_dir) { AuditOwner="managed_by_gpo" };
        var report=new FileAuditManager(_dir,_files,api).Reconcile(Policy(Request()),new FakeAudit("blocked"),Helpers.Now).Report!;
        Assert.Equal("verified",report["scopes"]![0]!["state"]!.ToString()); Assert.Equal(1,api.Writes);
    }

    [Fact]
    public void OwnerAndDaclReadbackDriftBlocksOwnershipEvenWhenSaclMatches()
    {
        var api=new FakeFileApi(_dir) { ChangeDacl=true };
        var report=new FileAuditManager(_dir,_files,api).Reconcile(Policy(Request()),new FakeAudit(),Helpers.Now).Report!;
        Assert.Equal("partial",report["scopes"]![0]!["state"]!.ToString());
        Assert.Equal("conflict",JsonNode.Parse(File.ReadAllBytes(Path.Combine(_dir,"state.json")))!["objects"]![@"C:\synthetic"]!["phase"]!.ToString());
    }

    [Fact]
    public void SharedPolicyConflictBlocksRestoreBeforeAnyNativeSaclWrite()
    {
        var api=new FakeFileApi(_dir); var manager=new FileAuditManager(_dir,_files,api);
        var applied=manager.Reconcile(Policy(Request()),new FakeAudit(),Helpers.Now).Report!; manager.Acknowledge(applied);
        var blocked=manager.Reconcile(Policy(Request("restore","restore-blocked")),new FakeAudit("blocked"),Helpers.Now).Report!;
        Assert.Equal(1,api.Writes); Assert.Equal("blocked",blocked["scopes"]![0]!["state"]!.ToString());
    }

    [Fact]
    public void CrashAfterNativeWriteRecoversExactNormalizationWithoutRepeatingMutation()
    {
        var api = new FakeFileApi(_dir) { FailAfterWrite = true };
        var policy = Policy(Request());
        var manager = new FileAuditManager(_dir,_files,api);
        var first = manager.Reconcile(policy,new FakeAudit(),Helpers.Now).Report!;
        manager.Acknowledge(first);
        var report = new FileAuditManager(_dir,_files,api).Reconcile(policy,new FakeAudit(),Helpers.Now).Report!;
        Assert.Equal("verified",report["scopes"]![0]!["state"]!.ToString()); Assert.Equal(1,api.Writes);
    }

    [Theory]
    [InlineData(false,"ok")]
    [InlineData(true,"managed_by_gpo")]
    [InlineData(true,"global_sacl_present")]
    public void WritesRequireManagementAndOwnership(bool manage, string owner)
    {
        var api = new FakeFileApi(_dir) { Owner = owner };
        var report = new FileAuditManager(_dir,_files,api).Reconcile(Policy(Request(),manage),new FakeAudit(),Helpers.Now).Report!;
        Assert.Equal(0,api.Writes); Assert.Equal("blocked",report["scopes"]![0]!["state"]!.ToString());
    }

    [Fact]
    public void OversizedDescriptorAndTraversalLimitsProduceBoundedPartialEvidence()
    {
        var api = new FakeFileApi(_dir); api.Object.Row["dacl"] = new string('x',40000);
        var config = Config(); config["max_bytes"]=1024; config["inventory_objects"]=1;
        var report = new FileAuditManager(_dir,_files,api).Reconcile(Policy(Request("check",config:config)),new FakeAudit(),Helpers.Now).Report!;
        var snapshot = report["snapshots"]![0]!;
        Assert.Empty(snapshot["objects"]!.AsArray()); Assert.Equal("partial",snapshot["completeness"]!.ToString());
        Assert.True(CanonicalJson.ToBytes(snapshot).Length <= 48*1024);
    }

    [Theory]
    [InlineData("inventory_depth",0,false)]
    [InlineData("inventory_objects",1,false)]
    [InlineData("inventory_depth",16,true)]
    public void DepthObjectAndNativePathLimitsAreReportedAsCoverageGaps(string limit,int value,bool denyChild)
    {
        var api=new FakeFileApi(_dir) { ChildNames=["child"],RejectChildren=denyChild };
        var config=Config(); config[limit]=value;
        var report=new FileAuditManager(_dir,_files,api).Reconcile(Policy(Request("check",config:config)),new FakeAudit(),Helpers.Now).Report!;
        Assert.Single(report["snapshots"]![0]!["objects"]!.AsArray());
        Assert.Equal(denyChild ? "directory_reparse_point" : "coverage_incomplete",report["scopes"]![0]!["reason_code"]!.ToString());
        Assert.Equal(1,report["snapshots"]![0]!["unread_objects"]!.GetValue<int>()); Assert.Equal(0,api.Writes);
    }

    [Fact]
    public void PagedInventoryKeepsEarlierMissingSaclEvidenceAcrossRestartAndAck()
    {
        var api=new FakeFileApi(_dir) { ChildNames=["child"],ChildSacl="S:exact-inheritance" }; api.Object.Row["dacl"]=new string('x',500);
        var config=Config(); config["max_bytes"]=1024; var policy=Policy(Request("check",config:config));
        var manager=new FileAuditManager(_dir,_files,api); var first=manager.Reconcile(policy,new FakeAudit(),Helpers.Now).Report!;
        Assert.True(first["snapshots"]![0]!["has_more"]!.GetValue<bool>()); Assert.Single(first["snapshots"]![0]!["objects"]!.AsArray());
        manager.Acknowledge(first);
        var last=new FileAuditManager(_dir,_files,api).Reconcile(policy,new FakeAudit(),Helpers.Now).Report!;
        Assert.False(last["snapshots"]![0]!["has_more"]!.GetValue<bool>()); Assert.Equal(1,last["snapshots"]![0]!["page_number"]!.GetValue<int>());
        Assert.False(last["snapshots"]![0]!["objects"]![0]!["sacl_missing"]!.GetValue<bool>());
        Assert.Equal("sacl_missing",last["scopes"]![0]!["reason_code"]!.ToString()); Assert.Equal("partial",last["scopes"]![0]!["state"]!.ToString());
    }

    private sealed class FakeAudit(string state="applied") : IWindowsAudit
    { public JsonObject Reconcile(AgentPolicy policy, DateTimeOffset now) => new() { ["windows_audit"]=new JsonObject { ["management_state"]=state } }; }

    internal sealed class FakeFileApi : IFileAuditApi
    {
        private readonly string _dir;
        public FakeFileApi(string dir) { _dir=dir; Object = new FakeObject(this); }
        public FakeObject Object { get; }
        public Dictionary<string, FakeObject> AdditionalRoots { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Writes { get; set; }
        public bool ForeignReadback { get; set; }
        public bool FailAfterWrite { get; set; }
        public string Owner { get; set; } = "ok";
        public string AuditOwner { get; set; } = "ok";
        public string AuditOwnership => AuditOwner;
        public bool ChangeDacl { get; set; }
        public string[] ChildNames { get; set; } = [];
        public bool RejectChildren { get; set; }
        public string ChildSacl { get; set; } = "S:old";
        public string? FailedRead { get; set; }
        public uint GroupError { get; set; } = 5;
        public bool UnresolvedGroupSid { get; set; }
        public bool IncompleteGroupPage { get; set; }
        public int LocalGroupReads { get; private set; }
        private void FailRead(string stage)
        {
            if (stage == FailedRead) throw new System.ComponentModel.Win32Exception(5, "synthetic private path or ACL");
        }
        public string Preflight(JsonArray roots)
        {
            if (FailedRead == "native_unavailable") throw new EntryPointNotFoundException();
            if (FailedRead == "preflight_privilege_missing") throw new FileAuditNativeReadException("agent_audit_privilege_unavailable", 1300);
            return Owner;
        }
        public int CheckPreflightCalls { get; private set; }
        public string CheckPreflight(JsonArray roots, bool describeReadErrors)
        {
            CheckPreflightCalls++;
            return Preflight(roots);
        }
        public Dictionary<string,int> QueryMasks(IReadOnlyCollection<string> guids)
        {
            if (FailedRead == "security_privilege_missing") throw new FileAuditNativeReadException("agent_audit_privilege_unavailable", 1300);
            FailRead("audit_policy");
            return guids.ToDictionary(g => g,g => 3);
        }
        public IFileAuditObject Open(string path,string root)
        {
            FailRead("directory");
            if (path == root) return AdditionalRoots.GetValueOrDefault(path, Object);
            if (RejectChildren) throw new AgentException("file_audit_reparse_point");
            var child=new FakeObject(this); child.Row["object_type"]="file"; child.Row["sacl"]=ChildSacl; child.Row["dacl"]=Object.Row["dacl"]!.DeepClone();
            return child;
        }
        public JsonObject Share(string name,string root)
        {
            if (FailedRead == "share_path_mismatch") throw new AgentException("file_audit_share_root_mismatch");
            FailRead("share");
            return new() { ["name"]=name,["path"]=root,["dacl"]="D:(A;;FA;;;SY)",["complete"]=true };
        }
        public JsonObject LocalGroups(int limit, bool allowUnresolvedSid = false)
        {
            LocalGroupReads++;
            if (FailedRead == "local_groups") throw new FileAuditNativeReadException("file_audit_groups_unavailable", GroupError);
            if (UnresolvedGroupSid && !allowUnresolvedSid) throw new AgentException("file_audit_group_sid_unresolved");
            return new() { ["complete"] = !UnresolvedGroupSid && !IncompleteGroupPage, ["groups"] = new JsonArray() };
        }
        public sealed class FakeObject(FakeFileApi api, string auditPath = @"C:\synthetic") : IFileAuditObject
        {
            public JsonObject Row { get; } = new() { ["object_id"]="1:2:3",["object_type"]="directory",["owner_sid"]="S-1-5-18",["dacl"]="D:(A;;FA;;;SY)",["sacl"]="S:old",["sacl_protected"]=false };
            public JsonObject Describe()
            {
                api.FailRead("acl");
                return (JsonObject)Row.DeepClone();
            }
            public string Plan(JsonArray aces) => Row["sacl"]!.ToString() == "S:foreign" ? "S:foreign-plus" : "S:exact-inheritance";
            public string ExpectedSacl(string value) => value == "S:old" ? value : "S:exact-inheritance";
            public void SetSacl(string value)
            {
                var state = JsonNode.Parse(File.ReadAllBytes(Path.Combine(api._dir,"state.json")))!;
                Assert.Contains(state["objects"]![auditPath]!["phase"]!.ToString(),new[] {"pending","restoring"});
                api.Writes++; Row["sacl"]=api.ForeignReadback ? "S:foreign" : value;
                if (api.ChangeDacl) Row["dacl"]="D:foreign";
                if (api.FailAfterWrite) { api.FailAfterWrite=false; throw new IOException("private-native-error"); }
            }
            public IEnumerable<string> Children() => Row["object_type"]!.ToString() == "directory" ? api.ChildNames : [];
            public bool InheritedFrom(string previous,string applied) => false;
            public void Dispose() { }
        }
    }
}
