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
        Assert.Equal("coverage_incomplete",report["scopes"]![0]!["reason_code"]!.ToString());
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
        public string Preflight(JsonArray roots) => Owner;
        public Dictionary<string,int> QueryMasks(IReadOnlyCollection<string> guids) => guids.ToDictionary(g => g,g => 3);
        public IFileAuditObject Open(string path,string root)
        {
            if (path == root) return Object;
            if (RejectChildren) throw new AgentException("file_audit_reparse_point");
            var child=new FakeObject(this); child.Row["object_type"]="file"; child.Row["sacl"]=ChildSacl; child.Row["dacl"]=Object.Row["dacl"]!.DeepClone();
            return child;
        }
        public JsonObject Share(string name,string root) => new() { ["name"]=name,["path"]=root,["dacl"]="D:(A;;FA;;;SY)",["complete"]=true };
        public JsonObject LocalGroups(int limit) => new() { ["complete"]=true,["groups"]=new JsonArray() };
        public sealed class FakeObject(FakeFileApi api) : IFileAuditObject
        {
            public JsonObject Row { get; } = new() { ["object_id"]="1:2:3",["object_type"]="directory",["owner_sid"]="S-1-5-18",["dacl"]="D:(A;;FA;;;SY)",["sacl"]="S:old",["sacl_protected"]=false };
            public JsonObject Describe() => (JsonObject)Row.DeepClone();
            public string Plan(JsonArray aces) => Row["sacl"]!.ToString() == "S:foreign" ? "S:foreign-plus" : "S:exact-inheritance";
            public string ExpectedSacl(string value) => value == "S:old" ? value : "S:exact-inheritance";
            public void SetSacl(string value)
            {
                var state = JsonNode.Parse(File.ReadAllBytes(Path.Combine(api._dir,"state.json")))!;
                Assert.Contains(state["objects"]![@"C:\synthetic"]!["phase"]!.ToString(),new[] {"pending","restoring"});
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
