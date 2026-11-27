using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class WindowsAuditTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();
    private readonly Api _api = new();
    public void Dispose() => Directory.Delete(_directory, true);
    internal sealed class Api : IWindowsAuditApi
    {
        public Dictionary<string, int> Values { get; } = WindowsAuditManager.Families.Values.SelectMany(x => x).DistinctBy(x => x.Guid).ToDictionary(x => x.Guid, _ => 0);
        public int Writes { get; private set; }
        public string Owner { get; set; } = "ok";
        public bool IsSystem { get; set; } = true;
        public int? CommandLine { get; set; }
        public bool IgnoreWrites { get; set; }
        public string? IgnoreGuid { get; set; }
        public int Reads { get; private set; }
        public Dictionary<string, string> Names { get; } = new();
        public Dictionary<string, int> Query(IReadOnlyCollection<string> guids) { Reads++; return guids.ToDictionary(g => g, g => Values[g]); }
        public void Set(IReadOnlyDictionary<string, int> changes) { Writes++; if (!IgnoreWrites) foreach (var item in changes) if (item.Key != IgnoreGuid) Values[item.Key] = item.Value; }
        public string Ownership() => Owner;
        public string CommandLineOwnership() => Owner;
        public IReadOnlyDictionary<string, string> PolicyNames(IReadOnlyCollection<string> guids) => Names;
        public JsonObject PowershellLogging() => new() { ["channel_enabled"] = false, ["script_block_logging_enabled"] = false };
        public DomainRootAuditSnapshot Root { get; set; } = new("DC=example,DC=test", "S:", false);
        public int RootWrites { get; private set; }
        public DomainRootAuditSnapshot? ReadDomainRootAudit() => Root;
        public string WithDomainRootAudit(string sddl) => sddl + "(AU;CISA;WP;;;WD)";
        public void SetDomainRootAudit(string domain, string expected, string sddl)
        {
            Assert.Equal(Root.Domain, domain);
            Assert.Equal(Root.Sddl, expected);
            RootWrites++;
            Root = Root with { Sddl = sddl, Configured = sddl.Contains("WP") };
        }
    }
    private static AgentPolicy Policy(bool manage = true)
    {
        var body = PolicyCycleTests.Assignment();
        body["collection_policy"]!["manage_windows_audit"] = manage;
        return AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load());
    }
    private WindowsAuditManager Manager(IDurableFiles? files = null) => new(_directory, files ?? new PhysicalDurableFiles(), _api);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WorkstationPolicyEnablesAndReportsProcessCreationAndPlugAndPlay(bool commandLine)
    {
        var policy = Policy();
        policy.Workstations!["families"]!["processes"] = true;
        policy.Workstations["families"]!["usb"] = true;
        policy = policy with { Control = policy.Control with { AuditProcessCommandLine = commandLine } };
        var report = Manager().Reconcile(policy, Helpers.Now)["windows_audit"]!;
        Assert.Equal("applied", report["management_state"]!.GetValue<string>());
        foreach (var (family, subcategory) in new[] { ("processes", "process_creation"), ("usb", "pnp_activity") })
        {
            var row = Assert.Single(report["families"]![family]!["required"]!.AsArray())!;
            Assert.Equal(subcategory, row["subcategory"]!.GetValue<string>());
            Assert.True(row["actual_success"]!.GetValue<bool>());
            Assert.Equal(1, _api.Values[row["guid"]!.GetValue<string>()]);
        }
        Assert.Equal(commandLine ? 1 : (int?)null, _api.CommandLine);
    }

    private static AgentPolicy DcPolicy(bool manage = true) => Policy(manage) with { Workstations = null, AdDc = new JsonObject() };

    private static AgentPolicy RootPolicy(bool enable = true) => DcPolicy(enable) with {
        Control = DcPolicy(enable).Control with { ManageDomainRootSacl = enable } };
    private static JsonNode RootRow(JsonObject report) => report["windows_audit"]!["families"]!["domain_controller"]!["required"]!.AsArray()
        .Single(r => r!["subcategory"]!.ToString() == "domain_root_sacl")!;

    [Theory]
    [InlineData("directory_service_access", "0cce923b-69ae-11d9-bed3-505054503030")]
    [InlineData("other_account_management", "0cce923a-69ae-11d9-bed3-505054503030")]
    [InlineData("authentication_policy_change", "0cce9230-69ae-11d9-bed3-505054503030")]
    [InlineData("authorization_policy_change", "0cce9231-69ae-11d9-bed3-505054503030")]
    public void DcEnablesTheNativeRareEventSubcategories(string name, string guid)
    {
        var rows = Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!["families"]!["domain_controller"]!["required"]!.AsArray();
        var row = Assert.Single(rows, r => r!["subcategory"]!.ToString() == name)!;
        Assert.Equal(guid, row["guid"]!.GetValue<string>());
        Assert.True(row["actual_success"]!.GetValue<bool>());
        if (name == "other_account_management") Assert.True(row["actual_failure"]!.GetValue<bool>());
    }

    [Fact]
    public void RootAuditReadsWithoutConsentAndAddsOnceWithDurableRestoreAcrossRestart()
    {
        Assert.Equal("missing", RootRow(Manager().Reconcile(DcPolicy(), Helpers.Now))["state"]!.ToString());
        Assert.Equal(0, _api.RootWrites);
        var before = _api.Root.Sddl;
        var enabled = RootRow(Manager().Reconcile(RootPolicy(), Helpers.Now));
        Assert.Equal("ok", enabled["state"]!.ToString());
        Assert.Equal(Helpers.Now, DateTimeOffset.Parse(enabled["enabled_at"]!.ToString()));
        Assert.Equal(before + "(AU;CISA;WP;;;WD)", _api.Root.Sddl);
        Manager().Reconcile(RootPolicy(), Helpers.Now.AddMinutes(1));
        Assert.Equal(1, _api.RootWrites);
        Assert.Equal("restored", RootRow(Manager().Reconcile(RootPolicy(false), Helpers.Now.AddMinutes(2)))["state"]!.ToString());
        Assert.Equal(before, _api.Root.Sddl);
        Assert.Equal(2, _api.RootWrites);
    }

    [Fact]
    public void RootAuditPreservesExistingEntryAndRefusesExternalDriftOrFailedIntent()
    {
        _api.Root = _api.Root with { Sddl = "S:(AU;CISA;WP;;;AU)", Configured = true };
        Manager().Reconcile(RootPolicy(), Helpers.Now);
        Manager().Reconcile(RootPolicy(false), Helpers.Now);
        Assert.Equal(0, _api.RootWrites);
        _api.Root = new("DC=example,DC=test", "S:", false);
        var files = new FaultyFiles(new PhysicalDurableFiles()) { FailWrite = _ => true };
        Assert.Equal("unknown", RootRow(Manager(files).Reconcile(RootPolicy(), Helpers.Now))["state"]!.ToString());
        Assert.Equal(0, _api.RootWrites);
        Manager().Reconcile(RootPolicy(), Helpers.Now);
        _api.Root = _api.Root with { Sddl = "S:(AU;SA;RP;;;WD)", Configured = false };
        Assert.Equal("missing", RootRow(Manager().Reconcile(RootPolicy(false), Helpers.Now))["state"]!.ToString());
        Assert.Equal(1, _api.RootWrites);
    }

    [Fact]
    public void RootConsentIsRequiredInParsedPolicyAndCannotWriteWithoutSystemIdentity()
    {
        var body = PolicyCycleTests.Assignment();
        body["collection_policy"]!["manage_domain_root_sacl"] = true;
        Assert.True(AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()).Control.ManageDomainRootSacl);
        body["collection_policy"]!["manage_domain_root_sacl"] = "true";
        Assert.Throws<AgentException>(() => AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load()));
        _api.IsSystem = false;
        Assert.Equal("missing", RootRow(Manager().Reconcile(RootPolicy(), Helpers.Now))["state"]!.ToString());
        Assert.Equal(0, _api.RootWrites);
    }

    [Fact]
    public void RootResumesAfterMutationBeforeConfirmationWasSaved()
    {
        var before = _api.Root.Sddl;
        _api.Root = _api.Root with { Sddl = before + "(AU;CISA;WP;;;WD)", Configured = true };
        File.WriteAllText(Path.Combine(_directory, "domain-root-sacl.json"), new JsonObject {
            ["domain"] = _api.Root.Domain, ["previous"] = before, ["applied"] = _api.Root.Sddl,
            ["phase"] = "pending", ["enabled_at"] = null }.ToJsonString());
        Assert.Equal("ok", RootRow(Manager().Reconcile(RootPolicy(), Helpers.Now))["state"]!.ToString());
        Assert.Equal(0, _api.RootWrites);
        Manager().Reconcile(RootPolicy(false), Helpers.Now.AddMinutes(1));
        Assert.Equal(before, _api.Root.Sddl);
        Assert.Equal(1, _api.RootWrites);
    }

    [Fact]
    public void DcRequirementsCoverDetectionsAndDomainChangesAndRestorePreviousMasks()
    {
        var expected = new Dictionary<string, int> {
            ["kerberos_authentication_service"] = 3, ["kerberos_service_ticket_operations"] = 1,
            ["credential_validation"] = 3, ["logon"] = 3, ["user_account_management"] = 1,
            ["security_group_management"] = 1, ["computer_account_management"] = 1,
            ["audit_policy_change"] = 1, ["other_object_access"] = 1, ["directory_service_changes"] = 1,
            ["directory_service_access"] = 1, ["other_account_management"] = 3,
            ["authentication_policy_change"] = 1, ["authorization_policy_change"] = 1,
        };
        foreach (var guid in _api.Values.Keys.ToArray()) _api.Values[guid] = 2;
        var before = new Dictionary<string, int>(_api.Values);
        var report = Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!;
        var rows = report["families"]!["domain_controller"]!["required"]!.AsArray();
        foreach (var (name, mask) in expected)
        {
            var row = Assert.Single(rows, r => r!["subcategory"]!.ToString() == name)!;
            Assert.Equal((mask & 1) != 0, row["success"]!.GetValue<bool>());
            Assert.Equal((mask & 2) != 0, row["failure"]!.GetValue<bool>());
            Assert.True(row["actual_success"]!.GetValue<bool>());
            Assert.True(row["actual_failure"]!.GetValue<bool>()); // Preserve unrelated failure auditing.
            Assert.Equal(Helpers.Now, DateTimeOffset.Parse(row["enabled_at"]!.ToString()));
        }
        var kerberos = rows.Single(r => r!["subcategory"]!.ToString() == "kerberos_authentication_service")!;
        Assert.Equal(new[] { 1, 2, 5 }, kerberos["detections"]!.AsArray().Select(n => n!.GetValue<int>()));
        Assert.True(rows.Single(r => r!["subcategory"]!.ToString() == "directory_service_changes")!["domain_changes"]!.GetValue<bool>());
        // A new manager models a service restart: originals must be on disk.
        Assert.Equal("restored", Manager().Reconcile(DcPolicy(false), Helpers.Now.AddMinutes(1))["windows_audit"]!["management_state"]!.ToString());
        Assert.All(before, pair => Assert.Equal(pair.Value, _api.Values[pair.Key]));
    }

    [Fact]
    public void DcOptOutSkipsWritesAndOptInOnlyChangesAuditSubcategories()
    {
        _api.CommandLine = 0;
        var before = new Dictionary<string, int>(_api.Values);
        Manager().Reconcile(DcPolicy(false), Helpers.Now);
        Assert.Equal(0, _api.Writes);

        Manager().Reconcile(DcPolicy(), Helpers.Now);
        Assert.True(_api.Writes > 0);
        Assert.Equal(0, _api.RootWrites);
        Assert.Equal(0, _api.CommandLine);

        Manager().Reconcile(DcPolicy(false), Helpers.Now);
        Assert.All(before, pair => Assert.Equal(pair.Value, _api.Values[pair.Key]));
    }

    [Fact]
    public void DcReportsPolicyThatRejectsWriteAndDoesNotRetryOrRestoreOverIt()
    {
        _api.IgnoreWrites = true;
        var report = Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!;
        Assert.Equal("blocked", report["management_state"]!.ToString());
        Assert.All(report["families"]!["domain_controller"]!["required"]!.AsArray().Where(r => r!["subcategory"]!.ToString() != "domain_root_sacl"), row => {
            Assert.Equal("managed_by_gpo", row!["state"]!.ToString());
            Assert.Null(row["enabled_at"]);
        });
        var writes = _api.Writes;
        Manager().Reconcile(DcPolicy(false), Helpers.Now.AddMinutes(1));
        Assert.Equal(writes, _api.Writes);
    }

    [Fact]
    public void DcDetectsSettingsRevertedByPolicyAfterRestart()
    {
        Manager().Reconcile(DcPolicy(), Helpers.Now);
        var guid = _api.Values.First(p => p.Value != 0).Key;
        _api.Values[guid] = 0;
        var writes = _api.Writes;
        var report = Manager().Reconcile(DcPolicy(), Helpers.Now.AddDays(1))["windows_audit"]!;
        Assert.Equal("managed_by_gpo", report["families"]!["domain_controller"]!["required"]!.AsArray().Single(r => r!["guid"]!.ToString() == guid)!["state"]!.ToString());
        Assert.Equal(writes, _api.Writes);
    }

    [Fact]
    public void DcConfiguresUnmanagedSettingsAndNamesThePolicyWithoutWritingItsSetting()
    {
        var kerberos = WindowsAuditManager.Families["domain_controller"].Single(r => r.Name == "kerberos_authentication_service");
        _api.Names[kerberos.Guid] = "LAB Audit"; _api.Owner = "managed_by_gpo";
        var report = Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!;
        var rows = report["families"]!["domain_controller"]!["required"]!.AsArray();
        var row = Assert.Single(rows, r => r!["guid"]!.ToString() == kerberos.Guid)!;
        Assert.Equal("LAB Audit", row["policy_name"]!.ToString());
        Assert.Equal("managed_by_gpo", row["state"]!.ToString());
        Assert.Equal(0, _api.Values[kerberos.Guid]);
        Assert.All(rows.Where(r => r!["guid"]!.ToString() != kerberos.Guid && r["subcategory"]!.ToString() != "domain_root_sacl"), r => Assert.Equal("ok", r!["state"]!.ToString()));
        Assert.Equal("blocked", report["management_state"]!.ToString());
    }

    [Fact]
    public void DcRechecksDailyOnNewCommandAndAfterRestart()
    {
        var manager = Manager();
        var policy = DcPolicy(false);
        manager.Reconcile(policy, Helpers.Now);
        manager.Reconcile(policy, Helpers.Now.AddMinutes(3));
        var reads = _api.Reads;
        manager.Reconcile(policy, Helpers.Now.AddHours(12));
        Assert.Equal(reads, _api.Reads);
        manager.Reconcile(policy, Helpers.Now.AddDays(1).AddMinutes(3));
        Assert.True(_api.Reads > reads);
        reads = _api.Reads;
        manager.Reconcile(policy with { Revision = 2, Control = policy.Control with { ManageWindowsAudit = true } }, Helpers.Now.AddDays(1).AddMinutes(4));
        Assert.True(_api.Reads > reads);
        reads = _api.Reads;
        Manager().Reconcile(policy, Helpers.Now.AddDays(1).AddMinutes(5));
        Assert.True(_api.Reads > reads);
    }

    [Fact]
    public void DcPartialReadbackReportsEachSettingAndRetainsOriginals()
    {
        _api.IgnoreGuid = WindowsAuditManager.Families["domain_controller"][0].Guid;
        var report = Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!;
        var rows = report["families"]!["domain_controller"]!["required"]!.AsArray();
        Assert.Equal("blocked", report["management_state"]!.ToString());
        Assert.Equal("managed_by_gpo", Assert.Single(rows, r => r!["guid"]!.ToString() == _api.IgnoreGuid)!["state"]!.ToString());
        Assert.All(rows.Where(r => r!["guid"]!.ToString() != _api.IgnoreGuid && r["subcategory"]!.ToString() != "domain_root_sacl"), r => {
            Assert.Equal("ok", r!["state"]!.ToString());
            Assert.NotNull(r["enabled_at"]);
        });
        Manager().Reconcile(DcPolicy(false), Helpers.Now.AddMinutes(1));
        Assert.All(_api.Values, p => Assert.Equal(0, p.Value));
    }

    [Fact]
    public void PowershellDisabledIsReportedWithoutEnablingIt()
    {
        // PowerShell logging is reported for the protection family, which collects 4104.
        var body = PolicyCycleTests.Assignment();
        body["collection_policy"]!["manage_windows_audit"] = false;
        body["assigned_modules"]![0]!["config"]!["families"]!["protection"] = true;
        var policy = AgentPolicy.Parse(body, Helpers.AgentId, EventCatalog.Load());
        var report = Manager().Reconcile(policy, Helpers.Now)["windows_audit"]!;
        Assert.False(report["powershell_logging"]!["channel_enabled"]!.GetValue<bool>());
        Assert.False(report["powershell_logging"]!["script_block_logging_enabled"]!.GetValue<bool>());
        Assert.Equal(0, _api.Writes);
    }

    [Fact]
    public void OwnedFileMasksSurviveModuleRemovalAndManagementDisableUntilExplicitRestore()
    {
        var masks=FileAuditPolicy.Parse(FileAuditManagerTests.Config()).RequiredMasks();
        foreach (var guid in masks.Keys) _api.Values.TryAdd(guid,0);
        var policy=Policy() with { FileAuditMasks=masks,FileAuditManage=true };
        Manager().Reconcile(policy,Helpers.Now);
        Assert.All(masks,p => Assert.Equal(p.Value,_api.Values[p.Key]));
        Manager().Reconcile(Policy(false) with { FileAuditMasks=masks },Helpers.Now);
        Assert.All(masks,p => Assert.Equal(p.Value,_api.Values[p.Key]));
        Manager().Reconcile(Policy(false),Helpers.Now);
        Assert.All(masks,p => Assert.Equal(0,_api.Values[p.Key]));
    }

    [Fact]
    public void ChangesAreReversibleAndExternalDriftBlocksFurtherWrites()
    {
        var manager = Manager();
        Assert.Equal("applied", manager.Reconcile(Policy(), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
        Assert.Equal(1, _api.Writes);
        Assert.Equal("restored", manager.Reconcile(Policy(false), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
        Assert.All(_api.Values.Values, value => Assert.Equal(0, value));
        manager.Reconcile(Policy(), Helpers.Now);
        _api.Values[WindowsAuditManager.Families["logons"][0].Guid] = 2;
        var writes = _api.Writes;
        Assert.Equal("blocked", manager.Reconcile(Policy(), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
        Assert.Equal(writes, _api.Writes);
        Assert.Equal("blocked", manager.Reconcile(Policy(false), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
    }

    [Fact]
    public void NoNativeWriteHappensBeforeDurableIntentOrWithoutOwnership()
    {
        var files = new FaultyFiles(new PhysicalDurableFiles()) { FailWrite = _ => true };
        Assert.Equal("unknown", Manager(files).Reconcile(Policy(), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
        Assert.Equal(0, _api.Writes);
        _api.Owner = "managed_by_gpo";
        Assert.Equal("blocked", Manager().Reconcile(Policy(), Helpers.Now)["windows_audit"]!["management_state"]!.GetValue<string>());
        Assert.Equal(0, _api.Writes);
        _api.Owner = "ok"; _api.IsSystem = false;
        Manager().Reconcile(Policy(), Helpers.Now);
        Assert.Equal(0, _api.Writes);
    }

    [Fact]
    public void InvalidSavedSettingsAreReportedWithoutNativeWrites()
    {
        var state = new JsonObject { ["subcategories"] = new JsonObject {
            [WindowsAuditManager.Families["domain_controller"][0].Guid] = 0 }, ["command_line"] = null };
        File.WriteAllText(Path.Combine(_directory, "state.json"), state.ToJsonString());
        Assert.Equal("unknown", Manager().Reconcile(DcPolicy(), Helpers.Now)["windows_audit"]!["management_state"]!.ToString());
        Assert.Equal(0, _api.Writes);
    }
}
