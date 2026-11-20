using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Server.Compatibility;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Behavioral vectors from tests/semantic/test_windows_ad_dc_normalization.py.
public sealed class WindowsAdDcNormalizationTests
{
    const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
    const string TaskChannel = "Microsoft-Windows-TaskScheduler/Operational";
    const string Instance = "{12345678-90AB-CDEF-1234-567890ABCDEF}";
    const string CanonicalInstance = "12345678-90ab-cdef-1234-567890abcdef";
    const string AccountSid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string GroupSid = "S-1-5-21-100000001-200000002-300000003-512";

    static JsonObject Source(int id, JsonObject? data = null, string channel = "Security", string provider = SecurityProvider) => new()
    {
        ["id"] = 1, ["event_id"] = id, ["channel"] = channel, ["provider_name"] = provider,
        ["server_id"] = 17, ["source_host_id"] = 17, ["domain_id"] = 8,
        ["computer"] = "dc-a.example.test", ["time_created_utc"] = "2026-09-11T00:00:00Z",
        ["event_data_json"] = data ?? new JsonObject()
    };

    public static TheoryData<int> SecurityHistory => new(
        4740, 4767, 4723, 4724, 4720, 4722, 4725, 4726, 4738, 4781,
        4728, 4729, 4732, 4733, 4756, 4757, 4727, 4730, 4737, 4731,
        4734, 4735, 4754, 4755, 4758, 4764, 4624, 4625, 4771, 4776, 4719, 1102);

    [Theory, MemberData(nameof(SecurityHistory))]
    public void Retained_security_vocabulary_resolves_exact_provider(int id)
    {
        string provider = id == 1102 ? "Microsoft-Windows-Eventlog" : SecurityProvider;
        Assert.NotEqual("event.unknown", SemanticNormalization.ProjectWindows(Source(id, provider: provider)).Type);
        Assert.Equal("event.unknown", SemanticNormalization.ProjectWindows(Source(id, provider: "Unrelated-Provider")).Type);
    }

    [Theory, InlineData("System", "Service Control Manager", "service.installed.fragment")]
    [InlineData("System", "Unrelated-Provider", "event.unknown")]
    [InlineData("Security", "Service Control Manager", "event.unknown")]
    public void Service_install_requires_its_exact_stream_and_provider(string channel, string provider, string expected)
        => Assert.Equal(expected, SemanticNormalization.Normalize(Source(7045, ServiceData(), channel, provider)).Type);

    static JsonObject ServiceData() => new()
    {
        ["ServiceName"] = "fixture-service", ["ServiceFileName"] = "C:/fixture.exe",
        ["ServiceAccount"] = "LocalSystem", ["ServiceStartType"] = "2", ["ClientProcessId"] = "0x44",
        ["SubjectUserSid"] = AccountSid, ["SubjectUserName"] = "fixture-system",
        ["SubjectDomainName"] = "example.test", ["SubjectLogonId"] = "0x3e7"
    };

    [Fact]
    public void Service_install_preserves_catalog_facts_without_process_attribution()
    {
        var semantic = SemanticNormalization.Normalize(Source(7045, ServiceData(), "System", "Service Control Manager"));
        var facts = Direct4624Facts.Document(1, Projection(7045, "System", "Service Control Manager", ServiceData()));
        foreach (var (key, value) in new[] { ("service_name", "fixture-service"), ("service_file", "C:/fixture.exe"), ("service_account", "LocalSystem"), ("service_start_type", "2") })
        {
            Assert.Equal(value, semantic.Facts[key]?.ToString()); Assert.Equal(value, facts[key]?.ToString());
        }
        foreach (string key in new[] { "native_process_id", "process_user_sid", "process_user_name", "process_user_domain", "process_logon_id" })
        {
            Assert.False(semantic.Facts.ContainsKey(key)); Assert.Null(facts[key]);
        }
    }

    [Theory, InlineData(100, "InstanceId"), InlineData(102, "InstanceId")]
    [InlineData(200, "TaskInstanceId"), InlineData(201, "TaskInstanceId")]
    public void Task_correlation_is_canonical_and_persisted_in_archive(int id, string field)
    {
        var row = NativeRow(id, TaskChannel, "Microsoft-Windows-TaskScheduler", new JsonObject { [field] = Instance, ["TaskName"] = "\\SLI\\Example" });
        var projection = Direct4624Projection.Create(row);
        Assert.Equal(CanonicalInstance, Direct4624Core.NpsCorrelation(projection));
        var archive = DirectNpsArchiveRows.Event(1, 1, 2, 3, 4, 5, new DateTime(2026, 7, 28, 0, 0, 0, DateTimeKind.Utc), row, projection);
        Assert.Equal(CanonicalInstance, archive["correlation_id"]?.ToString());
        Assert.Equal(Instance, JsonNode.Parse(archive["event_data_json"]!.ToString())![field]?.ToString());
    }

    [Theory, InlineData("Security", 100, "InstanceId", Instance)]
    [InlineData(TaskChannel, 106, "InstanceId", Instance)]
    [InlineData(TaskChannel, 100, "InstanceId", "not-a-uuid")]
    [InlineData(TaskChannel, 200, "InstanceId", Instance)]
    public void Task_correlation_fails_closed_for_unowned_shapes(string channel, int id, string field, string value)
        => Assert.Null(Direct4624Core.NpsCorrelation(Projection(id, channel, "Microsoft-Windows-TaskScheduler", new JsonObject { [field] = value })));

    [Fact]
    public void Import_preserves_execution_process_id_for_powershell_bridge()
    {
        var row = NativeRow(4103, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", new JsonObject { ["CommandName"] = "Get-ADUser" });
        Assert.Equal("4096", DirectNativeEvent.Data(row)["SystemExecutionProcessId"]?.ToString());
        Assert.Equal("4096", Direct4624Projection.Create(row).Data["SystemExecutionProcessId"]);
    }

    [Fact]
    public void Task_correlation_metrics_require_one_to_one_pair_cardinality()
    {
        var rows = JsonNode.Parse("""
            [{"event_id":100,"total":293,"nonempty":293,"distinct_ids":293,"uuid_shaped":293},
             {"event_id":102,"total":284,"nonempty":284,"distinct_ids":284,"uuid_shaped":284},
             {"event_id":200,"total":297,"nonempty":297,"distinct_ids":293,"uuid_shaped":297},
             {"event_id":201,"total":288,"nonempty":288,"distinct_ids":284,"uuid_shaped":288}]
            """)!.AsArray();
        var pairs = JsonNode.Parse("""[{"opener":100,"closer":102,"shared_ids":284},{"opener":200,"closer":201,"shared_ids":284}]""")!.AsArray();
        var result = SemanticNormalization.EvaluateTaskCorrelation(rows, pairs);
        Assert.Equal("ok", result["status"]?.ToString()); Assert.True(result["normalization_ready"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["100_to_102_by_correlation_id"] = true, ["200_to_201_by_correlation_id"] = false }, result["safe_pair_candidates"]));
        Assert.False(result["raw_identifiers_in_report"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(rows, result["event_metrics"])); Assert.True(JsonNode.DeepEquals(pairs, result["pair_metrics"]));
    }

    [Theory, InlineData("DNS Server", 5504, "Microsoft-Windows-DNS-Server-Service")]
    [InlineData("System", 101, "Application Management Group Policy")]
    [InlineData("System", 999, "Microsoft-Windows-GroupPolicy")]
    [InlineData(TaskChannel, 101, "Microsoft-Windows-TaskScheduler")]
    public void Warm_message_policy_is_stream_scoped(string channel, int id, string provider)
    {
        var p = Projection(id, channel, provider, new()) with { MessageText = " bounded diagnostic context " };
        Assert.True(Direct4624Facts.RetainMessageSample(channel, id, provider));
        if (id == 999) Assert.False(Direct4624Facts.HasFacts(Direct4624Facts.Document(1, p)));
        else
        {
            Assert.Equal("bounded diagnostic context", Direct4624Facts.Document(1, p)["message_sample"]?.ToString());
            // Executed unchanged Python event_facts_from_v1 for these three rows.
            Assert.Equal("50574e1e7654c3a9ed68390caaa0a895321f633c312ce9436a1a5888c8eadb04", Convert.ToHexStringLower(Direct4624Facts.Hash(1, p)));
            Assert.Equal(new string('я', 220), Direct4624Facts.Document(1, p with { MessageText = new string('я', 221) })["message_sample"]?.ToString());
        }
        var foreign = Projection(101, "Security", "Unrelated", new()) with { MessageText = "must stay only in canonical archive" };
        Assert.False(Direct4624Facts.RetainMessageSample("Security", 101, "Unrelated"));
        Assert.False(Direct4624Facts.HasFacts(Direct4624Facts.Document(1, foreign)));
    }

    [Fact]
    public void Powershell_facts_are_stream_and_event_scoped()
    {
        const string channel = "Microsoft-Windows-PowerShell/Operational", provider = "Microsoft-Windows-PowerShell";
        var command = Direct4624Facts.Document(1, Projection(4103, channel, provider, new JsonObject
        { ["User"] = "example.test\\operator", ["CommandName"] = "Get-ADUser", ["SystemExecutionProcessId"] = "4096", ["ScriptBlockText"] = "must not leak" }));
        Assert.Equal("example.test\\operator", command["powershell_user_name"]?.ToString());
        Assert.Equal("Get-ADUser", command["powershell_command_name"]?.ToString());
        Assert.Equal("4096", command["powershell_process_id"]?.ToString()); Assert.Null(command["powershell_script_block_text"]);
        var script = Direct4624Facts.Document(2, Projection(4104, channel, provider, new JsonObject
        { ["User"] = "example.test\\operator", ["CommandName"] = "must not leak", ["ScriptBlockText"] = "Get-ADUser -Identity alice" }));
        Assert.Equal("example.test\\operator", script["powershell_user_name"]?.ToString());
        Assert.Null(script["powershell_command_name"]); Assert.Equal("Get-ADUser -Identity alice", script["powershell_script_block_text"]?.ToString());
        Assert.False(Direct4624Facts.HasFacts(Direct4624Facts.Document(3, Projection(4104, "Security", SecurityProvider, new JsonObject
        { ["CommandName"] = "must not leak", ["ScriptBlockText"] = "must not leak" }))));
    }

    [Theory, InlineData(4688, "NewProcessId", "NewProcessName"), InlineData(4689, "ProcessId", "ProcessName")]
    public void Security_process_facts_use_created_process_identity(int id, string pidField, string nameField)
    {
        var data = new JsonObject { ["ProcessId"] = "0x11", [pidField] = "0x1000", [nameField] = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" };
        var facts = Direct4624Facts.Document(1, Projection(id, "Security", SecurityProvider, data));
        Assert.Equal("4096", facts["process_id"]?.ToString()); Assert.EndsWith("powershell.exe", facts["process_name"]?.ToString());
    }

    [Fact]
    public void Entity_and_state_semantics_do_not_leak_to_foreign_streams()
    {
        var group = new JsonObject { ["TargetUserName"] = "fixture-group", ["TargetSid"] = GroupSid };
        Assert.Contains(Projection(4728, "Security", SecurityProvider, group).Entities, e => e.Type == "ad_group");
        Assert.DoesNotContain(Projection(4728, "Unrelated/Channel", SecurityProvider, group).Entities, e => e.Type == "ad_group");
        Assert.Contains(Projection(7045, "System", "Service Control Manager", ServiceData()).Entities, e => e.Type == "service");
        Assert.Contains(Projection(4769, "Security", SecurityProvider, new JsonObject { ["TargetServerName"] = "dc-target.example.test" }).Entities, e => e.Type == "asset" && e.Role == "target");
        foreach (var (id, channel, provider, field, expected) in new[] { (4740, "Security", SecurityProvider, "status", "locked"), (140, TaskChannel, "Microsoft-Windows-TaskScheduler", "state_type", "scheduled_task.configuration") })
        {
            var row = NativeRow(id, channel, provider, new());
            Assert.Equal(expected, DirectStateProjection.Candidate(row, Direct4624Projection.Create(row), 1, 1)?[field]?.ToString());
        }
        var foreign = NativeRow(4740, "Unrelated", SecurityProvider, new());
        Assert.Null(DirectStateProjection.Candidate(foreign, Direct4624Projection.Create(foreign), 1, 1));
    }

    [Theory, InlineData(4720, "directory.account.created"), InlineData(4724, "account.password.reset.attempted")]
    [InlineData(4740, "authentication.account.locked"), InlineData(4767, "authentication.account.unlocked")]
    public void Account_relations_use_source_native_target_sid(int id, string type)
    {
        var actual = SemanticNormalization.Normalize(Source(id, new JsonObject { ["TargetSid"] = AccountSid }));
        Assert.Equal(type, actual.Type); Assert.Equal("8", actual.Facts["domain_id"]?.ToString());
        Assert.Equal(AccountSid, actual.Facts["relation_account_sid"]?.ToString());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["state"] = "exact", ["sid_field"] = "TargetSid" }, actual.Quality["relation_account_identity"]));
    }

    [Fact]
    public void Group_relations_require_exact_member_and_group_sids()
    {
        var actual = SemanticNormalization.Normalize(Source(4728, new JsonObject { ["MemberSid"] = AccountSid, ["TargetSid"] = GroupSid }));
        Assert.Equal("group.member.added", actual.Type); Assert.Equal("8", actual.Facts["domain_id"]?.ToString());
        Assert.Equal(AccountSid, actual.Facts["relation_member_sid"]?.ToString()); Assert.Equal(GroupSid, actual.Facts["relation_group_sid"]?.ToString());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["state"] = "exact", ["member_sid_field"] = "MemberSid", ["group_sid_field"] = "TargetSid" }, actual.Quality["relation_membership_identity"]));
        var names = SemanticNormalization.Normalize(Source(4733, new JsonObject { ["MemberName"] = "alice", ["TargetUserName"] = "Administrators" }));
        Assert.Equal("group.member.removed", names.Type); Assert.False(names.Facts.ContainsKey("relation_member_sid")); Assert.False(names.Facts.ContainsKey("relation_group_sid"));
        Assert.Equal("not_exact", names.Quality["relation_membership_identity"]?["state"]?.ToString());
    }

    [Theory, InlineData(null, "attempted", "unknown"), InlineData("0x8020000000000000", "succeeded", "success")]
    [InlineData("0x8010000000000000", "attempted", "failure")]
    public void Password_reset_success_requires_native_audit_keyword(string? keywords, string type, string result)
    {
        var source = Source(4724, new JsonObject { ["TargetUserSid"] = AccountSid, ["Status"] = "0x0" }); source["keywords"] = keywords;
        var actual = SemanticNormalization.Normalize(source);
        Assert.Equal("account.password.reset." + type, actual.Type); Assert.Equal(result, actual.Facts["result"]?.ToString());
    }

    [Fact]
    public void Logon_uses_target_user_sid_and_source_scoped_session()
    {
        var actual = SemanticNormalization.Normalize(Source(4624, new JsonObject { ["TargetUserSid"] = AccountSid, ["TargetSid"] = GroupSid, ["TargetLogonId"] = "0x123", ["LogonType"] = "3" }));
        Assert.Equal("authentication.session.created", actual.Type); Assert.Equal("17:0x123", actual.Roles["session_principal"]?.ToString());
        Assert.Equal("3", actual.Facts["logon_type"]?.ToString()); Assert.Equal(AccountSid, actual.Facts["relation_account_sid"]?.ToString());
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["state"] = "exact", ["sid_field"] = "TargetUserSid" }, actual.Quality["relation_account_identity"]));
    }

    [Fact]
    public void Windows_report_vocabulary_matches_source_pack_contracts()
    {
        Assert.Equal("lockout", LegacySemantics.AccountCategory(4740)); Assert.Equal("high", LegacySemantics.AccountSeverity(4740));
        Assert.DoesNotContain(999999, LegacySemantics.AccountIds);
        Assert.Contains(4624, LegacySemantics.Family("authentication")); Assert.Contains(4728, LegacySemantics.Family("account_management"));
        Assert.Equal(new[] { 4624 }, LegacySemantics.AnalysisFamily("successful_logon"));
        Assert.Equal(new[] { 4768, 4769, 4771 }, LegacySemantics.AnalysisFamily("kerberos"));
        Assert.Equal(1102, LegacySemantics.AnalysisFamily("audit_controls")[^1]); Assert.Empty(LegacySemantics.AnalysisFamily("unknown"));
        Assert.Equal("Учетная запись заблокирована", LegacySemantics.EventLabel(4740, "ru"));
        Assert.Equal("Account locked out", LegacySemantics.EventLabel(4740, "en")); Assert.Null(LegacySemantics.EventLabel(999999, "ru"));
        var rules = LegacySemantics.FindingRules;
        Assert.Equal("account_lockout", rules["4740"]?["rule_code"]?.ToString()); Assert.Equal("high", rules["4724"]?["severity"]?.ToString());
        Assert.Equal("Установлена служба", rules["7045"]?["title"]?.ToString()); Assert.Contains("источник ошибок входа", rules["4740"]?["recommendation"]?.ToString());
        Assert.Equal("failed_logons", LegacyInvestigationReader.Category(4625)); Assert.Equal("system", LegacyInvestigationReader.Category(7045));
        Assert.Contains(4768, LegacyInvestigationReader.EventIds("important")); Assert.DoesNotContain(4768, LegacyInvestigationReader.EventIds("hide_noise"));
        var groups = LegacySemantics.Groups.OfType<JsonObject>().ToDictionary(g => g["key"]!.ToString());
        Assert.Equal(new[] { 4723, 4724 }, groups["passwords"]["event_ids"]!.AsArray().Select(n => (int)n!));
        Assert.Equal(new[] { 4624, 4634 }, groups["all_logons"]["event_ids"]!.AsArray().Select(n => (int)n!));
        Assert.Equal(new[] { 4672, 4728, 4732, 4756 }, LegacySemantics.MonitorPrivilegedEventIds);
    }

    [Fact]
    public void Contextual_service_logon_is_windows_scoped()
    {
        var row = Source(4624, new JsonObject { ["LogonType"] = "10" }); row["server"] = "DC1"; row["target_user_name"] = "svc-backup";
        var actual = LegacySemantics.ClassifyContextual(row);
        Assert.Equal("critical", actual["severity"]?.ToString()); Assert.Equal("Интерактивный вход сервисной учеткой на DC", actual["title"]?.ToString());
        row["channel"] = "Unrelated/Channel"; Assert.Equal("info", LegacySemantics.ClassifyContextual(row)["severity"]?.ToString());
    }

    [Theory, InlineData("sid:" + AccountSid, AccountSid), InlineData("sam:example.test:alice", "alice")]
    public void Semantic_context_prefilter_translates_canonical_identity_key(string identity, string expected)
    {
        var roles = new Dictionary<string, string> { ["source_host"] = "1", ["affected_entity"] = identity };
        var filters = SemanticNormalization.CoreRoleFilters("authentication.session.created", ["source_host", "affected_entity"], roles);
        var filter = Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<(string Role, string PrimaryField, string? FallbackField, string Value)>>(filters));
        Assert.Equal(("affected_entity", "target_user_sid", "target_user_name", expected), filter);
    }

    static Direct4624Projection Projection(int id, string channel, string provider, JsonObject data)
        => Direct4624Projection.Create(NativeRow(id, channel, provider, data));

    static JsonObject NativeRow(int id, string channel, string provider, JsonObject data)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var xml = new XElement(ns + "Event", new XElement(ns + "System", new XElement(ns + "Provider", new XAttribute("Name", provider)),
            new XElement(ns + "EventID", id), new XElement(ns + "EventRecordID", 7), new XElement(ns + "TimeCreated", new XAttribute("SystemTime", "2026-07-28T00:00:00Z")),
            new XElement(ns + "Channel", channel), new XElement(ns + "Computer", "dc-fixture.example.test"), new XElement(ns + "Execution", new XAttribute("ProcessID", "4096"))),
            new XElement(ns + "EventData", data.Select(p => new XElement(ns + "Data", new XAttribute("Name", p.Key), p.Value?.ToString()))));
        return EventXml.Parse(xml.ToString(SaveOptions.DisableFormatting), "dc-fixture.example.test", "fixture", channel);
    }
}
