using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventRowTests
{
    private const string Computer = "dc01.example.test";
    private const string SubjectSid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string TargetSid = "S-1-5-21-100000001-200000002-300000003-1002";
    private static readonly XNamespace Ns = EventXml.Namespace;

    private static JsonObject Native(int kind, Dictionary<string, string>? fields = null,
        string channel = "Security", string provider = "Microsoft-Windows-Security-Auditing", XElement? userData = null)
    {
        var xml = new XElement(Ns + "Event",
            new XElement(Ns + "System", new XElement(Ns + "Provider", new XAttribute("Name", provider)),
                new XElement(Ns + "EventID", kind), new XElement(Ns + "EventRecordID", 17),
                new XElement(Ns + "TimeCreated", new XAttribute("SystemTime", "2026-11-15T01:02:03Z")),
                new XElement(Ns + "Keywords", "0x8020000000000000"), new XElement(Ns + "Channel", channel),
                new XElement(Ns + "Computer", Computer)),
            new XElement(Ns + "EventData", (fields ?? []).Select(f =>
                new XElement(Ns + "Data", new XAttribute("Name", f.Key), f.Value))), userData);
        return EventXml.Parse(xml.ToString(SaveOptions.DisableFormatting), Computer, Computer, channel);
    }

    private static ShortEventRow? Project(JsonObject row) => ShortEventRow.Create(91, 7, row, Direct4624Projection.Create(row));

    [Theory]
    [InlineData(4103, "Payload")]
    [InlineData(4104, "ScriptBlockText")]
    public void PowerShell_keeps_bounded_text_and_native_security_principal(int kind, string field)
    {
        string text = "<synthetic>'; --" + string.Concat(Enumerable.Repeat("🙂", 1100));
        var native = Native(kind, new() { [field] = text, ["$user_id"] = "forged" },
            "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell");
        var xml = XElement.Parse(native["xml"]!.GetValue<string>());
        xml.Element(Ns + "System")!.Add(new XElement(Ns + "Security", new XAttribute("UserID", SubjectSid)));
        native = EventXml.Parse(xml.ToString(), Computer, Computer, "Microsoft-Windows-PowerShell/Operational");
        var row = Assert.IsType<ShortEventRow>(Project(native));
        Assert.Equal("summary", row.Layer);
        Assert.Equal(SubjectSid, row.Actor);
        Assert.Equal(string.Concat(text.EnumerateRunes().Take(1024).Select(r => r.ToString())), row.Fields["ScriptBlockText"]);
        Assert.DoesNotContain("forged", JsonSerializer.Serialize(row));
        Assert.DoesNotContain("<synthetic>", JsonSerializer.Serialize(row));
    }

    [Theory]
    [InlineData(4648)]
    [InlineData(4769)]
    public void Destination_computer_identity_survives_in_daily_dimensions(int kind)
    {
        var row = Project(Native(kind,new() { ["TargetServerName"]="target.example.test",["ServiceName"]="target.example.test" }))!;
        Assert.Equal("server:target.example.test",JsonNode.Parse(row.Method)!["$target_server"]?.ToString());
    }

    [Theory]
    [InlineData(4624, "summary")]
    [InlineData(4625, "summary")]
    [InlineData(4776, "summary")]
    [InlineData(4720, "fact")]
    [InlineData(4743, "fact")]
    [InlineData(5137, "fact")]
    [InlineData(4716, "fact")]
    public void Accepted_kinds_keep_the_native_identity_time_and_selected_layer(int kind, string layer)
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(kind)));
        Assert.Equal(91, result.EventId);
        Assert.Equal(new DateTime(2026, 11, 15, 1, 2, 3, DateTimeKind.Utc), result.Time);
        Assert.Equal(kind, result.Kind);
        Assert.Equal(layer, result.Layer);
        Assert.Equal(Computer, result.Computer);
    }

    [Fact]
    public void Excluded_unlisted_and_same_number_from_another_provider_have_no_short_row()
    {
        Assert.Null(Project(Native(4634)));
        Assert.Null(Project(Native(65000)));
        Assert.Null(Project(Native(33, channel: "System", provider: "volsnap")));
        Assert.Null(Project(Native(4720, provider: "synthetic-provider")));
        Assert.Null(Project(Native(4720, channel: "Application")));
    }

    [Fact]
    public void Successful_logon_identifies_the_logged_on_account_and_origin()
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(4624, new() {
            ["SubjectUserSid"] = SubjectSid, ["TargetUserSid"] = TargetSid,
            ["TargetDomainName"] = "example.test", ["IpAddress"] = "192.0.2.17",
            ["LogonType"] = "3", ["AuthenticationPackageName"] = "Kerberos", ["TargetLogonId"] = "0x123"
        })));
        Assert.Equal(TargetSid, result.Actor);
        Assert.Equal(Computer, result.Target);
        Assert.Equal("192.0.2.17", result.Source);
        Assert.Equal(7, result.DomainId);
        Assert.Equal("3", result.Fields["LogonType"]);
        Assert.Equal("0x123", result.Fields["TargetLogonId"]);
    }

    [Fact]
    public void Explicit_credentials_keep_both_accounts_and_the_destination_server()
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(4648, new() {
            ["SubjectUserSid"] = SubjectSid, ["TargetUserName"] = "synthetic-target", ["TargetDomainName"] = "example.test",
            ["TargetServerName"] = "dc02.example.test", ["SubjectLogonId"] = "0x123", ["TargetLogonId"] = "0x456"
        })));
        Assert.Equal(SubjectSid, result.Actor);
        Assert.Equal("example.test\\synthetic-target", result.Target);
        Assert.Equal("dc02.example.test", result.Fields["TargetServerName"]);
        Assert.Equal("0x123", result.Fields["SubjectLogonId"]);
        Assert.Equal("0x456", result.Fields["TargetLogonId"]);
        var logoff = Assert.IsType<ShortEventRow>(Project(Native(4647, new() { ["SubjectLogonId"] = "0x123" })));
        Assert.Equal("0x123", logoff.Fields["LogonId"]);
    }

    [Fact]
    public void Group_change_preserves_administrator_group_and_member_separately()
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(4728, new() {
            ["SubjectUserSid"] = SubjectSid, ["TargetSid"] = TargetSid,
            ["MemberSid"] = "S-1-5-21-100000001-200000002-300000003-1003",
            ["MemberName"] = "CN=synthetic,DC=example,DC=test"
        })));
        Assert.Equal(SubjectSid, result.Actor);
        Assert.Equal(TargetSid, result.Target);
        Assert.Equal("S-1-5-21-100000001-200000002-300000003-1003", result.Fields["MemberSid"]);
        Assert.Equal("CN=synthetic,DC=example,DC=test", result.Fields["MemberName"]);
    }

    [Fact]
    public void Missing_values_remain_null_and_named_accounts_keep_their_domain()
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(4720, new() {
            ["SubjectUserSid"] = "-", ["SubjectUserName"] = "synthetic", ["SubjectDomainName"] = "example.test"
        })));
        Assert.Equal("example.test\\synthetic", result.Actor);
        Assert.Null(result.Target);
        Assert.Null(result.Source);
        Assert.Null(result.Fields["SamAccountName"]);
    }

    [Fact]
    public void Directory_change_keeps_the_observed_value_and_operation_without_inventing_a_before_value()
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(5136, new() {
            ["ObjectDN"] = "CN=synthetic,DC=example,DC=test", ["AttributeLDAPDisplayName"] = "description",
            ["OperationType"] = "%%14674", ["AttributeValue"] = "<script>'; select 1; --", ["OpCorrelationID"] = "synthetic-correlation"
        })));
        Assert.Equal("CN=synthetic,DC=example,DC=test", result.Target);
        Assert.Equal("<script>'; select 1; --", result.Fields["AttributeValue"]);
        Assert.Equal("%%14674", result.Fields["OperationType"]);
        Assert.Equal("synthetic-correlation", result.Fields["OpCorrelationID"]);
    }

    [Fact]
    public void Long_host_values_are_limited_in_unicode_codepoints()
    {
        string text = string.Concat(Enumerable.Repeat("🙂", 1100));
        var result = Assert.IsType<ShortEventRow>(Project(Native(4688, new() {
            ["SubjectUserName"] = text, ["CommandLine"] = text, ["NewProcessName"] = "synthetic.exe"
        })));
        Assert.Equal(string.Concat(Enumerable.Repeat("🙂", 256)), result.Actor);
        Assert.Equal(string.Concat(Enumerable.Repeat("🙂", 1024)), result.Fields["CommandLine"]);
    }

    [Theory]
    [InlineData(4698, "TaskContent")]
    [InlineData(4702, "TaskContentNew")]
    public void Task_xml_becomes_command_arguments_and_run_as(int kind, string field)
    {
        const string task = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Principals><Principal id='operator'><UserId>example.test\\synthetic</UserId></Principal></Principals><Actions Context='operator'><Exec><Command>synthetic.exe</Command><Arguments>--synthetic &amp; safe</Arguments></Exec></Actions></Task>";
        var result = Assert.IsType<ShortEventRow>(Project(Native(kind, new() { ["TaskName"] = "synthetic-task", [field] = task })));
        Assert.Equal("synthetic-task", result.Target);
        Assert.Equal("synthetic.exe", result.Fields["task_command"]);
        Assert.Equal("--synthetic & safe", result.Fields["task_arguments"]);
        Assert.Equal("example.test\\synthetic", result.Fields["task_user"]);
        Assert.DoesNotContain("<Task", JsonSerializer.Serialize(result));
    }

    [Fact]
    public void Host_cannot_supply_derived_task_values_or_load_an_external_entity()
    {
        var missing = Assert.IsType<ShortEventRow>(Project(Native(4698, new() { ["$task_command"] = "forged" })));
        Assert.Null(missing.Fields["task_command"]);
        const string unsafeTask = "<!DOCTYPE Task [<!ENTITY x SYSTEM 'file:///synthetic-never-read'>]><Task>&x;</Task>";
        var error = Assert.Throws<InvalidDataException>(() => Project(Native(4698, new() { ["TaskContent"] = unsafeTask })));
        Assert.Equal("short_event_task_xml_invalid", error.Message);
    }

    [Theory]
    [InlineData("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData("89e95b76-444d-4c62-991a-0facbeda640c")]
    public void Replication_access_keeps_only_matching_replication_rights(string guid)
    {
        var result = Assert.IsType<ShortEventRow>(Project(Native(4662, new() {
            ["Properties"] = "%{00000000-0000-0000-0000-000000000000}\n{" + guid.ToUpperInvariant() + "}",
            ["ObjectName"] = "DC=example,DC=test", ["AccessMask"] = "0x100"
        })));
        Assert.Equal("fact", result.Layer);
        Assert.Equal(guid, result.Fields["replication_rights"]);
        Assert.Equal("DC=example,DC=test", result.Target);
        Assert.Null(Project(Native(4662, new() { ["Properties"] = "00000000-0000-0000-0000-000000000000" })));
        Assert.Null(Project(Native(4662, new() { ["Properties"] = "0" + guid })));
    }

    [Fact]
    public void Native_userdata_named_leaves_are_available_without_keeping_the_wrapper()
    {
        XNamespace provider = "urn:synthetic-provider";
        var userData = new XElement(Ns + "UserData", new XElement(provider + "EventXML",
            new XElement(provider + "SubjectUserName", "synthetic"), new XElement(provider + "SubjectDomainName", "example.test")));
        var result = Assert.IsType<ShortEventRow>(Project(Native(1102, provider: "Microsoft-Windows-Eventlog", userData: userData)));
        Assert.Equal("example.test\\synthetic", result.Actor);
        Assert.Equal("Security", result.Fields["channel"]);
        Assert.DoesNotContain("EventXML", JsonSerializer.Serialize(result));
    }

    [Fact]
    public void Summary_dimensions_keep_failure_subcode_and_ticket_encryption_separate()
    {
        var failure = Assert.IsType<ShortEventRow>(Project(Native(4625, new() { ["Status"] = "0xc000006d", ["SubStatus"] = "0xc000006a" })));
        var other = Assert.IsType<ShortEventRow>(Project(Native(4625, new() { ["Status"] = "0xc000006d", ["SubStatus"] = "0xc0000064" })));
        Assert.NotEqual(failure.Outcome, other.Outcome);
        Assert.Equal("0xc000006d", JsonNode.Parse(failure.Outcome)!["Status"]!.GetValue<string>());
        Assert.Equal("0xc000006a", JsonNode.Parse(failure.Outcome)!["SubStatus"]!.GetValue<string>());
        var ticket = Assert.IsType<ShortEventRow>(Project(Native(4769, new() { ["TicketEncryptionType"] = "0x17" })));
        var encrypted = Assert.IsType<ShortEventRow>(Project(Native(4769, new() { ["TicketEncryptionType"] = "0x12" })));
        Assert.NotEqual(ticket.Method, encrypted.Method);
    }
}
