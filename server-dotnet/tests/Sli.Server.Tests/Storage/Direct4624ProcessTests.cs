using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Xunit;
namespace Sli.Server.Tests.Storage;
public class Direct4624ProcessTests
{
    private const string Xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>5</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='LogonType'>3</Data><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000002-300000003-500</Data><Data Name='SubjectUserName'>alice</Data><Data Name='SubjectDomainName'>D</Data><Data Name='TargetUserSid'>S-1-5-21-100000001-200000002-300000003-501</Data><Data Name='TargetUserName'>bob</Data><Data Name='TargetDomainName'>D</Data><Data Name='ProcessName'>C:\\Windows\\System32\\lsass.exe</Data><Data Name='ProcessId'>0x2a</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='LogonProcessName'>User32</Data><Data Name='IpPort'>49152</Data><Data Name='ElevatedToken'>%%1842</Data><Data Name='ImpersonationLevel'>%%1833</Data></EventData></Event>";
    [Fact] public void Source_process_entity_and_facts_are_published() {
        var p=Direct4624Projection.Create(EventXml.Parse(Xml,"dc.synthetic","fixture","Security"));
        var process=Assert.Single(p.Entities,e=>e.Type=="process");
        Assert.Equal("process:c:\\windows\\system32\\lsass.exe",process.NaturalKey);
        Assert.Equal("contextual",(string?)process.Attributes["risk_tier"]);
        var facts=Direct4624Facts.Document(1,p);
        Assert.Equal("C:\\Windows\\System32\\lsass.exe",(string?)facts["process_name"]);
        Assert.Equal("42",(string?)facts["process_id"]);
        Assert.Equal("feaf0699a09f3384ca12195f2045ccfa661198453ebe0b5d09a257647a0a6023",Convert.ToHexStringLower(Direct4624Facts.Hash(1,p)));
    }
    [Theory]
    [InlineData("0",null)]
    [InlineData("0xffffffff","4294967295")]
    [InlineData("0x100000000",null)]
    [InlineData("not-a-pid",null)]
    public void Pid_boundary_matches_source(string input,string? expected) {
        var xml=Xml.Replace("Name='ProcessId'>0x2a",$"Name='ProcessId'>{input}");
        var p=Direct4624Projection.Create(EventXml.Parse(xml,"dc.synthetic","fixture","Security"));
        Assert.Equal(expected,(string?)Direct4624Facts.Document(1,p)["process_id"]);
    }
    [Fact] public void Unmapped_fields_are_retained_without_inventing_entities() {
        var xml=Xml.Replace("</EventData>","<Data Name='NotPorted'>x</Data></EventData>");
        var baseline=Direct4624Projection.Create(EventXml.Parse(Xml,"dc.synthetic","fixture","Security"));
        var extended=Direct4624Projection.Create(EventXml.Parse(xml,"dc.synthetic","fixture","Security"));
        Assert.Equal("x",extended.Data["NotPorted"]);
        Assert.Equal(baseline.Entities.Select(e=>(e.Type,e.NaturalKey,e.Role)),extended.Entities.Select(e=>(e.Type,e.NaturalKey,e.Role)));
    }
    [Fact] public void Source_context_fields_do_not_change_facts_or_entities() {
        var extra="<Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='NetworkAccountName'>-</Data><Data Name='NetworkAccountDomain'>-</Data>";
        var baseline=Direct4624Projection.Create(EventXml.Parse(Xml,"dc.synthetic","fixture","Security"));
        var extended=Direct4624Projection.Create(EventXml.Parse(Xml.Replace("</EventData>",extra+"</EventData>"),"dc.synthetic","fixture","Security"));
        Assert.Equal(Direct4624Facts.Hash(1,baseline),Direct4624Facts.Hash(1,extended));
        Assert.Equal(baseline.Entities.Select(e=>(e.Type,e.NaturalKey,e.Role)),extended.Entities.Select(e=>(e.Type,e.NaturalKey,e.Role)));
    }
}
