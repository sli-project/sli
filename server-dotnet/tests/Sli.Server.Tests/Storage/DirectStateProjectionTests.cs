using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using System.Text.Json.Nodes;
using System.Runtime.CompilerServices;
using Xunit;
namespace Sli.Server.Tests.Storage;
public class DirectStateProjectionTests
{
    [Theory]
    [InlineData(4720,"account.lifecycle","created","account-created-4720","Создан пользователь")]
    [InlineData(4722,"account.access","enabled","account-enabled-4722","Включена учетная запись")]
    [InlineData(4740,"account.access","locked","account-locked-4740","Блокировка учетной записи")]
    public void Source_target_candidate_and_truncated_event_time(int kind,string state,string status,string rule,string title) {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>9</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>dc.synthetic</Computer></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000001-300000001-1101</Data><Data Name='SubjectUserName'>operator</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='TargetSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data></EventData></Event>";
        var row=EventXml.Parse(xml,"dc.synthetic","fixture","Security");var projection=Direct4624Projection.Create(row);
        var candidate=DirectStateProjection.Candidate(row,projection,42,99)!;
        Assert.Equal(state,(string?)candidate["state_type"]);Assert.Equal(status,(string?)candidate["status"]);Assert.Equal(rule,(string?)candidate["rule_id"]);Assert.Equal(title,(string?)candidate["summary"]);
        Assert.Equal("2026-10-07T00:00:00.123457Z",(string?)candidate["observed_at_utc"]);Assert.Equal("medium",(string?)candidate["severity"]);Assert.Equal(99,(int?)candidate["entity_id"]);Assert.Equal(42,(long?)candidate["source_event_db_id"]);
        Assert.False(Direct4624Facts.HasFacts(Direct4624Facts.Document(42,projection)));
        Assert.Equal(Guid.Parse("9e958750-ac5c-57d3-9bf3-d4e29ee5061b"),DirectStateProjection.JobId(42));
        var golden=JsonNode.Parse(File.ReadAllBytes(FixturePath()))!.AsArray().Single(x=>(int)x!["event_id"]! == kind)!;
        Assert.True(JsonNode.DeepEquals(golden["candidate"],candidate));
        Assert.Equal((string?)golden["identity"],projection.IdentityHash);
        Assert.Equal((string?)golden["core"],Convert.ToHexStringLower(Direct4624Core.SourceHash(42,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),row,projection)));
    }
    internal static string FixturePath([CallerFilePath]string path="")=>Path.Combine(Path.GetDirectoryName(path)!,"ad-state-source.json");
    [Theory]
    [InlineData(4624,9,30,"682b5f00c641dc046bac57e5b39085cb5af288cca4beabf40a6483488703bd78","b643a961e7fe0f228863d7a0ef768ffd6d27c4e86f978e3493ef85b8c7d47577",true)]
    [InlineData(4720,10,31,"a9dd215c77aaa127533e5b4acb2f07d8ed2617cf38c9ffb1742450489855f59f","5e896957534c53ccd0a2f1cfb7784b83420bf588e665c356444ff816dbaf5342",false)]
    [InlineData(4722,11,32,"78f18aa069b1c0bb65b2d7a227334a2907cdc4a6e20fa641c6024b79949df53e","3cba934dd6872044008daa016f9bfaf5c19dbb8a497dcb67b6a43665eb3308ce",false)]
    [InlineData(4740,12,33,"2c63f22e1eaa8b7eda3439b0be7475140d23a551c5201684325cb862e0e46731","7a5acabccc0250f0d02cfa9f76add83018a01cc97316d64ef36908a2c3a1beef",false)]
    public void Source_public_admitted_rows_match_identity_core_and_fact_presence(int kind,int record,int id,string identity,string core,bool facts) {
        string data=kind==4624?"<Data Name='LogonType'>3</Data>":"<Data Name='TargetSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data>";
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>fixture-dc</Computer></System><EventData>{data}</EventData></Event>";
        var row=EventXml.Parse(xml,"fixture-dc","fixture-endpoint","Security");var p=Direct4624Projection.Create(row);
        Assert.Equal(identity,p.IdentityHash);
        Assert.Equal(core,Convert.ToHexStringLower(Direct4624Core.SourceHash(id,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),row,p)));
        Assert.Equal(facts,Direct4624Facts.HasFacts(Direct4624Facts.Document(id,p)));
    }
}
