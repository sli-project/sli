using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Xunit;
namespace Sli.Server.Tests.Storage;
public class DirectNpsSecurityTests
{
    [Theory]
    [InlineData(6272,"  Accepted  ","Accepted","2a05047c170825ea30633e1f2b7fe510885bb1367d9e225333634af2f73aa258")]
    [InlineData(6273,"  16  ","16","434a634df378c51b0bfc524ae24d327e8ef396a7f798eaecaa726a5bc6ab6428")]
    public void Source_decisions_keep_nps_facts(int kind,string reason,string expected,string hash)
    {
        string resultField=kind==6272?"LoggingResult":"ReasonCode";
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>nps.synthetic</Computer></System><EventData><Data Name='AuthenticationType'> PEAP </Data><Data Name='AuthenticationServer'> nps.synthetic </Data><Data Name='NetworkPolicyName'> vpn </Data><Data Name='{resultField}'>{reason}</Data></EventData></Event>";
        var p=Direct4624Projection.Create(EventXml.Parse(xml,"nps.synthetic","fixture","Security"));
        Assert.Equal(hash,p.IdentityHash);
        if(kind==6273) {
            var source=DirectNpsArchiveRows.Event(20,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),EventXml.Parse(xml,"nps.synthetic","fixture","Security"),p);
            Assert.Equal("3336eac7e949db80354c12e7b49e87fb732443752d9358d6748e2c19ef71e142",Convert.ToHexStringLower(Direct4624Core.SourceHash(20,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),EventXml.Parse(xml,"nps.synthetic","fixture","Security"),p)));
            var bytes=System.Text.Encoding.UTF8.GetBytes(Sli.Agent.Protocol.CanonicalJson.Serialize(source,ensureAscii:false));
            Assert.Equal("e52554a32c8def5886bf36986069219e3f34d87b26ac1ce906449fe11565f718",Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
        }
        var facts=Direct4624Facts.Document(42,p);
        Assert.Equal(kind==6272 ? "f7c740b9f3e66276c4dcd0537278daebebee01180e93a8db08304ad020439ddb" : "38713349b699d81bcd78c540cd4c41fbc6020fa9a9a0898045c776c82eab23ac",Convert.ToHexStringLower(Direct4624Facts.Hash(42,p)));
        Assert.Equal(expected,(string?)facts["result_code"]);
        Assert.Equal("PEAP",(string?)facts["logon_type"]);
        Assert.Equal("nps.synthetic",(string?)facts["target_server_name"]);
        Assert.Equal("vpn",(string?)facts["object_name"]);
    }
    [Theory]
    [InlineData("alice","EXAMPLE","S-1-5-21-1-2-3-4","sid:S-1-5-21-1-2-3-4","resolved",1)]
    [InlineData("alice","","-","name:alice","unresolved",5)]
    public void Source_actor_keeps_resolved_or_unresolved_identity(string name,string domain,string sid,string key,string state,int step)
    {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>6273</EventID><EventRecordID>43</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>nps.synthetic</Computer></System><EventData><Data Name='SubjectUserName'>{name}</Data><Data Name='SubjectDomainName'>{domain}</Data><Data Name='SubjectUserSid'>{sid}</Data><Data Name='ReasonCode'>16</Data></EventData></Event>";
        var p=Direct4624Projection.Create(EventXml.Parse(xml,"nps.synthetic","fixture","Security"));
        var entity=Assert.Single(p.Entities,x=>x.Role=="actor");
        Assert.Equal(key,entity.NaturalKey);
        Assert.Equal(state=="unresolved" ? "e8c074e05cf5527c5ddb2b5dd99c69657d49950e99ff3808d9e0eb125b56acb4" : "e4228a5e1efb40cdc37e54d105b88f6d67a4403dc8be5a1df6ed83df9c431400",Convert.ToHexStringLower(DirectEntityModel.Digest(entity.Attributes)));
        Assert.Equal(state=="unresolved" ? 0.3 : 1.0,entity.Confidence);Assert.Equal(state,(string?)entity.Attributes["identity_state"]);Assert.Equal(step,(int?)entity.Attributes["identity_step"]);
        if(state=="unresolved") {
            Assert.Equal("нет_домена",(string?)entity.Attributes["identity_reason"]);
            Assert.Equal("ad_user:unknown:alice",(string?)entity.Attributes["identity_aliases"]![0]);
            Assert.Equal("3da278626656957db73dfbc805c1b09fa8d2848acf61956e3dac8174ac3c8b52",Convert.ToHexStringLower(DirectLinkCore.Hash(42,10,7,8,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),entity.Confidence)));
        }
    }
    [Fact]
    public void Empty_facts_and_duplicate_rows_preserve_source_values()
    {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>6273</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>nps.synthetic</Computer></System><EventData><Data Name='AuthenticationType'></Data><Data Name='ReasonCode'> </Data><Data Name='NASIdentifier'> nas </Data></EventData></Event>";
        var row=EventXml.Parse(xml,"nps.synthetic","fixture","Security");
        var batch=DirectAdDcPacket.PrepareBatch(new System.Text.Json.Nodes.JsonArray(row.DeepClone(),row.DeepClone()));
        Assert.Equal(2,batch.Count);Assert.Equal(batch[0].Projection.IdentityHash,batch[1].Projection.IdentityHash);
        var facts=Direct4624Facts.Document(42,batch[0].Projection);
        Assert.Null(facts["result_code"]);Assert.Null(facts["logon_type"]);Assert.Equal("nas",(string?)facts["object_name"]);
        var source=DirectNpsArchiveRows.Event(20,2,3,4,null,5,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc),row,batch[0].Projection);
        Assert.Contains("\"AuthenticationType\": null",(string?)source["event_data_json"]);
    }
    [Fact]
    public void Unknown_import_identity_is_retained_and_malformed_xml_is_rejected()
    {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>6274</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>nps.synthetic</Computer></System><EventData><Data Name='ReasonCode'>16</Data></EventData></Event>";
        Assert.Equal(6274,Direct4624Projection.Create(EventXml.Parse(xml,"nps.synthetic","fixture","Security")).EventKind);
        Assert.ThrowsAny<Exception>(()=>EventXml.Parse(xml[..^8],"nps.synthetic","fixture","Security"));
    }
    [Fact]
    public void Source_time_rounding_and_opaque_reason_are_preserved()
    {
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>6273</EventID><EventRecordID>43</EventRecordID><TimeCreated SystemTime='2026-10-07T02:00:00.1234575+02:00'/><Channel>Security</Channel><Computer>nps.synthetic</Computer></System><EventData><Data Name='ReasonCode'>?</Data></EventData></Event>";
        var p=Direct4624Projection.Create(EventXml.Parse(xml,"nps.synthetic","fixture","Security"));
        Assert.Equal("57297cd583fdf1878fd03887e6e13a711422ced7ad018d6dea4fa8a44464c3f1",p.IdentityHash);
        Assert.Equal("?",(string?)Direct4624Facts.Document(43,p)["result_code"]);
    }
    [Fact]
    public async Task Source_event_and_unresolved_link_round_trip_through_archive()
    {
        string root=Path.Combine(Path.GetTempPath(),"sli-nps-archive-test-"+Guid.NewGuid().ToString("N"));
        try {
            var entity=new DirectEntity("ad_user","name:alice","alice","actor",true,false,new System.Text.Json.Nodes.JsonObject { ["identity_state"]="unresolved" },0.3);
            var expected=DirectNpsArchiveRows.Link(42,entity,10,7,8,new DateTime(2026,10,7,0,0,0,DateTimeKind.Utc));
            var publisher=new Sli.Server.Storage.Archive.ArchivePublisher(root,new ArchivePublisherTests.MemoryManifest());
            var result=await publisher.PublishDirectAsync("3:fixture:1:42-42",[new System.Text.Json.Nodes.JsonObject { ["id"]=42L,["record_xml"]="<Event/>" }],[expected],TestContext.Current.CancellationToken);
            DirectNpsArchiveRows.VerifyLinks([expected],result.VerifiedLinkRows);
            result.VerifiedLinkRows[0]["confidence"]=1.0;
            Assert.Throws<InvalidDataException>(()=>DirectNpsArchiveRows.VerifyLinks([expected],result.VerifiedLinkRows));
        } finally { if(Directory.Exists(root))Directory.Delete(root,true); }
    }
}
