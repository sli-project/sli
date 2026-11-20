using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Sli.Server.Hosting;
using System.Xml;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentCollectionProfileTests
{
    private static readonly Guid Host = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static JsonObject Domain() => new() { ["domain_sid"]="S-1-5-21-100000001-200000002-300000003", ["fqdn"]="example.test" };

    [Fact]
    public void Default_profile_does_not_start_workstation_collection()
    {
        var config = new ConfigurationBuilder().Build();
        Assert.Empty(AgentEnrollmentService.DefaultModules(config,"workstation",Host,"fixture",null));
    }

    [Fact]
    public void Beta_dc_collects_journal_and_domain_bound_snapshots()
    {
        var modules = AgentEnrollmentService.DefaultModules(new ConfigurationBuilder().Build(),"domain_controller",Host,"fixture",Domain());
        var journal = modules.OfType<JsonObject>().Single(m=>m["module_id"]!.GetValue<string>()=="sli.windows.ad-dc");
        var dc = AdDcConfig.Parse(journal["config"]!.AsObject(),EventCatalog.Load());
        Assert.Contains(4625,dc.AllowEventIds!);
        Assert.Contains(4769,dc.AllowEventIds!);
        Assert.Contains(5136,dc.AllowEventIds!);
        Assert.Contains(4727,dc.AllowEventIds!);
        Assert.Contains(4741,dc.AllowEventIds!);
        Assert.DoesNotContain(4772,dc.AllowEventIds!);
        foreach (var module in new[] { SnapshotPolicy.Ad, SnapshotPolicy.Gpo })
        {
            var assignment=modules.OfType<JsonObject>().Single(m=>m["module_id"]!.GetValue<string>()==module);
            var policy=SnapshotPolicy.Parse(module,assignment["config"]!.AsObject());
            Assert.Equal("example.test",policy.Config["domain_dns"]!.GetValue<string>());
            Assert.Equal(Host.ToString(),policy.SourceId);
            if(module==SnapshotPolicy.Ad) Assert.DoesNotContain("ad_vpn_membership",policy.Families);
        }
        Assert.DoesNotContain(modules.OfType<JsonObject>(),m=>m["module_id"]!.GetValue<string>() is "sli.workstations" or "sli.file-audit" or "sli.nps-eventlog" or "sli.radius-accounting");
        AgentModuleAssignmentRules.ValidateChannelOwnership(modules);
    }

    [Fact]
    public void Unbound_dc_does_not_invent_a_domain_for_snapshots()
    {
        var modules=AgentEnrollmentService.DefaultModules(new ConfigurationBuilder().Build(),"domain_controller",Host,"fixture",null);
        Assert.DoesNotContain(modules.OfType<JsonObject>(),m=>m["module_id"]!.GetValue<string>() is SnapshotPolicy.Ad or SnapshotPolicy.Gpo);
    }

    [Theory]
    [InlineData("workstation","sli.workstations")]
    [InlineData("domain_controller","sli.windows.ad-dc")]
    public void Full_preserves_previous_default_assignments(string role,string expected)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:CollectionProfile"]="full" }).Build();
        var module=Assert.IsType<JsonObject>(Assert.Single(AgentEnrollmentService.DefaultModules(config,role,Host,"fixture",Domain())));
        Assert.Equal(expected,module["module_id"]!.GetValue<string>());
        Assert.Null(module["config"]!["allow_event_ids"]);
    }

    [Fact]
    public void Invalid_profile_cannot_silently_enable_full_collection()
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:CollectionProfile"]="ful" }).Build();
        Assert.Throws<ServerConfigurationException>(()=>AgentEnrollmentService.DefaultModules(config,"workstation",Host,"fixture",null));
    }

    [Theory]
    [InlineData(1104,true,true)]
    [InlineData(4625,true,true)]
    [InlineData(4727,true,true)]
    [InlineData(4741,true,true)]
    [InlineData(5136,true,true)]
    [InlineData(4662,true,true)]
    [InlineData(4706,true,true)]
    [InlineData(4707,true,true)]
    [InlineData(4713,true,true)]
    [InlineData(4716,true,true)]
    [InlineData(4739,true,true)]
    [InlineData(4743,true,true)]
    [InlineData(4765,true,true)]
    [InlineData(4766,true,true)]
    [InlineData(4794,true,true)]
    [InlineData(5137,true,true)]
    [InlineData(5141,true,true)]
    [InlineData(4634,false,false)]
    [InlineData(4772,false,false)]
    [InlineData(4663,false,false)]
    public void Both_profiles_collect_only_table_events_that_the_server_accepts(int id,bool beta,bool full)
    {
        var catalog=EventCatalog.Load();
        var cursor=ChannelProgress.Start("fixture");
        var document=new XmlDocument();
        document.LoadXml($"<Event><System><EventID>{id}</EventID></System></Event>");
        var readable=document.SelectNodes(EventQueries.Build("Security",cursor,catalog))!.Count>0;
        var provider = Provider(id);
        Assert.Equal(beta,readable && catalog.Contains("Security",provider,id) && AgentEnrollmentService.BetaEventIds().Contains(id));
        Assert.Equal(full,readable && catalog.Contains("Security",provider,id));
        foreach(var (profile,expected) in new[] { ("beta",beta),("full",full) })
        {
            var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:CollectionProfile"]=profile }).Build();
            var assignment=AgentEnrollmentService.DefaultModules(configuration,"domain_controller",Host,"fixture",null)[0]!;
            var config=AdDcConfig.Parse(assignment["config"]!.AsObject(),catalog);
            var sample=new AdDcModule(Host.ToString(),config,new EventSource(id),catalog)
                .Collect(null,new DateTimeOffset(2026,11,13,1,0,0,TimeSpan.Zero),"Security").Sample;
            Assert.Equal(expected?0L:1L,sample!.FilteredCount);
            var envelope=new Envelope(Guid.NewGuid().ToString(),Host.ToString(),sample.SourceInstanceId,
                sample.ModuleId,sample.ModuleVersion,sample.PolicyRevision,sample.Channel,sample.Generation,1,
                sample.CursorBefore,sample.CursorAfter,CollectionPacket.Contract,Packets.Digest(sample.Payload),
                sample.Payload["records"]!.AsArray().Count,CanonicalJson.Length(sample.Payload),
                "2026-11-13T01:00:00+00:00",sample.ContinuityState,sample.FilteredCount,sample.LostCount);
            var rows=AgentAdDcValidator.Validate(envelope,sample.Payload,config.ToJson(),"fixture");
            Assert.Equal(expected?1:0,rows.Count);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")]
    public void Server_rejects_4662_without_replication_rights_even_with_a_consistent_packet(string rights)
    {
        var assignment=AgentEnrollmentService.DefaultModules(new ConfigurationBuilder().Build(),"domain_controller",Host,"fixture",null)[0]!;
        var config=AdDcConfig.Parse(assignment["config"]!.AsObject(),EventCatalog.Load());
        var sample=new AdDcModule(Host.ToString(),config,new EventSource(4662),EventCatalog.Load())
            .Collect(null,new DateTimeOffset(2026,11,13,1,0,0,TimeSpan.Zero),"Security").Sample!;
        var record=sample.Payload["records"]![0]!;
        var xml=record["payload"]!["xml"]!.GetValue<string>().Replace("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",rights,StringComparison.Ordinal);
        record["payload"]=EventXml.Parse(xml,"fixture","fixture","Security");
        var envelope=new Envelope(Guid.NewGuid().ToString(),Host.ToString(),sample.SourceInstanceId,
            sample.ModuleId,sample.ModuleVersion,sample.PolicyRevision,sample.Channel,sample.Generation,1,
            sample.CursorBefore,sample.CursorAfter,CollectionPacket.Contract,Packets.Digest(sample.Payload),
            1,CanonicalJson.Length(sample.Payload),"2026-11-13T01:00:00+00:00",sample.ContinuityState,sample.FilteredCount,sample.LostCount);
        Assert.Throws<ProtocolException>(()=>AgentAdDcValidator.Validate(envelope,sample.Payload,config.ToJson(),"fixture"));
    }

    [Theory]
    [InlineData(4103)]
    [InlineData(4104)]
    public void Beta_PowerShell_packets_pass_the_same_identity_policy_and_cursor_validation(int id)
    {
        const string channel = "Microsoft-Windows-PowerShell/Operational";
        var catalog = EventCatalog.Load();
        var assignment = AgentEnrollmentService.DefaultModules(new ConfigurationBuilder().Build(),"domain_controller",Host,"fixture",null)[0]!;
        var input = assignment["config"]!.DeepClone().AsObject();
        input["channels"] = new JsonObject(DcCursor.Channels.Select(c => KeyValuePair.Create<string,JsonNode?>(c,JsonValue.Create(c==channel))));
        var config = AdDcConfig.Parse(input,catalog);
        var sample = new AdDcModule(Host.ToString(),config,new EventSource(id),catalog)
            .Collect(null,new DateTimeOffset(2026,11,13,1,0,0,TimeSpan.Zero)).Sample!;
        Assert.Single(sample.Payload["records"]!.AsArray());
        var envelope = new Envelope(Guid.NewGuid().ToString(),Host.ToString(),sample.SourceInstanceId,
            sample.ModuleId,sample.ModuleVersion,sample.PolicyRevision,sample.Channel,sample.Generation,1,
            sample.CursorBefore,sample.CursorAfter,CollectionPacket.Contract,Packets.Digest(sample.Payload),
            1,CanonicalJson.Length(sample.Payload),"2026-11-13T01:00:00+00:00",sample.ContinuityState,sample.FilteredCount,sample.LostCount);
        Assert.Single(AgentAdDcValidator.Validate(envelope,sample.Payload,config.ToJson(),"fixture"));
        var wrong = config.ToJson(); wrong["channels"]![channel] = false;
        Assert.Throws<ProtocolException>(() => AgentAdDcValidator.Validate(envelope,sample.Payload,wrong,"fixture"));
    }

    private static string Provider(int id) => id switch
    {
        1104 => "Microsoft-Windows-Eventlog",
        4103 or 4104 => "Microsoft-Windows-PowerShell",
        _ => "Microsoft-Windows-Security-Auditing"
    };

    private sealed class EventSource(int id) : IEventLogSource
    {
        public SourceBatch Read(string channel,ChannelProgress progress,int limit) => new([
            new EventRow($"""
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                  <System><Provider Name="{Provider(id)}"/><EventID>{id}</EventID>
                    <TimeCreated SystemTime="2026-11-13T00:00:00.000000Z"/><EventRecordID>1</EventRecordID>
                    <Channel>{channel}</Channel><Computer>fixture.example.test</Computer></System>
                  {(id == 1104 ? "<UserData><FileIsFull xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'/></UserData>"
                      : "<EventData><Data Name='TargetUserName'>fixture</Data><Data Name='Properties'>1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</Data></EventData>")}
                </Event>
                ""","fixture-bookmark")]);
    }
}
