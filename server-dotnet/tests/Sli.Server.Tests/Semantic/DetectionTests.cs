using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class DetectionTests
{
    internal static JsonArray Vectors(){using var stream=typeof(DetectionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.Fixtures.detection-vectors.json.gz")!;using var json=new GZipStream(stream,CompressionMode.Decompress);return JsonNode.Parse(json)!["vectors"]!.AsArray();}
    internal static JsonObject Vector(string name)=>Vectors().Select(n=>n!.AsObject()).Single(n=>D.Text(n["name"])==name);
    // Kerberos rules have catalog-driven behavior tests in KerberosDetectionTests.
    public static IEnumerable<object[]> Cases()=>Vectors().Where(n=>n!["rows"]!.AsArray().All(r=>r!["event_id"]!.GetValue<int>() is not (4768 or 4769))).Select(n=>new object[]{D.Text(n!["name"])});
    internal static DetectionRow Row(JsonNode n)=>new(DetectionRef.Read(n["reference"]),D.Time(n["at"]),n["event_id"]!.GetValue<int>(),D.Text(n["host"]),n["fields"] as JsonObject,n["record"] as JsonObject);
    internal static IReadOnlyList<JsonObject> Detect(JsonObject v)
    {
        var rows=v["rows"]!.AsArray().Select(n=>Row(n!)).ToArray();var now=D.Time(v["now"]);var scope=PasswordScope.Read(v["scope"]);
        return D.Text(v["mode"]) switch{
            "identity"=>IdentityAttacks.Evaluate(scope,rows,now,IdentityAttackPolicy.Read(v["policy"])),
            "identity_snapshot"=>IdentityAttacks.EvaluateSnapshot(scope,rows,now,IdentityAttackPolicy.Read(v["policy"])),
            "files"=>AttackPrecursors.DetectFiles(rows,now,PrecursorPolicy.Read(v["policy"])),
            _=>AttackPrecursors.DetectEvents(rows,now,PrecursorPolicy.Read(v["policy"]))};
    }
    [Theory][MemberData(nameof(Cases))]
    public void Python_branch_vectors_preserve_decisions_documents_and_ids(string name)
    {
        var v=Vector(name);var result=Detect(v);var expected=v["expected"]!.AsArray();Assert.Equal(expected.Count,result.Count);
        for(int i=0;i<result.Count;i++){
            Assert.True(JsonNode.DeepEquals(expected[i],result[i]),name+"\nExpected: "+expected[i]+"\nActual: "+result[i]);Assert.Equal(D.Text(v["ids"]![i]),DetectionSignal.Id(result[i]));
            if(D.Text(v["mode"]).StartsWith("identity",StringComparison.Ordinal))IdentityAttacks.Validate(result[i]);else AttackPrecursors.Validate(result[i]);
        }
    }
    internal static JsonObject Native(DetectionRow row,bool identity=true)
    {
        XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        var xml=new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"EventID",row.EventId),new XElement(ns+"TimeCreated",new XAttribute("SystemTime",D.Stamp(row.At))),new XElement(ns+"Computer",row.Get("Computer") is {Length:>0} computer?computer:row.Host)),new XElement(ns+"EventData",(row.Fields??new()).Where(p=>p.Key!="Computer").Select(p=>new XElement(ns+"Data",new XAttribute("Name",p.Key),D.Text(p.Value))))).ToString(SaveOptions.DisableFormatting);
        var result=new JsonObject{["event_id"]=row.EventId,["occurred_at_utc"]=D.Stamp(row.At),["sha256"]=row.Ref.Sha256,["source_xml"]=xml};if(identity)result["source_event_id"]=long.Parse(row.Ref.NativeId);else result["native_id"]=row.Ref.NativeId;return result;
    }
    [Fact]public void Native_parser_rejects_mutation_and_ignores_spoofed_EventData_Computer()
    {
        var v=Vector("fanout");var scope=PasswordScope.Read(v["scope"]);var rows=v["rows"]!.AsArray().Select(n=>Native(Row(n!))).ToArray();
        foreach(var row in rows){var root=XElement.Parse(D.Text(row["source_xml"]));XNamespace ns=root.Name.Namespace;root.Element(ns+"System")!.Element(ns+"Computer")!.Value="one-dc";root.Element(ns+"EventData")!.Add(new XElement(ns+"Data",new XAttribute("Name","Computer"),Guid.NewGuid().ToString()));row["source_xml"]=root.ToString();}
        Assert.Empty(IdentityAttacks.Evaluate(scope,DetectionNative.ParseEvents(scope,rows,true),D.Time(v["now"])));
        rows[0]["event_id"]=4769;Assert.Throws<DetectionFailure>(()=>DetectionNative.ParseEvents(scope,rows,true));
        rows[0]["source_xml"]="<!DOCTYPE x [<!ENTITY a 'x'>]><Event/>";Assert.ThrowsAny<Exception>(()=>DetectionNative.ParseEvents(scope,rows,true));
    }
    [Fact]public void Policy_signal_bounds_and_cross_source_evidence_fail_closed()
    {
        Assert.Throws<DetectionFailure>(()=>new IdentityAttackPolicy(FanoutHosts:0).Validate());Assert.ThrowsAny<Exception>(()=>IdentityAttackPolicy.Read(JsonNode.Parse("""{"fanout_hosts":true}""")));
        Assert.Throws<DetectionFailure>(()=>new PrecursorPolicy(FastFiles:0).Validate());Assert.Throws<DetectionFailure>(()=>new PrecursorPolicy(BackupSids:["bad"]).Validate());Assert.ThrowsAny<Exception>(()=>PrecursorPolicy.Read(JsonNode.Parse("""{"read_seconds":true}""")));
        var signal=Assert.Single(Detect(Vector("mass_read_10")));var scope=signal["evidence_refs"]![1]!["scope"]!;scope["source_generation"]="other";Assert.Throws<DetectionFailure>(()=>AttackPrecursors.Validate(signal));
        var row=Row(Vector("kerberoasting")["rows"]![0]!);Assert.Throws<DetectionFailure>(()=>IdentityAttacks.Evaluate(row.Ref.Scope,Enumerable.Repeat(row,10001).ToArray(),DateTimeOffset.MaxValue));
        var conflicting=row with{Host="changed"};Assert.Throws<DetectionFailure>(()=>IdentityAttacks.Evaluate(row.Ref.Scope,[row,conflicting],DateTimeOffset.MaxValue));
    }
    [Fact]public void Silence_escalates_only_recent_attack_online_host_and_packet_staleness()
    {
        var v=Vector("tamper_1");var threat=Assert.Single(Detect(v));var at=D.Time(threat["occurred_at_utc"]);var health=JsonNode.Parse("""{"state":"error","connection":"online","modules":[{"channels":[{"state":"error","failure_reason":"packet_stale"}]}]}""")!.AsObject();health["modules"]![0]!["channels"]![0]!["last_packet_at"]=D.Stamp(at);health["modules"]![0]!["channels"]![0]!["issue_since_utc"]=D.Stamp(at.AddSeconds(60));
        var item=AttackPrecursors.SilenceSignal(threat,health,at.AddSeconds(120));Assert.NotNull(item);AttackPrecursors.Validate(item);Assert.Equal("qw.agent-silenced",D.Text(item["rule_id"]));Assert.NotNull(item["attack_context"]!["health"]);
        Assert.Null(AttackPrecursors.SilenceSignal(threat,health,at));Assert.Null(AttackPrecursors.SilenceSignal(threat,health,at.AddHours(2)));health["connection"]="offline";Assert.Null(AttackPrecursors.SilenceSignal(threat,health,at.AddSeconds(120)));health["connection"]="online";health["state"]="current";Assert.Null(AttackPrecursors.SilenceSignal(threat,health,at.AddSeconds(120)));
    }
    [Fact]public void Real_collection_budget_and_import_backlog_precedence()
    {
        var at=DateTimeOffset.Parse("2026-01-01T00:00:00Z");var c=JsonNode.Parse("""{"agent":{"id":"fixture","status":"active","policy_revision":1,"applied_policy_revision":1,"applied_collection_state":"active","assigned_modules":[{"module_id":"sli.windows.ad-dc","enabled":true,"config":{}}]},"streams":[{"agent_id":"fixture","module_id":"sli.windows.ad-dc","revision":"1","channel":"Security"}]}""")!.AsObject();c["agent"]!["last_seen"]=D.Stamp(at);c["agent"]!["created_at"]=D.Stamp(at.AddDays(-1));c["streams"]![0]!["last_packet_at"]=D.Stamp(at.AddSeconds(-1100));
        var threat=Assert.Single(AttackPrecursors.DetectEvents([new(new(PasswordScope.Read(Vector("kerberoasting")["scope"]),"core_event","1",new('a',64)),at.AddSeconds(-1200),1102)],at));Assert.NotNull(AttackPrecursors.SilenceSignal(threat,DetectionHealth.Project(c,at),at));
        c["streams"]![0]!["pending_since"]=D.Stamp(at.AddSeconds(-1000));Assert.Null(AttackPrecursors.SilenceSignal(threat,DetectionHealth.Project(c,at),at));
    }
    [Fact]public async Task Producers_are_registered_in_the_existing_worker()
    {
        var env=new Dictionary<string,string?>{["ADLOG_SEMANTIC_WORKER_DSN"]="host=localhost dbname=sli user=synthetic password=synthetic"};await using var runtime=PasswordProducerRuntime.TryCreate(env.GetValueOrDefault,_=>[]);Assert.NotNull(runtime);
        using var services=new ServiceCollection().AddLogging().AddSingleton<IHostApplicationLifetime>(new Lifetime()).AddPasswordProducer(runtime,new(true)).BuildServiceProvider();Assert.NotNull(services.GetRequiredService<IdentityAttackProducer>());Assert.NotNull(services.GetRequiredService<AttackPrecursorProducer>());Assert.NotNull(services.GetRequiredService<DetectionProducer>());Assert.NotNull(services.GetRequiredService<PasswordProducerPoller>());Assert.Contains(services.GetServices<IHostedService>(),s=>s is PasswordProducerHostedService);
    }
    private sealed class Lifetime:IHostApplicationLifetime{public CancellationToken ApplicationStarted=>default;public CancellationToken ApplicationStopping=>default;public CancellationToken ApplicationStopped=>default;public void StopApplication(){}}
}
