using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class ShortDetectionTests
{
    [Theory, InlineData("brute"), InlineData("spray")]
    public void Compact_password_events_keep_qualification_and_exact_occurrences(string kind)
    {
        var scope = PasswordScope.Read(DetectionTests.Vector("kerberoasting")["scope"]);
        var start = DateTimeOffset.Parse("2026-11-15T01:00:00Z"); var oldEvents = new List<PasswordNative>(); var newEvents = new List<PasswordNative>();
        XNamespace ns = EventXml.Namespace;
        for (int id = 1; id <= 10; id++) {
            var at = start.AddSeconds(id); string account = kind == "spray" ? "synthetic-user"+id : "synthetic-user";
            var fields = new Dictionary<string,string> { ["TargetUserName"] = account, ["TargetDomainName"] = "example.test",
                ["IpAddress"] = "192.0.2.7", ["Status"] = "0xc000006d", ["SubStatus"] = "0xc000006a" };
            var root = new XElement(ns+"Event",new XElement(ns+"System",
                new XElement(ns+"Provider",new XAttribute("Name","Microsoft-Windows-Security-Auditing")),
                new XElement(ns+"EventID",4625),new XElement(ns+"EventRecordID",id),new XElement(ns+"Channel","Security"),
                new XElement(ns+"Computer","dc.example.test"),new XElement(ns+"TimeCreated",new XAttribute("SystemTime",D.Stamp(at)))),
                new XElement(ns+"EventData",fields.Select(p => new XElement(ns+"Data",new XAttribute("Name",p.Key),p.Value))));
            var input = EventXml.Parse(root.ToString(),"dc.example.test","dc.example.test","Security");
            var row = ShortEventRow.Create(id,1,input,Direct4624Projection.Create(input),1)!;
            var method = JsonNode.Parse(row.Method)!; var data = method["$principals"]!.DeepClone().AsObject();
            foreach (var (key,value) in JsonNode.Parse(row.Outcome)!.AsObject()) data[key] = value?.DeepClone();
            foreach (var (key,value) in row.Fields) data[key] = value;
            var document = new JsonObject { ["version"]="sli.short-event.1",["source_event_id"]=id,["event_id"]=4625,
                ["occurred_at_utc"]=D.Stamp(at),["scope"]=scope.Document,["fields"]=data };
            oldEvents.Add(PasswordNative.Parse(scope,id,new string('a',64),4625,at,root.ToString()));
            newEvents.Add(PasswordNative.Parse(scope,id,new string('a',64),4625,at,document.ToJsonString()));
        }
        var rule = new PasswordRule(scope,kind); var before = Assert.Single(rule.Advance(new(),oldEvents,start.AddSeconds(140)).Emissions);
        var after = Assert.Single(rule.Advance(new(),newEvents,start.AddSeconds(140)).Emissions);
        Assert.Equal((before.Entity,before.KnownBadPassword,before.DistinctNames),(after.Entity,after.KnownBadPassword,after.DistinctNames));
        Assert.Equal(before.Occurrences.Select(w => w.Ref.ToJsonString()),after.Occurrences.Select(w => w.Ref.ToJsonString()));
    }

    public static IEnumerable<object[]> Cases() => DetectionTests.Vectors().Where(v =>
        v!["mode"]!.ToString() is "identity" or "events" && v["rows"]!.AsArray().All(r =>
            r!["event_id"]!.GetValue<int>() is 4624 or 4768 or 4769 or 4720 or 4728 or 4732 or 4756 or 4688 or 4104 or 1102 or 4719 or 7036 or 7040 or 7045))
        .Select(v => new object[] { v!["name"]!.ToString() });

    [Theory, MemberData(nameof(Cases))]
    public void Short_projection_preserves_beta_rule_decisions_including_negative_cases(string name)
    {
        var vector = DetectionTests.Vector(name); var scope = PasswordScope.Read(vector["scope"]) with { PluginId = "sli.windows.ad-dc" };
        bool identity = vector["mode"]!.ToString() == "identity";
        var original = vector["rows"]!.AsArray().Select(n => DetectionTests.Native(DetectionTests.Row(n!), identity)).ToArray();
        var compact = new List<JsonObject>();
        for (int i = 0; i < original.Length; i++) {
            var input = original[i]; var reference = DetectionTests.Row(vector["rows"]![i]!).Ref;
            int kind = input["event_id"]!.GetValue<int>();
            string channel = kind == 4104 ? "Microsoft-Windows-PowerShell/Operational" : kind is 7036 or 7040 or 7045 ? "System" : "Security";
            string provider = kind == 4104 ? "Microsoft-Windows-PowerShell" : channel == "System" ? "Service Control Manager" : kind == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing";
            var root = XElement.Parse(input["source_xml"]!.GetValue<string>()); XNamespace ns = EventXml.Namespace;
            var system = root.Element(ns+"System")!;
            system.Add(new XElement(ns+"Provider", new XAttribute("Name", provider)), new XElement(ns+"Channel", channel), new XElement(ns+"EventRecordID", i+1));
            input["source_xml"] = root.ToString();
            string computer = system.Element(ns+"Computer")!.Value;
            var native = EventXml.Parse(root.ToString(), computer, computer, channel);
            native["computer_name"] = "collector-alias.example.test";
            var row = Assert.IsType<ShortEventRow>(ShortEventRow.Create(long.Parse(reference.NativeId), 1, native, Direct4624Projection.Create(native), 1));
            var method = JsonNode.Parse(row.Method)!.AsObject(); var fields = method["$principals"]!.DeepClone().AsObject();
            foreach (var (key,value) in method.Where(p => !p.Key.StartsWith('$'))) fields[key] = value?.DeepClone();
            foreach (var (key,value) in JsonNode.Parse(row.Outcome)!.AsObject()) fields[key] = value?.DeepClone();
            foreach (var (key,value) in row.Fields) fields[key] = value;
            var doc = new JsonObject { ["version"] = "sli.short-event.1", ["source_event_id"] = row.EventId,
                ["event_id"] = kind, ["occurred_at_utc"] = D.Stamp(new(row.Time)), ["scope"] = scope.Document,
                ["computer"] = method["$machine_name"]?.DeepClone(), ["channel"] = channel, ["provider"] = provider, ["fields"] = fields };
            var stored = input.DeepClone().AsObject(); stored["source_xml"] = doc.ToJsonString(); compact.Add(stored);
        }
        var now = D.Time(vector["now"]); var oldRows = DetectionNative.ParseEvents(scope, original, identity);
        var newRows = DetectionNative.ParseEvents(scope, compact, identity);
        Assert.Equal(oldRows.Select(r => (r.Ref,r.At,r.EventId)),newRows.Select(r => (r.Ref,r.At,r.EventId)));
        var oldSignals = identity ? IdentityAttacks.Evaluate(scope, oldRows, now, IdentityAttackPolicy.Read(vector["policy"])) : AttackPrecursors.DetectEvents(oldRows, now, PrecursorPolicy.Read(vector["policy"]));
        var newSignals = identity ? IdentityAttacks.Evaluate(scope, newRows, now, IdentityAttackPolicy.Read(vector["policy"])) : AttackPrecursors.DetectEvents(newRows, now, PrecursorPolicy.Read(vector["policy"]));
        if (oldRows.Any(r => r.Host.EnumerateRunes().Count() > EventStorageMeaning.Current.Common.MaxLength)) {
            // The S2 catalog bounds host strings. Oversized hostile labels keep
            // the decision and escaping, but cannot retain their unbounded key.
            Assert.Equal(oldSignals.Select(s => D.Text(s["rule_id"])),newSignals.Select(s => D.Text(s["rule_id"])));
            Assert.All(newRows,r => Assert.True(r.Host.Length <= EventStorageMeaning.Current.Common.MaxLength));
            Assert.All(newSignals,s => Assert.DoesNotContain("<",D.Text(s["attack_context"]?["host"])));
        } else {
            Assert.Equal(oldRows.Select(r => r.Host),newRows.Select(r => r.Host));
            Assert.Equal(oldSignals.Select(DetectionSignal.Id), newSignals.Select(DetectionSignal.Id));
        }
        if (compact.Count > 0) {
            var changed = JsonNode.Parse(compact[0]["source_xml"]!.GetValue<string>())!;
            changed["scope"]!["source_generation"] = "synthetic-other-generation";
            compact[0]["source_xml"] = changed.ToJsonString();
            Assert.Throws<DetectionFailure>(() => DetectionNative.ParseEvents(scope, compact, identity));
        }
    }
}
