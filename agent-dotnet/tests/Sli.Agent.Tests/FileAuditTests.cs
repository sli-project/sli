using System.Text.Json.Nodes;
using System.Runtime.Versioning;
using System.Xml.Linq;
using System.Xml.XPath;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class FileAuditTests
{
    private static JsonObject FirstStep() => Vectors.Load("file-audit-scenarios.json")[0]!["steps"]![0]!.AsObject();
    private sealed class RowsSource(IReadOnlyList<EventRow> rows) : IFileAuditEventSource
    { public SourceBatch Read(JsonObject progress,int limit) => new(rows); }
    private static EventRow FirstRow()
    {
        var row=FirstStep()["rows"]![0]!; return new(row["xml"]!.ToString(),row["bookmark"]!.ToString());
    }

    private static EventRow NativeRow(int id, int kind, string path, int second, string newDescriptor = "D:(A;;FR;;;WD)")
    {
        string provider = kind == 1102 ? "Microsoft-Windows-Eventlog" : FileAuditPolicy.Provider;
        return new($$"""
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><Provider Name="{{provider}}" /><EventID>{{kind}}</EventID><Keywords>0x8020000000000000</Keywords>
                <EventRecordID>{{id}}</EventRecordID><TimeCreated SystemTime="2026-10-01T01:02:{{second:D2}}.1234567Z" /><Channel>Security</Channel></System>
              <EventData><Data Name="ObjectServer">Security</Data><Data Name="ObjectType">File</Data>
                <Data Name="ObjectName">{{path}}</Data><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data>
                <Data Name="SubjectLogonId">0x12</Data><Data Name="ProcessId">0x10</Data><Data Name="HandleId">0x44</Data>
                <Data Name="OldSd">D:(A;;FA;;;WD)</Data><Data Name="NewSd">{{newDescriptor}}</Data></EventData>
            </Event>
            """,$"instant-{id}");
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Server_activity_query_selects_only_file_events_and_the_clear_marker()
    {
        var config = FileAuditManagerTests.Config();
        foreach (bool optional in new[] { false, true })
        {
            config["optional_events"] = optional;
            var selector = FileAuditEventSource.Filter(FileAuditPolicy.Parse(config));
            var selected = new List<int>();
            foreach (int id in new[] { 1102,4624,4625,4656,4658,4659,4660,4663,4664,4670,5140,5145 })
            {
                var system = XElement.Parse($"<System><Provider Name='{(id == 1102 ? "Microsoft-Windows-Eventlog" : FileAuditPolicy.Provider)}'/><EventID>{id}</EventID></System>");
                if ((bool)system.XPathEvaluate(selector)) selected.Add(id);
            }
            Assert.Equal(optional ? [1102,4656,4658,4660,4663,4670,5145] : new[] { 1102,4656,4660,4663,4670,5145 }, selected);
        }
    }

    [Fact]
    public void Server_activity_excludes_logons_and_paths_outside_the_scope()
    {
        const string root = @"C:\synthetic\share";
        const string file = root + @"\notes.txt";
        var config = FileAuditManagerTests.Config();
        config["roots"]![0]!["path"] = root;
        var rows = new[]
        {
            NativeRow(1,4625,file,10),
            NativeRow(2,4663,root + @"-other\notes.txt",11),
            NativeRow(3,4660,"",12),
            NativeRow(4,4663,file,13),
            NativeRow(5,1102,"",14)
        };
        var checkedPaths = new List<string>();
        var module = new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(config),new RowsSource(rows),
            (path,_) => checkedPaths.Add(path));
        var sample = module.Collect(null,Helpers.Now);
        Assert.Equal([4663,1102],sample.Payload["records"]!.AsArray().Select(r => r!["payload"]!["event_id"]!.GetValue<int>()));
        Assert.Equal([file],checkedPaths);
        Assert.Equal(3,sample.FilteredCount);
        Assert.Equal("gap",sample.ContinuityState);
    }

    [Fact]
    public void Server_activity_keeps_scoped_native_rows_and_pinned_file_kind()
    {
        const string root = @"C:\synthetic\Обмен";
        var file = $@"{root}\notes.txt";
        var config = FileAuditManagerTests.Config();
        config["roots"]![0]!["path"] = root;
        config["roots"]![0]!["important"] = true;
        var share = NativeRow(3,5145,root,12);
        share = new EventRow(share.Xml.Replace("ObjectName", "ShareLocalPath", StringComparison.Ordinal)
            .Replace("</EventData>", """<Data Name="RelativeTargetName">notes.txt</Data></EventData>""", StringComparison.Ordinal), share.Bookmark);
        var module = new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(config),
            new RowsSource([NativeRow(1,4663,file,10),NativeRow(2,4660,"",11),share,NativeRow(4,4670,file,13)]),
            (path,scope) => { Assert.Equal(root,scope); Assert.Equal(file,path); },
            pathKind: (path,scope) => { Assert.Equal(root,scope); Assert.Equal(file,path); return "file"; });
        var sample = module.Collect(null, Helpers.Now);
        var entries = sample.Payload["records"]!.AsArray();
        Assert.Equal(new[] { 4663, 4660, 5145, 4670 }, entries.Select(entry => entry!["payload"]!["event_id"]!.GetValue<int>()));
        Assert.All(entries, entry => Assert.Equal("event_xml",entry!["format"]!.GetValue<string>()));
        Assert.DoesNotContain(file,entries[1]!["payload"]!["xml"]!.GetValue<string>());
        var kinds = sample.Payload["context"]!["object_kinds"]!.AsObject();
        Assert.Equal("file",Assert.Single(kinds).Value!.GetValue<string>());
        Assert.Equal("file",kinds["1"]!.GetValue<string>());
    }

    [Fact]
    public void Server_permissions_fold_only_native_acl_changes_and_deliver_journal_clear_separately()
    {
        var policy = FileAuditPolicy.Parse(FileAuditManagerTests.Config());
        var ordinaryFile = @"C:\synthetic\notes.txt";
        var ordinaryDirectory = @"C:\synthetic\notes";
        var first = NativeRow(1,4670,ordinaryFile,10);
        var directory = NativeRow(2,4670,ordinaryDirectory,12);
        var second = NativeRow(3,4670,ordinaryFile,14);
        var ordinaryAccess = NativeRow(4,4663,ordinaryFile,15);
        var journalClear = NativeRow(5,1102,ordinaryFile,16);
        var seen = new List<string>();
        FileAuditModule Module(params EventRow[] events) =>
            new(Helpers.HostId,policy,new RowsSource(events),(path,root) => { Assert.Equal(@"C:\synthetic",root); seen.Add(path); },
                permissionsOnly:true);

        var batch = Module(first,directory,second,ordinaryAccess,journalClear).Collect(null,Helpers.Now);
        var entries = batch.Payload["records"]!.AsArray();
        Assert.Equal(2,entries.Count);
        Assert.All(entries,r => Assert.Equal("file_action",r!["format"]!.GetValue<string>()));
        Assert.Equal(ordinaryDirectory,entries[0]!["payload"]!["path"]!.GetValue<string>());
        var folded = entries[1]!["payload"]!;
        Assert.Equal(ordinaryFile,folded["path"]!.GetValue<string>());
        Assert.Equal("permissions",folded["operation"]!.GetValue<string>());
        Assert.Equal(2,folded["count"]!.GetValue<int>());
        Assert.Equal("2026-10-01T01:02:10.123456+00:00",folded["first_seen_utc"]!.GetValue<string>());
        Assert.Equal("2026-10-01T01:02:14.123456+00:00",folded["last_seen_utc"]!.GetValue<string>());
        Assert.Equal(1,batch.FilteredCount);
        var cursor = JsonNode.Parse(batch.CursorAfter.Token)!;
        Assert.Equal(4,cursor["record_id"]!.GetValue<int>());
        Assert.Equal("instant-4",cursor["bookmark"]!.GetValue<string>());
        Assert.Equal(new[] {ordinaryFile,ordinaryDirectory,ordinaryFile},seen);
        Assert.DoesNotContain("OldSd",CanonicalJson.Serialize(batch.Payload));

        var gap = Module(journalClear).Collect(new(batch.Generation,batch.CursorAfter),Helpers.Now);
        var record = Assert.Single(gap.Payload["records"]!.AsArray())!;
        Assert.Equal("event_xml",record["format"]!.GetValue<string>());
        Assert.Equal(1102,record["payload"]!["event_id"]!.GetValue<int>());
        Assert.Equal("gap",gap.ContinuityState);
        Assert.Equal(batch.CursorAfter,gap.CursorBefore);
    }

    [Fact]
    public void Server_permissions_reject_unproven_changes_and_unavailable_paths()
    {
        var policy = FileAuditPolicy.Parse(FileAuditManagerTests.Config());
        var sample = new FileAuditModule(Helpers.HostId,policy,new RowsSource([
            NativeRow(1,4670,@"C:\synthetic\unchanged.txt",10,"D:(A;;FA;;;WD)"),
            NativeRow(2,4670,@"C:\unrelated\notes.txt",11),
            NativeRow(3,4670,@"C:\synthetic\unavailable.txt",12)
        ]),(_,_) => throw new IOException(),permissionsOnly:true).Collect(null,Helpers.Now);
        Assert.Empty(sample.Payload["records"]!.AsArray());
        Assert.Equal(2,sample.FilteredCount);
        Assert.Equal(1,sample.LostCount);
        Assert.Equal("gap",sample.ContinuityState);
    }

    [Fact]
    public void QueueBackpressureAndRestartRetainEvidenceUntilTheExactReceipt()
    {
        var dir=Helpers.TempDirectory();
        using var key=Helpers.NewKey();
        try
        {
            var module=new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(FileAuditManagerTests.Config()),new RowsSource([FirstRow()]),(_,_) => { });
            SignedPacket packet;
            using (var queue=Helpers.Queue(dir,maxBytes:1))
            {
                var sample=module.Collect(queue.Captured(FileAuditModule.ModuleId),Helpers.Now);
                Assert.Throws<QueueFullException>(() => queue.Capture(Helpers.Signer(key),Helpers.AgentId,sample,Helpers.Now));
                Assert.Null(queue.Captured(FileAuditModule.ModuleId));
                queue.MaxBytes=1000000;
                var retried=module.Collect(queue.Captured(FileAuditModule.ModuleId),Helpers.Now);
                Assert.Equal(sample.CursorAfter,retried.CursorAfter); Assert.Equal(CanonicalJson.Serialize(sample.Payload),CanonicalJson.Serialize(retried.Payload));
                packet=queue.Capture(Helpers.Signer(key),Helpers.AgentId,retried,Helpers.Now);
            }
            using (var queue=Helpers.Queue(dir))
            {
                Assert.Equal(packet.ToCanonical(),Assert.Single(queue.Pending()).ToCanonical());
                var wrong=Helpers.Receipt(packet); wrong["committed_cursor"]=Cursor.Start("bookmark").ToJson();
                Assert.False(queue.Acknowledge(packet,wrong)); Assert.Single(queue.Pending());
                Assert.True(queue.Acknowledge(packet,Helpers.Receipt(packet,"duplicate"))); Assert.Empty(queue.Pending());
                var next=new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(FileAuditManagerTests.Config()),new RowsSource([]),(_,_) => { }).Collect(queue.Captured(FileAuditModule.ModuleId),Helpers.Now);
                Assert.Equal(packet.Envelope.CursorAfter,next.CursorBefore); Assert.Equal(next.CursorBefore,next.CursorAfter);
            }
        }
        finally { Directory.Delete(dir,true); }
    }

    [Fact]
    public void EventByteCountAndWallLimitsDoNotAdvanceTheSourceOnRejectedEvidence()
    {
        var config=FileAuditManagerTests.Config(); config["max_bytes"]=1024;
        var source=new RowsSource([FirstRow()]);
        var module=new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(config),source,(_,_) => { });
        Assert.Equal("file_audit_event_size_limit",Assert.Throws<AgentException>(() => module.Collect(null,Helpers.Now)).Code);
        config["max_bytes"]=1048576; config["max_events"]=1;
        Assert.Equal("file_audit_range_invalid",Assert.Throws<AgentException>(() => new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(config),new RowsSource([FirstRow(),FirstRow()]),(_,_) => { }).Collect(null,Helpers.Now)).Code);
        config["wall_seconds"]=1; var time=-1;
        var sample=new FileAuditModule(Helpers.HostId,FileAuditPolicy.Parse(config),source,(_,_) => { },clock:() => TimeSpan.FromSeconds(++time)).Collect(null,Helpers.Now);
        Assert.Empty(sample.Payload["records"]!.AsArray()); Assert.Equal(sample.CursorBefore,sample.CursorAfter);
    }

    [Theory]
    [InlineData(@"\\server\share")]
    [InlineData(@"C:\synthetic\..\escape")]
    [InlineData(@"C:\synthetic\item:stream")]
    [InlineData(@"C:\synthetic\trailing.")]
    public void InvalidPathsCannotAuthorizeReadsOrSaclWrites(string path)
    {
        var config=FileAuditManagerTests.Config(); config["roots"]![0]!["path"]=path;
        Assert.Throws<AgentException>(() => FileAuditPolicy.Parse(config));
    }

    [Fact]
    public void ModuleIsDisabledByDefaultAndExplicitDisabledAssignmentDoesNotParseItsConfig()
    {
        var assignment=PolicyCycleTests.Assignment(); assignment["assigned_modules"]=new JsonArray();
        Assert.Null(AgentPolicy.Parse(assignment,Helpers.AgentId,EventCatalog.Load()).FileAudit);
        assignment["assigned_modules"]!.AsArray().Add(new JsonObject { ["module_id"]=FileAuditModule.ModuleId,["enabled"]=false,["config"]=new JsonObject { ["roots"]="invalid" } });
        Assert.Null(AgentPolicy.Parse(assignment,Helpers.AgentId,EventCatalog.Load()).FileAudit);
        assignment["assigned_modules"]![0]!["enabled"]=true;
        Assert.Throws<AgentException>(() => AgentPolicy.Parse(assignment,Helpers.AgentId,EventCatalog.Load()));
    }

    private sealed class GapSource : IFileAuditEventSource
    { public SourceBatch Read(JsonObject progress,int limit) => throw new FileAuditJournalGap(); }
    [Fact]
    public void ProvenJournalGapIsDurableAndTheNextReadUsesTheNewGeneration()
    {
        var policy=FileAuditPolicy.Parse(FileAuditManagerTests.Config());
        var first=new FileAuditModule(Helpers.HostId,policy,new RowsSource([FirstRow()]),(_,_) => { }).Collect(null,Helpers.Now);
        var id=Guid.Parse("00000000-0000-4000-8000-000000000001");
        var gap=new FileAuditModule(Helpers.HostId,policy,new GapSource(),(_,_) => { },newId:() => id).Collect(new(first.Generation,first.CursorAfter),Helpers.Now);
        Assert.Equal(Helpers.HostId+":"+id,gap.Generation); Assert.Equal(Cursor.Start("bookmark"),gap.CursorBefore);
        Assert.Equal("gap",gap.ContinuityState); Assert.Null(gap.LostCount);
        var next=new FileAuditModule(Helpers.HostId,policy,new RowsSource([]),(_,_) => { }).Collect(new(gap.Generation,gap.CursorAfter),Helpers.Now);
        Assert.Equal(gap.Generation,next.Generation); Assert.Equal(gap.CursorAfter,next.CursorBefore);
    }

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("file-audit-scenarios.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory, MemberData(nameof(Names))]
    public void MatchesPythonEvidencePrivacyAndRestartCursor(string name)
    {
        var scenario = Vectors.Load("file-audit-scenarios.json").AsArray().Single(x => x!["name"]!.GetValue<string>() == name)!;
        var config = FileAuditPolicy.Parse(scenario["config"]!.AsObject());
        Assert.Equal(CanonicalJson.Serialize(scenario["normalized"]), CanonicalJson.Serialize(config.Value));
        Assert.Equal(CanonicalJson.Serialize(scenario["aces"]), CanonicalJson.Serialize(FileAuditPolicy.DesiredAces(config.Roots[0]!.AsObject())));
        Assert.Equal(CanonicalJson.Serialize(scenario["required_masks"]), CanonicalJson.Serialize(JsonSerializerNode(config.RequiredMasks())));
        CapturedPosition? position = null;
        using var key=Helpers.NewKey(); var packets=new JsonArray();
        foreach (var step in scenario["steps"]!.AsArray())
        {
            // Construct a new module every step, as after a service restart.
            var source = new VectorFileSource(step!.AsObject());
            var module = new FileAuditModule(scenario["host_id"]!.GetValue<string>(), config, source,
                (path, root) => { if (name == "path-unavailable") throw new IOException("private-path"); }, _ => true,
                newId:() => Guid.Parse("00000000-0000-4000-8000-000000000001"));
            var sample = module.Collect(position, Iso8601.ParseUtc(step["now"]!.GetValue<string>()));
            var expected = JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
            var oldRows = expected["records"]!.AsArray();
            // These historical capture fixtures contain rows excluded by the scoped server collector.
            var excluded = name switch
            {
                "events-restart-filter" => oldRows.Where(r => r!["payload"]!["event_id"]!.GetValue<int>() is 4660 or 4624).ToArray(),
                "handle-negative-evidence" => oldRows.ToArray(),
                "important-optional" => oldRows.Where(r => r!["payload"]!["event_id"]!.GetValue<int>() == 4664).ToArray(),
                _ => []
            };
            foreach (var row in excluded) oldRows.Remove(row);
            long filtered = step["filtered_count"]!.GetValue<long>() + excluded.Length;
            var range = expected["header"]!["record_id_range"]!;
            range["first"] = oldRows.FirstOrDefault()?["record_id"]?.DeepClone();
            range["last"] = oldRows.LastOrDefault()?["record_id"]?.DeepClone();
            expected["context"]!["filtered_count"] = filtered;
            Assert.Equal(CanonicalJson.Serialize(expected), CanonicalJson.Serialize(sample.Payload));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_before"]), CanonicalJson.Serialize(sample.CursorBefore.ToJson()));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_after"]), CanonicalJson.Serialize(sample.CursorAfter.ToJson()));
            Assert.Equal(excluded.Length > 0 ? "filtered" : step["continuity_state"]!.GetValue<string>(), sample.ContinuityState);
            Assert.Equal(filtered, sample.FilteredCount);
            Assert.Equal(step["lost_count"]?.GetValue<long>(), sample.LostCount);
            Assert.DoesNotContain("private-secret", CanonicalJson.Serialize(sample.Payload));
            Assert.DoesNotContain("private-account", CanonicalJson.Serialize(sample.Payload));
            packets.Add(Packets.Make(Helpers.Signer(key),Helpers.AgentId,packets.Count+1,sample,Iso8601.ParseUtc(step["now"]!.ToString())).ToJson());
            position = new(sample.Generation, sample.CursorAfter);
        }
        if (Environment.GetEnvironmentVariable("SLI_DOTNET_INTEROP_DIR") is { Length: > 0 } target)
        {
            Directory.CreateDirectory(target);
            File.WriteAllText(Path.Combine(target,"file-audit-"+name+".json"),new JsonObject
            { ["host_id"]=scenario["host_id"]!.DeepClone(),["config"]=config.Value.DeepClone(),["public_key_spki_b64"]=Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),["packets"]=packets }.ToJsonString());
        }
    }

    private static JsonObject JsonSerializerNode(Dictionary<string, int> values) => new(values.Select(x => new KeyValuePair<string, JsonNode?>(x.Key, JsonValue.Create(x.Value))));

    private sealed class VectorFileSource(JsonObject step) : IFileAuditEventSource
    {
        public SourceBatch Read(JsonObject progress, int limit)
        {
            Assert.Equal(CanonicalJson.Serialize(step["progress"]), CanonicalJson.Serialize(progress));
            if (step["rows"]?.ToString() == "gap") throw new FileAuditJournalGap();
            if (step["rows"] is not JsonArray rows) throw new EventLogReadException(code: "file_audit_read_failed");
            return new(rows.Select(r => new EventRow(r!["xml"]!.GetValue<string>(), r["bookmark"]!.GetValue<string>())).ToArray());
        }
    }
}
