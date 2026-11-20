using System.Text.Json.Nodes;
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
            Assert.Equal(step["payload_canonical"]!.GetValue<string>(), CanonicalJson.Serialize(sample.Payload));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_before"]), CanonicalJson.Serialize(sample.CursorBefore.ToJson()));
            Assert.Equal(CanonicalJson.Serialize(step["cursor_after"]), CanonicalJson.Serialize(sample.CursorAfter.ToJson()));
            Assert.Equal(step["continuity_state"]!.GetValue<string>(), sample.ContinuityState);
            Assert.Equal(step["filtered_count"]!.GetValue<long>(), sample.FilteredCount);
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
