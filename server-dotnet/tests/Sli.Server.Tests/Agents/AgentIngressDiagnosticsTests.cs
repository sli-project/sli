using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentIngressDiagnosticsTests
{
    private sealed class MemoryLogger : ILogger<AgentIngressDiagnostics>
    {
        public readonly List<string> Messages=[];
        public bool Throw;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState,Exception?,string> formatter)
        { if (Throw) throw new IOException("synthetic sink failure"); Messages.Add(formatter(state,error)); }
    }
    private sealed class Clock : TimeProvider
    {
        public long Tick;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Tick;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(Tick);
    }
    private static Envelope Envelope(string module="sli.heartbeat") => new("00000000-0000-4000-8000-000000000001",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","host",module,"1.0.0","1","heartbeat","host",1,
        new Cursor("record_id",""),new Cursor("record_id","1"),"sli.heartbeat.v1",new string('a',64),0,0,
        "2026-10-07T12:00:00+00:00","not_proven",0,null);

    [Fact]
    public void RejectionAfterCommitUsesSafeMetadataAndBoundedWindow()
    {
        string dir=Path.Combine(Path.GetTempPath(),"sli-diag-"+Guid.NewGuid().ToString("N"));
        var log=new MemoryLogger(); var clock=new Clock(); var diagnostics=new AgentIngressDiagnostics(dir,log,clock);
        var identity=new AgentIdentity(Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),Guid.NewGuid(),new string('a',64),"active");
        var receipt=new JsonObject { ["status"]="retry_later", ["error_code"]="SECRET\nINJECTION" };
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope(),receipt));
        Assert.False(diagnostics.RejectionAfterCommit(identity,Envelope(),receipt));
        clock.Tick=TimeSpan.FromSeconds(61).Ticks;
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope(),receipt));
        Assert.Equal(2,log.Messages.Count); Assert.All(log.Messages,m => Assert.Contains("agent_delivery_rejected",m));
        Assert.DoesNotContain("SECRET",string.Join("\n",log.Messages));
        receipt["status"]="committed"; Assert.False(diagnostics.RejectionAfterCommit(identity,Envelope(),receipt));
        receipt["status"]="retry_later";
        log.Throw=true; clock.Tick=TimeSpan.FromSeconds(122).Ticks;
        Assert.False(diagnostics.RejectionAfterCommit(identity,Envelope(),receipt));
    }

    [Fact]
    public void FileAuditRejectionLogsOnlyAllowlistedReasons()
    {
        var log=new MemoryLogger(); var clock=new Clock();
        var diagnostics=new AgentIngressDiagnostics(Path.GetTempPath(),log,clock);
        var identity=new AgentIdentity(Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),Guid.NewGuid(),new string('a',64),"active");
        var receipt=new JsonObject { ["status"]="rejected",["error_code"]=Receipt.FileAuditInvalid,
            ["error_reason"]=Receipt.FileAuditWrongEvent };
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.file-audit"),receipt));
        Assert.Contains("error_reason=event_id_not_file_audit",Assert.Single(log.Messages));
        receipt["error_reason"]="untrusted-data";
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.file-audit"),receipt));
        Assert.DoesNotContain("untrusted-data",log.Messages[1]);
        receipt["error_reason"]=Receipt.FileAuditInvalidPayload;
        receipt["error_detail"]="invalid_observation_time";
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.file-audit"),receipt));
        Assert.Contains("error_reason=invalid_observation_time",log.Messages[2]);
        receipt["error_detail"]="untrusted-data";
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.file-audit"),receipt));
        Assert.Contains("error_reason=invalid_payload",log.Messages[3]);
        Assert.DoesNotContain("untrusted-data",log.Messages[3]);
    }

    [Fact]
    public void RejectionLimiterCapsGlobalWindowAndRecoversAfterInterval()
    {
        var log=new MemoryLogger(); var clock=new Clock();
        var diagnostics=new AgentIngressDiagnostics(Path.GetTempPath(),log,clock);
        var identity=new AgentIdentity(Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),Guid.NewGuid(),new string('a',64),"active");
        var receipt=new JsonObject { ["status"]="rejected",["error_code"]="agent_sequence_conflict" };
        for(int i=0;i<1024;i++) Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.fixture"+i),receipt));
        Assert.False(diagnostics.RejectionAfterCommit(identity,Envelope("sli.overflow"),receipt));
        clock.Tick=TimeSpan.FromSeconds(60).Ticks;
        Assert.True(diagnostics.RejectionAfterCommit(identity,Envelope("sli.overflow"),receipt));
        Assert.Equal(1025,log.Messages.Count);
    }
    [Fact]
    public void DataDirectoryUsesSourcePrecedenceAndFallback()
    {
        string parent=Path.Combine(Path.GetTempPath(),"sli-path-"+Guid.NewGuid().ToString("N"));
        string root=Path.Combine(parent,"repo"); Directory.CreateDirectory(root);
        try
        {
            var env=new Dictionary<string,string?> { ["ADLOG_DATA_DIR"]="one",["SLI_DATA_DIR"]="two" };
            string? Read(string name) => env.TryGetValue(name,out var value) ? value : null;
            Assert.Equal(Path.Combine(root,"one"),AgentIngressDiagnostics.ResolveDataDirectory(root,Read));
            env["ADLOG_DATA_DIR"]=" "; Assert.Equal(Path.Combine(root,"two"),AgentIngressDiagnostics.ResolveDataDirectory(root,Read));
            env.Clear(); Assert.Equal(Path.Combine(root,"data"),AgentIngressDiagnostics.ResolveDataDirectory(root,Read));
            Directory.CreateDirectory(Path.Combine(parent,"sli_data"));
            Assert.Equal(Path.Combine(parent,"sli_data"),AgentIngressDiagnostics.ResolveDataDirectory(root,Read));
        }
        finally { Directory.Delete(parent,true); }
    }
    [Fact]
    public void QuotaAuditIsSafeBoundedAndSinkFailureCannotEscape()
    {
        string dir=Path.Combine(Path.GetTempPath(),"sli-diag-"+Guid.NewGuid().ToString("N"));
        try
        {
            var log=new MemoryLogger(); var diagnostics=new AgentIngressDiagnostics(dir,log,new Clock(),maxBytes:256);
            var usage=new Dictionary<string,long> { ["agent_count"]=1,["storage_bytes"]=123 };
            var quota=new AgentQuotaRejection(Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),"sli.windows-eventlog","agent_inbox_agent_count_limit",usage,1,100);
            for(int i=0;i<8;i++) diagnostics.QuotaRejected(quota);
            string file=Path.Combine(dir,"logs","audit-actions.log");
            Assert.True(File.Exists(file)); Assert.True(File.Exists(file+".1")); Assert.False(File.Exists(file+".6"));
            using var json=JsonDocument.Parse(File.ReadAllLines(file).Last());
            Assert.Equal("packet_quota_rejected",json.RootElement.GetProperty("event").GetString());
            Assert.Equal("agent_packet_admission",json.RootElement.GetProperty("action").GetString());
            Assert.Equal(100,json.RootElement.GetProperty("packet_bytes").GetInt32());
            log.Throw=true; var broken=new AgentIngressDiagnostics(file,log,new Clock());
            broken.QuotaRejected(quota);
        }
        finally { if(Directory.Exists(dir)) Directory.Delete(dir,true); }
    }
}




