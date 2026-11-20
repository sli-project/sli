using System.Reflection;
using Sli.Agent.Core;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusAccountingProjectionTests
{
    private static string Line(string packet,string status="",string session="opaque-session",string nas="VPN-GW-01") {
        var f=Enumerable.Repeat("",66).ToArray();f[0]="NPS01";f[1]="IAS";f[2]="07/30/2026";f[3]="15:00:00";f[4]=packet;f[6]="example.test/Users/sample.user";f[11]=nas;f[26]="opaque-class";f[31]=status;f[35]=session;return string.Join(',',f);
    }
    [Fact]
    public void PythonStripHandlesInterleavedWhitespaceAndGpoWrapperAgrees()
    {
        var assembly=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly;
        var strip=assembly.GetType("Sli.Server.Compatibility.PythonText")!.GetMethod("Strip",BindingFlags.Static|BindingFlags.NonPublic)!;
        var wrapper=assembly.GetType("Sli.Server.Agents.SnapshotPublication.GpoGovernanceSettings")!.GetMethod("PythonTrim",BindingFlags.Static|BindingFlags.NonPublic)!;
        const string input="\u001c \u2003\u001fVPN GW\u001e\u00a0 \u001d";
        Assert.Equal("VPN GW",strip.Invoke(null,[input]));
        Assert.Equal("VPN GW",wrapper.Invoke(null,[input]));
    }
    [Fact]
    public void ParserExposesSameReviewedCsvFieldsWithoutLosingQuotedCommas()
    {
        var method=typeof(RadiusAccountingRecord).GetMethod("ParseFields");Assert.NotNull(method);
        var fields=(IReadOnlyList<string>)method.Invoke(null,[Line("4","1", "\"id,with,commas\"")])!;
        Assert.Equal(66,fields.Count);Assert.Equal("id,with,commas",fields[35]);Assert.Equal("VPN-GW-01",fields[11]);
    }
    [Fact]
    public async Task SourceAccessAcceptThenAccountingProducesResolvedSessionAtSourceOffset()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner");Assert.NotNull(type);
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("2"),Line("4","1")},"radius-radius01-1","N. Central Asia Standard Time",420,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>("sid:S-1-5-21-100000003-200000003-300000003-1101"))])!;await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;
        var hashes=((System.Collections.IEnumerable)plan.GetType().GetProperty("EvidenceHashes")!.GetValue(plan)!).Cast<string>().ToArray();
        Assert.Equal(new[]{"0d176fef68a82662f7a6d292f06a75fecd27ce0045c93eb39b38c26bd7599a96","d8667391d01db0e50fb06f5234a73651fef311a207a088caa2a264b54163366b"},hashes);
        var obs=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().Single();
        Assert.Equal("radius-session:8b381b0cc646d59d1d340a3fcb5e7166655acd7c4fb43b4e72ed9f99ee3a8276",obs.GetType().GetProperty("SessionIdentityKey")!.GetValue(obs));
        Assert.Equal(new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),obs.GetType().GetProperty("ObservedAt")!.GetValue(obs));
    }
    [Fact]
    public void EvidenceIdentityMatchesSourceAndSeparateOrdinalsPreserveDuplicates()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusEvidenceStore");Assert.NotNull(type);
        var method=type.GetMethod("Identity")!;var epoch=Guid.Parse("00000000-0000-4000-8000-000000000001");
        var first=(Guid)method.Invoke(null,["radius-radius01-1","radius-accounting","unc-logfiles-in",epoch,"in-20260730",0L,0])!;
        Assert.Equal(Guid.Parse("fb1622ce-99a6-5a67-b8a9-01c584adfdb6"),first);
        Assert.NotEqual(first,method.Invoke(null,["radius-radius01-1","radius-accounting","unc-logfiles-in",epoch,"in-20260730",0L,1]));
    }    [Fact]
    public void EvidenceObjectIsImmutableAndDuplicateRecordsHaveDistinctIds()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusEvidenceStore")!;var publish=type.GetMethod("Publish")!;
        string temp=Path.GetFullPath(Path.GetTempPath());string root=Path.GetFullPath(Path.Combine(temp,"sli-radius-owned-"+Guid.NewGuid().ToString("N")));Assert.StartsWith(temp,root,StringComparison.OrdinalIgnoreCase);
        var epoch=Guid.Parse("00000000-0000-4000-8000-000000000001");
        object?[] Args(int ordinal,string record)=>[root,"radius-radius01-1","radius-accounting","unc-logfiles-in",epoch,"in-20260730",0L,ordinal,record];
        try {
            var first=publish.Invoke(null,Args(0,"synthetic record"))!;var again=publish.Invoke(null,Args(0,"synthetic record"))!;var second=publish.Invoke(null,Args(1,"synthetic record"))!;
            var id=(Guid)first.GetType().GetProperty("Id")!.GetValue(first)!;Assert.Equal(id,again.GetType().GetProperty("Id")!.GetValue(again));Assert.NotEqual(id,second.GetType().GetProperty("Id")!.GetValue(second));
            Assert.Equal("synthetic record",File.ReadAllText(Path.Combine(root,"published","acquisition-radius",id.ToString("N")[..2],id.ToString("N")+".record")));
            var error=Assert.Throws<TargetInvocationException>(()=>publish.Invoke(null,Args(0,"different record")));Assert.IsType<IOException>(error.InnerException);
        } finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }    [Fact]
    public async Task UnmatchedClassDoesNotPromoteUserNameToExactIdentity()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("4","1")},"radius-radius01-1","N. Central Asia Standard Time",420,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>(null))])!;await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;
        var obs=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().Single();
        Assert.Null(obs.GetType().GetProperty("SessionIdentityKey")!.GetValue(obs));Assert.Null(obs.GetType().GetProperty("Principal")!.GetValue(obs));
        Assert.Equal("start",obs.GetType().GetProperty("Lifecycle")!.GetValue(obs));
    }
    [Fact]
    public async Task RepeatedAccountingLinesRemainTwoObservationsAndTwoEvidenceOrdinals()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;string line=Line("4","1");
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{line,line},"radius-radius01-1","N. Central Asia Standard Time",420,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>(null))])!;await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;
        var observations=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().ToArray();var hashes=((System.Collections.IEnumerable)plan.GetType().GetProperty("EvidenceHashes")!.GetValue(plan)!).Cast<string>().ToArray();
        Assert.Equal(2,observations.Length);Assert.Equal(2,hashes.Length);Assert.Equal(hashes[0],hashes[1]);
    }    [Fact]
    public async Task SessionHashPreservesPythonUtf8UnicodeSeparators()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("2"),Line("4","1","abc\u2028def")},"radius-radius01-1","N. Central Asia Standard Time",420,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>("sid:S-1-5-21-100000003-200000003-300000003-1101"))])!;
        await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;var obs=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().Single();
        Assert.Equal("radius-session:b521872ad9e3b2b9003c9787cf63b436e732f836d48f3c572c9c0a930f7e6e21",obs.GetType().GetProperty("SessionIdentityKey")!.GetValue(obs));
    }    [Fact]
    public async Task AccountingControlRowsKeepEvidenceButCreateNoSession()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("4","7",""),Line("4","8","")},"radius-radius01-1","N. Central Asia Standard Time",420,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>(null))])!;
        await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;
        Assert.Empty(((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>());
        Assert.Equal(2,((System.Collections.IEnumerable)plan.GetType().GetProperty("EvidenceHashes")!.GetValue(plan)!).Cast<object>().Count());
    }
    [Fact]
    public async Task LifecycleRejectsMissingNasOrSessionRatherThanInventingIdentity()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        async Task Run(string line) { var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{line},"radius-radius01-1","UTC",0,DateTimeOffset.UtcNow,new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>(null))])!;await task; }
        await Assert.ThrowsAsync<ArgumentException>(()=>Run(Line("4","1","")));
        await Assert.ThrowsAsync<ArgumentException>(()=>Run(Line("4","1","opaque-session","")));
    }    [Fact]
    public async Task NasAddressFallbackIsOnlyUsedAsNasIdentity()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var fields=Line("4","1","opaque-session","").Split(',');fields[12]="192.0.2.100";
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("2"),string.Join(',',fields)},"radius-radius01-1","UTC",0,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>("sid:S-1-5-21-100000003-200000003-300000003-1101"))])!;
        await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;var obs=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().Single();
        Assert.Equal("radius-session:68da62b440ded7d70e42acf91be1e4706a043cb05e1be5abfabaec0de55416ec",obs.GetType().GetProperty("SessionIdentityKey")!.GetValue(obs));
    }    [Fact]
    public async Task SourceTrimRemovesInformationSeparatorAroundNas()
    {
        var type=typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly.GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var task=(Task)type.GetMethod("ProjectAsync")!.Invoke(null,[new[]{Line("2"),Line("4","1","opaque-session","\u001cVPN-GW-01\u001c")},"radius-radius01-1","UTC",0,new DateTimeOffset(2026,7,30,8,0,0,TimeSpan.Zero),new Dictionary<string,(string,DateTimeOffset)>(),(Func<string,Task<string?>>)(_=>Task.FromResult<string?>("sid:S-1-5-21-100000003-200000003-300000003-1101"))])!;
        await task;var plan=task.GetType().GetProperty("Result")!.GetValue(task)!;var obs=((System.Collections.IEnumerable)plan.GetType().GetProperty("Observations")!.GetValue(plan)!).Cast<object>().Single();
        Assert.Equal("radius-session:8b381b0cc646d59d1d340a3fcb5e7166655acd7c4fb43b4e72ed9f99ee3a8276",obs.GetType().GetProperty("SessionIdentityKey")!.GetValue(obs));
    }

    [Theory]
    [InlineData(10000, true)]
    [InlineData(10001, false)]
    public async Task ClassCacheUsesRuntimeContractCapacity(int entries, bool accepted)
    {
        var now = new DateTimeOffset(2026, 7, 30, 8, 0, 0, TimeSpan.Zero);
        var cache = Enumerable.Range(0, entries).ToDictionary(i => i.ToString("x64"),
            _ => ("sid:S-1-5-21-100000001-200000002-300000003-1101", now.AddDays(1)));
        var type = typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly
            .GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        var task = (Task)type.GetMethod("ProjectAsync")!.Invoke(null,
            [Array.Empty<string>(), "radius-radius01-1", "UTC", 0, now, cache,
             (Func<string, Task<string?>>)(_ => Task.FromResult<string?>(null))])!;
        if (accepted)
        {
            await task;
            var plan = task.GetType().GetProperty("Result")!.GetValue(task)!;
            Assert.Equal(entries, ((IReadOnlyDictionary<string, (string, DateTimeOffset)>)
                plan.GetType().GetProperty("Cache")!.GetValue(plan)!).Count);
        }
        else
        {
            Assert.Equal("class_cache_capacity_exceeded",
                (await Assert.ThrowsAsync<ArgumentException>(() => task)).Message);
        }
        Assert.Equal(entries, cache.Count);
    }

    // tests/sources/test_radius_accounting_runtime_contract.py: the second batch
    // must use only unexpired bindings from the first, without mutating its cache.
    [Theory]
    [InlineData(604799, true)]
    [InlineData(604800, false)]
    [InlineData(691200, false)]
    public async Task ClassBindingExpiresAfterSevenDays(int elapsedSeconds, bool identityReady)
    {
        var now = new DateTimeOffset(2026, 7, 30, 8, 0, 0, TimeSpan.Zero);
        const string principal = "sid:S-1-5-21-100000001-200000002-300000003-1101";
        var type = typeof(Sli.Server.Agents.Ingress.AgentRadiusValidator).Assembly
            .GetType("Sli.Server.Agents.Radius.RadiusPlanner")!;
        async Task<object> Project(string[] lines, DateTimeOffset observed,
            Dictionary<string, (string Principal, DateTimeOffset Expires)> cache)
        {
            var task = (Task)type.GetMethod("ProjectAsync")!.Invoke(null,
                [lines, "radius-radius01-1", "N. Central Asia Standard Time", 420,
                 observed, cache, (Func<string, Task<string?>>)(dn =>
                     Task.FromResult<string?>(dn == "example.test/Users/sample.user" ? principal : null))])!;
            await task;
            return task.GetType().GetProperty("Result")!.GetValue(task)!;
        }
        var original = new Dictionary<string, (string Principal, DateTimeOffset Expires)>();
        var first = await Project([Line("2")], now.AddSeconds(-elapsedSeconds), original);
        var cache = ((IReadOnlyDictionary<string, (string Principal, DateTimeOffset Expires)>)
            first.GetType().GetProperty("Cache")!.GetValue(first)!).ToDictionary(x => x.Key, x => x.Value);
        Assert.Empty(original);
        Assert.Empty(((System.Collections.IEnumerable)first.GetType().GetProperty("Observations")!.GetValue(first)!).Cast<object>());
        var binding = Assert.Single(cache).Value;
        Assert.Equal(principal, binding.Principal);
        Assert.Equal(now.AddSeconds(604800 - elapsedSeconds), binding.Expires);

        var second = await Project([Line("4", "1")], now, cache);
        var observation = Assert.Single(((System.Collections.IEnumerable)
            second.GetType().GetProperty("Observations")!.GetValue(second)!).Cast<object>());
        Assert.Equal("start", observation.GetType().GetProperty("Lifecycle")!.GetValue(observation));
        Assert.Equal(now, observation.GetType().GetProperty("ObservedAt")!.GetValue(observation));
        Assert.Equal(identityReady ? principal : null, observation.GetType().GetProperty("Principal")!.GetValue(observation));
        Assert.Equal(identityReady, observation.GetType().GetProperty("SessionIdentityKey")!.GetValue(observation) is not null);
        var updated = (IReadOnlyDictionary<string, (string Principal, DateTimeOffset Expires)>)
            second.GetType().GetProperty("Cache")!.GetValue(second)!;
        Assert.Equal(identityReady ? 1 : 0, updated.Count);
        Assert.Single(cache);
        Assert.Equal(binding, Assert.Single(cache).Value);
    }
}
