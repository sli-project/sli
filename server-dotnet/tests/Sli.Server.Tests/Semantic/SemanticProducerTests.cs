using Sli.Server.Storage.Direct;
using Sli.Server.Semantic;
using System.Text.Json.Nodes;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[CollectionDefinition("Semantic producer environment", DisableParallelization=true)]
public sealed class SemanticProducerEnvironment;

[Collection("Semantic producer environment")]
public sealed class SemanticProducerTests
{
    [Theory][InlineData(21,2)][InlineData(65536,32)]
    public void Backfill_unknown_sample_keeps_python_ceiling_and_cap_for_the_whole_window(int count,int selected)
    {
        var result=SemanticProducer.Select(Enumerable.Range(1,count).Select(i=>new SemanticProducer.Source(i,"999999","Security","synthetic")).ToArray(),maxBatch:SemanticProducerBackfill.WindowSize);
        Assert.Equal(Enumerable.Range(1,selected).Select(i=>(long)i),result.Jobs.Select(j=>j.Id));
        Assert.Equal(selected,result.Counters.Number("unknown_queued"));
        Assert.Equal(count-selected,result.Counters.Number("unknown_suppressed"));
    }
    [Fact]
    public void Runtime_admission_matches_python_modes_and_rejects_partial_chains()
    {
        var env=new Dictionary<string,string?>();
        string? Get(string name)=>env.GetValueOrDefault(name);
        Assert.Null(SemanticProducer.RuntimeMode(Get));
        env["ADLOG_SEMANTIC_RUNTIME_MODE"]="facts-v1";
        Assert.Throws<InvalidOperationException>(()=>SemanticProducer.RuntimeMode(Get));
        env["ADLOG_SEMANTIC_PRODUCTION_ENABLED"]="1";
        Assert.Throws<InvalidOperationException>(()=>SemanticProducer.RuntimeMode(Get));
        foreach(var mode in new[]{SemanticRuntimeSettings.FactsMode,SemanticRuntimeSettings.InvestigationMode,SemanticRuntimeSettings.FindingsMode}) {
            env["ADLOG_SEMANTIC_RUNTIME_MODE"]=mode;
            env["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"]="1"; env["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"]="1";
            env["ADLOG_SEMANTIC_CORRELATION_ENABLED"]=mode==SemanticRuntimeSettings.FactsMode?"0":"1";
            env["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"]=env["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"]=mode==SemanticRuntimeSettings.FindingsMode?"1":"0";
            Assert.Equal(mode,SemanticProducer.RuntimeMode(Get));
        }
        env["ADLOG_SEMANTIC_RUNTIME_MODE"]=""; Assert.Equal(SemanticRuntimeSettings.FindingsMode,SemanticProducer.RuntimeMode(Get));
        env["ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED"]="1";
        Assert.Throws<InvalidOperationException>(()=>SemanticProducer.RuntimeMode(Get));
    }
    [Fact]
    public void Selection_and_identities_match_executed_python_vectors()
    {
        using var stream=typeof(SemanticProducerTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.producer-reference.json")!;
        var vectors=JsonNode.Parse(stream)!;
        foreach(var item in vectors["cases"]!.AsArray()) {
            var rows=item!["rows"]!.AsArray().Select(r=>new SemanticProducer.Source(r.Number("source_event_id"),r.Text("event_key")!,r.Text("stream")!,r.Text("provider_name")!)).ToArray();
            var actual=SemanticProducer.Select(rows,item.Flag("include_context"),item["context_ids"]!.AsArray().Select(x=>x!.GetValue<long>()).ToHashSet());
            Assert.Equal(item["jobs"]!.ToJsonString(),new JsonArray(actual.Jobs.Select(j=>(JsonNode)new JsonObject { ["id"]=j.Id,["reason"]=j.Reason }).ToArray()).ToJsonString());
            actual.Counters.Remove("queued");
            Assert.True(JsonNode.DeepEquals(item["counters"],actual.Counters),item.Text("name"));
        }
        foreach(var identity in vectors["identities"]!.AsArray()) {
            var row=SemanticProducer.JobRows([new(identity.Number("id"),"signal",identity.Text("kind")!)])[0]!;
            Assert.Equal("\\x"+identity.Text("hash"),row.Text("hash"));
        }
        foreach(var outcome in vectors["outcomes"]!.AsArray()) Assert.Equal(outcome.Text("outcome"),SemanticProducer.AuditOutcome(outcome.Text("value")));
        Assert.Throws<ArgumentOutOfRangeException>(()=>SemanticProducer.Select(Enumerable.Range(1,5001).Select(i=>new SemanticProducer.Source(i,"1","Security","synthetic")).ToArray()));
        Assert.Throws<ArgumentOutOfRangeException>(()=>SemanticProducer.Select([new(0,"1","Security","synthetic")]));
    }
    [Fact]
    public void Admitted_facts_mode_can_publish_direct_events()
    {
        var values = new Dictionary<string,string?> {
            ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"]="true", ["ADLOG_SEMANTIC_RUNTIME_MODE"]="facts-v1",
            ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"]="1", ["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"]="1",
            ["ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED"]="0", ["ADLOG_SEMANTIC_CORRELATION_ENABLED"]="0",
            ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"]="0", ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"]="0"
        };
        var previous = values.ToDictionary(p=>p.Key,p=>Environment.GetEnvironmentVariable(p.Key));
        try {
            foreach(var pair in values) Environment.SetEnvironmentVariable(pair.Key,pair.Value);
            Direct4624Publication.EnsureSupportedMode();
        } finally { foreach(var pair in previous) Environment.SetEnvironmentVariable(pair.Key,pair.Value); }
    }
}
