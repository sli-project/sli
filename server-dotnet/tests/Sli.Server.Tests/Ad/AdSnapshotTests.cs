using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdSnapshotTests
{
    static JsonObject Reference()
    {
        using var stream=typeof(AdSnapshotTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.snapshot-reference.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    [Fact] public void Every_agent_family_normalizes_like_python_and_whole_cycle_is_qualified()
    {
        var reference=Reference();var families=reference["families"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.AsObject());
        var bundles=AdSnapshotPreparation.Prepare(reference["policy"]!.AsObject(),families);
        foreach(var (family,bundle) in bundles)Assert.True(JsonNode.DeepEquals(reference["bundles"]![family],bundle),family);
    }
    [Fact] public void Exact_users_projection_matches_python_without_latest_reads()
    {
        var reference=Reference();var bundles=reference["bundles"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.AsObject());
        var ids=reference["ids"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.GetValue<long>());
        var users=AdUsersSnapshot.Build(bundles,7,reference["policy"]!["domain_dns"]!.GetValue<string>(),ids);
        var expected=reference["users"]!.AsObject();
        Assert.True(JsonNode.DeepEquals(expected,users),FirstDifference(expected,users));
    }
    static string FirstDifference(JsonNode? expected,JsonNode? actual,string path="")
    {
        if(JsonNode.DeepEquals(expected,actual))return "";
        if(expected is JsonObject obj&&actual is JsonObject other)
        {foreach(string key in obj.Select(p=>p.Key).Union(other.Select(p=>p.Key))){string result=FirstDifference(obj[key],other[key],path+"."+key);if(result.Length>0)return result;}}
        if(expected is JsonArray a&&actual is JsonArray b&&a.Count==b.Count)
        {for(int i=0;i<a.Count;i++){string result=FirstDifference(a[i],b[i],path+"["+i+"]");if(result.Length>0)return result;}}
        return path+" expected "+expected+" actual "+actual;
    }
    [Theory] [InlineData("ad_domain_health")] [InlineData("ad_context_base")] [InlineData("computers_v6")]
    public void Missing_family_never_reaches_publication(string family)
    {
        var reference=Reference();var families=reference["families"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.AsObject());families.Remove(family);
        Assert.Throws<ProtocolException>(()=>AdSnapshotPreparation.Prepare(reference["policy"]!.AsObject(),families));
    }
    [Fact] public void Changed_domain_and_population_are_rejected_before_import()
    {
        var reference=Reference();var families=reference["families"]!.AsObject().ToDictionary(p=>p.Key,p=>p.Value!.AsObject());
        families["computers_v6"]["metadata"]!["domain"]="other.invalid";
        Assert.Throws<ProtocolException>(()=>AdSnapshotPreparation.Prepare(reference["policy"]!.AsObject(),families));
    }
    [Fact] public void Exact_projection_is_immutable_and_hashes_utf8_like_python()
    {
        var manifest=JsonNode.Parse("{\"manifest_id\":\"00000000-0000-0000-0000-000000000001\",\"manifest_sha256\":\"abc\",\"members\":[{\"family\":\"users_v2\",\"source_id\":\"1\",\"payload_sha256\":\"def\"}]}")!.AsObject();
        var source=JsonNode.Parse("{\"users\":[{\"displayName\":\"Тест\"}]}")!.AsObject();
        var result=AdJobPlugin.Project(manifest,"ad.users.v2","users_v2",source,out var output);
        Assert.True(JsonNode.DeepEquals(source,output));output["users"]![0]!["displayName"]="changed";
        Assert.Equal("Тест",source["users"]![0]!["displayName"]!.GetValue<string>());
        Assert.NotEqual(result["output_sha256"]!.ToString(),AdJobPlugin.Digest(output));
    }
}
