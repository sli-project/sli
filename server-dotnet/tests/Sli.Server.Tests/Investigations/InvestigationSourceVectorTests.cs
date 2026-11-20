using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationSourceVectorTests
{
    static JsonElement Vectors()
    {
        using var input=typeof(InvestigationSourceVectorTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Investigations.Fixtures.source-vectors.json")!;
        using var doc=JsonDocument.Parse(input); return doc.RootElement.Clone();
    }
    static IReadOnlyList<IReadOnlyList<AccessResource>> Groups(JsonElement input)=>input.EnumerateArray().Select(g=>(IReadOnlyList<AccessResource>)g.EnumerateArray().Select(r=>new AccessResource(
        r.GetProperty("kind").GetString()!,r.TryGetProperty("id",out var id)?id.GetInt64():null,r.TryGetProperty("value",out var value)?value.GetString():null)).ToArray()).ToArray();
    [Fact]
    public void CapabilityDecisionsMatchExecutedFrozenPython()
    {
        foreach(var vector in Vectors().GetProperty("capability").EnumerateArray())
        {
            var caps=new CapabilityComposer().Compose(new(false,"viewer",[],[],vector.GetProperty("policies").EnumerateArray().ToArray(),[],[],[],[]));
            caps=caps with {IsOwner=vector.GetProperty("owner").GetBoolean(),Capabilities=vector.GetProperty("global").GetBoolean()?new HashSet<string>{"investigations.manage"}:new HashSet<string>()};
            var actual=caps.DecideForResourceGroups("investigations.manage",Groups(vector.GetProperty("groups")));
            Assert.True(actual.Allowed==vector.GetProperty("allowed").GetBoolean() && actual.Reason==vector.GetProperty("reason").GetString(),vector.GetProperty("name").GetString()+": "+actual);
        }
    }
    [Fact]
    public void AtomicReportDecisionsMatchExecutedFrozenPython()
    {
        foreach(var vector in Vectors().GetProperty("report").EnumerateArray())
        {
            var grants=vector.GetProperty("grants").EnumerateArray().Select(g=>new AtomicReportGrant(g.GetProperty("scope"),g.GetProperty("field_categories").EnumerateArray().Select(x=>x.GetString()!).ToHashSet(),g.GetProperty("allowed_actions").EnumerateArray().Select(x=>x.GetString()!).ToHashSet(),1,1)).ToArray();
            var access=new AccessDecision("viewer",new(false,new HashSet<string>(),new HashSet<string>(),[],new Dictionary<string,JsonElement>()),[new("cases.workspace",true,grants)]);
            var actual=ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",Groups(vector.GetProperty("groups")),vector.GetProperty("fields").EnumerateArray().Select(x=>x.GetString()!).ToHashSet());
            Assert.True(actual.Allowed==vector.GetProperty("allowed").GetBoolean() && actual.Reason==vector.GetProperty("reason").GetString(),vector.GetProperty("name").GetString()+": "+actual);
        }
    }
    [Fact]
    public void BodyCoercionMatchesExecutedSourceAddNote()
    {
        foreach(var vector in Vectors().GetProperty("body").EnumerateArray())
        {
            using var input=JsonDocument.Parse("{\"body\":"+vector.GetProperty("raw").GetString()+"}");
            if(vector.GetProperty("error").ValueKind==JsonValueKind.Null) Assert.Equal(vector.GetProperty("clean").GetString(),InvestigationAccess.CleanBody(input.RootElement));
            else Assert.Equal(vector.GetProperty("error").GetString(),Assert.Throws<InvestigationException>(()=>InvestigationAccess.CleanBody(input.RootElement)).Code);
        }
    }
}
