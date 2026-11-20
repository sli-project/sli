using System.Text.Json.Nodes;
using Sli.Server.Entities.State;
using Xunit;
namespace Sli.Server.Tests.Entities;
public class EntityStateResolutionTests
{
    private static JsonObject State(string time,long id,string rule,string status)=>new(){["observed_at_utc"]=time,["source_event_db_id"]=id,["rule_version"]=rule,["status"]=status,["details"]=new JsonObject()};
    [Fact] public void Source_order_and_conflict_preserve_evidence() {
        var a=State("2026-10-07T00:00:00Z",10,"v1","enabled");
        Assert.Equal("insert",EntityStateResolution.Resolve(null,a).Action);
        Assert.Equal("older",EntityStateResolution.Resolve(a,State("2026-10-06T00:00:00Z",99,"z","locked")).Action);
        Assert.Equal("replace",EntityStateResolution.Resolve(a,State("2026-10-07T00:00:00Z",11,"v1","locked")).Action);
        Assert.Equal("same",EntityStateResolution.Resolve(a,State("2026-10-07T00:00:00Z",10,"v1","enabled")).Action);
        var conflict=EntityStateResolution.Resolve(a,State("2026-10-07T00:00:00Z",10,"v1","locked"));
        Assert.Equal("conflict",conflict.Action);Assert.Equal("unknown",(string?)conflict.Result["status"]);Assert.Equal(new[]{"enabled","locked"},conflict.Result["conflict_statuses"]!.AsArray().Select(x=>(string)x!).ToArray());
    }
    [Fact] public void Source_timestamp_strip_microseconds_and_rule_tie_break() {
        var current=State("2026-10-07T00:00:00.123456Z",10,"v1","enabled");
        Assert.Equal("same",EntityStateResolution.Resolve(current,State("\u001c2026-10-07T00:00:00.1234569Z\u001f",10,"v1","enabled")).Action);
        Assert.Equal("replace",EntityStateResolution.Resolve(current,State("2026-10-07T00:00:00.123456Z",10,"v2","enabled")).Action);
        Assert.Equal("older",EntityStateResolution.Resolve(current,State("not-a-time",100,"z","locked")).Action);
    }
    [Fact] public void Source_details_object_and_string_pairs_are_preserved() {
        var candidate=JsonNode.Parse("{\"details\":[[\"x\",1],[\"x\",2],[\"nested\",{\"ok\":true}]]}")!.AsObject();
        var details=EntityStateProjector.ReadDetails(candidate);
        Assert.Equal(2,(int)details["x"]!);Assert.True((bool)details["nested"]!["ok"]!);
        Assert.Empty(EntityStateProjector.ReadDetails(JsonNode.Parse("{\"details\":false}")!.AsObject()));
        Assert.Throws<InvalidDataException>(()=>EntityStateProjector.ReadDetails(JsonNode.Parse("{\"details\":\"bad\"}")!.AsObject()));
    }
}
