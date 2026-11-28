using System.Text.Json.Nodes;
using Sli.Server.Workstations;
using Xunit;
namespace Sli.Server.Tests.Workstations;
public sealed class WorkstationProjectionTests
{
    [Fact]
    public void DisabledLogonRuleKeepsItsScheduleAndStopsEvaluatingIt()
    {
        var reference = Reference()["logons"]!.AsArray().OfType<JsonObject>()
            .First(item => item["expected"]?["outside"]?.GetValue<bool>() == true);
        var config = reference["config"]!.DeepClone().AsObject();
        var row = reference["row"]!.AsObject();
        var station = reference["station"]!.AsObject();
        var enabled = WorkstationEvaluators.EvaluateLogon(row, station, config);
        Assert.True(enabled!["outside"]!.GetValue<bool>());

        config["enabled"] = false;
        var normalized = Sli.Server.InstallationSetup.InstallationSettings.LogonPolicy(config.ToJsonString());
        var disabled = WorkstationEvaluators.ValidatePolicy(normalized);
        Assert.Null(WorkstationEvaluators.EvaluateLogon(row, station, disabled)!["outside"]);
        Assert.True(JsonNode.DeepEquals(config["policies"], disabled["policies"]));

        disabled["enabled"] = true;
        Assert.True(WorkstationEvaluators.EvaluateLogon(row, station, disabled)!["outside"]!.GetValue<bool>());
    }

    static JsonObject Reference()=>JsonNode.Parse(new StreamReader(typeof(WorkstationProjectionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Workstations.reference.json")!).ReadToEnd())!.AsObject();
    static void Equal(JsonNode? expected,JsonNode? actual)=>Assert.True(JsonNode.DeepEquals(expected,actual),"Expected: "+expected+"\nActual: "+actual);
    [Fact]public void Request_parameters_and_errors_match_the_reference_parser()
    {
        foreach(var vector in Reference()["requests"]!.AsArray().OfType<JsonObject>())
        {
            var query=new Microsoft.AspNetCore.Http.QueryCollection(vector["query"]!.AsObject().ToDictionary(p=>p.Key,p=>new Microsoft.Extensions.Primitives.StringValues(p.Value!.AsArray().Select(n=>n!.GetValue<string>()).ToArray())));
            WorkstationRequest Parse()=>WorkstationReportContract.Parse(vector.Text("key")!,query,now:DateTimeOffset.Parse("2026-10-19T12:00:00Z"));
            if(vector.Text("error") is {} error)Assert.Equal(error,Assert.Throws<WorkstationException>(()=>Parse()).Message);
            else{var r=Parse();Equal(vector["parameters"],r.Parameters);Assert.Equal(vector.Number("limit"),r.Limit);Assert.Equal(vector.Text("cursor"),r.Cursor);}
        }
    }
    [Fact]public void Protection_matches_reference_for_false_unknown_missing_stale_and_future()
    {
        var fixture=Reference();var now=Ws.Time(fixture.Text("now"));
        foreach(var row in fixture["protection"]!.AsArray())Equal(row!["expected"],WorkstationEvaluators.EvaluateProtection(row["snapshot"] as JsonObject,now,"server"));
    }
    [Fact]public void Process_findings_match_native_reference_without_current_process_claims()
    {
        var fixture=Reference();foreach(var row in fixture["processes"]!.AsArray())Equal(row!["expected"],WorkstationEvaluators.ProcessFinding(row["row"]!.AsObject(),fixture.Text("station")!,Ws.Time(fixture.Text("now"))));
    }
    [Fact]public void Native_admin_episodes_keep_actor_member_and_removal_separate()
    {
        var f=Reference();var r=f["admin"]!;var e=WorkstationEvaluators.AdminEvent(r["row"]!.AsObject(),f.Text("station")!);Equal(r["event"],e);
        Equal(r["expected"],WorkstationEvaluators.AdminFinding(e!,r["removed"]!.AsObject(),f.Text("station")!,Ws.Time(f.Text("now")),Ws.Time(f.Text("now"))));
    }
    [Fact]public void Service_and_task_episodes_match_reference_including_exact_pair_and_ambiguity()
    {
        var f=Reference();foreach(var r in f["services"]!.AsArray())
        {
            var events=r!["rows"]!.AsArray().Select(row=>WorkstationEvaluators.ServiceEvent(row!.AsObject(),f.Text("station")!)!).ToList();Equal(r["events"],Ws.Array(events));
            var (groups,superseded)=WorkstationEvaluators.ServiceEpisodes(events,f.Text("station")!);
            Equal(r["superseded"],new JsonArray(superseded.Select(s=>(JsonNode?)JsonValue.Create(s)).ToArray()));
            Equal(r["expected"],Ws.Array(groups.Select(g=>WorkstationEvaluators.ServiceFinding(g.Id,g.Items,g.Dedup,events,f.Text("station")!,Ws.Time(f.Text("now"))))));
        }
    }
    [Fact]public void Logon_policy_matches_timezone_cached_and_unknown_reference()
    {
        var f=Reference();foreach(var r in f["logons"]!.AsArray())Equal(r!["expected"],WorkstationEvaluators.EvaluateLogon(r["row"]!.AsObject(),r["station"]!.AsObject(),r["config"] as JsonObject));
    }
    [Fact]public void Failure_sliding_window_buckets_match_reference_and_bound_evidence()
    {
        var f=Reference();var r=f["failures"]!;var events=r["rows"]!.AsArray().Select(row=>WorkstationEvaluators.FailureEvent(row!.AsObject())!).ToList();Equal(r["events"],Ws.Array(events));
        Equal(r["expected"],Ws.Array(WorkstationEvaluators.FailureBuckets(events,f.Text("station")!,Ws.Time(f.Text("now")),Ws.Time(f.Text("now")))));
    }
    [Fact]public void Device_merge_matches_reference_and_late_delivery_preserves_endpoints()
    {
        var f=Reference();var d=f["device"]!;var e=WorkstationEvaluators.DeviceEvent(d["row"]!.AsObject());Equal(d["event"],e);
        var merged=WorkstationEvaluators.MergeDevice(f.Text("station")!,e!,null);Equal(d["expected"],merged);
        Equal(merged,WorkstationEvaluators.MergeDevice(f.Text("station")!,e!,merged));
    }
    [Theory][InlineData(@"C:\Windows\Temp\..\fixture.exe")][InlineData(@"C:\Windows\Temp\NUL.exe")][InlineData(@"\\fixture\share\fixture.exe")][InlineData(@"C:\Windows\Temp\fixture.exe:stream")]
    public void Ambiguous_paths_never_generate_path_findings(string path)=>Assert.Null(WorkstationEvaluators.PathCategory(path));
    [Fact]public void Corrupt_protection_hash_is_rejected()
    {
        var f=Reference();var snapshot=f["protection"]![0]!["snapshot"]!.DeepClone().AsObject();snapshot["state_sha256"]=new string('0',64);
        Assert.Equal("workstation_protection_snapshot_conflict",Assert.Throws<WorkstationException>(()=>WorkstationEvaluators.EvaluateProtection(snapshot,Ws.Time(f.Text("now")))).Message);
    }
    [Fact]public void Policy_validation_preserves_versioned_consumer_and_rejects_duplicate_scopes()
    {
        var f=Reference();var config=f["logons"]![0]!["config"]!.DeepClone().AsObject();Equal(config,WorkstationEvaluators.ValidatePolicy(config.ToJsonString()));Assert.Equal(2,WorkstationEvaluators.Identities(config)["workstations.C07"]);
        config["policies"]!.AsArray().Add(config["policies"]![0]!.DeepClone());Assert.Throws<WorkstationException>(()=>WorkstationEvaluators.ValidatePolicy(config.ToJsonString()));
    }
}
