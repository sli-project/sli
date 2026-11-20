using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusJobsTests
{
    static JsonObject Job(string handler="radius-session-observation",params long[] ids)=>VpnRouteTests.Json(new {plugin_id="sli.remote-access",handler_id=handler,result_contract="sli.radius-job-output.v1",budget=new {max_records=500000},pinned_input=new {subscription_id="synthetic-subscription",delivery_ids=ids}});
    [Fact] public void Compiled_catalog_registers_both_allowlisted_light_handlers()
    {
        var catalog=CoreJobPluginCatalog.Compiled();foreach(string handler in new[]{"radius-acquisition","radius-session-observation"}) Assert.NotNull(catalog.Resolve(Job(handler)));
        Assert.Contains("sli.remote-access",catalog.Owners);
    }
    [Fact] public async Task Acquisition_remains_blocked_without_source_or_database_contact()
    {
        await using var unopened=new NpgsqlConnection();var job=Job("radius-acquisition");var result=await RadiusJobs.StageAsync(unopened,job,TestContext.Current.CancellationToken);
        Assert.Equal("blocked",result["status"]!.ToString());Assert.Equal("acquisition_disabled",result["error_code"]!.ToString());Assert.Equal("not_collected",result["coverage_state"]!.ToString());Assert.Empty(result["delivery_ids"]!.AsArray());
        await RadiusJobs.PublishAsync(unopened,job,result,TestContext.Current.CancellationToken);Assert.Equal(System.Data.ConnectionState.Closed,unopened.State);
    }
    [Fact] public async Task Empty_observation_result_and_cancellation_have_no_effects()
    {
        await using var unopened=new NpgsqlConnection();var job=Job();
        await RadiusJobs.PublishAsync(unopened,job,JsonNode.Parse("{\"status\":\"partial\",\"delivery_ids\":[]}")!.AsObject(),TestContext.Current.CancellationToken);
        await RadiusJobs.PublishAsync(unopened,job,JsonNode.Parse("{\"status\":\"cancelled\"}")!.AsObject(),TestContext.Current.CancellationToken);
    }
    [Theory] [InlineData("[1,1]","job_result_invalid")] [InlineData("[0]","job_result_invalid")] [InlineData("[true]","job_result_invalid")] [InlineData("[\"1\"]","job_result_invalid")] [InlineData("[1.5]","job_result_invalid")] [InlineData("[2]","radius_input_changed")] [InlineData("[]","radius_input_changed")]
    public async Task Publisher_rejects_changed_duplicate_or_noninteger_ids_before_DB(string input,string expected)
    {
        await using var unopened=new NpgsqlConnection();var result=JsonNode.Parse("{\"status\":\"partial\",\"delivery_ids\":"+input+"}")!.AsObject();
        var error=await Assert.ThrowsAsync<VpnInputException>(()=>RadiusJobs.PublishAsync(unopened,Job("radius-session-observation",1),result,TestContext.Current.CancellationToken));Assert.Equal(expected,error.Message);
    }
    [Fact] public void Publisher_checks_record_budget_and_fifty_delivery_bound()
    {
        long[] ids=Enumerable.Range(1,51).Select(x=>(long)x).ToArray();var job=Job("radius-session-observation",ids);var result=VpnRouteTests.Json(new {delivery_ids=ids});
        Assert.Equal("job_row_budget_exceeded",Assert.Throws<VpnInputException>(()=>RadiusJobs.ValidateResult(job,result)).Message);
        job=Job("radius-session-observation",1,2);job["budget"]!["max_records"]=1;result=VpnRouteTests.Json(new {delivery_ids=new long[]{1,2}});Assert.Equal("job_row_budget_exceeded",Assert.Throws<VpnInputException>(()=>RadiusJobs.ValidateResult(job,result)).Message);
    }
    [Fact] public void Scheduler_pins_exact_source_subscription_deliveries_and_never_schedules_acquisition()
    {
        var registry=new CoreJobRegistry();registry.Register(CoreJobRegistry.Bundled("sli.remote-access"));
        var source=JsonNode.Parse("{\"source_instance_id\":\"synthetic-radius\",\"subscription_id\":\"synthetic-subscription\",\"revision\":\"1\",\"delivery_ids\":[1,2],\"access_scope\":{\"mode\":\"restricted\",\"clauses\":[]}}")!.AsObject();
        var job=Assert.Single(CoreJobScheduler.Create(registry,"light",source,DateTimeOffset.Parse("2026-01-01T00:00:00Z")));
        Assert.Equal("radius-session-observation",job["handler_id"]!.ToString());Assert.Equal("synthetic-subscription",job["pinned_input"]!["subscription_id"]!.ToString());Assert.True(JsonNode.DeepEquals(source["delivery_ids"],job["pinned_input"]!["delivery_ids"]));
        Assert.Equal(CoreJobJson.Digest(job["pinned_input"]),job["input_sha256"]!.ToString());Assert.Empty(CoreJobScheduler.Create(registry,"heavy",source,DateTimeOffset.UtcNow));
    }
}
