using Npgsql;
using Sli.Server.Semantic.Password;
using Xunit;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Tests.Semantic;

public class PasswordProducerRuntimeTests
{
    [Fact] public async Task Live_passes_precede_every_history_slice_and_failed_live_work_blocks_history()
    {
        var scope=new PasswordScope("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","source","1","");
        var live=new[]{new PasswordRule(scope,revision:3),new PasswordRule(scope,"spray",3)};
        var history=new[]{new PasswordRule(scope),new PasswordRule(scope,"spray")};
        var order=new List<string>();
        await PasswordProducerPoller.RunPassesAsync(live,history,(rule,ct)=> {
            order.Add(rule.Revision+":"+rule.Kind);
            return Task.FromResult(new PasswordProducerOutcome(Failed:false,Status:"committed",Work:new JsonObject{["watermark"]=PasswordJson.Stamp(DateTimeOffset.UtcNow)}));
        },CancellationToken.None);
        Assert.Equal(new[]{"3:brute","3:spray","3:brute","3:spray","2:brute","3:brute","3:spray","2:spray"},order);
        order.Clear();
        await PasswordProducerPoller.RunPassesAsync(live,history,(rule,ct)=> {
            order.Add(rule.Revision+":"+rule.Kind);return Task.FromResult(new PasswordProducerOutcome());
        },CancellationToken.None);
        Assert.DoesNotContain(order,item=>item.StartsWith("2:",StringComparison.Ordinal));
    }
    [Fact] public async Task Disabled_rule_does_not_hold_the_other_rules_history()
    {
        var scope=new PasswordScope("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","source","1","");
        var live=new[]{new PasswordRule(scope,revision:3),new PasswordRule(scope,"spray",3)};
        var history=new[]{new PasswordRule(scope),new PasswordRule(scope,"spray")};
        var order=new List<string>();
        await PasswordProducerPoller.RunPassesAsync(live,history,(rule,ct)=> {
            order.Add(rule.Revision+":"+rule.Kind);
            return Task.FromResult(new PasswordProducerOutcome(Failed:false,Status:rule.Kind=="brute"?"disabled":"committed"));
        },CancellationToken.None);
        Assert.Equal(new[]{"3:brute","3:spray","3:brute","3:spray","2:spray"},order);
    }

    [Fact] public async Task Failed_brute_is_logged_before_spray_and_retried_while_catchup_yields()
    {
        var scope=PasswordScope.Read(JsonNode.Parse("""{"installation_id":"00000000-0000-4000-8000-000000000001","plugin_id":"sli.windows.ad-dc","source_instance_id":"source","source_generation":"1","collection_scope_id":""}"""));
        var order=new List<string>();int brute=0;int calls=0;
        var results=await PasswordProducerPoller.RunBatchesAsync(scope,(rule,ct)=> {
            order.Add(rule.Kind);
            if(rule.Kind=="brute"&&++brute==1)return Task.FromResult(new PasswordProducerOutcome(Diagnostic:DetectionDiagnostics.Describe(new PasswordFailure("password_v2_proposal_unavailable") {
                ProposalDiagnostics=new Dictionary<string,int>{{"state_bound",1}},StateBytes=18000000,WatermarkMatches=true},"password_proposal")));
            return Task.FromResult(new PasswordProducerOutcome(Failed:false,Status:"committed",Work:new JsonObject{["watermark"]=PasswordJson.Stamp(++calls<4?DateTimeOffset.UtcNow.AddHours(-1):DateTimeOffset.UtcNow)}));
        },CancellationToken.None,line=>order.Add(line));
        Assert.Equal("brute",order[0]);Assert.StartsWith("password_producer_batch_failed:",order[1]);Assert.Equal("spray",order[2]);
        Assert.Contains("\"rule_id\":\"qw.password-brute-force\"",order[1]);
        Assert.Contains("\"state_bytes\":18000000",order[1]);Assert.Contains("\"state_bound\":1",order[1]);
        Assert.True(brute>1);Assert.Contains(results,r=>r.Failed);Assert.Contains(results,r=>!r.Failed);
        Assert.InRange(results.Count,4,16);
        var diagnostics=new DetectionDiagnostics();diagnostics.Add(results.First(r=>r.Failed).Diagnostic!);
        var lines=new List<string>();diagnostics.Write("password_producer",lines.Add);
        Assert.Contains(lines,line=>line.StartsWith("password_producer_source_failed:",StringComparison.Ordinal)&&line.Contains("\"rule_id\":\"qw.password-brute-force\"",StringComparison.Ordinal));
    }

    [Fact] public async Task Successful_catchup_keeps_alternating_past_four_rounds_until_within_twelve_minutes()
    {
        var scope=new PasswordScope("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","source","1","");
        var start=DateTimeOffset.UtcNow.AddHours(-6);var marks=new Dictionary<string,DateTimeOffset>();
        var results=await PasswordProducerPoller.RunBatchesAsync(scope,(rule,ct)=> {
            var through=marks.GetValueOrDefault(rule.Id,start).AddMinutes(30);marks[rule.Id]=through;
            return Task.FromResult(new PasswordProducerOutcome(Failed:false,Status:"committed",Work:new JsonObject{["watermark"]=PasswordJson.Stamp(through)}));
        },CancellationToken.None,_=>{});
        Assert.All(marks.Values,at=>Assert.True(at>=DateTimeOffset.UtcNow.AddMinutes(-12)));
        Assert.All(results,r=>Assert.False(r.Failed));
    }

    [Fact] public async Task Disabled_and_unconfigured_rules_finish_without_retries()
    {
        var scope=PasswordScope.Read(JsonNode.Parse("""{"installation_id":"00000000-0000-4000-8000-000000000001","plugin_id":"sli.windows.ad-dc","source_instance_id":"source","source_generation":"1","collection_scope_id":""}"""));
        var results=await PasswordProducerPoller.RunBatchesAsync(scope,(rule,ct)=>Task.FromResult(new PasswordProducerOutcome(Failed:false,Status:rule.Kind=="brute"?"disabled":"unconfigured")),CancellationToken.None,_=>{});
        Assert.Equal(2,results.Count);
    }
    [Fact] public async Task Explicit_semantic_profile_is_nonpooled_and_does_not_cancel_live_queries()
    {
        var env=new Dictionary<string,string?>{["ADLOG_SEMANTIC_WORKER_DSN"]="host=localhost dbname=sli user=semantic_worker",["ADLOG_SEMANTIC_WORKER_PASSWORD_FILE"]="synthetic"};
        await using var runtime=PasswordProducerRuntime.TryCreate(env.GetValueOrDefault,_=>System.Text.Encoding.UTF8.GetBytes("synthetic-password\n"));
        Assert.NotNull(runtime);var b=new NpgsqlConnectionStringBuilder(runtime.DataSource.ConnectionString);
        Assert.False(b.Pooling);Assert.False(b.Multiplexing);Assert.Equal("adlog_semantic_worker",b.ApplicationName);Assert.Equal("-c statement_timeout=0 -c lock_timeout=0",b.Options);Assert.Equal(0,b.CommandTimeout);
    }
    [Fact] public void No_admin_fallback_or_conflicting_secret_sources()
    {
        var env=new Dictionary<string,string?>{["ADLOG_PG_ADMIN_DSN"]="host=localhost dbname=sli user=owner"};
        Assert.Null(PasswordProducerRuntime.TryCreate(env.GetValueOrDefault,_=>[]));
        env["ADLOG_SEMANTIC_WORKER_DSN"]="host=localhost dbname=sli user=semantic password=one";env["ADLOG_SEMANTIC_WORKER_PASSWORD"]="two";
        Assert.Null(PasswordProducerRuntime.TryCreate(env.GetValueOrDefault,_=>[]));
    }
}
