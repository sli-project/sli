using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginRuntimeActivationExecutorTests
{
    const string Uid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const string Confirmation = "PLUGIN-ENABLE-SLI-REMOTE-ACCESS-R2-AAAAAAAAAAAA";
    static readonly IReadOnlySet<string> Manage = new HashSet<string> { "plugins.manage" };
    static JsonObject Plan() => JsonNode.Parse("""
        {"plugin_id":"sli.remote-access","requested_action":"enable","expected_revision":2,
         "plan_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "preserve_immutable_evidence":true,"production_read_path_cutover":false,"destructive_purge":false}
        """)!.AsObject();
    static ScriptDatabase Database(string row = """
        [{"operation_id":7,"committed_revision":3,"desired_activation":"enabled_manual",
          "component_runtime":"running","queue_state":"drained"}]
        """) => new() { Override = (_, _) => ScriptDatabase.Rows(row) };
    static Task<JsonObject> Execute(ScriptDatabase db, JsonObject? plan = null, string confirmation = Confirmation,
        string uid = Uid, string kind = "windows", string key = @"EXAMPLE\operator", IReadOnlySet<string>? capabilities = null)
        => new PluginRuntimeActivationExecutor(db).ExecuteAsync(plan ?? Plan(), confirmation, uid, kind, key,
            capabilities ?? Manage, TestContext.Current.CancellationToken);

    // tests/sources/test_plugin_runtime_activation_executor.py::test_exact_enable_call
    [Fact]
    public async Task ExactEnableCall()
    {
        var db = Database();
        var result = await Execute(db);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"status":"succeeded","plugin_id":"sli.remote-access","requested_action":"enable",
             "operation_uid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","operation_id":7,"committed_revision":3,
             "desired_activation":"enabled_manual","component_runtime":"running","queue_state":"drained",
             "source_contacted":false,"process_started_or_stopped":false,"production_read_path_cutover":false}
            """), result));
        var call = Assert.Single(db.Calls);
        Assert.True(call.Write);
        Assert.Equal("""
            select operation_id,committed_revision,desired_activation,
                   component_runtime,queue_state
            from execute_plugin_runtime_transition_v1(
              @p0::uuid,@p1,@p2::bigint,@p3,@p4,@p5,@p6
            )
            """, call.Sql);
        Assert.Equal<object?[]>([Uid, "enable", 2L, new string('a', 64), Confirmation, "windows", @"EXAMPLE\operator"], call.Args);
        Assert.Equal(1, db.Commits);
        Assert.Equal(0, db.Rollbacks);
    }

    [Theory]
    [InlineData("drain", "enabled_manual", "draining", "pending")]
    [InlineData("disable", "disabled", "stopped", "drained")]
    public async Task OtherActionsReturnDatabaseState(string action, string activation, string runtime, string queue)
    {
        var db = Database(new JsonArray(new JsonObject { ["operation_id"] = 8, ["committed_revision"] = 3,
            ["desired_activation"] = activation, ["component_runtime"] = runtime, ["queue_state"] = queue }).ToJsonString());
        var plan = Plan(); plan["requested_action"] = action;
        string confirmation = $"PLUGIN-{action.ToUpperInvariant()}-SLI-REMOTE-ACCESS-R2-AAAAAAAAAAAA";
        var result = await Execute(db, plan, confirmation);
        Assert.Equal(action, result["requested_action"]!.GetValue<string>());
        Assert.Equal(activation, result["desired_activation"]!.GetValue<string>());
        Assert.Equal(runtime, result["component_runtime"]!.GetValue<string>());
        Assert.Equal(queue, result["queue_state"]!.GetValue<string>());
        Assert.Equal(action, Assert.Single(db.Calls).Args[1]);
    }

    [Fact]
    public async Task PermissionIsCheckedBeforePlanOrDatabase()
    {
        var db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, new JsonObject(),
            capabilities: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "PLUGINS.MANAGE" }));
        Assert.Equal("plugins_manage_required", error.Message); Assert.Equal(403, error.Status);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits);
    }

    [Theory]
    [InlineData("plugin_id", "\"sli.ad\"")]
    [InlineData("requested_action", "\"purge\"")]
    [InlineData("expected_revision", "true")]
    [InlineData("expected_revision", "\"2\"")]
    [InlineData("expected_revision", "2.0")]
    [InlineData("expected_revision", "null")]
    [InlineData("plan_sha256", "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"")]
    [InlineData("plan_sha256", "\"aaa\"")]
    [InlineData("preserve_immutable_evidence", "false")]
    [InlineData("production_read_path_cutover", "true")]
    [InlineData("destructive_purge", "true")]
    [InlineData("destructive_purge", "0")]
    [InlineData("production_read_path_cutover", "null")]
    public async Task InvalidPlansNeverOpenATransaction(string field, string json)
    {
        var db = Database(); var plan = Plan(); plan[field] = JsonNode.Parse(json);
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, plan));
        Assert.Equal("plugin_runtime_transition_plan_invalid", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits);
    }

    [Theory]
    [InlineData("confirmation", "plugin-enable-sli-remote-access-r2-aaaaaaaaaaaa", "plugin_runtime_transition_plan_invalid")]
    [InlineData("confirmation", "PLUGIN-ENABLE-SLI-REMOTE-ACCESS-R1-AAAAAAAAAAAA", "plugin_runtime_transition_plan_invalid")]
    [InlineData("uid", "invalid", "plugin_runtime_operation_uid_invalid")]
    [InlineData("kind", "admin", "plugin_runtime_actor_invalid")]
    [InlineData("key", "   ", "plugin_runtime_actor_invalid")]
    public async Task InvalidCallerInputsNeverReachDatabase(string field, string value, string code)
    {
        var db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db,
            confirmation: field == "confirmation" ? value : Confirmation, uid: field == "uid" ? value : Uid,
            kind: field == "kind" ? value : "windows", key: field == "key" ? value : @"EXAMPLE\operator"));
        Assert.Equal(code, error.Message); Assert.Empty(db.Calls);
    }

    [Fact]
    public async Task CallerNormalizationAndActorLengthBoundary()
    {
        var db = Database(); string key = string.Concat(Enumerable.Repeat("\U0001F600", 200));
        await Execute(db, uid: "urn:uuid:AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", kind: " windows ", key: " " + key + " ");
        var call = Assert.Single(db.Calls);
        Assert.Equal(Uid, call.Args[0]); Assert.Equal("windows", call.Args[5]); Assert.Equal(key, call.Args[6]);
        var rejected = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(rejected, key: key + "x"));
        Assert.Equal("plugin_runtime_actor_invalid", error.Message); Assert.Empty(rejected.Calls);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[{\"operation_id\":0,\"committed_revision\":3}]")]
    [InlineData("[{\"operation_id\":7,\"committed_revision\":2}]")]
    [InlineData("[{\"operation_id\":7,\"committed_revision\":4}]")]
    public async Task InvalidDatabaseResultsAreRejected(string rows)
    {
        var db = Database(rows);
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db));
        Assert.Equal("plugin_runtime_transition_result_invalid", error.Message);
    }

    [Fact]
    public async Task DatabaseFailureRollsBackAndPropagates()
    {
        var failure = new InvalidOperationException("synthetic failure");
        var db = new ScriptDatabase { Override = (_, _) => throw failure };
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => Execute(db)));
        Assert.Equal(0, db.Commits); Assert.Equal(1, db.Rollbacks);
    }

    [Fact]
    public async Task ExecutorIsAvailableFromInstallationServices()
    {
        await using var fixture = new InstallationFixture(); await fixture.StartAsync();
        using var scope = fixture.Host.Services.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<PluginRuntimeActivationExecutor>());
    }
}
