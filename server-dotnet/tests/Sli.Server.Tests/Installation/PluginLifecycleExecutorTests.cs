using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginLifecycleExecutorTests
{
    const string Uid = "22222222-2222-2222-2222-222222222222";
    const string Hash = "9a5b96b88db59fd71632291b79f3507c5637906f8f94704b7c4e5f97bf342f1f";
    const string Confirmation = "PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R1-9A5B96B88DB5";
    static readonly IReadOnlySet<string> Caps = new HashSet<string> { "plugins.manage" };
    // Executor inputs frozen from plan_plugin_lifecycle(initial_remote_access_state()).
    static JsonObject Plan() => JsonNode.Parse("""
        {"contract_id":"sli.plugin-lifecycle.v1","plugin_id":"sli.remote-access","requested_action":"install",
         "expected_revision":1,"target_version":"0.1.0","effects":{"package_lifecycle":"registered"},
         "preserve_immutable_evidence":true,"production_read_path_cutover":false,"destructive_purge":false,
         "preconditions_met":true,"execution_allowed":true,
         "plan_sha256":"9a5b96b88db59fd71632291b79f3507c5637906f8f94704b7c4e5f97bf342f1f",
         "confirmation":"PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R1-9A5B96B88DB5"}
        """)!.AsObject();
    static ScriptDatabase Database() => new()
    {
        Override = (_, _) => ScriptDatabase.Rows("""
            [{"operation_id":7,"committed_revision":2,"package_lifecycle":"registered","desired_activation":"disabled"}]
            """)
    };
    static Task<JsonObject> Execute(ScriptDatabase db, JsonObject? plan = null, string confirmation = Confirmation,
        IReadOnlySet<string>? caps = null, string uid = Uid, string kind = "windows", string key = @"EXAMPLE\operator") =>
        new BundledPluginInstallExecutor(db).ExecuteAsync(plan ?? Plan(), confirmation, uid, kind, key, caps ?? Caps, TestContext.Current.CancellationToken);

    [Fact]
    public async Task ExactInstallUsesOneParameterizedDatabaseCallAndKeepsRuntimeDisabled()
    {
        var db = Database();
        var result = await Execute(db);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"status":"registered","plugin_id":"sli.remote-access","operation_uid":"22222222-2222-2222-2222-222222222222",
             "operation_id":7,"committed_revision":2,"package_lifecycle":"registered","desired_activation":"disabled",
             "process_started_or_stopped":false,"source_contacted":false,"runtime_enabled":false,"autostart_enabled":false,
             "production_read_path_cutover":false}
            """), result));
        var call = Assert.Single(db.Calls);
        Assert.True(call.Write);
        Assert.Equal(1, db.Commits);
        Assert.Contains("from execute_bundled_plugin_install_v1(", call.Sql, StringComparison.Ordinal);
        Assert.Contains("@p0::uuid,@p1,@p2::bigint,@p3,@p4,@p5,@p6", call.Sql, StringComparison.Ordinal);
        Assert.Equal(new object?[] { Uid, "sli.remote-access", 1L, Hash, Confirmation, "windows", @"EXAMPLE\operator" }, call.Args);
        Assert.DoesNotContain(Uid, call.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingCapabilityBlocksBeforeOpeningDatabaseEvenWithInvalidConfirmation()
    {
        var db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, confirmation: "wrong", caps: new HashSet<string>()));
        Assert.Equal("plugins_manage_required", error.Message);
        Assert.Equal(403, error.Status);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(0, db.Rollbacks);
    }

    [Fact]
    public async Task WrongConfirmationBlocksBeforeOpeningDatabase()
    {
        var db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, confirmation: "wrong"));
        Assert.Equal("plugin_lifecycle_confirmation_invalid", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(0, db.Rollbacks);
    }

    [Fact]
    public async Task NonInstallActionIsRejectedBeforeOpeningDatabase()
    {
        var db = Database(); var plan = Plan();
        plan["requested_action"] = "upgrade"; plan["target_version"] = "0.2.0";
        plan["effects"] = JsonNode.Parse("""{"package_version":"0.2.0","rollback_version":"0.1.0"}""");
        plan["preconditions_met"] = false; plan["execution_allowed"] = false;
        plan["plan_sha256"] = "e8fa3ec66120d9d7cc6e0cdc0e8ceb7679a0bbc544f9b4e9669f756e3c54f9fc";
        plan["confirmation"] = "PLUGIN-UPGRADE-SLI-REMOTE-ACCESS-R1-E8FA3EC66120";
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, plan, "PLUGIN-UPGRADE-SLI-REMOTE-ACCESS-R1-E8FA3EC66120"));
        Assert.Equal("plugin_bundled_install_plan_invalid", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(0, db.Rollbacks);
    }

    [Theory]
    [InlineData("plugin_id", "\"sli.ad\"", "plan")]
    [InlineData("effects", "{\"package_lifecycle\":\"registered\",\"runtime_enabled\":true}", "plan")]
    [InlineData("preconditions_met", "false", "plan")]
    [InlineData("preserve_immutable_evidence", "false", "plan")]
    [InlineData("production_read_path_cutover", "true", "plan")]
    [InlineData("destructive_purge", "true", "plan")]
    [InlineData("production_read_path_cutover", "null", "plan")]
    [InlineData("plan_sha256", "\"bad\"", "plan_hash")]
    [InlineData("plan_sha256", "null", "plan_hash")]
    [InlineData("expected_revision", "true", "revision")]
    [InlineData("expected_revision", "1.5", "revision")]
    [InlineData("expected_revision", "\"1\"", "revision")]
    [InlineData("expected_revision", "null", "revision")]
    public async Task InvalidPlanCannotReachDatabase(string field, string value, string reason)
    {
        var db = Database(); var plan = Plan(); plan[field] = JsonNode.Parse(value);
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, plan));
        Assert.Equal("plugin_bundled_install_" + reason + "_invalid", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(0, db.Rollbacks);
    }

    [Theory]
    [InlineData("not-a-uuid", "windows", "actor", "operation_uid")]
    [InlineData(Uid, "untrusted", "actor", "actor")]
    [InlineData(Uid, "windows", " ", "actor")]
    public async Task InvalidOperationContextCannotReachDatabase(string uid, string kind, string key, string reason)
    {
        var db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, uid: uid, kind: kind, key: key));
        Assert.Equal("plugin_bundled_install_" + reason + "_invalid", error.Message);
        Assert.Empty(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(0, db.Rollbacks);
    }

    [Theory]
    [InlineData("session")]
    [InlineData("api_key")]
    [InlineData("windows")]
    [InlineData("system")]
    [InlineData("local_operator")]
    public async Task ContextIsNormalizedAndActorKeyIsBoundAsData(string kind)
    {
        var db = Database();
        const string key = "actor'; select 1; --";
        await Execute(db, uid: "{" + Uid + "}", kind: " " + kind + " ", key: " " + key + " ");
        var call = Assert.Single(db.Calls);
        Assert.Equal(Uid, call.Args[0]); Assert.Equal(kind, call.Args[5]); Assert.Equal(key, call.Args[6]);
        Assert.DoesNotContain(key, call.Sql, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ActorKeyLengthBoundaryMatchesPython()
    {
        var db = Database(); await Execute(db, key: new string('x', 200));
        Assert.Equal(new string('x', 200), Assert.Single(db.Calls).Args[6]);
        db = Database();
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db, key: new string('x', 201)));
        Assert.Equal("plugin_bundled_install_actor_invalid", error.Message); Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[{\"operation_id\":0,\"committed_revision\":2,\"package_lifecycle\":\"registered\",\"desired_activation\":\"disabled\"}]")]
    [InlineData("[{\"operation_id\":7,\"committed_revision\":3,\"package_lifecycle\":\"registered\",\"desired_activation\":\"disabled\"}]")]
    [InlineData("[{\"operation_id\":7,\"committed_revision\":2,\"package_lifecycle\":\"validated\",\"desired_activation\":\"disabled\"}]")]
    [InlineData("[{\"operation_id\":7,\"committed_revision\":2,\"package_lifecycle\":\"registered\",\"desired_activation\":\"enabled_manual\"}]")]
    public async Task UnexpectedDatabaseResultCannotReportSuccess(string rows)
    {
        var db = new ScriptDatabase { Override = (_, _) => ScriptDatabase.Rows(rows) };
        var error = await Assert.ThrowsAsync<InstallationException>(() => Execute(db));
        Assert.Equal("plugin_bundled_install_result_invalid", error.Message); Assert.Single(db.Calls);
    }

    [Fact]
    public async Task DatabaseFailureIsPropagatedWithoutRetryOrSuccess()
    {
        var failure = new InvalidOperationException("test_database_failure");
        var db = new ScriptDatabase { Override = (_, _) => throw failure };
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => Execute(db)));
        Assert.Single(db.Calls); Assert.Equal(0, db.Commits); Assert.Equal(1, db.Rollbacks);
    }
}
