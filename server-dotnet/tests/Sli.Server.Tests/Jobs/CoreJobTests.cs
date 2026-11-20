using System.Text.Json.Nodes;
using System.Text.Json;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public class CoreJobTests
{
    internal static CoreJobRegistry Registry()
    {
        var registry = new CoreJobRegistry();
        foreach (var plugin in new[] { "sli.ad", "sli.gpo", "sli.remote-access", "sli.workstations", "sli.workstations.projection" })
            registry.Register(CoreJobRegistry.Bundled(plugin));
        return registry;
    }

    internal static JsonObject Job(string handlerId = "radius-session-observation")
    {
        var registry = Registry();
        var handler = registry.Handlers.Single(h => h["handler_id"]!.GetValue<string>() == handlerId);
        var job = (JsonObject)handler.DeepClone();
        job["job_type"] = job["kind"]!.DeepClone();
        job["job_id"] = "00000000-0000-0000-0000-000000000001";
        job["lease_token"] = "00000000-0000-0000-0000-000000000002";
        job["lease_generation"] = 2;
        job["remaining_seconds"] = 60;
        job["source_instance_id"] = "synthetic-source";
        job["partition_key"] = handlerId;
        job["pinned_input"] = JsonNode.Parse("{\"generation\":\"1\",\"input_range\":[1],\"policy_revision\":\"1\",\"continuation\":null}");
        job["input_sha256"] = CoreJobJson.Digest(job["pinned_input"]);
        return job;
    }

    [Fact] public void Bundled_manifests_pin_all_eleven_handlers_and_profiles()
    {
        var registry = Registry();
        Assert.Equal(11, registry.Handlers.Count);
        Assert.Equal(4, registry.Identities("light").Count);
        Assert.Equal(5, registry.Identities("heavy").Count);
        Assert.Equal(2, registry.Identities("long").Count);
        registry.Resolve(Job());
    }

    [Theory]
    [InlineData("rights_profile", "ad-read", "handler_version_unavailable")]
    [InlineData("resource_profile", "heavy", "handler_version_unavailable")]
    [InlineData("manifest_sha256", "tampered", "handler_version_unavailable")]
    [InlineData("input_sha256", "tampered", "job_input_hash_conflict")]
    public void Changed_pin_or_rights_are_rejected(string field, string value, string code)
    {
        var job = Job(); job[field] = value;
        Assert.Equal(code, Assert.Throws<CoreJobContractException>(() => Registry().Resolve(job)).Message);
    }

    [Fact] public void Registry_rejects_invalid_manifest_atomically_and_caps_budgets()
    {
        var registry = new CoreJobRegistry();
        var manifest = CoreJobRegistry.Bundled("sli.remote-access");
        manifest["handlers"]![0]!["rights_profile"] = "ad-read";
        Assert.Throws<CoreJobContractException>(() => registry.Register(manifest));
        Assert.Empty(registry.Handlers);
        manifest = CoreJobRegistry.Bundled("sli.remote-access");
        manifest["handlers"]![0]!["budget"]!["wall_seconds"] = 9999;
        registry.Register(manifest);
        Assert.Equal(90L, registry.Handlers[0]["budget"]!["wall_seconds"]!.GetValue<long>());
        Assert.Throws<CoreJobContractException>(() => registry.Register(manifest));
    }

    [Theory]
    [InlineData("interval", "2026-01-01T00:00:31Z", "58907521")]
    [InlineData("input_available", "2026-01-01T00:00:31Z", "generation-1")]
    public void Schedule_slots_match_reference(string trigger, string time, string expected)
    {
        var schedule = (JsonObject)CoreJobRegistry.Bundled("sli.remote-access")["schedules"]![0]!.DeepClone();
        schedule["trigger"] = trigger;
        Assert.Equal(expected, CoreJobScheduler.Slot(schedule, DateTimeOffset.Parse(time), "generation-1"));
    }

    [Fact] public void Calendar_fold_has_one_key_and_nonmatching_slot_skips()
    {
        var schedule = JsonNode.Parse("{\"trigger\":\"calendar\",\"timezone\":\"America/New_York\",\"calendar\":{\"local_times\":[\"01:30\"]}}")!.AsObject();
        Assert.Equal(CoreJobScheduler.Slot(schedule, DateTimeOffset.Parse("2026-11-01T05:30Z")), CoreJobScheduler.Slot(schedule, DateTimeOffset.Parse("2026-11-01T06:30Z")));
        Assert.Null(CoreJobScheduler.Slot(schedule, DateTimeOffset.Parse("2026-11-01T07:30Z")));
    }

    [Theory]
    [InlineData("lost")]
    [InlineData("duplicate")]
    [InlineData("conflict")]
    public async Task Publication_checks_fence_before_effects(string state)
    {
        var session = new Session(state); var queue = new CoreJobQueue(session); bool applied = false;
        if (state == "lost") await Assert.ThrowsAsync<CoreJobLeaseLost>(() => queue.PublishAsync(Job(), new() { ["status"] = "success" }, _ => { applied = true; return Task.CompletedTask; }, TestContext.Current.CancellationToken));
        else Assert.Equal(state, await queue.PublishAsync(Job(), new() { ["status"] = "success" }, _ => { applied = true; return Task.CompletedTask; }, TestContext.Current.CancellationToken));
        Assert.False(applied);
    }

    [Fact] public async Task Expired_final_fence_rolls_back_effects()
    {
        var session = new Session("publish", false); var queue = new CoreJobQueue(session);
        await Assert.ThrowsAsync<CoreJobLeaseLost>(() => queue.PublishAsync(Job(), new() { ["status"] = "partial" }, _ => { session.Effect = true; return Task.CompletedTask; }, TestContext.Current.CancellationToken));
        Assert.False(session.Effect); Assert.True(session.RolledBack);
    }

    [Fact] public async Task Publisher_exception_rolls_back_and_oversized_or_invalid_results_never_start_transaction()
    {
        var session = new Session("publish"); var queue = new CoreJobQueue(session);
        await Assert.ThrowsAsync<InvalidOperationException>(() => queue.PublishAsync(Job(), new() { ["status"] = "success" }, _ => throw new InvalidOperationException("synthetic"), TestContext.Current.CancellationToken));
        Assert.True(session.RolledBack);
        session = new Session(); queue = new CoreJobQueue(session);
        foreach (var result in new[] { new JsonObject { ["status"] = "wrong" }, new JsonObject { ["status"] = "success", ["payload"] = new string('x', 65536) } })
            await Assert.ThrowsAsync<CoreJobContractException>(() => queue.PublishAsync(Job(), result, _ => Task.CompletedTask, TestContext.Current.CancellationToken));
        Assert.Empty(session.Calls);
    }

    [Fact] public async Task Queue_pins_claims_and_reports_conflict_and_stale_lease()
    {
        var job = Job(); var session = new Session(Guid.Parse(job.Text("job_id")), null, job, false, false);
        var queue = new CoreJobQueue(session); var ct = TestContext.Current.CancellationToken;
        Assert.Equal(job.Text("job_id"), await queue.EnqueueAsync(job, ct));
        await Assert.ThrowsAsync<CoreJobConflict>(() => queue.EnqueueAsync(job, ct));
        Assert.Same(job, await queue.ClaimAsync("light", "synthetic-executor", Registry().Identities("light"), ct));
        await Assert.ThrowsAsync<CoreJobLeaseLost>(() => queue.HeartbeatAsync(job, ct));
        await Assert.ThrowsAsync<CoreJobLeaseLost>(() => queue.FailAsync(job, "job_execution_failed", true, ct));
        Assert.Equal("claim_core_job_v1", session.Calls[2].Function);
        Assert.Contains("manifest_sha256", ((JsonArray)session.Calls[2].Args[2]!).ToJsonString());
        Assert.IsType<Guid>(session.Calls[3].Args[0]); Assert.Equal(2L, session.Calls[3].Args[2]);
    }

    [Fact] public void Schedule_spec_and_idempotency_keep_source_scope_and_pinned_input()
    {
        var source = JsonNode.Parse("{\"source_instance_id\":\"synthetic-source\",\"subscription_id\":\"synthetic-subscription\",\"revision\":\"1\",\"delivery_ids\":[1],\"access_scope\":{\"mode\":\"restricted\"}}")!.AsObject();
        var spec = Assert.Single(CoreJobScheduler.Create(Registry(), "light", source, DateTimeOffset.Parse("2026-01-01T00:00:31Z")));
        Assert.Equal("radius-session-observation", spec.Text("handler_id"));
        Assert.Equal("schedule:radius-session-observation:58907521", spec.Text("input_ref"));
        Assert.True(JsonNode.DeepEquals(source["access_scope"], spec["access_scope"]));
        Assert.Equal(CoreJobJson.Digest(spec["pinned_input"]), spec.Text("input_sha256"));
        string key = CoreJobQueue.IdempotencyKey(spec, spec["pinned_input"]!.AsObject());
        spec["attempts"] = 9; spec["lease_token"] = "synthetic-token";
        Assert.Equal(key, CoreJobQueue.IdempotencyKey(spec, spec["pinned_input"]!.AsObject()));
        spec["pinned_input"]!["input_range"] = new JsonArray(2);
        Assert.NotEqual(key, CoreJobQueue.IdempotencyKey(spec, spec["pinned_input"]!.AsObject()));
        Assert.Empty(CoreJobScheduler.Create(Registry(), "heavy", source, DateTimeOffset.UtcNow));
    }

    [Fact] public void Calendar_and_input_schedules_validate_cross_fields_and_registration_is_atomic()
    {
        foreach (string scenario in new[] { "unknown", "duplicate", "trigger", "timezone", "budget", "code", "dependency", "core" })
        {
            var registry = new CoreJobRegistry(); var manifest = CoreJobRegistry.Bundled("sli.remote-access");
            switch (scenario)
            {
                case "unknown": manifest["schedules"]![0]!["handler_id"] = "unknown"; break;
                case "duplicate": manifest["schedules"]!.AsArray().Add(manifest["schedules"]![0]!.DeepClone()); break;
                case "trigger": manifest["schedules"]![0]!["trigger"] = "input_available"; break;
                case "timezone": manifest["schedules"]![0]!["timezone"] = "not/a/timezone"; break;
                case "budget": manifest["handlers"]![0]!["budget"]!["wall_seconds"] = 0; break;
                case "code": manifest["command"] = "synthetic"; break;
                case "dependency": manifest["dependencies"]!.AsArray().Add(JsonNode.Parse("{\"contract_id\":\"example.contract\",\"versions\":{\"minimum\":\"1.0.0\",\"maximum_exclusive\":\"2.0.0\"},\"required\":true,\"exchange\":\"immutable_typed_result\"}")); break;
                case "core": manifest["core_api"]!["minimum"] = "2.0.0"; break;
            }
            Assert.Throws<CoreJobContractException>(() => registry.Register(manifest)); Assert.Empty(registry.Handlers);
        }
    }

    [Fact] public void Canonical_digest_matches_frozen_python_unicode_vector()
    {
        Assert.Equal("{\"a\":\"\\u0416\\ud83d\\ude00\",\"z\":[1,null,true]}", Sli.Agent.Protocol.CanonicalJson.Serialize(JsonNode.Parse("{\"z\":[1,null,true],\"a\":\"Ж😀\"}")));
        Assert.Equal("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", CoreJobJson.Digest(new JsonObject()));
    }

    [Fact] public void Retained_generations_resolve_old_jobs_but_only_active_manifest_schedules()
    {
        using var files = new PluginPackageFixture("sli.remote-access", "1.0.1");
        string root = files.Root, plugin = files.Plugin;
        var manifest = files.Jobs;
        files.Activate();
        {
            var catalog = new CoreJobPluginCatalog();
            catalog.Add("sli.remote-access", "radius-session-observation", new((_, _, _) => throw new Exception("unused"), (_, _, _, _) => Task.CompletedTask));
            var registry = catalog.Registry(root); Assert.Equal(4, registry.Handlers.Count);
            registry.Resolve(Job()); Assert.Equal("1.0.1", Assert.Single(registry.Manifests).Text("plugin_version"));
            manifest["plugin_version"] = "1.0.0";
            files.Release["plugin_version"] = "1.0.0"; files.Release["version"] = "1.0.0";
            files.Descriptor["version"] = "1.0.0";
            files.WriteJobs(); files.WriteUi(); files.WriteRelease();
            var retained = catalog.Registry(root); Assert.Equal(2, retained.Handlers.Count); Assert.Single(retained.Manifests);
            File.WriteAllText(Path.Combine(plugin, "draining.json"), "{}");
            Assert.Equal("plugin_update_draining", Assert.Throws<InvalidOperationException>(() => CoreJobAdmission.Enter("sli.remote-access", root, null)).Message);
        }
    }

    [Fact] public void Compiled_modules_cannot_register_unknown_handlers_or_change_other_owner_manifests()
    {
        var catalog = new CoreJobPluginCatalog();
        Assert.Throws<CoreJobContractException>(() => catalog.Add("sli.ad", "radius-session-observation", new((_, _, _) => throw new Exception("unused"), (_, _, _, _) => Task.CompletedTask)));
        Assert.Empty(catalog.Owners);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("partial")]
    [InlineData("blocked")]
    [InlineData("cancelled")]
    public async Task Accepted_results_commit_with_audit_envelope(string status)
    {
        var session = new Session("publish", true); var queue = new CoreJobQueue(session);
        Assert.Equal("committed", await queue.PublishAsync(Job(), new() { ["status"] = status }, _ => { session.Effect = true; return Task.CompletedTask; }, TestContext.Current.CancellationToken));
        Assert.True(session.Committed); Assert.True(session.Effect);
        var envelope = Assert.IsType<JsonObject>(session.Calls.Last().Args[4]);
        Assert.Equal("sli.core-job-result.v1", envelope["contract_id"]!.GetValue<string>());
        Assert.Equal(status, envelope["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("publish","publish",true)]
    [InlineData("lost","publish",false)]
    [InlineData("publish","lost",false)]
    public async Task Drain_batch_checks_both_fences_and_keeps_job_leased(string begin,string commit,bool valid)
    {
        var session=new Session(begin,commit);var queue=new CoreJobQueue(session);bool applied=false;
        Task Batch()=>queue.ApplyBatchAsync(Job(),new(){["work_ids"]=new JsonArray(1)},_=>{applied=true;session.Effect=true;return Task.CompletedTask;},TestContext.Current.CancellationToken);
        if(valid)await Batch();else await Assert.ThrowsAsync<CoreJobLeaseLost>(Batch);
        Assert.Equal(begin=="publish",applied);
        Assert.Equal(valid,session.Committed);Assert.Equal(!valid,session.RolledBack);Assert.Equal(valid,session.Effect);
        Assert.All(session.Calls,c=>Assert.Equal("begin_core_job_result_v1",c.Function));
    }

    internal sealed class Session(params object?[] responses) : ICoreJobSession
    {
        private readonly Queue<object?> responses = new(responses);
        public List<(string Function, object?[] Args)> Calls { get; } = [];
        public bool Effect, Committed, RolledBack;
        public Task<object?> CallAsync(string function, object?[] args, CancellationToken ct) { Calls.Add((function, args)); return Task.FromResult(responses.Dequeue()); }
        public Task BeginAsync(CancellationToken ct) => Task.CompletedTask;
        public Task CommitAsync(CancellationToken ct) { Committed = true; return Task.CompletedTask; }
        public Task RollbackAsync(CancellationToken ct) { RolledBack = true; Effect = false; return Task.CompletedTask; }
    }
}
