using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed partial class WorkstationInventoryJobPostgresTests
{
    static async Task<(Guid Agent, long Device)> Device(NpgsqlConnection db, params long[] targets)
    {
        var agent = await Agent(db);
        long device = Convert.ToInt64(await Scalar(db, "select coalesce(max(id),0)+1 from entities_v2"));
        // Same canonical identity digest as the trusted Python builder.
        string natural = "core:" + Ws.Sha($"[\"device\",\"sli.agent.key\",\"agent-registry\",\"{agent}\"]");
        await Exec(db, """
            insert into storage_v2_entity_type(value) values('device') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256)
            select @p0,id,@p1,'synthetic-device',sha256(convert_to(@p2,'UTF8')) from storage_v2_entity_type where value='device';
            insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,entity_kind,entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution)
            select sha256(convert_to(host_id::text,'UTF8')),'sli.workstations',host_id::text,'device',@p0,clock_timestamp(),'[{}]',array['synthetic'],'resolved' from sli_agents where id=@p3
            """, device, natural, agent.ToString(), agent);
        foreach (long target in targets) await Associate(db, device, target);
        return (agent, device);
    }
    static Task<int> Associate(NpgsqlConnection db, long device, long target) => Exec(db, """
        insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs)
        select @p0,@p1,'directory_computer',id,array['synthetic'] from auth_users where username='platform-owner'
        """, device, target);
    static async Task<JsonObject> Run(NpgsqlConnection db, int domain)
    {
        var job = await Job(db, domain); var result = await Stage(db, job);
        Assert.Equal("committed", await Publish(db, job, result));
        return result;
    }
    static Task<int> MoreDirectory(NpgsqlConnection db, long first, long own, int count = 1) => Exec(db, """
        insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select @p0+n,entity_type_id,'synthetic-control-'||(@p0+n)::text,'synthetic-control',11,decode(repeat('00',32),'hex')
        from entities_v2 cross join generate_series(0,@p2-1) n where id=@p1
        """, first, own, count);
    static Task<List<JsonObject>> InventoryRows(NpgsqlConnection db) => Rows(db, "select station_id,agent_key,ad_computer_id,revision from sli_plugin_workstations.station_inventory order by station_id");
    static void EqualRows(List<JsonObject> expected, List<JsonObject> actual) => Equal(Ws.Array(expected), Ws.Array(actual));

    [Fact]
    public async Task Empty_unknown_inventory_and_continuation_preserve_replay_revision()
    {
        await using var db = await fixture.Open();
        var empty = await Run(db, 0); Assert.Empty(empty["inventory_ids"]!.AsArray()); Assert.Equal("not_proven", empty.Text("coverage_state"));
        await Exec(db, """
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name)
            select gen_random_uuid(),gen_random_uuid(),repeat('a',64),'[{"module_id":"sli.workstations"}]'::jsonb,'synthetic-agent-'||n from generate_series(1,101) n
            """);
        var first = await Run(db, 0); Assert.Equal(80, first["inventory_ids"]!.AsArray().Count); Assert.Equal("partial", first.Text("status"));
        var second = await Run(db, 0); Assert.Equal(21, second["inventory_ids"]!.AsArray().Count); Assert.Equal("success", second.Text("status"));
        await Run(db, 0);
        var rows = await Rows(db, "select domain_id,station_type,quality->>'status' as quality,revision from sli_plugin_workstations.station_inventory");
        Assert.Equal(101, rows.Count);
        foreach (var row in rows) { Assert.Null(row["domain_id"]); Assert.Equal("unknown", row.Text("station_type")); Assert.Equal("not_collected", row.Text("quality")); Assert.Equal(1, row.Number("revision")); }
    }

    [Fact]
    public async Task Explicit_linked_ownership_and_ambiguous_inputs_never_mix_domains()
    {
        await using var db = await fixture.Open(); var (own, foreign) = await Directory(db);
        var (ownAgent, ownDevice) = await Device(db, own); var (foreignAgent, _) = await Device(db, foreign); var (ambiguous, _) = await Device(db, own, foreign);
        foreach (var (domain, expected) in new[] { (11, ownAgent), (22, foreignAgent), (0, ambiguous) })
        {
            var job = await Job(db, domain);
            await As(db, "sli_job_executor_light", async () => {
                var input = await Input(db, job);
                Assert.Equal(expected.ToString(), Assert.Single(input["sources"]!["agents"]!.AsArray()).Text("agent_key"));
                if (domain == 0) { Assert.Empty(input["sources"]!["directory"]!.AsArray()); Assert.Empty(input["sources"]!["devices"]!.AsArray()); }
            });
            Assert.Equal("committed", await Publish(db, job, await Stage(db, job)));
        }
        var rows = await Rows(db, "select agent_key,entity_id,ad_computer_id,domain_id,association_status,station_type,quality->>'status' as quality from sli_plugin_workstations.station_inventory");
        var linked = rows.Single(r => r.Text("agent_key") == ownAgent.ToString());
        Assert.Equal(ownDevice, linked.Number("entity_id")); Assert.Equal(own, linked.Number("ad_computer_id")); Assert.Equal(11, linked.Number("domain_id"));
        Assert.Equal("unique", linked.Text("association_status")); Assert.Equal("unknown", linked.Text("station_type")); Assert.Equal("not_collected", linked.Text("quality"));
        var unknown = rows.Single(r => r.Text("agent_key") == ambiguous.ToString());
        foreach (string key in new[] { "entity_id", "ad_computer_id", "domain_id" }) Assert.Null(unknown[key]);
        Assert.Equal("ambiguous", unknown.Text("association_status")); Assert.Equal("unknown", unknown.Text("station_type")); Assert.Equal("partial", unknown.Text("quality"));
    }

    static async Task<(long Own, Guid Agent, JsonObject Job, List<JsonObject> Before, JsonNode History)> PendingConflict(NpgsqlConnection db)
    {
        var (own, _) = await Directory(db); var (agent, device) = await Device(db);
        await Run(db, 0); await Run(db, 11); var before = await InventoryRows(db);
        string station = before.Single(r => r.Text("agent_key") == agent.ToString()).Text("station_id")!;
        await Exec(db, """
            insert into sli_plugin_workstations.station_summary(station_id,as_of_utc) values(@p0,now());
            insert into sli_plugin_workstations.station_changes(id,station_id,change_kind,detected_at,reason_code,evidence_refs)
            values(@p1,@p0,'synthetic',now(),'synthetic_preserve','[{"kind":"synthetic","id":"unchanged"}]')
            """, station, Ws.Sha(station));
        var history = JsonNode.Parse((string)(await Scalar(db, "select to_jsonb(c)::text from sli_plugin_workstations.station_changes c where id=@p0", Ws.Sha(station)))!)!;
        await Associate(db, device, own);
        return (own, agent, await Job(db), before, history);
    }
    static async Task AssertHistory(NpgsqlConnection db, JsonNode history)
    {
        Equal(history, JsonNode.Parse((string)(await Scalar(db, "select to_jsonb(c)::text from sli_plugin_workstations.station_changes c where id=@p0", history.Text("id")))!));
        Assert.Equal(1L, await Scalar(db, "select count(*) from sli_plugin_workstations.station_summary where station_id=@p0", history.Text("station_id")));
    }

    [Fact]
    public async Task Persisted_ids_defer_without_rewriting_history_or_blocking_other_rows_then_resolve()
    {
        await using var db = await fixture.Open(); var (own, agent, job, before, history) = await PendingConflict(db);
        long control = own + 100; await MoreDirectory(db, control, own);
        var staged = await Stage(db, job); Assert.Equal("partial", staged.Text("status"));
        Equal(JsonNode.Parse($$"""[{"station_id":"ws:ad:{{own}}","reason":"identity_owner_conflict"}]"""), staged["inventory_deferred"]);
        Assert.Equal("committed", await Publish(db, job, staged));
        EqualRows(before, (await InventoryRows(db)).Where(r => r.Text("station_id") != $"ws:ad:{control}").ToList());
        Assert.Equal(1L, await Scalar(db, "select revision from sli_plugin_workstations.station_inventory where station_id=@p0", $"ws:ad:{control}"));
        Assert.Equal("pending", await Scalar(db, "select state from sli_plugin_workstations.inventory_deferred"));
        Assert.Equal(1L, await Scalar(db, "select attempts from sli_plugin_workstations.inventory_deferred"));
        await Exec(db, "update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'");
        var retry = await Run(db, 11); Assert.Equal("partial", retry.Text("status"));
        Assert.Equal(2L, await Scalar(db, "select attempts from sli_plugin_workstations.inventory_deferred")); await AssertHistory(db, history);
        await Exec(db, "update sli_agents set host_id=@p0 where id=@p1; update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'", Guid.NewGuid(), agent);
        var resolved = await Run(db, 11); Assert.Equal("success", resolved.Text("status")); Assert.Empty(resolved["inventory_deferred"]!.AsArray());
        Assert.Equal("resolved", await Scalar(db, "select state from sli_plugin_workstations.inventory_deferred")); await AssertHistory(db, history);
    }

    [Fact]
    public async Task Disappeared_scoped_source_stays_deferred_without_foreign_metadata()
    {
        await using var db = await fixture.Open(); var (own, _, job, _, _) = await PendingConflict(db);
        Assert.Equal("committed", await Publish(db, job, await Stage(db, job)));
        await Exec(db, "update entities_v2 set domain_id=22 where id=@p0; update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'", own);
        await As(db, "sli_job_dispatcher_light", async () => {
            var sources = await Rows(db, "select public.read_workstation_inventory_job_sources_v1() as source");
            Assert.Contains(sources, r => r["source"].Text("source_instance_id") == "workstations:inventory:11");
        });
        var retry = await Job(db);
        await As(db, "sli_job_executor_light", async () => { var input = await Input(db, retry); Assert.Empty(input["sources"]!["directory"]!.AsArray()); Assert.Empty(input["sources"]!["agents"]!.AsArray()); });
        var result = await Stage(db, retry); Assert.Equal("partial", result.Text("status"));
        Equal(JsonNode.Parse($$"""[{"station_id":"ws:ad:{{own}}","reason":"source_identity_unavailable"}]"""), result["inventory_deferred"]);
        Assert.Equal("committed", await Publish(db, retry, result));
        Assert.Equal("pending", await Scalar(db, "select state from sli_plugin_workstations.inventory_deferred"));
        Assert.Equal("source_identity_unavailable", await Scalar(db, "select reason from sli_plugin_workstations.inventory_deferred"));
        Assert.Equal(11L, await Scalar(db, "select domain_id from sli_plugin_workstations.station_inventory where ad_computer_id=@p0", own));
    }

    [Fact]
    public async Task Conflict_at_normal_page_boundary_does_not_stall_next_page()
    {
        await using var db = await fixture.Open(); var (own, _) = await Directory(db);
        await MoreDirectory(db, own + 100, own, 80); await Run(db, 11); await Run(db, 11);
        var (agent, device) = await Device(db); await Run(db, 0);
        long target = new[] { own }.Concat(Enumerable.Range(0, 80).Select(i => own + 100 + i)).OrderBy(n => $"ws:ad:{n}", StringComparer.Ordinal).ElementAt(79);
        await Associate(db, device, target);
        long control = long.Parse((own + 179).ToString() + "9"); await MoreDirectory(db, control, own);
        var first = await Run(db, 11); Assert.Equal(80, first["inventory_ids"]!.AsArray().Count);
        Equal(JsonNode.Parse($$"""[{"station_id":"ws:ad:{{target}}","reason":"identity_owner_conflict"}]"""), first["inventory_deferred"]);
        Assert.Equal($"ws:ad:{target}", await Scalar(db, "select last_key from sli_plugin_workstations.inventory_checkpoints where domain_id=11"));
        await Run(db, 11);
        Assert.Equal(1L, await Scalar(db, "select count(*) from sli_plugin_workstations.station_inventory where ad_computer_id=@p0", control));
        Assert.Equal($"ws:agent:{agent}", await Scalar(db, "select station_id from sli_plugin_workstations.station_inventory where agent_key=@p0", agent.ToString()));
        Assert.Equal("pending", await Scalar(db, "select state from sli_plugin_workstations.inventory_deferred"));
    }

    [Fact]
    public async Task Source_overflow_fails_without_silent_population_truncation()
    {
        await using var db = await fixture.Open();
        await Exec(db, """
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name)
            select gen_random_uuid(),gen_random_uuid(),repeat('a',64),'[{"module_id":"sli.workstations"}]'::jsonb,'synthetic-overflow-'||n from generate_series(1,10001) n
            """);
        var job = await Job(db, 0);
        Assert.Contains("workstation_inventory_source_limit", (await Assert.ThrowsAsync<PostgresException>(() => Stage(db, job))).MessageText);
        await Empty(db);
    }
}
