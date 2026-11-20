using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using CoreJobPluginCatalog = Sli.Server.Jobs.CoreJobPluginCatalog;
using CoreJobRegistry = Sli.Server.Jobs.CoreJobRegistry;
using CoreJobHandler = Sli.Server.Jobs.CoreJobHandler;
using CoreJobJson = Sli.Server.Jobs.CoreJobJson;
using CoreJobQueue = Sli.Server.Jobs.CoreJobQueue;
using PostgresCoreJobSession = Sli.Server.Jobs.PostgresCoreJobSession;
using CoreJobLeaseLost = Sli.Server.Jobs.CoreJobLeaseLost;
using ICoreJobSession = Sli.Server.Jobs.ICoreJobSession;
using Sli.Server.Tests.Agents;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

// Vectors from tests/reporting/test_workstation_inventory_job_postgres.py.
// Each case clones the clean-install schema into its own disposable database.
public sealed partial class WorkstationInventoryJobPostgresTests(WorkstationInventoryJobPostgresTests.Fixture fixture)
    : IClassFixture<WorkstationInventoryJobPostgresTests.Fixture>
{
    public sealed class Fixture : IAsyncLifetime
    {
        internal readonly SqlPostgresFixture Schema = new();
        public ValueTask InitializeAsync() => new(Schema.StartAsync(TestContext.Current.CancellationToken));
        public ValueTask DisposeAsync() => Schema.DisposeAsync();
        internal async Task<NpgsqlConnection> Open()
        {
            var ct = TestContext.Current.CancellationToken;
            string name = "synthetic_inventory_" + Guid.NewGuid().ToString("N");
            await using (var admin = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Schema.Pg.ConnectionString) { Database = "template1" }.ConnectionString))
            {
                await admin.OpenAsync(ct);
                await PostCollectionPostgres.Sql(admin, "create database " + name + " template postgres", ct);
            }
            var db = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Schema.Pg.ConnectionString) { Database = name, CommandTimeout = 0 }.ConnectionString);
            await db.OpenAsync(ct);
            return db;
        }
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly CoreJobPluginCatalog Catalog = CoreJobPluginCatalog.Compiled();
    static readonly CoreJobRegistry Registry = Catalog.Registry(null);
    static CoreJobHandler Handler(JsonObject job) => Catalog.Resolve(job);
    static async Task<object?> Scalar(NpgsqlConnection db, string sql, params object?[] args)
    { var value = await Ws.Scalar(db, sql, Ct, args); return value is DBNull ? null : value; }
    static Task<int> Exec(NpgsqlConnection db, string sql, params object?[] args) => Ws.Exec(db, sql, Ct, args);
    static Task<List<JsonObject>> Rows(NpgsqlConnection db, string sql, params object?[] args) => Ws.Rows(db, sql, Ct, args);
    static void Equal(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), $"Expected: {expected}\nActual: {actual}");
    static object?[] Fence(JsonObject job) => [Guid.Parse(job.Text("job_id")!), Guid.Parse(job.Text("lease_token")!), job.Number("lease_generation")];
    static async Task As(NpgsqlConnection db, string role, Func<Task> action)
    {
        // All roles are fixed test constants, never host data.
        Assert.Contains(role, new[] { "sli_job_executor_light", "sli_job_publisher_light", "sli_job_dispatcher_light", "sli_job_executor_heavy", "adlog_user" });
        await Exec(db, "set session authorization " + role);
        try { await action(); }
        finally { await Exec(db, "reset session authorization"); }
    }
    static async Task<JsonObject> Job(NpgsqlConnection db, int domain = 11)
    {
        var manifest = CoreJobRegistry.Bundled("sli.workstations.projection");
        var spec = manifest["handlers"]![0]!.DeepClone().AsObject();
        spec["plugin_id"] = "sli.workstations"; spec["plugin_version"] = "1.0.0";
        spec["job_type"] = "reconcile";
        string source = "workstations:inventory:" + domain;
        spec["source_instance_id"] = source; spec["partition_key"] = source;
        spec["manifest_sha256"] = CoreJobJson.Digest(manifest);
        spec["access_scope"] = JsonNode.Parse($$"""
            {"mode":"restricted","clauses":[{"source_instance_ids":["{{source}}"],"collection_scope_ids":["ad-domain:{{domain}}"],"device_ids":[],"entity_ids":[]}],"decision_id":"core-workstation-inventory-v1","policy_revision":"1"}
            """);
        var id = Guid.NewGuid(); var token = Guid.NewGuid();
        await Install(db);
        await Exec(db, """
            insert into sli_jobs.jobs(job_id,spec,idempotency_key,plugin_id,source_instance_id,partition_key,resource_profile,rights_profile,state,priority,max_attempts,available_at,deadline_at,lease_token,lease_generation,lease_until)
            values(@p0,@p1::jsonb,@p2,'sli.workstations',@p3,@p3,'light','workstations-projection','leased',1,3,clock_timestamp(),clock_timestamp()+interval '5 minutes',@p4,1,clock_timestamp()+interval '5 minutes')
            """, id, spec, CoreJobJson.Digest(JsonValue.Create(id.ToString())), source, token);
        spec["job_id"] = id.ToString(); spec["lease_token"] = token.ToString(); spec["lease_generation"] = 1;
        return spec;
    }
    static Task<int> Install(NpgsqlConnection db) => Exec(db, """
        insert into public.plugin_installations_v1(plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
        values('sli.workstations','fixture',@p0,'1.0.0','registered','enabled_manual','unknown','running','drained',1,1)
        on conflict(plugin_id) do update set package_version='1.0.0',package_lifecycle='registered',desired_activation='enabled_manual',component_runtime='running'
        """, CoreJobJson.Digest(CoreJobRegistry.Bundled("sli.workstations.projection")));
    static async Task<JsonObject> Input(NpgsqlConnection db, JsonObject job)
        => JsonNode.Parse((string)(await Scalar(db, "select public.read_workstation_inventory_input_v1(@p0,@p1,@p2)::text", Fence(job)))!)!.AsObject();
    static async Task<JsonObject> Stage(NpgsqlConnection db, JsonObject job)
    {
        JsonObject result = null!;
        await As(db, "sli_job_executor_light", async () => result = await Handler(job).Stage(db, job, Ct));
        return result;
    }
    static async Task<string> Publish(NpgsqlConnection db, JsonObject job, JsonObject result, Func<Task>? after = null)
    {
        string state = "";
        await As(db, "sli_job_publisher_light", async () => state = await new CoreJobQueue(new PostgresCoreJobSession(db)).PublishAsync(job, result, async ct => {
            await Handler(job).Publish(db, job, result, ct);
            if (after is not null) await after();
        }, Ct));
        return state;
    }
    static Task<object?> Direct(NpgsqlConnection db, JsonObject job, JsonObject input, JsonNode? rows, string? cursor)
        => Scalar(db, "select public.publish_workstation_inventory_v1(@p0,@p1,@p2,@p3,@p4::jsonb,@p5)", [.. Fence(job), input.Text("source_sha256"), rows?.ToJsonString() ?? "null", cursor]);
    static async Task<(long Own, long Foreign)> Directory(NpgsqlConnection db)
    {
        long first = Convert.ToInt64(await Scalar(db, "select coalesce(max(id),0)+1000 from entities_v2"));
        await Exec(db, """
            insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select @p0+n,t.id,'synthetic-inventory-'||(@p0+n)::text,'synthetic-station-'||(@p0+n)::text,11+n*11,decode(repeat('00',32),'hex')
            from storage_v2_entity_type t cross join generate_series(0,1) n where t.value='ad_computer'
            """, first);
        return (first, first + 1);
    }
    static async Task<Guid> Agent(NpgsqlConnection db)
    {
        var id = Guid.NewGuid();
        await Exec(db, "insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name) values(@p0,@p1,repeat('a',64),'[{\"module_id\":\"sli.workstations\"}]'::jsonb,'synthetic-agent-only')", id, Guid.NewGuid());
        return id;
    }
    static async Task Empty(NpgsqlConnection db)
    {
        foreach (string table in new[] { "station_inventory", "inventory_checkpoints", "inventory_publications" })
            Assert.Equal(0L, await Scalar(db, "select count(*) from sli_plugin_workstations." + table));
    }
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); await Ws.Exec(db, "set role adlog_user", ct); return db; }
    }
    static readonly AccessFacts Facts = new(false, "operator", [], [],
        [JsonSerializer.SerializeToElement(new { capability_key = "workstations.read", effect = "allow", scope_json = new { kind = "all" } })], [], [], [], []);
    static AccessDecision Access(int? domain = null) => new("operator", new CapabilityComposer().Compose(Facts), [new("workstations.overview", true,
        [new AtomicReportGrant(JsonSerializer.SerializeToElement(domain is null ? (object)new { kind = "all" } : new { kind = "domain", ids = new[] { domain.Value } }), WorkstationReportContract.Fields.ToHashSet(), new HashSet<string> { "view" }, 1, 1)])]);
    static Task<JsonObject> Overview(NpgsqlConnection db, JsonObject? parameters = null, int? domain = null, string? station = null)
        => new WorkstationReports(new Connections(db.ConnectionString), new ConfigurationBuilder().Build()).ReadAsync(new("workstations.overview", parameters ?? new(), 50, null, station), Facts, Access(domain), Ct);

    [Fact]
    public async Task Directory_and_agent_sources_reach_overview_via_fenced_publication_and_replay()
    {
        await using var db = await fixture.Open(); var (own, foreign) = await Directory(db); var agent = await Agent(db);
        foreach (int domain in new[] { 11, 22, 0 })
        {
            var job = await Job(db, domain); var result = await Stage(db, job);
            Assert.Equal("committed", await Publish(db, job, result));
            Assert.Equal("duplicate", await Publish(db, job, result));
        }
        var body = await Overview(db);
        Assert.Equal(new[] { $"ws:ad:{own}", $"ws:ad:{foreign}", $"ws:agent:{agent}" }.Order(), body["items"]!.AsArray().Select(r => r.Text("station_id")).Order());
        Equal(new JsonArray($"ws:ad:{own}"), new JsonArray((await Overview(db, new() { ["domain"] = 11L }))["items"]!.AsArray().Select(r => r!["station_id"]!.DeepClone()).ToArray()));
        Assert.Equal("not_proven", body["coverage"].Text("completeness"));
    }

    [Fact]
    public async Task Changed_source_and_tampered_page_are_rejected_before_writes()
    {
        await using var db = await fixture.Open(); var (own, _) = await Directory(db); var job = await Job(db); var result = await Stage(db, job);
        foreach (string key in new[] { "inventory_ids", "inventory_deferred" })
        {
            var forged = result.DeepClone().AsObject(); forged[key] = new JsonArray("synthetic-forged");
            Assert.Equal("workstation_inventory_page_changed", (await Assert.ThrowsAsync<WorkstationException>(() => Publish(db, job, forged))).Message);
            await Empty(db);
        }
        await Exec(db, "update entities_v2 set display_name='synthetic-renamed' where id=@p0", own);
        Assert.Equal("workstation_inventory_input_changed", (await Assert.ThrowsAsync<WorkstationException>(() => Publish(db, job, result))).Message);
        await Empty(db);
    }
}
