using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsPasswordDetectionStatusTests
{
    private const string WorkersRoute = "/api/v1/operations/overview?view=workers";

    [Fact]
    public async Task Mapped_controller_without_native_scope_reports_unknown_rule_statuses()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var connections = new Connections(fixture);
        await RegisterMappedControllerWithoutNativeScope(owner, connections, ShortEventAdmissionPostgresTests.Agent,
            900001, "dc.example.test", ct);

        using var app = await OperationsEndpointTests.Start(postgresQueries: new OperationsQueries(connections));
        var workers = await Workers(app);
        Assert.Equal("ok", workers["password_detection"]!["status"]!.GetValue<string>());
        Assert.Equal("unknown", ReadRule(workers, "brute")["state"]!.GetValue<string>());
        Assert.Equal("unknown", ReadRule(workers, "spray")["state"]!.GetValue<string>());
    }

    [Fact]
    public async Task Status_selects_latest_failure_timestamp_across_sources_without_events()
    {
        const string rule = "qw.password-brute-force";
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 399);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/400_password_detection_status.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var connections = new Connections(fixture);
        var first = ShortEventAdmissionPostgresTests.Agent;
        var second = Guid.Parse("00000000-0000-4000-8000-000000000350");
        await RegisterMappedControllerWithoutNativeScope(owner, connections, first, 900001, "dc-one.example.test", ct);
        await RegisterMappedControllerWithoutNativeScope(owner, connections, second, 900002, "dc-two.example.test", ct);
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var latest = now.AddMinutes(-5);
        // Seed only source metadata and status checkpoints. The read model may receive
        // independent completion and failure times, without running either producer.
        await using (var seed = new NpgsqlCommand("""
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,storage_kind,log_source_id,agent_id)
            select roles.oid,roles.rolname,i.installation_id,b.module_id,b.source_instance_id,b.source_instance_id,'core_event',
                   case when b.agent_id=@first then 900001 else 900002 end,b.agent_id
            from public.sli_agent_module_bindings b cross join public.semantic_default_installation i cross join pg_roles roles
            where b.agent_id in (@first,@second) and b.module_id='sli.windows.ad-dc' and roles.rolname='sli_semantic_login';

            with candidate(agent,completed_at,failure_at) as (
                values (@first,@now-interval '20 minutes',@now-interval '10 minutes'),
                       (@second,@now-interval '40 minutes',@latest)
            ), configured as (
                select public.password_v2_configured_identity(agent)->'scope' as scope,completed_at,failure_at
                from candidate
            ), executions as (
                select *,public.password_v2_coverage_execution(scope,@rule) as execution,
                       floor(extract(epoch from failure_at)/3600)::bigint as failure_hour
                from configured
            ), checkpoints as (
                insert into public.semantic_password_checkpoints(scope_digest,pin,scope_json,execution_json,owner_domain_id,
                    last_attempt_at,last_completed_at,health_status,health_reason,loss_buckets)
                select public.password_v2_scope_key(scope),encode(sha256(convert_to(public.password_v2_json_compact(execution),'UTF8')),'hex'),
                       scope,execution,1,failure_at,completed_at,'error','source_error',
                       jsonb_build_object('source_error',jsonb_set(to_jsonb(array_fill(null::jsonb,array[25])),
                           array[(failure_hour%25)::text],jsonb_build_object('hour',failure_hour,'count',1,
                               'observed_min',public.password_v2_iso(failure_at),'observed_max',public.password_v2_iso(failure_at),
                               'from',null,'to',null)))
                from executions returning scope_digest,pin
            )
            insert into public.password_pass_state393(scope_digest,rule_id,definition_revision,live_pin)
            select scope_digest,@rule,2,pin from checkpoints;
            """, owner))
        {
            seed.Parameters.AddWithValue("first", first);
            seed.Parameters.AddWithValue("second", second);
            seed.Parameters.AddWithValue("now", now);
            seed.Parameters.AddWithValue("latest", latest);
            seed.Parameters.AddWithValue("rule", rule);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await using (var events = new NpgsqlCommand("select count(*) from public.event_hot", owner))
            Assert.Equal(0L, await events.ExecuteScalarAsync(ct));

        using var app = await OperationsEndpointTests.Start(postgresQueries: new OperationsQueries(connections), clock: TimeProvider.System);
        app.Files.Native["semantic"] = new JsonObject { ["status"] = "running", ["heartbeat_at_utc"] = OpsJson.Stamp(now) };
        var workers = await Workers(app);
        Assert.Contains(workers["items"]!.AsArray(), row => (string?)row?["worker_name"] == "semantic" && (string?)row?["state"] == "active");
        var failure = ReadRule(workers, "brute");
        Assert.Equal("failed", (string?)failure["state"]);
        Assert.Equal(latest, OpsJson.Time(failure["observed_at"]));
        Assert.Equal("unknown", (string?)ReadRule(workers, "spray")["state"]);
    }

    [Fact]
    public async Task Status_separates_live_failures_and_recovery_from_a_running_process_and_backlog()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 398);
        var queries = new OperationsQueries(new Connections(fixture));
        using var app = await OperationsEndpointTests.Start(postgresQueries: queries, clock: TimeProvider.System);
        using (var denied = await OperationsEndpointTests.Start(allow: false, postgresQueries: queries))
        using (var deniedResponse = await OperationsEndpointTests.Request(denied, "GET", WorkersRoute))
            Assert.Equal(HttpStatusCode.Forbidden, deniedResponse.StatusCode);

        Assert.Equal("unavailable", (await Workers(app))["password_detection"]!["status"]!.GetValue<string>());
        string migrations = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        string predecessor = Path.Combine(migrations, "399_password_queue_projection.sql");
        string migration = Path.Combine(migrations, "400_password_detection_status.sql");
        var invalidOrder = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(migration, null, ct));
        Assert.Contains("password_detection_status400_preflight", invalidOrder.Message);
        await fixture.Pg.ApplyFileAsync(predecessor, null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.Equal(2, (await queries.ReadAsync(OperationsService.PasswordLiveStatusSql, ct)).Count);
        Assert.Equal("unknown", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());

        var now = DateTimeOffset.UtcNow;
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using (var privileges = new NpgsqlCommand("""
            select has_function_privilege('adlog_user','public.read_password_live_status400(bigint[])','EXECUTE')
              and not has_function_privilege('adlog_semantic_worker','public.read_password_live_status400(bigint[])','EXECUTE')
              and not has_table_privilege('adlog_user','public.semantic_password_checkpoints','SELECT')
            """, owner))
            Assert.Equal(true, await privileges.ExecuteScalarAsync(ct));
        var initial = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: now.AddMinutes(-8), eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, initial, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var source = new NpgsqlCommand("""
            select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
            """, worker);
        var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        await using (var admin = await new Connections(fixture).OpenAsync(ct))
        await using (var bind = new NpgsqlCommand(
            "select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", admin))
        {
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }
        async Task<PasswordRule> Plan(string kind, string ruleId)
        {
            await using var select = new NpgsqlCommand("select public.password_plan388(@scope::jsonb,@rule)::text", worker);
            select.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            select.Parameters.AddWithValue("rule", ruleId);
            var plan = JsonNode.Parse((string)(await select.ExecuteScalarAsync(ct))!)!;
            return new(scope,kind,plan["live"]!["rule_version"]!.GetValue<int>());
        }
        var brute = await Plan("brute", "qw.password-brute-force");
        var spray = await Plan("spray", "qw.password-spray");
        var producer = new PasswordProducer();
        foreach (var rule in new[] { brute, spray, new PasswordRule(scope) })
        {
            var first = await producer.RunAsync(worker, rule, ct);
            Assert.False(first.Failed, first.Diagnostic?.ToJsonString());
            Assert.NotNull(first.Work?["watermark"]);
        }
        var history = new PasswordRule(scope, "spray");
        var historyStart = await producer.RunAsync(worker, history, ct);
        Assert.False(historyStart.Failed, historyStart.Diagnostic?.ToJsonString());
        var historyWatermark = PasswordJson.Time(historyStart.Work?["watermark"]);

        void ObserveWorker(string status) => app.Files.Native["semantic"] = new JsonObject {
            ["status"] = status, ["heartbeat_at_utc"] = OpsJson.Stamp(DateTimeOffset.UtcNow),
            ["started_at"] = OpsJson.Stamp(DateTimeOffset.UtcNow.AddMinutes(-5))
        };
        ObserveWorker("running");
        Assert.Equal("quiet", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());

        async Task Admit(int record, int minutesAgo)
        {
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: now.AddMinutes(-minutesAgo),
                eventKinds: [4625], registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                sequence: record, firstRecordId: record);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        }

        async Task SetProgressAge(string pin, int minutes)
        {
            await using var command = new NpgsqlCommand("""
                update semantic_password_checkpoints
                set last_completed_at=statement_timestamp()-@age, last_attempt_at=statement_timestamp()-@age
                where pin=@pin
                """, owner);
            command.Parameters.AddWithValue("pin", pin);
            command.Parameters.AddWithValue("age", TimeSpan.FromMinutes(minutes));
            Assert.Equal(1, await command.ExecuteNonQueryAsync(ct));
        }

        await Admit(2, 4);
        Assert.Equal("catching_up", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());
        ObserveWorker("stopped");
        Assert.Equal("stalled", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());
        ObserveWorker("running");

        await SetProgressAge(brute.Pin, 14);
        var slowPass = await Workers(app);
        var oldProgress = ReadRule(slowPass, "brute");
        Assert.Equal("behind", oldProgress["state"]!.GetValue<string>());
        var oldProgressAt = OpsJson.Time(oldProgress["observed_at"]);
        Assert.NotNull(oldProgressAt);
        var semantic = Assert.Single(slowPass["items"]!.AsArray().OfType<JsonObject>(),
            row => row["worker_name"]!.GetValue<string>() == "semantic");
        Assert.Equal("active", semantic["state"]!.GetValue<string>());

        var intermediate = await producer.RunAsync(worker, brute, ct);
        Assert.False(intermediate.Failed, intermediate.Diagnostic?.ToJsonString());
        Assert.True(PasswordJson.Time(intermediate.Work?["watermark"]) > historyWatermark);
        await SetProgressAge(brute.Pin, 6);
        await SetProgressAge(spray.Pin, 6);
        await Admit(3, 3);
        ObserveWorker("running");
        var newProgress = ReadRule(await Workers(app), "brute");
        Assert.Equal("behind", newProgress["state"]!.GetValue<string>());
        Assert.True(OpsJson.Time(newProgress["observed_at"]) > oldProgressAt);

        ObserveWorker("stopped");
        var stalled = await Workers(app);
        Assert.Equal("stalled", ReadRule(stalled, "brute")["state"]!.GetValue<string>());
        ObserveWorker("running");

        await using (var fail = new NpgsqlCommand("""
            select public.observe_password_failure_v2(@s::jsonb,@e::jsonb,
                (public.begin_password_attempt(@s::jsonb,@e::jsonb)->>'token')::bigint,
                '{"source_error":{"count":1,"from":null,"to":null}}'::jsonb)
            """, worker))
        {
            fail.Parameters.AddWithValue("s", scope.Document.ToJsonString());
            fail.Parameters.AddWithValue("e", brute.Execution.ToJsonString());
            Assert.Equal(true, await fail.ExecuteScalarAsync(ct));
        }
        var failed = await Workers(app);
        var failure = ReadRule(failed, "brute");
        Assert.Equal("failed", failure["state"]!.GetValue<string>());
        Assert.Equal("behind", ReadRule(failed, "spray")["state"]!.GetValue<string>());
        Assert.Equal(new[] { "observed_at", "rule_id", "state" }, failure.Select(p => p.Key).Order().ToArray());
        var failedAt = OpsJson.Time(failure["observed_at"]);
        Assert.True(failedAt > OpsJson.Time(newProgress["observed_at"]));

        var completed = await producer.RunAsync(worker, brute, ct);
        Assert.False(completed.Failed, completed.Diagnostic?.ToJsonString());
        var recovered = ReadRule(await Workers(app), "brute");
        Assert.Equal("recovered", recovered["state"]!.GetValue<string>());
        Assert.True(OpsJson.Time(recovered["observed_at"]) > failedAt);

        var liveSpray = await producer.RunAsync(worker, spray, ct);
        Assert.False(liveSpray.Failed, liveSpray.Diagnostic?.ToJsonString());
        Assert.Equal("current", ReadRule(await Workers(app), "spray")["state"]!.GetValue<string>());
        await SetProgressAge(history.Pin, 14);
        await using (var attach = new NpgsqlCommand("""
            update password_pass_state393 set history_pin=@history,history_from=@start,history_to=@end
            where live_pin=@live
            """, owner))
        {
            attach.Parameters.AddWithValue("history", history.Pin);
            attach.Parameters.AddWithValue("start", historyWatermark);
            attach.Parameters.AddWithValue("end", PasswordJson.Time(liveSpray.Work?["watermark"]));
            attach.Parameters.AddWithValue("live", spray.Pin);
            Assert.Equal(1, await attach.ExecuteNonQueryAsync(ct));
        }
        var historical = ReadRule(await Workers(app), "spray");
        Assert.Equal("history_pending", historical["state"]!.GetValue<string>());
        Assert.True(OpsJson.Time(historical["observed_at"]) < OpsJson.Time(recovered["observed_at"]));
        var historyFinished = await producer.RunAsync(worker, history, ct);
        Assert.False(historyFinished.Failed, historyFinished.Diagnostic?.ToJsonString());
        Assert.Equal("current", ReadRule(await Workers(app), "spray")["state"]!.GetValue<string>());

        string predecessorRollback = Path.ChangeExtension(predecessor, ".rollback.sql");
        var invalidRollback = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(predecessorRollback, null, ct));
        Assert.Contains("password_queue_projection399_rollback_preflight", invalidRollback.Message);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(predecessorRollback, null, ct);
        Assert.Equal("unavailable", (await Workers(app))["password_detection"]!["status"]!.GetValue<string>());
        await fixture.Pg.ApplyFileAsync(predecessor, null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.Equal("recovered", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());
        await RegisterMappedControllerWithoutNativeScope(owner, new Connections(fixture), Guid.NewGuid(),
            900002, "dc-sibling.example.test", ct);
        Assert.Equal("recovered", ReadRule(await Workers(app), "brute")["state"]!.GetValue<string>());
    }

    private static async Task RegisterMappedControllerWithoutNativeScope(NpgsqlConnection owner, Connections connections,
        Guid agent, long server, string hostname, CancellationToken ct)
    {
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, agent, agent, server, 1, hostname, "Security", ct);
        await using (var runtime = await connections.OpenAsync(ct))
        await using (var bind = new NpgsqlCommand("select public.reconcile_password_detection_domain371(@agent)", runtime))
        {
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal(1L, await bind.ExecuteScalarAsync(ct));
        }
        await using var verify = new NpgsqlCommand("""
            select public.password_v2_configured_identity(agent_id) is null
            from public.sli_agent_module_bindings
            where agent_id=@agent and module_id='sli.windows.ad-dc' and password_detection_domain_id=1
            """, owner);
        verify.Parameters.AddWithValue("agent", agent);
        Assert.Equal(true, await verify.ExecuteScalarAsync(ct));
    }

    private static async Task<JsonObject> Workers(OperationsEndpointTests.App app)
    {
        using var response = await OperationsEndpointTests.Request(app, "GET", WorkersRoute);
        response.EnsureSuccessStatusCode();
        return (await OperationsEndpointTests.Body(response))["workers"]!.AsObject();
    }

    private static JsonObject ReadRule(JsonObject workers, string kind) =>
        Assert.Single(workers["password_detection"]!["items"]!.AsArray().OfType<JsonObject>(),
            item => item["rule_id"]!.GetValue<string>() == (kind == "brute" ? "qw.password-brute-force" : "qw.password-spray"));

    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
            await db.OpenAsync(ct);
            return db;
        }
    }
}
