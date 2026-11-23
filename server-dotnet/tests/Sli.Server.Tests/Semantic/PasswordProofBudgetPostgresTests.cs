using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordProofBudgetPostgresTests
{
    [Fact]
    public async Task Both_rules_commit_a_smaller_prefix_when_native_documents_exceed_the_window_budget()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 397);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var seed = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, seed, ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, 1400, 1, noise: true, missingTargets: true);
        // Size the synthetic short documents without changing any classifier fields.
        await PostCollectionPostgres.Sql(owner, """
            update event_hot set fields=fields||jsonb_build_object('FixturePadding',repeat('x',30000))
            """, ct);

        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);
        var rules = new[] { new PasswordRule(scope), new PasswordRule(scope, "spray") };
        foreach (var rule in rules) {
            var rejected = await new PasswordProducer().RunAsync(worker, rule, ct);
            Assert.True(rejected.Failed);
            Assert.True(rejected.FailureObserved);
            Assert.Equal("password_v2_window_incomplete", rejected.Diagnostic!["reason"]!.GetValue<string>());
        }
        await using (var unchanged = new NpgsqlCommand(
            "select bool_and(watermark is null and state_revision=0) from semantic_password_checkpoints", owner))
            Assert.Equal(true, await unchanged.ExecuteScalarAsync(ct));

        async Task<string> Definitions()
        {
            await using var command = new NpgsqlCommand("""
                select jsonb_object_agg(oid::regprocedure::text,jsonb_build_array(pg_get_functiondef(oid),proowner,proacl))::text
                from pg_proc where oid=any(array[
                    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
                    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure,
                    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure])
                """, owner);
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }
        string baseline = await Definitions();
        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/398_password_proof_budget_progress.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        Assert.Equal(baseline, await Definitions());
        await fixture.Pg.ApplyFileAsync(migration, null, ct);

        foreach (var rule in rules) {
            var first = await new PasswordProducer().RunAsync(worker, rule, ct);
            Assert.False(first.Failed, first.Diagnostic?.ToJsonString());
            Assert.Equal("committed", first.Status);
            var proofBudget = Assert.IsType<JsonObject>(first.Work?["proof_budget"]);
            Assert.Equal("Reader", proofBudget["phase"]!.GetValue<string>());
            Assert.Equal("xml_bytes", proofBudget["limit"]!.GetValue<string>());
            Assert.True(proofBudget["xml_bytes"]!.GetValue<long>() > 33554432);
            var before = PasswordJson.Time(first.Work!["watermark"]);
            Assert.InRange(before, start, start.AddSeconds(1398));
            Assert.Equal(0, first.Jobs);

            await using var restarted = await runtime.OpenAsync(ct);
            var second = await new PasswordProducer().RunAsync(restarted, rule, ct);
            Assert.False(second.Failed, second.Diagnostic?.ToJsonString());
            Assert.True(PasswordJson.Time(second.Work!["watermark"]) > before);
            Assert.Equal(0, second.Jobs);
        }
    }
    [Fact]
    public async Task Both_rules_shrink_the_union_of_new_rows_overlap_and_retained_chain()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var firstRows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: Enumerable.Repeat(4625, 900).ToArray(),
            nativeTimestamps: Enumerable.Range(0, 900).Select(i => PasswordJson.Stamp(start.AddSeconds(i))).ToArray(),
            nativeAccounts: Enumerable.Range(0, 900).Select(i => i < 700 ? "synthetic-base" : $"synthetic-{i}").ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, firstRows, ct);
        await PostCollectionPostgres.Sql(owner, """
            update event_hot set fields=fields||jsonb_build_object('FixturePadding',repeat('x',30000))
            """, ct);

        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);
        var rules = new[] { new PasswordRule(scope), new PasswordRule(scope, "spray") };
        foreach (var rule in rules) {
            var root = await new PasswordProducer().RunAsync(worker, rule, ct);
            Assert.False(root.Failed, root.Diagnostic?.ToJsonString());
            Assert.True(root.Jobs > 0);
            Assert.Equal(start.AddSeconds(899), PasswordJson.Time(root.Work!["watermark"]));
        }

        var oldSignals = await SignalIds(owner, ct);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        int nextRecordId = 901;
        foreach (int[] packet in Enumerable.Range(0, 650).Chunk(100)) {
            var suffix = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: Enumerable.Repeat(4625, packet.Length).ToArray(),
                nativeTimestamps: packet.Select(i => PasswordJson.Stamp(start.AddSeconds(1000 + 1.5 * i))).ToArray(),
                nativeAccounts: Enumerable.Repeat("synthetic-base", packet.Length).ToArray(),
                registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(), sequence: 2 + packet[0] / 100,
                firstRecordId: nextRecordId);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, suffix, ct);
            nextRecordId += packet.Length;
        }
        await PostCollectionPostgres.Sql(owner, """
            update event_hot set fields=fields||jsonb_build_object('FixturePadding',repeat('y',30000))
            where event_record_id>=901
            """, ct);

        foreach (var rule in rules) {
            // A fresh worker connection has to rebuild the proof from durable state.
            await using var restarted = await runtime.OpenAsync(ct);
            var result = await new PasswordProducer().RunAsync(restarted, rule, ct);
            Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
            var budget = Assert.IsType<JsonObject>(result.Work?["proof_budget"]);
            Assert.Equal("RetainedChain", budget["phase"]!.GetValue<string>());
            Assert.Equal("xml_bytes", budget["limit"]!.GetValue<string>());
            Assert.True(budget["xml_bytes"]!.GetValue<long>() > 33554432);
            Assert.InRange(PasswordJson.Time(result.Work!["watermark"]), start.AddSeconds(1000), start.AddSeconds(1973));
        }
        var committedSignals = await SignalIds(owner, ct);
        Assert.True(oldSignals.IsSubsetOf(committedSignals));
        Assert.True(committedSignals.Count > oldSignals.Count);
        await using var jobs = new NpgsqlCommand("""
            select count(*)=count(distinct idempotency_key) from semantic_risk_evaluation_jobs
            """, owner);
        Assert.Equal(true, await jobs.ExecuteScalarAsync(ct));
    }

    private static async Task<HashSet<string>> SignalIds(NpgsqlConnection owner, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select signal_id from semantic_qw_signals", owner);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var ids = new HashSet<string>();
        while (await rows.ReadAsync(ct)) Assert.True(ids.Add(rows.GetString(0)));
        return ids;
    }

    private static async Task<PasswordScope> ConfigureScope(SqlPostgresFixture fixture, NpgsqlConnection worker, CancellationToken ct)
    {
        await using var source = new NpgsqlCommand(
            "select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
        var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand(
                "select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
            bind.Parameters.AddWithValue("agent", ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }

        return scope;
    }
}
