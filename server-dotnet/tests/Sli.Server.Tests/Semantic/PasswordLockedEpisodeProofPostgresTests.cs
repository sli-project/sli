using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordLockedEpisodeProofPostgresTests
{
    private const string Combined = "public.read_locked_password_episode402";
    private const string ExistingLock = "public.lock_password_publication_v2";

    [Fact]
    public async Task Locked_proof_matches_order_hashes_authority_barriers_and_round_trip()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        var start = DateTimeOffset.UtcNow.AddMinutes(-35);
        var initial = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: Enumerable.Repeat(4625, 270).ToArray(),
            nativeTimestamps: Enumerable.Range(0, 270).Select(i => PasswordJson.Stamp(start.AddSeconds(i / 2.0))).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, initial, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var source = new NpgsqlCommand("""
            select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
            """, worker);
        var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        await using (var bind = new NpgsqlCommand(
            "select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app))
        {
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }

        var rule = new PasswordRule(scope, "brute");
        var producer = new PasswordProducer();
        async Task Produce()
        {
            var result = await producer.RunAsync(worker, rule, ct);
            Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
            Assert.True(result.Jobs > 0);
        }
        await Produce();
        for (int i = 1; i <= 2; i++)
        {
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(), sequence: i + 1, firstRecordId: 271 + (i - 1) * 12,
                eventKinds: Enumerable.Repeat(4625, 12).ToArray(),
                nativeTimestamps: Enumerable.Range(0, 12).Select(n => PasswordJson.Stamp(start.AddSeconds(i * 840 + n))).ToArray());
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            await Produce();
        }
        await using var episodeKeys = new NpgsqlCommand("""
            select array_agg(episode_key order by first_ledger_revision)
            from public.semantic_password_episode_budgets where pin=@pin
            """, owner);
        episodeKeys.Parameters.AddWithValue("pin", rule.Pin);
        string[] episodes = Assert.IsType<string[]>(await episodeKeys.ExecuteScalarAsync(ct));
        Assert.Equal(3, episodes.Length);

        async Task<JsonObject> Compare(string episode)
        {
            await using var tx = await worker.BeginTransactionAsync(ct);
            await using var oldLock = Command(worker, tx, $"select {ExistingLock}(@s::jsonb,@e::jsonb,@episode)::text", rule, episode);
            var ledger = JsonNode.Parse((string)(await oldLock.ExecuteScalarAsync(ct))!);
            await using var oldRead = Command(worker, tx, """
                select jsonb_agg(jsonb_build_object('signal_id',signal_id,'document_json',document_json)
                    order by ordinality)::text
                from public.read_password_episode_portions_v2(@s::jsonb,@e::jsonb,@episode) with ordinality
                """, rule, episode);
            var portions = JsonNode.Parse((string)(await oldRead.ExecuteScalarAsync(ct))!);
            await using var combined = Command(worker, tx, $"""
                select jsonb_build_object('ledger',ledger,'portions',portions)::text
                from {Combined}(@s::jsonb,@e::jsonb,@episode)
                """, rule, episode);
            var result = Assert.IsType<JsonObject>(JsonNode.Parse((string)(await combined.ExecuteScalarAsync(ct))!));
            Assert.True(JsonNode.DeepEquals(ledger, result["ledger"]));
            Assert.True(JsonNode.DeepEquals(portions, result["portions"]));
            await tx.RollbackAsync(ct);
            return result;
        }

        var first = await Compare(episodes[0]);
        Assert.True(first["portions"]!.AsArray().Count > 1);
        Assert.Null(first["ledger"]!["historical_barrier"]);

        static async Task<long> Publications(NpgsqlConnection db, CancellationToken token)
        {
            await using var count = new NpgsqlCommand("select count(*) from public.semantic_finding_publications", db);
            return (long)(await count.ExecuteScalarAsync(token))!;
        }
        Assert.Equal(0, await Publications(owner, ct));
        var processed = await new PasswordRiskConsumer(runtime, new()).RunOnceAsync(ct);
        Assert.Equal(0, processed.Failed);
        Assert.Equal(3, processed.Published);
        Assert.Equal(3, await Publications(owner, ct));

        await Freeze(owner, rule, episodes[1], ct);
        var historical = await Compare(episodes[0]);
        Assert.Equal(episodes[1], historical["ledger"]!["historical_barrier"]!["barrier_episode_key"]!.GetValue<string>());
        foreach (string read in new[] { ExistingLock, Combined })
        {
            await Refuses(worker, rule, read, episodes[1], "55000", "episode_frozen", ct);
            await Refuses(worker, rule, read, episodes[2], "55000", "password_v2_barrier_unresolved", ct);
            await Refuses(worker, new PasswordRule(scope, "spray"), read, episodes[0],
                "55000", "password_v2_episode_absent", ct);
            await Refuses(worker, new PasswordRule(scope with { SourceInstanceId = "unbound" }), read, episodes[0],
                "42501", "password_v2_source_denied", ct);
        }
        await Refuses(app, rule, Combined, episodes[0], "42501", "permission denied", ct);

        var files = await fixture.RollbackAfterAsync(401, ct);
        var migration = Assert.Single(files);
        await using (var predecessor = new NpgsqlCommand("""
            select max(version)=401 and to_regprocedure('public.read_locked_password_episode402(jsonb,jsonb,text)') is null
            from public.schema_migrations
            """, owner))
            Assert.Equal(true, await predecessor.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.True(JsonNode.DeepEquals(historical, await Compare(episodes[0])));
        Assert.Equal(3, await Publications(owner, ct));
    }

    private static NpgsqlCommand Command(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, PasswordRule rule, string episode)
    {
        var command = new NpgsqlCommand(sql, db, tx);
        command.Parameters.AddWithValue("s", rule.Scope.Document.ToJsonString());
        command.Parameters.AddWithValue("e", rule.Execution.ToJsonString());
        command.Parameters.AddWithValue("episode", episode);
        return command;
    }

    private static async Task Refuses(NpgsqlConnection db, PasswordRule rule, string read, string episode,
        string state, string message, CancellationToken ct)
    {
        await using var command = Command(db, null, $"select * from {read}(@s::jsonb,@e::jsonb,@episode)", rule, episode);
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(ct));
        Assert.Equal(state, error.SqlState);
        Assert.Contains(message, error.MessageText);
    }

    private static async Task Freeze(NpgsqlConnection owner, PasswordRule rule, string key, CancellationToken ct)
    {
        // Owner-only fixture for a complete historical frozen barrier.
        await using var tx = await owner.BeginTransactionAsync(ct);
        await using var bindOwner = new NpgsqlCommand("""
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_key,agent_id)
            select owner_role.oid,owner_role.rolname,b.installation_id,b.plugin_id,b.source_instance_id,
                b.source_generation,b.collection_scope_id,b.storage_kind,b.log_source_id,b.agent_key,b.agent_id
            from public.finding_evidence_source_bindings b cross join pg_roles owner_role
            where owner_role.rolname=session_user and b.principal_name='sli_semantic_login'
                and b.plugin_id='sli.windows.ad-dc' and b.storage_kind='core_event'
                and b.installation_id=@installation and b.source_instance_id=@source and b.source_generation=@generation
            on conflict do nothing
            """, owner, tx);
        bindOwner.Parameters.AddWithValue("source", rule.Scope.SourceInstanceId);
        bindOwner.Parameters.AddWithValue("installation", Guid.Parse(rule.Scope.InstallationId));
        bindOwner.Parameters.AddWithValue("generation", rule.Scope.SourceGeneration);
        Assert.Equal(1, await bindOwner.ExecuteNonQueryAsync(ct));
        await using var freeze = new NpgsqlCommand("""
            update public.semantic_password_episode_budgets
            set frozen=true,frozen_at=clock_timestamp(),frozen_reason='episode_evidence_budget_exhausted',
                barrier_unresolved=true,tracking_endpoint=last_admitted_endpoint,tracking_epoch=coverage_epoch,
                tracking_through=(last_admitted_endpoint->>'at')::timestamptz
            where episode_key=@key returning to_jsonb(semantic_password_episode_budgets)::text
            """, owner, tx);
        freeze.Parameters.AddWithValue("key", key);
        var ledger = JsonNode.Parse((string)(await freeze.ExecuteScalarAsync(ct))!)!.AsObject();
        await using var checkpoint = new NpgsqlCommand("""
            select state_document::text from public.semantic_password_checkpoints where pin=@pin for update
            """, owner, tx);
        checkpoint.Parameters.AddWithValue("pin", rule.Pin);
        var state = PasswordState.Read(JsonNode.Parse((string)(await checkpoint.ExecuteScalarAsync(ct))!));
        var frozen = new PasswordEpisode(key, ledger["entity"]!.GetValue<string>(), PasswordWitness.Read(ledger["seed"]),
            PasswordWitness.Read(ledger["tracking_endpoint"]), ledger["root_id"]!.GetValue<string>(),
            ledger["last_emission_id"]!.GetValue<string>(), ledger["last_sequence"]!.GetValue<int>(),
            new PasswordBudget(ledger["reserved_ref_occurrences"]!.GetValue<int>(),
                ledger["reserved_portions"]!.GetValue<int>(), ledger["reserved_xml_bytes"]!.GetValue<int>()), Frozen: true);
        state = state with { Active = state.Episodes.Where(episode => episode.Entity != frozen.Entity).Append(frozen)
            .OrderBy(episode => episode.Entity, StringComparer.Ordinal).ToArray() };
        await using var stage = new NpgsqlCommand("""
            update public.semantic_password_checkpoints set state_document=@state::jsonb,state_revision=state_revision+1,
                last_observed_token=active_token, health_status='partial', health_reason='episode_evidence_budget_exhausted'
            where pin=@pin
            """, owner, tx);
        stage.Parameters.AddWithValue("pin", rule.Pin);
        stage.Parameters.AddWithValue("state", state.Document.ToJsonString());
        Assert.Equal(1, await stage.ExecuteNonQueryAsync(ct));
        await tx.CommitAsync(ct);
    }
}
