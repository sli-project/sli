using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordProofBudgetPostgresTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(429, 20000, 300)]
    [InlineData(3, 30, 30000)]
    public async Task Brute_advances_with_durable_prefixes_and_retains_the_exact_origin(int origins, int limit, int spacingMs)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 409);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var seed = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start,
            eventKinds: [4625], nativeTargetSids: ["S-1-0-0"]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, seed, ct);
        await InstallTestClock(owner, ct);
        await SetTestClock(owner, start.AddMinutes(2), ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);
        var rule = new PasswordRule(scope);
        await using (var plan = new NpgsqlCommand(
            "select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::integer", worker)) {
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            plan.Parameters.AddWithValue("rule", rule.Id);
            rule = new PasswordRule(scope, revision: (int)(await plan.ExecuteScalarAsync(ct))!);
        }

        var before = start.AddMilliseconds((limit - 1) * spacingMs);
        var next = before.AddMilliseconds(spacingMs);
        // Admit the boundary row up front. The durable cutoff, not arrival,
        // decides when the next witness joins an origin.
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, limit + 1, spacing: spacingMs / 1000.0, noise: true,
            clients: 1, accountCount: origins, continuityRows: limit + 1);
        var qualificationTime = next.AddSeconds(130);
        var qualification = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: Enumerable.Repeat(4625, 10).ToArray(),
            nativeTimestamps: Enumerable.Range(0, 10).Select(i => PasswordJson.Stamp(qualificationTime.AddSeconds(i))).ToArray(),
            nativeAccounts: Enumerable.Repeat("noise1", 10).ToArray(),
            nativeTargetSids: Enumerable.Repeat("S-1-0-0", 10).ToArray(),
            registered: (ShortEventAdmissionPostgresTests.Agent, ShortEventAdmissionPostgresTests.Agent, 900001, 1),
            packetId: Guid.NewGuid(), sequence: 203, firstRecordId: limit + 2);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, qualification, ct);

        async Task<PasswordProducerOutcome> Run()
        {
            await using var restarted = await runtime.OpenAsync(ct);
            return await new PasswordProducer().RunAsync(restarted, rule, ct);
        }
        await SetTestClock(owner, before.AddMinutes(2), ct);
        DateTimeOffset? watermark = null;
        for (int i = 0; i < 10 && watermark != before; i++) {
            var batch = await Run();
            Assert.False(batch.Failed, batch.Diagnostic?.ToJsonString());
            watermark = PasswordJson.Time(batch.Work!["watermark"]);
        }
        Assert.Equal(before, watermark);

        string oldKey;
        PasswordWitness[] oldOrigin;
        await using (var saved = new NpgsqlCommand("""
            with checkpoint as (
                select c.* from public.semantic_password_checkpoints c where c.pin=@pin
            ), episodes as (
                select e.value from checkpoint c
                cross join lateral public.password_state_episodes385(c.state_document) e(value)
            )
            select (select count(*) from episodes where value->>'sequence'='0'),
                (select sum(jsonb_array_length(value->'prequalification')) from episodes),
                octet_length(c.state_document::text), e.value->>'key', (e.value->'prequalification')::text
            from checkpoint c cross join episodes e
            where public.password_v2_time(e.value#>'{seed,at}')=@initial
            """, owner) { CommandTimeout = 0 }) {
            saved.Parameters.AddWithValue("pin", rule.Pin);
            saved.Parameters.AddWithValue("initial", start.AddMilliseconds(spacingMs));
            await using var rows = await saved.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal((long)origins, rows.GetInt64(0));
            Assert.Equal((long)limit, rows.GetInt64(1));
            output.WriteLine($"At 409 cutoff {before:O}: {origins} origins, {limit} references, {rows.GetInt32(2)} JSONB bytes.");
            oldKey = rows.GetString(3);
            oldOrigin = JsonNode.Parse(rows.GetString(4))!.AsArray().Select(PasswordWitness.Read).ToArray();
            Assert.False(await rows.ReadAsync(ct));
        }
        Assert.True(oldOrigin[0].At < before.AddSeconds(-600));
        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/410_password_origin_prefix.sql");
        string rollback = Path.ChangeExtension(migration, ".rollback.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using (var acl = new NpgsqlCommand("""
            select c.relowner='adlog_storage_owner'::regrole
                and not has_table_privilege('adlog_semantic_worker',c.oid,'SELECT,INSERT,UPDATE,DELETE')
                and not has_table_privilege('adlog_user',c.oid,'SELECT,INSERT,UPDATE,DELETE')
                and has_function_privilege('adlog_semantic_worker','public.read_password_checkpoint410(jsonb,jsonb)','EXECUTE')
                and not has_function_privilege('adlog_user','public.read_password_checkpoint410(jsonb,jsonb)','EXECUTE')
            from pg_class c where c.oid='public.password_origin_prefix410'::regclass
            """, owner))
            Assert.Equal(true, await acl.ExecuteScalarAsync(ct));

        await SetTestClock(owner, next.AddMinutes(2), ct);
        var advanced = await Run();
        var diagnostic = advanced.Diagnostic?.ToJsonString();
        output.WriteLine($"Witness {limit + 1} at {next:O}: {diagnostic ?? advanced.Work?.ToJsonString()}");
        Assert.False(advanced.Failed, diagnostic);
        Assert.Equal(next, PasswordJson.Time(advanced.Work!["watermark"]));

        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new PasswordSql(worker, tx);
            var denied = await Assert.ThrowsAsync<PostgresException>(
                () => sql.Call("read_password_checkpoint_v2", ct, scope.Document, rule.Execution));
            Assert.Equal("password_v2_origin_prefix_reader_required", denied.MessageText);
            await tx.RollbackAsync(ct);
        }
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new PasswordSql(worker, tx);
            var attempt = PasswordJson.Obj(await sql.Call("begin_password_attempt", ct, scope.Document, rule.Execution));
            var denied = await Assert.ThrowsAsync<PostgresException>(() => sql.Call(
                "complete_password_producer_batch_v2", ct, scope.Document, rule.Execution,
                attempt["token"]!.GetValue<long>(), attempt["state_revision"]!.GetValue<long>(), "advance",
                new JsonObject { ["version"] = "sli.password.v2.producer-batch.1" }));
            Assert.Equal("password_v2_origin_prefix_reader_required", denied.MessageText);
            await tx.RollbackAsync(ct);
        }
        var unsafeRollback = await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Pg.ApplyFileAsync(rollback, null, ct));
        Assert.Contains("password_origin_prefix410_rollback_pending_state", unsafeRollback.Message);

        var qualifiedThrough = qualificationTime.AddSeconds(9);
        await SetTestClock(owner, qualifiedThrough.AddMinutes(2), ct);
        var qualified = await Run();
        Assert.False(qualified.Failed, qualified.Diagnostic?.ToJsonString());
        Assert.Equal(qualifiedThrough, PasswordJson.Time(qualified.Work!["watermark"]));
        await using var root = new NpgsqlCommand("""
            select (document_json->'password_context')::text from public.semantic_qw_signals
            where document_json->>'episode_key'=@key and document_json#>>'{password_context,sequence}'='1'
            order by (document_json#>>'{password_context,portion_index}')::int
            """, owner);
        root.Parameters.AddWithValue("key", oldKey);
        var portions = new List<JsonObject>();
        await using (var rows = await root.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) portions.Add(JsonNode.Parse(rows.GetString(0))!.AsObject());
        var admission = PasswordEmission.Reassemble(scope, portions);
        Assert.Equal(oldKey, admission.EpisodeKey);
        Assert.Equal(oldOrigin[0], admission.Seed);
        Assert.Equal(oldOrigin, admission.Origin.Take(oldOrigin.Length).ToArray());

        // Removing the native row for an unrelated, non-inline archived
        // witness must block the next advance and its new finding jobs.
        await using (var missing = new NpgsqlCommand("""
            delete from public.event_hot h where h.event_id=(
                select (p.witnesses->1#>>'{ref,native_id}')::bigint from public.password_origin_prefix410 p
                where p.pin=@pin and p.episode_key<>@key and jsonb_array_length(p.witnesses)>2
                order by p.witnesses->1->>'at' limit 1
            )
            """, owner)) {
            missing.Parameters.AddWithValue("pin", rule.Pin);
            missing.Parameters.AddWithValue("key", oldKey);
            Assert.Equal(1, await missing.ExecuteNonQueryAsync(ct));
        }
        DateTimeOffset after=qualifiedThrough.AddSeconds(1);
        await AdmitEvents(fixture, owner, [(4625, after, 800, 201)], sequence: 204, recordId: limit + 12, ct);
        await SetTestClock(owner, after.AddMinutes(2), ct);
        var unavailable = await Run();
        Assert.True(unavailable.Failed, unavailable.Work?.ToJsonString());
        Assert.Equal("complete_password_producer_batch_v2", unavailable.Diagnostic?["step"]?.GetValue<string>());
        Assert.Equal("password_v2_retained_unavailable", unavailable.Diagnostic?["reason"]?.GetValue<string>());
        await using var savedWatermark = new NpgsqlCommand("""
            select watermark from public.semantic_password_checkpoints where pin=@pin
            """, owner);
        savedWatermark.Parameters.AddWithValue("pin", rule.Pin);
        Assert.Equal(qualifiedThrough.UtcDateTime, await savedWatermark.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Brute_advances_past_ten_thousand_continuity_witnesses_from_many_unqualified_origins()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 408);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var seed = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start,
            eventKinds: [4625], nativeTargetSids: ["S-1-0-0"]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, seed, ct);
        await InstallTestClock(owner, ct);
        await SetTestClock(owner, start.AddMinutes(2), ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);
        var rule = new PasswordRule(scope);
        await using (var plan = new NpgsqlCommand(
            "select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::integer", worker)) {
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            plan.Parameters.AddWithValue("rule", rule.Id);
            rule = new PasswordRule(scope, revision: (int)(await plan.ExecuteScalarAsync(ct))!);
        }

        const int count = 10000;
        // Each origin receives failures about 129 seconds apart: close enough to
        // retain the chain, too sparse to qualify for brute force in ten minutes.
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, count, spacing: 0.3, noise: true,
            clients: 1, accountCount: 429, continuityRows: count);
        var before = start.AddMilliseconds((count - 1) * 300);
        await SetTestClock(owner, before.AddMinutes(2), ct);
        async Task<PasswordProducerOutcome> Run()
        {
            await using var restarted = await runtime.OpenAsync(ct);
            return await new PasswordProducer().RunAsync(restarted, rule, ct);
        }
        DateTimeOffset? watermark = null;
        for (int i = 0; i < 6 && watermark != before; i++) {
            var result = await Run();
            Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
            watermark = PasswordJson.Time(result.Work!["watermark"]);
        }
        Assert.Equal(before, watermark);

        async Task<string> Composition()
        {
            await using var query = new NpgsqlCommand("""
                select concat_ws(':', count(*),count(*) filter (where e.value->>'sequence'='0'),
                    sum(jsonb_array_length(e.value->'prequalification')))
                from public.semantic_password_checkpoints c
                cross join lateral public.password_state_episodes385(c.state_document) e(value)
                where c.pin=@pin
                """, owner);
            query.Parameters.AddWithValue("pin", rule.Pin);
            return (string)(await query.ExecuteScalarAsync(ct))!;
        }
        Assert.Equal("429:429:10000", await Composition());
        var next = before.AddSeconds(1);
        await AdmitEvents(fixture, owner, [(4625, next, 800, 201)], sequence: 102, recordId: count + 1, ct);
        await SetTestClock(owner, next.AddMinutes(2), ct);
        var timer = Stopwatch.StartNew();
        var blocked = await Run();
        output.WriteLine($"Predecessor at the continuity limit: {timer.Elapsed.TotalSeconds:F3}s");
        Assert.True(blocked.Failed, blocked.Work?.ToJsonString());
        Assert.Equal("Checkpoint", blocked.Diagnostic?["proof_budget"]?["phase"]?.GetValue<string>());
        Assert.Equal(10001L, blocked.Diagnostic?["proof_budget"]?["references"]?.GetValue<long>());
        Assert.Equal("429:429:10000", await Composition());

        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/409_password_checkpoint_continuity.sql");
        string rollback = Path.ChangeExtension(migration, ".rollback.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using (var acl = new NpgsqlCommand("""
            select p.proowner='adlog_storage_owner'::regrole
                and not has_function_privilege('adlog_semantic_worker',p.oid,'EXECUTE')
                and not has_function_privilege('adlog_user',p.oid,'EXECUTE')
            from pg_proc p where p.oid='public.password_continuity_native_cost409(jsonb,jsonb)'::regprocedure
            """, owner))
            Assert.Equal(true, await acl.ExecuteScalarAsync(ct));

        timer.Restart();
        var advanced = await Run();
        Assert.False(advanced.Failed, advanced.Diagnostic?.ToJsonString());
        Assert.Equal(next, PasswordJson.Time(advanced.Work!["watermark"]));
        Assert.Equal(10000, advanced.Work["checkpoint_max_unit_refs"]!.GetValue<int>());
        Assert.Equal("430:430:10001", await Composition());
        output.WriteLine($"Advanced one second at capacity in {timer.Elapsed.TotalSeconds:F3}s");

        // The maximum canonical ID is in the second sorted continuity unit.
        // Remove rolling overlap from this private verifier probe so the native
        // checksum check, rather than the global conflict check, rejects it.
        await PostCollectionPostgres.Sql(owner, """
            insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select r.oid,r.rolname,b.installation_id,b.plugin_id,b.source_instance_id,b.source_generation,
                b.collection_scope_id,b.storage_kind,b.log_source_id,b.agent_id
            from public.finding_evidence_source_bindings b cross join pg_roles r
            where b.principal_name='sli_semantic_login' and b.storage_kind='core_event' and r.rolname=session_user
            """, ct);
        await using (var bad = new NpgsqlCommand("""
            with latest as (
                select c.*,array['episodes',(e.ordinal-1)::text,'witnesses',(w.ordinal-1)::text,'xml_sha256'] as path
                from public.semantic_password_checkpoints c
                cross join lateral jsonb_array_elements(c.state_document->'episodes') with ordinality e(value,ordinal)
                cross join lateral jsonb_array_elements(e.value->'witnesses') with ordinality w(value,ordinal)
                where c.pin=@pin
                order by (w.value#>>'{ref,native_id}') collate "C" desc limit 1
            )
            select public.password_checkpoint_native_cost403(scope_json,
                jsonb_set(jsonb_set(state_document,path,to_jsonb(repeat('0',64))),'{window}','[]'),
                scope_digest,pin,'{}') from latest
            """, owner) { CommandTimeout = 0 }) {
            bad.Parameters.AddWithValue("pin", rule.Pin);
            var denied = await Assert.ThrowsAsync<PostgresException>(() => bad.ExecuteScalarAsync(ct));
            Assert.Equal("42501", denied.SqlState);
            Assert.Equal("password_v2_retained_unavailable", denied.MessageText);
        }
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Pg.ApplyFileAsync(rollback, null, ct));
        Assert.Contains("password_checkpoint_continuity409_rollback_pending_state", refused.Message);
        Assert.Equal("430:430:10001", await Composition());
    }

    [Fact]
    public async Task Both_live_pins_resume_a_checkpoint_near_the_proof_limit_after_upgrade()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 402);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var seed = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, seed, ct);
        await InstallTestClock(owner, ct);

        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);
        await SetTestClock(owner, start.AddMinutes(2), ct);

        var rules = new List<PasswordRule>();
        foreach (string kind in new[] { "brute", "spray" }) {
            var rule = new PasswordRule(scope, kind);
            await using var plan = new NpgsqlCommand(
                "select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::integer", worker);
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            plan.Parameters.AddWithValue("rule", rule.Id);
            rules.Add(new PasswordRule(scope, kind, (int)(await plan.ExecuteScalarAsync(ct))!));
        }

        const int initialEvents = 9998;
        const int continuityRows = 8300;
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, initialEvents, spacing: 0.55, noise: true,
            clients: 128, accountCount: 128, continuityRows: continuityRows);
        var before = start.AddTicks(continuityRows * 5_500_000L + (initialEvents - 1 - continuityRows) * 13_750L);
        int sequence = 102, recordId = initialEvents + 1;
        async Task Admit(IEnumerable<(int Kind, DateTimeOffset At, int Account, int Client)> events)
        {
            (sequence, recordId) = await AdmitEvents(fixture, owner, events, sequence, recordId, ct);
        }
        // Keep a previously published finding per rule, without putting its
        // expired witnesses in the near-limit checkpoint.
        await Admit(Enumerable.Range(0, 10).Select(i => (4625, start.AddSeconds(1 + i), 1, 211))
            .Concat(Enumerable.Range(0, 5).Select(i => (4625, start.AddSeconds(1 + i), 10 + i, 212))));
        await SetTestClock(owner, before.AddMinutes(2), ct);
        async Task<PasswordProducerOutcome> Run(PasswordRule rule)
        {
            await using var restarted = await runtime.OpenAsync(ct);
            return await new PasswordProducer().RunAsync(restarted, rule, ct);
        }

        foreach (var rule in rules) {
            DateTimeOffset? last = null;
            for (int i = 0; i < 6 && last != before; i++) {
                var batch = await Run(rule);
                Assert.False(batch.Failed, batch.Diagnostic?.ToJsonString());
                last = PasswordJson.Time(batch.Work!["watermark"]);
            }
            Assert.Equal(before, last);
        }

        await using (var saved = new NpgsqlCommand("""
            select c.pin,count(*) from public.password_pass_state393 p
            join public.semantic_password_checkpoints c on c.scope_digest=p.scope_digest and c.pin=p.live_pin
            cross join lateral (
                select w.value->'witness' as witness from jsonb_array_elements(c.state_document->'window') w(value)
                union select e.value->'seed' from public.password_state_episodes385(c.state_document) e(value)
                union select e.value->'last' from public.password_state_episodes385(c.state_document) e(value)
                union select w.value from public.password_state_episodes385(c.state_document) e(value)
                    cross join lateral jsonb_array_elements(e.value->'prequalification') w(value)
            ) refs group by c.pin
            """, owner))
        await using (var rows = await saved.ExecuteReaderAsync(ct)) {
            foreach (var rule in rules) {
                Assert.True(await rows.ReadAsync(ct));
                Assert.Contains(rows.GetString(0), rules.Select(r => r.Pin));
                Assert.InRange(rows.GetInt64(1), 9997, 10000);
            }
            Assert.False(await rows.ReadAsync(ct));
        }

        var consumer = new PasswordRiskConsumer(runtime, new());
        async Task<HashSet<long>> Findings()
        {
            await using var command = new NpgsqlCommand("select finding_id from semantic_finding_publications", owner);
            await using var rows = await command.ExecuteReaderAsync(ct);
            var ids = new HashSet<long>();
            while (await rows.ReadAsync(ct)) ids.Add(rows.GetInt64(0));
            return ids;
        }
        async Task<string> FinalizerContract()
        {
            await using var command = new NpgsqlCommand("""
                select jsonb_build_array(pg_get_functiondef(oid), proowner, proacl)::text from pg_proc
                where oid='public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure
                """, owner);
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }
        await Publish(consumer, ct);
        var priorFindings = await Findings();
        Assert.Equal(2, priorFindings.Count);

        var next = before.AddSeconds(1);
        await Admit(Enumerable.Range(0, 4).Select(_ => (4625, next, 200, 201)));
        await SetTestClock(owner, next.AddMinutes(2), ct);
        foreach (var rule in rules) {
            var result = await Run(rule);
            Assert.True(result.Failed);
            Assert.True(result.FailureObserved);
            Assert.Equal("Checkpoint", result.Diagnostic?["proof_budget"]?["phase"]?.GetValue<string>());
            Assert.True(result.Diagnostic?["proof_budget"]?["references"]?.GetValue<long>() > 10000);
        }

        string path = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/403_password_checkpoint_proof.sql");
        string finalizer = await FinalizerContract();
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await using (var grants = new NpgsqlCommand("""
            select p.proowner='adlog_storage_owner'::regrole and p.proacl=d.acl and
                not has_function_privilege('adlog_semantic_worker',
                    'public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[])','execute')
            from public.password_restore403 d join pg_proc p on p.oid=d.signature
            """, owner))
            Assert.Equal(true, await grants.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct);
        Assert.Equal(finalizer, await FinalizerContract());
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        foreach (var rule in rules) {
            var recovered = await Run(rule);
            Assert.False(recovered.Failed, recovered.Diagnostic?.ToJsonString());
            Assert.Equal(next, PasswordJson.Time(recovered.Work!["watermark"]));
            Assert.InRange(recovered.Work["checkpoint_proof_refs"]!.GetValue<int>(), 10001, 10008);
            Assert.InRange(recovered.Work["checkpoint_max_unit_refs"]!.GetValue<int>(), 1, 10000);
        }

        var incompatible = await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct));
        Assert.Contains("password_checkpoint_proof403_rollback_pending_state", incompatible.Message);
        var loadStart = next.AddSeconds(1);
        for (int batch = 0; batch < 2; batch++) {
            var throughput = LoadBatch(loadStart, batch);
            await Admit(throughput);
            var through = throughput[^1].At;
            await SetTestClock(owner, through.AddMinutes(2), ct);
            foreach (var rule in rules) {
                DateTimeOffset? watermark = null;
                for (int i = 0; i < 4 && watermark != through; i++) {
                    var result = await Run(rule);
                    Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
                    watermark = PasswordJson.Time(result.Work!["watermark"]);
                    Assert.InRange(result.Work["checkpoint_max_unit_refs"]!.GetValue<int>(), 0, 10000);
                    Assert.InRange(result.Work["window_items"]!.GetValue<int>(), 0, 10000);
                }
                Assert.Equal(through, watermark);
            }
            await Publish(consumer, ct);
        }

        await AssertReceived(owner, loadStart, ct);
        var after = await Findings();
        Assert.True(priorFindings.IsSubsetOf(after));
        Assert.True(after.Count > priorFindings.Count);
        await AssertPublished(owner, loadStart, ct);
        await using var remaining = new NpgsqlCommand("""
            select count(*)=count(distinct idempotency_key) and count(*) filter (where evaluation_status='queued')=0
            from semantic_risk_evaluation_jobs where source_kind='qw_signal'
            """, owner);
        Assert.Equal(true, await remaining.ExecuteScalarAsync(ct));
        var signalCount = (await SignalIds(owner, ct)).Count;
        foreach (var rule in rules) {
            var repeated = await Run(rule);
            Assert.False(repeated.Failed, repeated.Diagnostic?.ToJsonString());
            Assert.Equal(0, repeated.Jobs);
        }
        Assert.Equal(signalCount, (await SignalIds(owner, ct)).Count);
        Assert.True(after.SetEquals(await Findings()));
    }
    [Fact]
    public async Task Failed_live_pins_resume_near_now_while_both_historical_intervals_remain_recoverable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 403);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds());
        var start = now.AddHours(-4);
        var events = new[] { start, start.AddMinutes(20), start.AddHours(1), now.AddSeconds(-121) };
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4625,4625,4625,4625],
            nativeTimestamps: events.Select(PasswordJson.Stamp).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        await InstallTestClock(owner, ct);

        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await ConfigureScope(fixture, worker, ct);

        async Task<(PasswordRule Live, PasswordRule History)> Plan(string kind)
        {
            await using var restarted = await runtime.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select public.password_plan388(@scope::jsonb,@rule)::text", restarted);
            command.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            command.Parameters.AddWithValue("rule", new PasswordRule(scope, kind).Id);
            var plan = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!;
            return (new(scope, kind, plan["live"]!["rule_version"]!.GetValue<int>()),
                new(scope, kind, plan["catchup"]![0]!["rule_version"]!.GetValue<int>()));
        }
        async Task<PasswordProducerOutcome> Run(PasswordRule rule)
        {
            await using var restarted = await runtime.OpenAsync(ct);
            var outcome = await new PasswordProducer().RunAsync(restarted, rule, ct);
            Assert.False(outcome.Failed, outcome.Diagnostic?.ToJsonString());
            return outcome;
        }
        async Task<(long Revision, DateTimeOffset? Watermark)> Checkpoint(PasswordRule rule)
        {
            await using var command = new NpgsqlCommand(
                "select state_revision,watermark from semantic_password_checkpoints where pin=@pin", owner);
            command.Parameters.AddWithValue("pin", rule.Pin);
            await using var cursor = await command.ExecuteReaderAsync(ct);
            Assert.True(await cursor.ReadAsync(ct));
            return (cursor.GetInt64(0), cursor.IsDBNull(1) ? null : cursor.GetFieldValue<DateTimeOffset>(1));
        }

        async Task<string> PolicyStatus(PasswordRule rule)
        {
            await using var command = new NpgsqlCommand("""
                select lifecycle_status from semantic_risk_policies where policy_id=@policy and policy_version=1
                """, owner);
            command.Parameters.AddWithValue("policy", PasswordSignal.PolicyId(rule));
            return (string)(await command.ExecuteScalarAsync(ct))!;
        }

        await SetTestClock(owner, start.AddMinutes(15), ct);
        var original = new[] { await Plan("brute"), await Plan("spray") };
        await SetTestClock(owner, start.AddMinutes(22), ct);
        var originalCheckpoints = new Dictionary<string, (long Revision, DateTimeOffset? Watermark)>();
        var originalPolicies = new Dictionary<string, string>();
        foreach (var (live, history) in original) {
            await Run(live);
            originalCheckpoints.Add(live.Pin, await Checkpoint(live));
            originalPolicies.Add(live.Pin, await PolicyStatus(live));
            originalCheckpoints.Add(history.Pin, await Checkpoint(history));
            // Record the observed worker failure through the public worker API.
            await using var fail = new NpgsqlCommand("""
                with attempt as materialized (select public.begin_password_attempt(@scope::jsonb,@execution::jsonb) as a)
                select public.observe_password_failure_v2(@scope::jsonb,@execution::jsonb,(a->>'token')::bigint,
                    '{"source_error":{"count":1,"from":null,"to":null}}'::jsonb) from attempt
                """, worker);
            fail.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            fail.Parameters.AddWithValue("execution", live.Execution.ToJsonString());
            Assert.Equal(true, await fail.ExecuteScalarAsync(ct));
        }
        await SetTestClock(owner, now, ct);
        foreach (var (live, history) in original) {
            var oldPlan = await Plan(live.Kind);
            Assert.Equal(live.Pin, oldPlan.Live.Pin);
            Assert.Equal(history.Pin, oldPlan.History.Pin);
        }

        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/404_password_live_recovery.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        string rollback = Path.ChangeExtension(migration, ".rollback.sql");
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        var resumed = new Dictionary<string, PasswordRule>();
        foreach (var (live, history) in original) {
            var planned = await Plan(live.Kind);
            Assert.NotEqual(live.Pin, planned.Live.Pin);
            resumed.Add(live.Kind, planned.Live);
            Assert.Equal(history.Pin, planned.History.Pin);
            Assert.Equal(originalCheckpoints[live.Pin], await Checkpoint(live));
            Assert.Equal(originalCheckpoints[history.Pin], await Checkpoint(history));
            Assert.Equal(planned.Live.Pin, (await Plan(live.Kind)).Live.Pin);
            Assert.Equal(originalPolicies[live.Pin], await PolicyStatus(live));

            await using (var status = new NpgsqlCommand("select public.password_catchup_status388()::text", worker)) {
                var pending = JsonNode.Parse((string)(await status.ExecuteScalarAsync(ct))!)!;
                Assert.Equal(start, PasswordJson.Time(pending["from"]));
                Assert.Equal(now.AddSeconds(-600), PasswordJson.Time(pending["to"]));
            }
            Assert.Null((await Run(live)).Work);
            Assert.Equal(originalCheckpoints[live.Pin], await Checkpoint(live));

            await Run(planned.Live);
            await Run(planned.Live);
            Assert.Equal(now.AddSeconds(-120), (await Checkpoint(planned.Live)).Watermark);
            Assert.Equal(originalCheckpoints[history.Pin], await Checkpoint(history));
            Assert.Equal(originalCheckpoints[live.Pin], await Checkpoint(live));

        }

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Pg.ApplyFileAsync(rollback, null, ct));
        Assert.Contains("password_live_recovery404_pending_history", refused.Message);

        var loadStart = now.AddSeconds(1);
        int sequence = 2, recordId = 5;
        var consumer = new PasswordRiskConsumer(runtime, new());
        for (int batch = 0; batch < 2; batch++) {
            var eventsUnderLoad = LoadBatch(loadStart, batch);
            (sequence, recordId) = await AdmitEvents(fixture, owner, eventsUnderLoad, sequence, recordId, ct);
            var through = eventsUnderLoad[^1].At;
            var pollAt = through.AddMinutes(2);
            await SetTestClock(owner, pollAt, ct);
            var poller = new PasswordProducerPoller(runtime, new(), new(new(), new())) { Clock = new FixtureClock(pollAt) };
            var results = await poller.RunSourceAsync(scope, ct);
            Assert.NotEmpty(results);
            Assert.All(results, result => {
                Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
                Assert.Equal("committed", result.Status);
                if (result.Work?["window_items"] is {} items) Assert.InRange(items.GetValue<int>(), 0, 10000);
            });
            foreach (var (live, _) in original) {
                Assert.Equal(through, (await Checkpoint(resumed[live.Kind])).Watermark);
                Assert.Equal(originalCheckpoints[live.Pin], await Checkpoint(live));
            }
            await Publish(consumer, ct);
        }
        await AssertReceived(owner, loadStart, ct);
        await AssertPublished(owner, loadStart, ct);

        foreach (var (live, history) in original) {
            Assert.Equal(start.AddMinutes(5), (await Checkpoint(history)).Watermark);
            await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
                await app.OpenAsync(ct);
                await using var status = new NpgsqlCommand("""
                    select state from public.read_password_live_status400(array[1::bigint]) where rule_id=@rule
                    """, app);
                status.Parameters.AddWithValue("rule", live.Id);
                Assert.Equal("history_pending", await status.ExecuteScalarAsync(ct));
            }
            var next = await Plan(live.Kind);
            Assert.Equal(resumed[live.Kind].Pin, next.Live.Pin);
            Assert.Equal(live.Pin, next.History.Pin);
            Assert.Equal(originalCheckpoints[live.Pin], await Checkpoint(live));
            await Run(live);
            Assert.InRange((await Checkpoint(live)).Watermark!.Value, events[2], now.AddMinutes(-10));
        }
        await fixture.Pg.ApplyFileAsync(rollback, null, ct);
        foreach (var (live, _) in original)
            Assert.Equal(live.Pin, (await Plan(live.Kind)).History.Pin);
    }

    [Fact]
    public async Task Checkpoint_proof_rollback_waits_for_episode_tracking_to_finish()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 403);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var transaction = await owner.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(owner, "lock table public.semantic_password_episode_budgets in row exclusive mode", ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(),
            "config/postgres_migrations/403_password_checkpoint_proof.rollback.sql");
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(migration, null, ct));
        Assert.Contains("could not obtain lock", refused.Message);
        await transaction.RollbackAsync(ct);

        // No part of the schema change committed while future tracking could
        // invalidate its compatibility scan.
        await using (var unchanged = new NpgsqlCommand("""
            select max(version)=403 and
                to_regprocedure('public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[])') is not null
            from schema_migrations
            """, owner))
            Assert.Equal(true, await unchanged.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var restored = new NpgsqlCommand("select max(version) from schema_migrations", owner);
        Assert.Equal(402, await restored.ExecuteScalarAsync(ct));
    }
    private static async Task<(int Sequence, int RecordId)> AdmitEvents(SqlPostgresFixture fixture, NpgsqlConnection owner,
        IEnumerable<(int Kind, DateTimeOffset At, int Account, int Client)> events, int sequence, int recordId, CancellationToken ct)
    {
        var agent = ShortEventAdmissionPostgresTests.Agent;
        foreach (var packet in events.Chunk(100)) {
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: packet.Select(e => e.Kind).ToArray(),
                nativeTimestamps: packet.Select(e => PasswordJson.Stamp(e.At)).ToArray(),
                nativeAccounts: packet.Select(e => $"fixture-account-{e.Account}").ToArray(),
                nativeTargetSids: packet.Select(e => $"S-1-5-21-100000001-200000002-300000003-{1100 + e.Account}").ToArray(),
                nativeAddresses: packet.Select(e => $"192.0.2.{e.Client}").ToArray(),
                nativeWorkstations: packet.Select(e => $"fixture-{e.Client}.example.test").ToArray(),
                registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                sequence: sequence++, firstRecordId: recordId);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            recordId += rows.Length;
        }
        return (sequence, recordId);
    }

    private static (int Kind, DateTimeOffset At, int Account, int Client)[] LoadBatch(DateTimeOffset start, int batch)
    {
        var events = Enumerable.Range(batch * 2000, 2000)
            .SelectMany(i => new[] { (4625, start.AddMilliseconds(900 * i), i % 40, 151 + i % 40),
                (4776, start.AddMilliseconds(900 * i + 450), i % 40, 151 + i % 40) })
            .ToArray();
        // Both rules have a qualifying pattern at the start of each cohort.
        for (int i = 0; i < 15; i++) {
            var (kind, at, _, _) = events[i * 2];
            events[i * 2] = i < 10 ? (kind, at, 501 + batch, 221) : (kind, at, 510 + i, 222);
        }
        return events;
    }

    private static async Task Publish(PasswordRiskConsumer consumer, CancellationToken ct)
    {
        for (int i = 0; i < 32; i++) {
            var batch = await consumer.RunOnceAsync(ct);
            Assert.Equal(0, batch.Failed);
            if (batch.Claimed == 0) return;
        }
        Assert.Fail("Publication did not drain the bounded fixture");
    }

    private static async Task AssertReceived(NpgsqlConnection owner, DateTimeOffset loadStart, CancellationToken ct)
    {
        await using var received = new NpgsqlCommand("""
            select event_kind,count(*),
                count(distinct case when event_kind=4776 then method#>>'{$principals,Workstation}' else source end),
                count(distinct (method#>>'{$principals,TargetUserName}'))
            from event_hot where time_created_utc>=@at and source_sha256 is not null group by event_kind order by event_kind
            """, owner);
        received.Parameters.AddWithValue("at", loadStart);
        await using var rows = await received.ExecuteReaderAsync(ct);
        foreach (int kind in new[] { 4625, 4776 }) {
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(kind, rows.GetInt32(0));
            Assert.Equal(4000L, rows.GetInt64(1));
            Assert.True(rows.GetInt64(2) >= 40);
            Assert.True(rows.GetInt64(3) >= 30);
        }
        Assert.False(await rows.ReadAsync(ct));
    }

    private static async Task AssertPublished(NpgsqlConnection owner, DateTimeOffset loadStart, CancellationToken ct)
    {
        await using var published = new NpgsqlCommand("""
            select count(distinct s.document_json->>'rule_id')
            from semantic_finding_publications p
            join semantic_risk_evaluation_jobs j on j.job_id=p.first_job_id
            join semantic_qw_signals s on s.signal_id=j.qw_signal_id
            where (s.document_json->>'occurred_at_utc')::timestamptz>=@at
            """, owner);
        published.Parameters.AddWithValue("at", loadStart);
        Assert.Equal(2L, await published.ExecuteScalarAsync(ct));
    }

    private sealed class FixtureClock(DateTimeOffset at) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => at;
    }
    private static Task InstallTestClock(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, """
            create table public.password_test_clock(at timestamptz not null);
            insert into public.password_test_clock values (now());
            grant select on public.password_test_clock to adlog_storage_owner;
            do $$ declare fn regprocedure; begin
                foreach fn in array array['public.password_plan388(jsonb,text)'::regprocedure,
                    'public.password_event_clock362(jsonb,jsonb)'::regprocedure] loop
                    execute replace(replace(pg_get_functiondef(fn),'statement_timestamp()',
                        '(select at from public.password_test_clock)'), 'transaction_timestamp()',
                        '(select at from public.password_test_clock)');
                end loop;
            end $$;
            """, ct);

    private static async Task SetTestClock(NpgsqlConnection owner, DateTimeOffset at, CancellationToken ct)
    {
        await using var move = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
        move.Parameters.AddWithValue("at", at);
        await move.ExecuteNonQueryAsync(ct);
    }
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
