using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordSuccessorCoveragePostgresTests
{
    [Fact]
    public async Task Spray_advances_before_a_qualified_denial_endpoint_without_rewriting_its_barrier()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        await PostCollectionPostgres.Sql(owner, """
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

        int sequence = 1, recordId = 1;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        async Task Admit(DateTimeOffset[] times, int client, bool large = false)
        {
            int first = recordId;
            var input = Enumerable.Range(0, times.Length).ToArray();
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: input.Select(_ => 4625).ToArray(),
                nativeTimestamps: times.Select(PasswordJson.Stamp).ToArray(),
                nativeAccounts: input.Select(i => $"spray-test-{i}").ToArray(),
                nativeTargetSids: input.Select(i => $"S-1-5-21-100000001-200000002-300000003-{1001 + i}").ToArray(),
                nativeAddresses: input.Select(_ => $"192.0.2.{client}").ToArray(),
                registered: sequence == 1 ? null : (agent, agent, 900001, 1),
                packetId: Guid.NewGuid(), sequence: sequence++, firstRecordId: first);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            recordId += times.Length;
            if (large) {
                // Real native XML costs exhaust the lifetime budget. No ledger
                // counters or proof limits are changed to manufacture a freeze.
                await using var padding = new NpgsqlCommand("""
                    update public.event_hot
                    set fields=fields||jsonb_build_object('FixturePadding',repeat('x',3500000))
                    where event_record_id between @first and @last
                    """, owner);
                padding.Parameters.AddWithValue("first", first);
                padding.Parameters.AddWithValue("last", recordId - 1);
                await padding.ExecuteNonQueryAsync(ct);
            }
        }
        async Task Clock(DateTimeOffset through)
        {
            await using var clock = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
            clock.Parameters.AddWithValue("at", through.AddSeconds(120));
            await clock.ExecuteNonQueryAsync(ct);
        }

        await Admit(Enumerable.Range(0, 9).Select(i => start.AddSeconds(50 * i)).ToArray(), 1, large: true);
        await Clock(start.AddSeconds(400));
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        PasswordRule rule;
        await using (var worker = await runtime.OpenAsync(ct)) {
            await using var source = new NpgsqlCommand(
                "select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            var scope = PasswordScope.Read(JsonNode.Parse(Assert.IsType<string>(await source.ExecuteScalarAsync(ct)))!["scope"]);
            await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand(
                "select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
            await using var plan = new NpgsqlCommand(
                "select (public.password_plan388(@s::jsonb,'qw.password-spray')#>>'{live,rule_version}')::int", worker);
            plan.Parameters.AddWithValue("s", scope.Document.ToJsonString());
            rule = new PasswordRule(scope, "spray", Assert.IsType<int>(await plan.ExecuteScalarAsync(ct)));
        }
        async Task<PasswordProducerOutcome> Run(DateTimeOffset through, bool small = false)
        {
            await Clock(through);
            await using var worker = await runtime.OpenAsync(ct);
            if (small) {
                // This connection owns only this attempt. The production reader
                // and finalizer independently use the same smaller decision cap.
                await using var limit = new NpgsqlCommand("select set_config('sli.password_decision_limit','1',false)", worker);
                await limit.ExecuteScalarAsync(ct);
            }
            var outcome = await new PasswordProducer().RunAsync(worker, rule, ct);
            Assert.False(outcome.Failed, outcome.Diagnostic?.ToJsonString());
            return outcome;
        }
        async Task<(PasswordState State, JsonObject Ledger)> Saved()
        {
            await using var command = new NpgsqlCommand("""
                select c.state_document::text,to_jsonb(b)::text
                from public.semantic_password_checkpoints c
                join public.semantic_password_episode_budgets b using(scope_digest,pin)
                where c.pin=@pin and b.predecessor_episode_key is null
                """, owner);
            command.Parameters.AddWithValue("pin", rule.Pin);
            await using var rows = await command.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            var saved = (PasswordState.Read(JsonNode.Parse(rows.GetString(0))),
                JsonNode.Parse(rows.GetString(1))!.AsObject());
            Assert.False(await rows.ReadAsync(ct));
            return saved;
        }
        async Task<string> Evidence(string key, int lastRecord)
        {
            await using var command = new NpgsqlCommand("""
                select encode(sha256(convert_to(jsonb_build_object(
                    'native',(select jsonb_agg(jsonb_build_array(h.event_id,
                        encode(sha256(convert_to(to_jsonb(h)::text,'UTF8')),'hex')) order by h.event_id)
                        from public.event_hot h where h.event_record_id<=@last),
                    'receipts',(select jsonb_agg(to_jsonb(r) order by sequence) from public.sli_agent_receipts r
                        where sequence<=3),
                    'portions',(select jsonb_agg(to_jsonb(s) order by signal_id) from public.semantic_qw_signals s
                        where document_json->>'episode_key'=@key
                          and document_json#>>'{password_context,pin}'=@pin))::text,'UTF8')),'hex')
                """, owner) { CommandTimeout = 0 };
            command.Parameters.AddWithValue("last", lastRecord);
            command.Parameters.AddWithValue("key", key);
            command.Parameters.AddWithValue("pin", rule.Pin);
            return Assert.IsType<string>(await command.ExecuteScalarAsync(ct));
        }

        Assert.Equal(1, (await Run(start.AddSeconds(400))).Jobs);
        var watermark = start.AddSeconds(900);
        await Admit([watermark], 2);
        Assert.Equal(watermark, PasswordJson.Time((await Run(watermark)).Work!["watermark"]));

        var deniedAt = start.AddSeconds(950);
        await Admit([deniedAt], 1, large: true);
        var denied = await Run(deniedAt);
        Assert.True(denied.CommittedQualifiedDenial);
        Assert.Equal(0, denied.Jobs);
        var frozen = await Saved();
        Assert.Equal(watermark, frozen.State.Watermark);
        Assert.True(frozen.Ledger["frozen"]!.GetValue<bool>());
        Assert.True(frozen.Ledger["barrier_unresolved"]!.GetValue<bool>());
        Assert.Equal(deniedAt, PasswordJson.Time(frozen.Ledger["tracking_through"]));
        var endpoint = PasswordWitness.Read(frozen.Ledger["tracking_endpoint"]);
        Assert.Equal(deniedAt, endpoint.At);
        string key = PasswordJson.Text(frozen.Ledger["episode_key"]);
        int lastRecord = recordId - 1;
        string evidence = await Evidence(key, lastRecord);

        var earlier = start.AddSeconds(925);
        await Admit([earlier], 2);
        // A direct request still cannot move a frozen tracker backwards.
        await using (var worker = await runtime.OpenAsync(ct))
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new PasswordSql(worker, tx);
            var attempt = PasswordJson.Obj(await sql.Call("begin_password_attempt", ct, rule.Scope.Document, rule.Execution));
            await sql.Execute("select set_config('sli.password_decision_limit','1',true)", ct);
            var error = await Assert.ThrowsAsync<PostgresException>(() => sql.Call("track_password_frozen_entity_v2", ct,
                rule.Scope.Document, rule.Execution, attempt["token"]!.GetValue<long>(),
                attempt["state_revision"]!.GetValue<long>(), key, endpoint.Document, frozen.State.Epoch,
                watermark.AddSeconds(-600), earlier));
            Assert.Equal("22023", error.SqlState);
            Assert.Equal("password_v2_tracking_invalid", error.MessageText);
            await tx.RollbackAsync(ct);
        }

        var prefix = await Run(deniedAt, small: true);
        Assert.Equal(earlier, PasswordJson.Time(prefix.Work!["watermark"]));
        Assert.False(prefix.CommittedQualifiedDenial);
        var held = await Saved();
        Assert.Equal(earlier, held.State.Watermark);
        Assert.True(JsonNode.DeepEquals(frozen.Ledger, held.Ledger));
        Assert.Equal(evidence, await Evidence(key, lastRecord));

        Assert.Equal(deniedAt, PasswordJson.Time((await Run(deniedAt)).Work!["watermark"]));
        Assert.True(JsonNode.DeepEquals(frozen.Ledger, (await Saved()).Ledger));
        var successorAt = deniedAt.AddSeconds(601);
        await Admit(Enumerable.Range(0, 5).Select(i => successorAt.AddSeconds(i)).ToArray(), 1);
        Assert.Equal(1, (await Run(successorAt.AddSeconds(4))).Jobs);
        var resolved = await Saved();
        Assert.False(resolved.Ledger["barrier_unresolved"]!.GetValue<bool>());
        Assert.Equal(endpoint, PasswordWitness.Read(resolved.Ledger["tracking_endpoint"]));
        Assert.Equal(successorAt.AddSeconds(4), PasswordJson.Time(resolved.Ledger["tracking_through"]));
        Assert.Equal(evidence, await Evidence(key, lastRecord));
        await using var successor = new NpgsqlCommand("""
            select count(*) from public.semantic_password_episode_budgets
            where pin=@pin and predecessor_episode_key=@previous and episode_key=@next
                and (seed->>'at')::timestamptz=@seed and last_sequence=1
            """, owner);
        successor.Parameters.AddWithValue("pin", rule.Pin);
        successor.Parameters.AddWithValue("previous", key);
        successor.Parameters.AddWithValue("next", PasswordJson.Text(resolved.Ledger["successor_episode_key"]));
        successor.Parameters.AddWithValue("seed", successorAt);
        Assert.Equal(1L, await successor.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Spray_publishes_a_single_successor_after_persisting_the_verified_gap_coverage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        await PostCollectionPostgres.Sql(owner, """
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

        int sequence = 1, recordId = 1;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        async Task Admit(DateTimeOffset first, int events, int client)
        {
            var input = Enumerable.Range(0, events).ToArray();
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: input.Select(_ => 4625).ToArray(),
                nativeTimestamps: input.Select(i => PasswordJson.Stamp(first.AddSeconds(i))).ToArray(),
                nativeAccounts: input.Select(i => $"spray-test-{i}").ToArray(),
                nativeTargetSids: input.Select(i => $"S-1-5-21-100000001-200000002-300000003-{1001 + i}").ToArray(),
                nativeAddresses: input.Select(_ => $"192.0.2.{client}").ToArray(),
                registered: sequence == 1 ? null : (agent, agent, 900001, 1),
                packetId: Guid.NewGuid(), sequence: sequence++, firstRecordId: recordId);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            recordId += events;
        }
        async Task Clock(DateTimeOffset end)
        {
            await using var clock = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
            clock.Parameters.AddWithValue("at", end.AddMinutes(2));
            await clock.ExecuteNonQueryAsync(ct);
        }
        await Admit(start, 5, 1);
        var initialEnd = start.AddSeconds(4);
        await Clock(initialEnd);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        PasswordRule rule;
        await using (var worker = await runtime.OpenAsync(ct)) {
            await using var source = new NpgsqlCommand(
                "select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            var scope = PasswordScope.Read(JsonNode.Parse(Assert.IsType<string>(await source.ExecuteScalarAsync(ct)))!["scope"]);
            await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand(
                "select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
            await using var plan = new NpgsqlCommand(
                "select (public.password_plan388(@s::jsonb,'qw.password-spray')#>>'{live,rule_version}')::int", worker);
            plan.Parameters.AddWithValue("s", scope.Document.ToJsonString());
            rule = new PasswordRule(scope, "spray", Assert.IsType<int>(await plan.ExecuteScalarAsync(ct)));
        }

        async Task Run(DateTimeOffset through)
        {
            await Clock(through);
            await using var worker = await runtime.OpenAsync(ct);
            var outcome = await new PasswordProducer().RunAsync(worker, rule, ct);
            Assert.False(outcome.Failed, outcome.Diagnostic?.ToJsonString());
        }
        await Run(initialEnd);

        await using var oldKey = new NpgsqlCommand("select episode_key from public.semantic_password_episode_budgets where pin=@pin", owner);
        oldKey.Parameters.AddWithValue("pin", rule.Pin);
        var previousKey = Assert.IsType<string>(await oldKey.ExecuteScalarAsync(ct));
        var prior = await new PasswordRiskConsumer(runtime, new()).RunOnceAsync(ct);
        Assert.Equal(1, prior.Published);
        Assert.Equal(0, prior.Failed);
        await PasswordLockedEpisodeProofPostgresTests.Freeze(owner, rule, previousKey, ct);

        async Task<(DateTimeOffset Tracking, DateTimeOffset Through, DateTimeOffset Watermark,
            long Epoch, long References, int Portions, bool Unresolved, string? Successor)> Barrier()
        {
            await using var command = new NpgsqlCommand("""
                select (b.tracking_endpoint->>'at')::timestamptz,b.tracking_through,c.watermark,
                       b.tracking_epoch,b.reserved_ref_occurrences,b.reserved_portions,b.barrier_unresolved,b.successor_episode_key
                from public.semantic_password_episode_budgets b
                join public.semantic_password_checkpoints c using(scope_digest,pin)
                where b.pin=@pin and b.episode_key=@key and b.frozen
                """, owner);
            command.Parameters.AddWithValue("pin", rule.Pin);
            command.Parameters.AddWithValue("key", previousKey);
            await using var rows = await command.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            return (rows.GetFieldValue<DateTimeOffset>(0), rows.GetFieldValue<DateTimeOffset>(1),
                rows.GetFieldValue<DateTimeOffset>(2), rows.GetInt64(3), rows.GetInt64(4),
                rows.GetInt32(5), rows.GetBoolean(6), rows.IsDBNull(7) ? null : rows.GetString(7));
        }
        async Task<string> HistoricalProof(int endingSequence)
        {
            await using var read = new NpgsqlCommand("""
                select encode(sha256(convert_to(jsonb_build_object(
                    'receipts',(select jsonb_agg(to_jsonb(r) order by sequence) from public.sli_agent_receipts r where sequence<=@last),
                    'publications',(select jsonb_agg(to_jsonb(p) order by p.scenario_id)
                        from public.semantic_finding_publications p
                        join public.semantic_security_scenarios s using(scenario_id)
                        where s.scenario_kind='qw.password-spray' and s.strict_keys_json->>'episode'=@key),
                    'portions',(select jsonb_agg(to_jsonb(s) order by signal_id) from public.semantic_qw_signals s
                        where document_json->>'episode_key'=@key and document_json#>>'{password_context,pin}'=@pin))::text,'UTF8')),'hex')
                """, owner) { CommandTimeout = 0 };
            read.Parameters.AddWithValue("last", endingSequence);
            read.Parameters.AddWithValue("key", previousKey);
            read.Parameters.AddWithValue("pin", rule.Pin);
            return Assert.IsType<string>(await read.ExecuteScalarAsync(ct));
        }
        async Task<(DateTimeOffset From, DateTimeOffset Through)> RecordedLoss()
        {
            await using var command = new NpgsqlCommand("""
                select (entry->>'from')::timestamptz,(entry->>'to')::timestamptz from (
                  select public.password_v2_health(c,clock_timestamp())#>'{loss,episode_evidence_budget_exhausted}' as entry
                  from public.semantic_password_checkpoints c where c.pin=@pin
                ) q
                """, owner);
            command.Parameters.AddWithValue("pin", rule.Pin);
            await using var rows = await command.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            return (rows.GetFieldValue<DateTimeOffset>(0), rows.GetFieldValue<DateTimeOffset>(1));
        }

        var frozen = await Barrier();
        Assert.True(frozen.Unresolved);
        Assert.Null(frozen.Successor);
        int oldReceiptEnd = sequence - 1;
        string oldHash = await HistoricalProof(oldReceiptEnd);
        var touch = frozen.Watermark.AddSeconds(1);
        await Admit(touch, 1, 1);
        await Run(touch);
        var tracked = await Barrier();
        Assert.Equal(touch, tracked.Tracking);
        var lossBefore = await RecordedLoss();

        var emptyCovered = touch.AddSeconds(590);
        await Admit(emptyCovered, 1, 2);
        await Run(emptyCovered);
        var absent = await Barrier();
        Assert.Equal(touch, absent.Tracking);
        Assert.True(absent.Through >= emptyCovered);
        Assert.True(absent.Unresolved);
        Assert.Null(absent.Successor);

        var boundary = touch.AddSeconds(600);
        await Admit(boundary, 1, 1);
        await Run(boundary);
        var held = await Barrier();
        Assert.Equal(boundary, held.Tracking);
        Assert.Equal(tracked.Epoch, held.Epoch);
        Assert.True(held.Unresolved);
        Assert.Null(held.Successor);

        var covered = boundary.AddSeconds(600);
        await Admit(covered, 1, 2);
        await Run(covered);
        var beforeRestart = await Barrier();
        Assert.Equal(boundary, beforeRestart.Tracking);
        Assert.True(beforeRestart.Through >= covered);
        await owner.CloseAsync();
        await fixture.Pg.RestartExistingAsync(ct);
        await owner.OpenAsync(ct);
        Assert.Equal(beforeRestart, await Barrier());

        var candidate = boundary.AddSeconds(601);
        await Admit(candidate, 5, 1);
        await Clock(candidate.AddSeconds(4));
        PasswordWitness firstAdmitted;
        await using (var reader = await runtime.OpenAsync(ct))
        await using (var tx = await reader.BeginTransactionAsync(ct)) {
            var sql = new PasswordSql(reader, tx);
            var rows = await sql.Rows("select * from public.read_password_event_window362(@s::jsonb,@e::jsonb)",
                ct, ("s", rule.Scope.Document), ("e", rule.Execution));
            var native = Assert.Single(rows, row => row["occurred_at_utc"] is { } stamp
                && PasswordJson.Time(stamp) == candidate);
            firstAdmitted = PasswordNative.Parse(rule.Scope, native["source_event_id"]!.GetValue<long>(),
                PasswordJson.Text(native["sha256"]), native["event_id"]!.GetValue<int>(), candidate,
                PasswordJson.Text(native["source_xml"]), normalizeAccount: true).Witness;
            await tx.RollbackAsync(ct);
        }
        async Task VerifyCoverageGuard(long epoch, DateTimeOffset coverageStart)
        {
            await using var worker = await runtime.OpenAsync(ct);
            await using var transaction = await worker.BeginTransactionAsync(ct);
            var sql = new PasswordSql(worker, transaction);
            var attempt = PasswordJson.Obj(await sql.Call(
                "begin_password_attempt", ct, rule.Scope.Document, rule.Execution));
            var tracking = PasswordJson.Obj(await sql.Call("track_password_frozen_entity_v2", ct,
                rule.Scope.Document, rule.Execution, attempt["token"]!.GetValue<long>(),
                attempt["state_revision"]!.GetValue<long>(), previousKey, firstAdmitted.Document, epoch,
                coverageStart, candidate.AddSeconds(4)));
            Assert.Equal("held", tracking["status"]!.GetValue<string>());
            Assert.Null(tracking["successor_episode_key"]);
            await transaction.RollbackAsync(ct);
            Assert.Equal(beforeRestart, await Barrier());
        }

        await VerifyCoverageGuard(held.Epoch, candidate);
        await VerifyCoverageGuard(held.Epoch + 1, covered);
        await Run(candidate.AddSeconds(4));
        var resolved = await Barrier();
        Assert.Equal(held.Epoch, resolved.Epoch);
        Assert.False(resolved.Unresolved);
        Assert.NotNull(resolved.Successor);
        await using var verify = new NpgsqlCommand("""
            select count(*) from public.semantic_password_episode_budgets
            where pin=@pin and predecessor_episode_key=@previous and episode_key=@next
                and (seed->>'at')::timestamptz=@expected_seed and last_sequence>0
            """, owner);
        verify.Parameters.AddWithValue("pin", rule.Pin);
        verify.Parameters.AddWithValue("previous", previousKey);
        verify.Parameters.AddWithValue("next", resolved.Successor!);
        verify.Parameters.AddWithValue("expected_seed", candidate);
        Assert.Equal(1L, await verify.ExecuteScalarAsync(ct));
        Assert.Equal(oldHash, await HistoricalProof(oldReceiptEnd));
        var linkedLoss = await RecordedLoss();
        Assert.True(linkedLoss.From <= lossBefore.From && linkedLoss.Through >= lossBefore.Through);

        var risk = new PasswordRiskConsumer(runtime, new());
        var publishedBatch = await risk.RunOnceAsync(ct);
        Assert.Equal(0, publishedBatch.Failed);
        Assert.Equal(1, publishedBatch.Published);
        Assert.Equal(candidate.AddSeconds(4), resolved.Through);

        await using var published = new NpgsqlCommand("""
            select count(*) from public.semantic_finding_publications p
            join public.semantic_security_scenarios s using(scenario_id)
            where s.scenario_kind='qw.password-spray' and s.strict_keys_json->>'episode'=@next
            """, owner);
        published.Parameters.AddWithValue("next", resolved.Successor!);
        Assert.Equal(1L, await published.ExecuteScalarAsync(ct));
        Assert.Equal(oldHash, await HistoricalProof(oldReceiptEnd));
        var lossAfter = await RecordedLoss();
        Assert.True(lossAfter.From <= lossBefore.From && lossAfter.Through >= lossBefore.Through);

        await owner.CloseAsync();
        await fixture.Pg.RestartExistingAsync(ct);
        await owner.OpenAsync(ct);
        Assert.Equal(resolved, await Barrier());
        Assert.Equal(1L, await published.ExecuteScalarAsync(ct));
        await Run(candidate.AddSeconds(4));
        Assert.Equal(0, (await risk.RunOnceAsync(ct)).Claimed);
        Assert.Equal(1L, await verify.ExecuteScalarAsync(ct));
        Assert.Equal(oldHash, await HistoricalProof(oldReceiptEnd));
    }
}
