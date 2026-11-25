using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed partial class PasswordConcurrentImportWindowPostgresTests
{
    [Fact]
    public async Task Measures_both_rules_after_two_turns_with_a_changed_window()
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(4));
        var ct = deadline.Token;
        await using var fixture = new SqlPostgresFixture(trackCommitTimestamps: true);
        await fixture.StartAsync(ct, throughVersion: 410);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await InstallPrepareGateAsync(owner, ct);
        await InstallLeaseProbeAsync(owner, ct);

        const int windowRows = 1001;
        // Event-time distances from the two saved checkpoints, using the
        // observed lower bound on rows. Runtime on this runner is measured.
        var target = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 150);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        Task<ShortEventRow[]> Stage(int first, int sequence, params SyntheticEvent[] events) =>
            ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: events.Select(_ => 4625).ToArray(),
                nativeTimestamps: events.Select(e => PasswordJson.Stamp(e.At)).ToArray(),
                nativeAccounts: events.Select(e => $"synthetic-{e.Account}").ToArray(),
                nativeTargetSids: events.Select(e =>
                    $"S-1-5-21-100000001-200000002-300000003-{1000 + e.Account}").ToArray(),
                nativeAddresses: events.Select(e => e.Address).ToArray(),
                registered: sequence == 1 ? null : (agent, agent, 900001L, 1L),
                packetId: Guid.NewGuid(), sequence: sequence, firstRecordId: first);

        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,
            await Stage(1, 1, new SyntheticEvent(target.AddSeconds(-424), 1, "192.0.2.240")), ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var importer = new NpgsqlConnection(fixture.Dsn("sli_storage_login"));
        await importer.OpenAsync(ct);

        await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user")))
        {
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand("""
                select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'
                """, app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }

        await using var source = new NpgsqlCommand("""
            select source::text from public.default_detection_sources()
            where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
            """, worker);
        var scope = PasswordScope.Read(JsonNode.Parse(Assert.IsType<string>(await source.ExecuteScalarAsync(ct)))!["scope"]);
        async Task<PasswordRule> Plan(string kind)
        {
            await using var plan = new NpgsqlCommand("""
                select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::int
                """, worker);
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            plan.Parameters.AddWithValue("rule", new PasswordRule(scope, kind).Id);
            return new(scope, kind, Assert.IsType<int>(await plan.ExecuteScalarAsync(ct)));
        }

        var brute = await Plan("brute");
        var spray = await Plan("spray");
        var producer = new PasswordProducer();
        var caches = new Dictionary<string, Dictionary<long, PasswordNative>>
        {
            ["brute"] = [],
            ["spray"] = []
        };
        AssertCommitted(await producer.RunAsync(worker, spray, ct, caches["spray"]));
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,
            await Stage(2, 2, new SyntheticEvent(target.AddSeconds(-394), 2, "192.0.2.241")), ct);
        AssertCommitted(await producer.RunAsync(worker, brute, ct, caches["brute"]));
        var before = new Dictionary<string, Checkpoint>
        {
            ["brute"] = await ReadCheckpointAsync(owner, brute.Pin, ct),
            ["spray"] = await ReadCheckpointAsync(owner, spray.Pin, ct)
        };
        Assert.Equal(394, (target - before["brute"].Watermark).TotalSeconds);
        Assert.Equal(424, (target - before["spray"].Watermark).TotalSeconds);

        // At most four noise records share an address and every noise account is
        // different. The other records qualify one episode for each rule.
        var events = Enumerable.Range(0, windowRows - 15)
            .Select(i => new SyntheticEvent(target.AddSeconds(-393).AddMilliseconds(i * 380),
                100 + i, $"198.51.100.{1 + i % 250}"))
            .Concat(Enumerable.Range(0, 10)
                .Select(i => new SyntheticEvent(target.AddSeconds(-22 + i), 3000, "192.0.2.22")))
            .Concat(Enumerable.Range(0, 5)
                .Select(i => new SyntheticEvent(target.AddSeconds(-10 + i), 4000 + i, "192.0.2.23")))
            .OrderBy(e => e.At).ToArray();
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, await Stage(3, 3, events), ct);
        int bruteRecord = windowRows + 3;
        int sprayRecord = bruteRecord + 1;
        var arriving = new Dictionary<string, ShortEventRow[]>
        {
            ["brute"] = await Stage(bruteRecord, 4, new SyntheticEvent(target.AddSeconds(-1), 3000, "192.0.2.22")),
            ["spray"] = await Stage(sprayRecord, 5, new SyntheticEvent(target, 4005, "192.0.2.23"))
        };

        var turns = new List<string>();
        var commits = new Dictionary<string, CommitProbe>();
        var outcomes = await PasswordProducerPoller.RunBatchesAsync(scope, async (rule, token) =>
        {
            var watch = Stopwatch.StartNew();
            var cache = caches[rule.Kind];
            bool first = arriving.Remove(rule.Kind, out var lateRows);
            var result = first
                ? await RunGatedAsync(producer, worker, importer, rule, cache, lateRows!, token)
                : await producer.RunAsync(worker, rule, token, cache);
            watch.Stop();
            turns.Add($"{rule.Kind}:{result.Status}");
            var checkpoint = await ReadCheckpointAsync(owner, rule.Pin, token);
            output.WriteLine("p1_turn " + JsonSerializer.Serialize(new
            {
                rule = rule.Kind, turn = turns.Count, result.Status,
                elapsed_ms = watch.Elapsed.TotalMilliseconds, checkpoint.Revision, checkpoint.Watermark,
                lag_seconds = (target - checkpoint.Watermark).TotalSeconds
            }));
            if (first)
            {
                Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
                Assert.Equal("busy", result.Status);
                Assert.Equal("40001", result.Diagnostic?["sql_state"]?.GetValue<string>());
                Assert.Equal("password_v2_window_changed393", result.Diagnostic?["reason"]?.GetValue<string>());
                Assert.Equal(before[rule.Kind], checkpoint);
            }
            else
            {
                AssertCommitted(result);
                Assert.Equal(1, result.Jobs);
                Assert.Equal(before[rule.Kind].Revision + 1, checkpoint.Revision);
                Assert.Equal(target, checkpoint.Watermark);
                commits.Add(rule.Kind, await ReadProducerCommitAsync(owner, rule.Pin, token));
            }
            return result;
        }, ct, rules: [brute, spray], targetWatermark: target);
        Assert.Equal(new[] { "brute:busy", "spray:busy", "brute:committed", "spray:committed" }, turns);
        Assert.Equal(4, outcomes.Count);

        var risk = new PasswordRiskConsumer(runtime, new(MaxJobs: 16));
        var published = await risk.RunOnceAsync(ct);
        Assert.Equal(0, published.Failed);
        Assert.Equal(2, published.Published);
        foreach (var rule in new[] { brute, spray })
        {
            var commit = commits[rule.Kind];
            var delivery = await ReadPublicationAsync(owner, commit.Job, ct);
            var record = rule.Kind == "brute" ? bruteRecord : sprayRecord;
            var eligible = (rule.Kind == "brute" ? target.AddSeconds(-1) : target).AddSeconds(120);
            long nativeId = 900000L + record;
            Assert.Equal(1L, await CountNewOccurrencesAsync(owner, rule.Pin, nativeId, ct));
            Assert.Equal(commit.CheckpointCommittedAt, commit.JobCommittedAt);
            Assert.True(eligible <= commit.CheckpointCommittedAt);
            Assert.True(commit.JobCommittedAt <= delivery.LeaseCommittedAt);
            Assert.True(delivery.LeaseCommittedAt <= delivery.PublicationCommittedAt);
            output.WriteLine("p1_timing " + JsonSerializer.Serialize(new
            {
                rule = rule.Kind,
                input_latest_event = target,
                case_eligible_at = eligible,
                checkpoint_committed_at = commit.CheckpointCommittedAt,
                job_committed_at = commit.JobCommittedAt,
                first_lease_committed_at = delivery.LeaseCommittedAt,
                publication_committed_at = delivery.PublicationCommittedAt,
                eligible_to_checkpoint_ms = (commit.CheckpointCommittedAt - eligible).TotalMilliseconds,
                checkpoint_to_lease_ms = (delivery.LeaseCommittedAt - commit.JobCommittedAt).TotalMilliseconds,
                lease_to_publication_ms = (delivery.PublicationCommittedAt - delivery.LeaseCommittedAt).TotalMilliseconds,
                latest_finding_event = delivery.FindingEvent,
                window_rows = windowRows
            }));
        }
        Assert.Equal(0, (await risk.RunOnceAsync(ct)).Claimed);
    }

    private sealed record SyntheticEvent(DateTimeOffset At, int Account, string Address);
    private sealed record CommitProbe(DateTimeOffset CheckpointCommittedAt, DateTimeOffset JobCommittedAt, Guid Job);
    private sealed record PublicationProbe(DateTimeOffset LeaseCommittedAt, DateTimeOffset PublicationCommittedAt, DateTimeOffset FindingEvent);

    private static Task InstallLeaseProbeAsync(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, """
            create table public.p1_probe_first_lease(job_id uuid primary key);
            create function public.p1_probe_first_lease_write() returns trigger
            language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
            begin
                insert into public.p1_probe_first_lease(job_id) values(new.job_id) on conflict do nothing;
                return new;
            end $$;
            revoke all on function public.p1_probe_first_lease_write() from public;
            create trigger p1_probe_first_lease_write
            after update of evaluation_status on public.semantic_risk_evaluation_jobs
            for each row when (new.evaluation_status='leased' and old.evaluation_status is distinct from new.evaluation_status)
            execute function public.p1_probe_first_lease_write();
            """, ct);

    private static async Task<CommitProbe> ReadProducerCommitAsync(NpgsqlConnection db, string pin, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            select pg_xact_commit_timestamp(c.xmin),pg_xact_commit_timestamp(j.xmin),j.job_id
            from public.semantic_password_checkpoints c
            join public.semantic_qw_signals q on q.document_json#>>'{password_context,pin}'=c.pin
            join public.semantic_risk_evaluation_jobs j on j.qw_signal_id=q.signal_id
            where c.pin=@pin
            """, db);
        query.Parameters.AddWithValue("pin", pin);
        await using var reader = await query.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        var probe = new CommitProbe(reader.GetFieldValue<DateTimeOffset>(0),
            reader.GetFieldValue<DateTimeOffset>(1), reader.GetGuid(2));
        Assert.False(await reader.ReadAsync(ct));
        return probe;
    }

    private static async Task<PublicationProbe> ReadPublicationAsync(NpgsqlConnection db, Guid job, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("""
            select pg_xact_commit_timestamp(l.xmin),pg_xact_commit_timestamp(p.xmin),f.last_seen_utc::timestamptz
            from public.p1_probe_first_lease l
            join public.semantic_finding_publications p on p.first_job_id=l.job_id
            join public.findings f on f.id=p.finding_id
            where l.job_id=@job
            """, db);
        query.Parameters.AddWithValue("job", job);
        await using var reader = await query.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        var probe = new PublicationProbe(reader.GetFieldValue<DateTimeOffset>(0),
            reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2));
        Assert.False(await reader.ReadAsync(ct));
        return probe;
    }
}
