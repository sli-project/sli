using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordThresholdPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public void BruteForceUsesTheCollectionDomainAndFoldedAccount()
    {
        var scope = new PasswordScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "synthetic", "generation", "");
        var start = DateTimeOffset.Parse("2026-11-13T08:00:00Z", CultureInfo.InvariantCulture);
        var claims = new[] { "DEMO", "", "WORKGROUP" };
        var rows = Enumerable.Range(1, 60).Select(id =>
        {
            int stream = (id - 1) / 20;
            return new DetectionRow(new(scope, "core_event", id.ToString(CultureInfo.InvariantCulture), new('a', 64)),
                start.AddSeconds(id), 4625, Fields: new JsonObject {
                    ["TargetUserName"] = stream == 0 ? "Администратор" : "АДМИНИСТРАТОР",
                    ["TargetDomainName"] = claims[stream], ["IpAddress"] = $"192.0.2.{stream + 1}",
                    ["domain_id"] = 1, ["domain_netbios"] = "EXAMPLE", ["domain_fqdn"] = "example.test"
                });
        }).ToArray();
        var signal = Assert.Single(PasswordAttacks.Evaluate(scope, PasswordAttacks.Brute, new(), rows, 0, new Dictionary<string, PasswordAttacks.Episode>(), start.AddMinutes(2)));
        var facts = PasswordAttacks.Validate(signal);
        Assert.Equal(60, facts.Number("attempts"));
        Assert.Equal(3, facts.Number("address_count"));
        Assert.Equal(new[] { "DEMO", "WORKGROUP" }, facts["reported_domains"]!.AsArray().Select(value => value!.ToString()));

        var active = new Dictionary<string, PasswordAttacks.Episode> {
            [D.Text(signal["entity_key"])] = PasswordAttacks.Episode.Read(D.Text(signal["episode_key"]), facts)
        };
        var later = rows.Take(20).Select((row, index) => row with {
            At = row.At.AddHours(25), Ref = row.Ref with { NativeId = (61 + index).ToString(CultureInfo.InvariantCulture) }
        }).ToArray();
        Assert.Empty(PasswordAttacks.Evaluate(scope, PasswordAttacks.Brute, new(), later[..19], 60, active, start.AddHours(26)));
        var resumed = Assert.Single(PasswordAttacks.Evaluate(scope, PasswordAttacks.Brute, new(), later, 60, active, later[^1].At.AddSeconds(1)));
        Assert.Equal(D.Text(signal["episode_key"]), D.Text(resumed["episode_key"]));
        Assert.Equal(80, PasswordAttacks.Validate(resumed).Number("attempts"));

        foreach (var row in rows[40..]) row.Fields!["domain_id"] = 2;
        var split = PasswordAttacks.Evaluate(scope, PasswordAttacks.Brute, new(), rows, 0, new Dictionary<string, PasswordAttacks.Episode>(), start.AddMinutes(2));
        Assert.Equal(new long[] { 40, 20 }, split.Select(item => PasswordAttacks.Validate(item).Number("attempts")));
    }

    [Fact]
    public async Task Previous_maximum_accepts_the_threshold_migration_and_rollback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 417);
        string path = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/418_password_threshold_rules.sql");
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(path, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task UpgradeMergesThresholdFindingsAndResolvesV2WithReversibleDecisions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 417);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var runtime = Runtime(fixture);
        await using var worker = await runtime.OpenAsync(ct);
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddMinutes(-6).ToUnixTimeSeconds());
        var legacyAccounts = Enumerable.Repeat("synthetic-legacy", 25).Concat(Enumerable.Range(1, 15).Select(i => "legacy-user-" + i)).ToArray();
        var legacy = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start,
            eventKinds: legacyAccounts.Select(_ => 4625).ToArray(), nativeAccounts: legacyAccounts,
            nativeTargetSids: legacyAccounts.Select((_, i) => $"S-1-5-21-100000001-200000002-300000003-{(i < 25 ? 1001 : 1100 + i)}").ToArray(),
            nativeTimestamps: legacyAccounts.Select((_, i) => PasswordJson.Stamp(start.AddSeconds(i))).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, legacy, ct);
        var scope = await Scope(worker, ct);
        await PostCollectionPostgres.Sql(owner, """
            update sli_agent_module_bindings set password_detection_domain_id=1 where module_id='sli.windows.ad-dc';
            """, ct);
        foreach (string kind in new[] { "brute", "spray" }) {
            var result = await new PasswordProducer().RunAsync(worker, new(scope, kind), ct);
            Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
            Assert.True(result.Jobs > 0);
        }
        var v2 = await new PasswordRiskConsumer(runtime, new()).RunOnceAsync(ct);
        Assert.Equal(0, v2.Failed);
        await using var retired = new NpgsqlCommand("select count(distinct rule_code) from findings where status='new'", owner);
        Assert.Equal(2L, await retired.ExecuteScalarAsync(ct));

        var migrations = MigrationDirectory.Read(418);
        foreach (var migration in migrations.Where(m => m.Version < 420)) await fixture.Pg.ApplyFileAsync(migration.Path, null, ct);
        string upgrade = migrations.Single(m => m.Version == 420).Path;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        var ids = Enumerable.Range(0, 60).ToArray();
        var claims = new[] { "DEMO", "", "WORKGROUP" };
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: ids.Select(_ => 4625).ToArray(),
            registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(), sequence: 2, firstRecordId: 101,
            nativeAccounts: ids.Select(i => i < 20 ? "Администратор" : "АДМИНИСТРАТОР").ToArray(),
            nativeDomains: ids.Select(i => claims[i / 20]).ToArray(),
            nativeAddresses: ids.Select(i => $"192.0.2.{10 + i / 20}").ToArray(),
            nativeTimestamps: ids.Select(i => PasswordJson.Stamp(start.AddSeconds(60 + i))).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new DetectionSql(worker, tx);
            var policy = new PasswordThresholdPolicy();
            var definition = PasswordAttacks.PolicyDefinition(scope, PasswordAttacks.Brute, policy);
            Assert.True((await sql.Rows("select public.admit_password_threshold418(@id,@definition) as enabled", ct,
                ("id", DetectionSignal.PolicyId(definition["source_selector"]!["execution"]!.AsObject())),
                ("definition", CanonicalJson.Serialize(definition, ensureAscii: false)))).Single().Flag("enabled"));
            var seen = await sql.Rows("select * from public.read_password_threshold_events418(@scope,@rule,@from,@from,0,@now,9223372036854775807)", ct,
                ("scope", scope.Document), ("rule", PasswordAttacks.Brute), ("from", start.AddSeconds(59)), ("now", start.AddMinutes(3)));
            Assert.Equal(60, seen.Count);
            var episodes = new JsonArray();
            foreach (var batch in seen.Chunk(20)) {
                string entity = D.Hash(new JsonArray(batch[0]["fields"]!["TargetDomainName"]?.DeepClone(), JsonValue.Create("администратор")));
                string episode = D.Hash(JsonValue.Create(batch[0].Number("native_id")));
                var facts = new JsonObject { ["version"] = 1, ["attempts"] = 20, ["first"] = D.Stamp(D.Time(batch[0]["occurred_at_utc"])),
                    ["last_failure"] = D.Stamp(D.Time(batch[^1]["occurred_at_utc"])), ["last"] = D.Stamp(D.Time(batch[^1]["occurred_at_utc"])),
                    ["password_success"] = false, ["account"] = batch[0]["fields"]!["TargetUserName"]!.DeepClone(),
                    ["address_count"] = 1, ["addresses"] = new JsonArray(batch[0]["fields"]!["IpAddress"]!.DeepClone()) };
                var refs = batch.Select(row => new DetectionRef(scope, "core_event", row.Number("native_id").ToString(CultureInfo.InvariantCulture), D.Text(row["sha256"])));
                var signal = DetectionSignal.Create(PasswordAttacks.Brute, "threshold", D.Text(PasswordAttacks.Execution(scope, PasswordAttacks.Brute, policy)["rule_sha256"]),
                    entity, episode, refs, D.Time(batch[^1]["occurred_at_utc"]), start.AddMinutes(3), "high",
                    "password_threshold_context", new() { ["policy"] = policy.Document, ["facts"] = facts.DeepClone() });
                Assert.Equal(1, await DetectionProducer.Enqueue(sql, signal, ct));
                episodes.Add(new JsonObject { ["entity_key"] = entity, ["episode_key"] = episode, ["facts"] = facts });
            }
            await sql.Execute("select public.write_password_threshold_pass418(@scope,@rule,@cursor,'current',@episodes)", ct,
                ("scope", scope.Document), ("rule", PasswordAttacks.Brute), ("cursor", seen[^1].Number("native_id")), ("episodes", episodes));
            await tx.CommitAsync(ct);
        }
        await Publish(runtime, worker, 3, ct);
        await using var threshold = new NpgsqlCommand("select min(id) from findings where password_threshold_facts418 is not null", owner);
        long oldest = Assert.IsType<long>(await threshold.ExecuteScalarAsync(ct));
        async Task<long> Count(string sql) {
            await using var command = new NpgsqlCommand(sql, owner);
            command.Parameters.AddWithValue("oldest", oldest);
            return Assert.IsType<long>(await command.ExecuteScalarAsync(ct));
        }
        long retiredCount = await Count("select count(*) from findings where password_threshold_facts418 is null and status='new'");
        await fixture.Pg.ApplyFileAsync(upgrade, null, ct);
        Assert.Equal(retiredCount, await Count("""
            select count(*) from findings_active f join finding_status_history h on h.finding_id=f.id
            where f.status='closed' and h.new_status='closed' and h.changed_by='SLI' and h.note='password_rule_replaced420'
            """));
        Assert.Equal(2L, await Count("""
            select count(*) from findings_active f join finding_status_history h on h.finding_id=f.id
            where f.status='closed' and h.changed_by='SLI' and h.note='password_rule_merged420:'||@oldest
            """));
        Assert.Equal(1L, await Count("""
            select count(*) from findings where id=@oldest and status='new'
                and (password_threshold_facts418->>'attempts')::bigint=60
                and (password_threshold_facts418->>'address_count')::bigint=3 and evidence_count=50
                and password_threshold_facts418->'reported_domains' @> '["DEMO","WORKGROUP"]'::jsonb
            """));

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(upgrade, ".rollback.sql"), null, ct);
        Assert.Equal(retiredCount, await Count("select count(*) from findings where password_threshold_facts418 is null and status='new'"));
        Assert.Equal(3L, await Count("select count(*) from findings where status='new' and password_threshold_facts418->>'attempts'='20' and evidence_count=20"));
        Assert.Equal(0L, await Count("select count(*) from finding_status_history where changed_by='SLI'"));
        await fixture.Pg.ApplyFileAsync(upgrade, null, ct);

        var secondDc = Guid.NewGuid();
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, secondDc, secondDc, 900002, 1, "dc2.example.test", "Security", ct);
        var continued = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            registered: (secondDc, secondDc, 900002, 1), packetId: Guid.NewGuid(), hostName: "dc2.example.test", firstRecordId: 201,
            occurredAt: start.AddSeconds(120), eventKinds: [4625], nativeAccounts: ["администратор"], nativeDomains: ["NEW-CLAIM"]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, continued, ct);
        var secondScope = await Scope(worker, ct, secondDc.ToString());
        Assert.Equal(1, await DetectionProducer.RunPasswordThreshold(worker, secondScope, PasswordAttacks.Brute, start.AddMinutes(3), ct));
        await Publish(runtime, worker, 1, ct);
        Assert.Equal(1L, await Count("select count(*) from findings where status='new' and rule_code='semantic.qw.password-brute-force'"));
        Assert.Equal(61L, await Count("select (password_threshold_facts418->>'attempts')::bigint from findings where id=@oldest"));
        Assert.Equal(4L, await Count("select (password_threshold_facts418->>'address_count')::bigint from findings where id=@oldest"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Spray_publishes_130_accounts_and_survives_three_hours_and_restart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddHours(-4).ToUnixTimeSeconds());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,
            await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start, eventKinds: [4625]), ct);
        await PasswordFirstBatchPostgresTests.SeedBacklog(owner, ct, total: 30001, spacing: 0.36, accountCount: 130);
        await PostCollectionPostgres.Sql(owner, """
            update sli_agent_module_bindings set password_detection_domain_id=1 where module_id='sli.windows.ad-dc';
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select '00000000-0000-4000-8000-000000004180',id,id,'telegram',true
                from auth_users where username='platform-owner';
            """, ct);

        long finding = 0;
        long attempts = 0;
        double worst = 0;
        var passes = new[] { 0, 1 }.Concat(Enumerable.Range(14, 23)).ToArray();
        foreach (int pass in passes)
        {
            // Each new runtime and physical connection reads the durable cursor.
            await using var runtime = Runtime(fixture);
            await using var worker = await runtime.OpenAsync(ct);
            var scope = await Scope(worker, ct);
            var now = pass == 0 ? start.AddSeconds(215.8) : start.AddMinutes(5 * pass);
            var timer = Stopwatch.StartNew();
            await Pass(runtime, worker, scope, PasswordAttacks.Spray, now, ct);
            timer.Stop();
            worst = Math.Max(worst, timer.Elapsed.TotalMilliseconds);
            var observed = Assert.Single(await Findings(owner, PasswordAttacks.Spray, ct));
            long count = observed.Facts.Number("attempts");
            Assert.True(count > attempts);
            attempts = count;
            if (pass == 0)
            {
                finding = observed.Id;
                Assert.Equal(600, attempts);
                Assert.Equal(130, observed.Facts.Number("account_count"));
                Assert.Equal(20, observed.Facts["accounts"]!.AsArray().Count);
                Assert.Contains("130", Title(observed.Facts, PasswordAttacks.Spray, "en"));
                Assert.Contains("600", Title(observed.Facts, PasswordAttacks.Spray, "ru"));
            }
            Assert.Equal(finding, observed.Id);
            Assert.Equal(50, observed.Evidence);
        }
        Assert.Equal(30001, attempts);
        await using (var evidence = new NpgsqlCommand("select array_agg(event_id order by event_id) from public.finding_event_copies337 where finding_id=@finding", owner))
        {
            evidence.Parameters.AddWithValue("finding", finding);
            Assert.Equal(Enumerable.Range(900001, 10).Concat(Enumerable.Range(929962, 40)).Select(id => (long)id),
                (long[])(await evidence.ExecuteScalarAsync(ct))!);
        }
        output.WriteLine($"Spray: first pass 600 / 130, 3 h total {attempts}, {passes.Length} passes, maximum {worst:F0} ms including publication, one finding after restart and an 11,000-event catch-up.");
        Assert.True(worst < 2000, $"Maximum detection + publication pass: {worst:F0} ms");
        await using var status = new NpgsqlCommand("select state from public.read_password_threshold_status418(array[1::bigint]) where rule_id=@rule", owner);
        status.Parameters.AddWithValue("rule", PasswordAttacks.Spray);
        Assert.Equal("current", await status.ExecuteScalarAsync(ct));
        await using var retired = new NpgsqlCommand("select count(*) from public.semantic_password_checkpoints", owner);
        Assert.Equal(0L, await retired.ExecuteScalarAsync(ct));
        await using var notifications = new NpgsqlCommand("select count(*) from public.notification_outbox where object_kind='semantic_finding' and channel='telegram'", owner);
        Assert.Equal(1L, await notifications.ExecuteScalarAsync(ct));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Flood_opens_five_problems_and_upgrade_preserves_history(bool upgrade)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: upgrade ? 442 : null);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddHours(-7).ToUnixTimeSeconds());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,
            await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start.AddSeconds(-5),
                eventKinds: [4625], nativeAddresses: ["192.0.2.250"]), ct);
        await PostCollectionPostgres.Sql(owner, """
            update sli_agent_module_bindings set password_detection_domain_id=1 where module_id='sli.windows.ad-dc';
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                select '00000000-0000-4000-8000-000000004401',id,id,'telegram',true
                from auth_users where username='platform-owner';
            """, ct);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        await using var runtime = Runtime(fixture);
        await using var worker = await runtime.OpenAsync(ct);
        var scope = await Scope(worker, ct);
        foreach (string rule in PasswordAttacks.Rules)
            await Pass(runtime, worker, scope, rule, start, ct);

        var spray = Enumerable.Range(1, 40).SelectMany(address => Enumerable.Range(1, 18)
            .Select(user => (Account: $"spray-user-{user}", Address: $"192.0.2.{address}",
                At: start.AddMinutes(9 * (address - 1)).AddSeconds(user - 1))));
        var brute = Enumerable.Range(1, 3).SelectMany(account => Enumerable.Range(1, 20)
            .Select(address => (Account: $"brute-user-{account}", Address: $"198.51.100.{address}",
                At: start.AddMinutes(350).AddSeconds(address))));
        var attacks = spray.Concat(brute).OrderBy(item => item.At).ToArray();
        var last = attacks[^1].At;
        async Task AttackInput((string Account, string Address, DateTimeOffset At)[] rows, int sequence, int record)
        {
            var input = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: rows.Select(_ => 4625).ToArray(), registered: (agent, agent, 900001, 1),
                packetId: Guid.NewGuid(), sequence: sequence, firstRecordId: record,
                nativeAccounts: rows.Select(row => row.Account).ToArray(),
                nativeAddresses: rows.Select(row => row.Address).ToArray(),
                nativeTimestamps: rows.Select(row => PasswordJson.Stamp(row.At)).ToArray());
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, input, ct);
        }
        await AttackInput(attacks, 2, 101);
        foreach (string rule in PasswordAttacks.Rules)
            await Pass(runtime, worker, scope, rule, last.AddMinutes(1), ct);

        var auditAt = start.AddMinutes(352);
        var audit = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: Enumerable.Repeat(4719, 16).ToArray(), registered: (agent, agent, 900001, 1),
            packetId: Guid.NewGuid(), sequence: 3, firstRecordId: 1001,
            nativeTimestamps: Enumerable.Range(0, 16).Select(i => PasswordJson.Stamp(auditAt.AddSeconds(i))).ToArray(),
            nativeFields: new Dictionary<string, string> {
                ["SubjectUserName"] = "audit-operator", ["SubjectDomainName"] = "example.test",
                ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1105",
                ["CategoryId"] = "%%8273", ["SubcategoryId"] = "%%12544",
                ["SubcategoryGuid"] = "{0cce9215-69ae-11d9-bed3-505054503030}", ["AuditPolicyChanges"] = "%%8448"
            });
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, audit, ct);
        var detection = await new DetectionProducer(new(), new()).RunOnceAsync(worker, ct, refreshImport: false);
        Assert.Equal(0, detection.Failed);
        Assert.Equal(16, detection.Jobs);
        await Publish(runtime, worker, detection.Jobs, ct);

        async Task<long> Count(string query)
        {
            await using var command = new NpgsqlCommand(query, owner);
            return (long)(await command.ExecuteScalarAsync(ct))!;
        }
        const string open = "select count(*) from findings where status='new'";
        const string notifications = "select count(*) from notification_outbox where object_kind='semantic_finding' and state='pending'";
        const string history = "select count(*) from finding_status_history";
        var later = last.AddMinutes(21);
        Task LaterBurst() => AttackInput(Enumerable.Range(1, 18)
            .Select(i => ($"spray-user-{i}", "192.0.2.1", later.AddSeconds(i))).ToArray(), 4, 2001);
        if (upgrade)
        {
            Assert.Equal(59L, await Count(open));
            await PostCollectionPostgres.Sql(owner, """
                update findings set password_threshold_facts418=password_threshold_facts418-'account_members'-'address_members'
                where password_threshold_facts418 is not null;
                """, ct);
            await PostCollectionPostgres.Sql(owner, """
                with retired as (
                    insert into findings(fingerprint,rule_code,title,severity,confidence,status,first_seen_utc,last_seen_utc,
                        evidence_count,status_reason,repeat_count,closed_at)
                    values('synthetic-closed-440','semantic.qw.password-spray','Reviewed campaign','high',1,'closed',
                        to_jsonb(clock_timestamp()-interval '2 days')#>>'{}',to_jsonb(clock_timestamp()-interval '2 days')#>>'{}',
                        0,'Reviewed before upgrade',0,clock_timestamp()-interval '1 day') returning id
                )
                insert into finding_status_history(finding_id,old_status,new_status,changed_by,note)
                select id,'new','closed','fixture-operator','Reviewed before upgrade' from retired
                """, ct);
            Assert.Equal(442L, await Count("select max(version)::bigint from schema_migrations"));
            await PostCollectionPostgres.Sql(owner, "revoke temporary on database postgres from public", ct);
            long before = await Count(history);
            string path = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/444_detection_campaigns.sql");
            await fixture.Pg.ApplyFileAsync(path, null, ct);
            Assert.Equal(5L, await Count(open));
            Assert.Equal(54L, await Count("select count(*) from findings where status='closed' and status_reason like 'problem_campaign_merged444:%'"));
            Assert.Equal(before + 54, await Count(history));
            Assert.Equal(1L, await Count("""
                select count(*) from finding_status_history h join findings f on f.id=h.finding_id
                where f.fingerprint='synthetic-closed-440' and f.status='closed'
                  and h.changed_by='fixture-operator' and h.note=f.status_reason and h.note='Reviewed before upgrade'
                """));
            await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(path, ".rollback.sql"), null, ct);
            Assert.Equal(59L, await Count(open));
            Assert.Equal(before, await Count(history));
            await fixture.Pg.ApplyFileAsync(path, null, ct);
        }
        else Assert.Equal(5L, await Count(notifications));
        Assert.Equal(5L, await Count(open));
        Assert.Equal(5L, await Count("select count(*) from public.home_published_findings424(array(select id from findings where status='new'))"));
        Assert.Equal(1L, await Count("select count(*) from findings where status='new' and rule_code='semantic.qw.audit-disabled'"));
        await using (var command = new NpgsqlCommand("""
            select last_seen_utc::timestamptz from findings where status='new' and rule_code='semantic.qw.audit-disabled'
            """, owner))
            Assert.Equal(auditAt.AddSeconds(15).UtcDateTime, await command.ExecuteScalarAsync(ct));
        Assert.Equal(3L, await Count("""
            select count(*) from findings where status='new' and rule_code='semantic.qw.password-brute-force'
            and password_threshold_facts418->>'attempts'='20' and password_threshold_facts418->>'address_count'='20'
            """));
        await using (var command = new NpgsqlCommand("""
            select password_threshold_facts418::text from findings where status='new' and rule_code='semantic.qw.password-spray'
            """, owner))
        {
            var facts = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsObject();
            Assert.Equal(40, facts.Number("address_count"));
            Assert.Equal(18, facts.Number("account_count"));
            Assert.Equal(720, facts.Number("attempts"));
            Assert.Equal(start, D.Time(facts["first"]));
            Assert.Equal(last, D.Time(facts["last"]));
            Assert.Contains("40 addresses", Title(facts, PasswordAttacks.Spray, "en"));
            Assert.Contains("40 адресов", Title(facts, PasswordAttacks.Spray, "ru"));
            Assert.Contains("5 h 51 min", Title(facts, PasswordAttacks.Spray, "en", queue: true));
        }

        if (!upgrade)
        {
            await LaterBurst();
            await Pass(runtime, worker, scope, PasswordAttacks.Spray, later.AddMinutes(1), ct);
            Assert.Equal(6L, await Count(notifications));
            Assert.Equal(5L, await Count(open));
            Assert.Equal(1L, await Count("select count(*) from finding_status_history where note='password_campaign_quiet444'"));
            await using var expire = new NpgsqlCommand("select public.expire_password_campaigns444()", worker);
            Assert.Equal(1, await expire.ExecuteScalarAsync(ct));
            Assert.Equal(4L, await Count(open));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Brute_force_correlates_success_and_4776_without_crossing_subthreshold_counts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = DateTimeOffset.UtcNow.AddMinutes(-5);
        var rows = new List<(int Kind, string Account, string Address, int Second)>();
        for (int i = 0; i < 25; i++) rows.Add((4625, "Case-Target", $"192.0.2.{i % 4 + 1}", i));
        rows.Add((4624, "case-target", "192.0.2.4", 25));
        for (int i = 0; i < 20; i++) rows.Add((4776, "fallback", "-", i));
        for (int i = 0; i < 19; i++)
        {
            rows.Add((4625, "sub-threshold", "192.0.2.50", i));
            rows.Add((4776, "sub-threshold", "-", i));
        }
        for (int i = 0; i < 9; i++) rows.Add((4625, $"spray-target-{i}", "192.0.2.51", i));
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, occurredAt: start,
            eventKinds: rows.Select(r => r.Kind).ToArray(), nativeAccounts: rows.Select(r => r.Account).ToArray(),
            nativeAddresses: rows.Select(r => r.Address).ToArray(), nativeTimestamps: rows.Select(r =>
                start.AddSeconds(r.Second).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture)).ToArray());
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using var runtime = Runtime(fixture);
        await using var worker = await runtime.OpenAsync(ct);
        var detection = await new DetectionProducer(new(), new()).RunOnceAsync(worker, ct, refreshImport: false);
        Assert.Equal(0, detection.Failed);
        Assert.Equal(2, detection.Jobs);
        await Publish(runtime, worker, detection.Jobs, ct);

        var findings = await Findings(owner, PasswordAttacks.Brute, ct);
        Assert.Equal(2, findings.Count);
        var brute = Assert.Single(findings, f => f.Severity == "critical");
        Assert.Equal(25, brute.Facts.Number("attempts"));
        Assert.Equal(4, brute.Facts.Number("address_count"));
        Assert.True(brute.Facts.Flag("password_success"));
        Assert.Contains("25", Title(brute.Facts, PasswordAttacks.Brute, "en"));
        var fallback = Assert.Single(findings, f => f.Severity == "high");
        Assert.Equal(20, fallback.Facts.Number("attempts"));
        Assert.Empty(await Findings(owner, PasswordAttacks.Spray, ct));
        output.WriteLine("Brute force: 25 failures across 4 addresses plus success => critical. NTLM-only 20 => high. 19 with same-second NTLM duplicates and 9 spray accounts => no findings.");
    }

    private static string Title(JsonObject facts, string rule, string locale, bool queue = false) => ProblemJson.Text(ProblemPresentation.RuleMessage(
        new() { ["rule_code"] = "semantic." + rule, ["presentation_facts"] = facts.DeepClone() }, "title", locale, queueTitle: queue)["text"]);

    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture) => PasswordProducerRuntime.Create(
        name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
        _ => throw new InvalidOperationException());

    private static async Task<PasswordScope> Scope(NpgsqlConnection db, CancellationToken ct, string sourceInstance = "")
    {
        await using var source = new NpgsqlCommand("""
            select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
                and (@instance='' or source#>>'{scope,source_instance_id}'=@instance)
            """, db);
        source.Parameters.AddWithValue("instance", sourceInstance);
        return PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
    }

    private static async Task Pass(PasswordProducerRuntime runtime, NpgsqlConnection worker, PasswordScope scope, string rule, DateTimeOffset now, CancellationToken ct)
    {
        int jobs = await DetectionProducer.RunPasswordThreshold(worker, scope, rule, now, ct);
        await Publish(runtime, worker, jobs, ct);
    }

    private static async Task Publish(PasswordProducerRuntime runtime, NpgsqlConnection worker, int jobs, CancellationToken ct)
    {
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.FindingsMode, 16);
        int completed = 0;
        do
        {
            var result = await production.ProcessRisk(worker, ct);
            if (result.Number("failed") != 0)
            {
                await using var error = new NpgsqlCommand("select last_error_detail from semantic_risk_evaluation_jobs where evaluation_status='failed' order by updated_at desc limit 1", worker);
                Assert.Fail($"Threshold risk publication failed: {await error.ExecuteScalarAsync(ct)}");
            }
            completed += (int)result.Number("completed");
            if (result.Number("completed") == 0) break;
        } while (completed < jobs);
        Assert.Equal(jobs, completed);
    }

    private static async Task<List<(long Id, string Severity, int Evidence, JsonObject Facts)>> Findings(NpgsqlConnection db, string rule, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select id,severity,evidence_count,public.password_problem_facts395(id,rule_code)::text from findings where rule_code=@rule", db);
        command.Parameters.AddWithValue("rule", "semantic." + rule);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var result = new List<(long, string, int, JsonObject)>();
        while (await rows.ReadAsync(ct)) result.Add((rows.GetInt64(0), rows.GetString(1), rows.GetInt32(2), JsonNode.Parse(rows.GetString(3))!.AsObject()));
        return result;
    }
}
