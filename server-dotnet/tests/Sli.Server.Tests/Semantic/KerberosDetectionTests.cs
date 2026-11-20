using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using HomePresentation = Sli.Server.Domains.HomePresentation;
using HomeSummaryRepository = Sli.Server.Domains.HomeSummaryRepository;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class KerberosDetectionTests
{
    static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-11-13T08:00:00Z");
    static readonly PasswordScope Scope = new("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "synthetic", "generation", "");
    internal static DetectionRow[] Events(bool asrep, int offset = 0, string account = "synthetic-user") =>
        Enumerable.Range(0, asrep ? 1 : 10).Select(i => new DetectionRow(
            new(Scope, "core_event", (offset + i + 1).ToString(), new string('a', 64)), Start.AddSeconds(offset + i),
            asrep ? 4768 : 4769, "dc.example.test", new() {
                ["TargetUserName"] = account, ["TargetDomainName"] = "example.test", ["IpAddress"] = "192.0.2.8",
                ["ServiceName"] = "synthetic-service-" + i, ["TicketEncryptionType"] = "0x17", ["PreAuthType"] = "0", ["Status"] = "0x0"
            })).ToArray();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CatalogSeriesAndRepeatProduceOneAccountSignalWithNewEvidence(bool asrep)
    {
        var first = Assert.Single(IdentityAttacks.Evaluate(Scope, Events(asrep), Start.AddMinutes(2)));
        var repeated = Assert.Single(IdentityAttacks.Evaluate(Scope, [..Events(asrep), ..Events(asrep, 20)], Start.AddMinutes(2)));
        IdentityAttacks.Validate(repeated);
        Assert.Equal(asrep ? "qw.asrep-roasting" : "qw.kerberoasting", repeated["rule_id"]!.ToString());
        Assert.Equal(first["entity_key"]!.ToString(), repeated["entity_key"]!.ToString());
        Assert.Equal("high", repeated["effective_severity"]!.ToString());
        Assert.Contains(repeated["evidence_refs"]!.AsArray(), r => int.Parse(r!["native_id"]!.ToString()) > 20);
        Assert.Single(IdentityAttacks.Evaluate(Scope, [..Events(asrep), ..Events(asrep)], Start.AddMinutes(2)));
    }

    [Fact]
    public void DifferentAccountsAtOneAddressDoNotCombineServiceCounts()
    {
        var rows = Events(false).Select((r, i) => r with { Fields = new JsonObject(r.Fields!.Select(p =>
            KeyValuePair.Create(p.Key, p.Key == "TargetUserName" ? JsonValue.Create("synthetic-user-" + i) : p.Value?.DeepClone()))) }).ToArray();
        Assert.Empty(IdentityAttacks.Evaluate(Scope, rows, Start.AddMinutes(2)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProblemObjectIsTheAccountAcrossClientAddresses(bool asrep)
    {
        var original = Assert.Single(IdentityAttacks.Evaluate(Scope, Events(asrep), Start.AddMinutes(2)));
        var moved = Events(asrep, 20);
        foreach (var row in moved) row.Fields!["IpAddress"] = "198.51.100.8";
        var next = Assert.Single(IdentityAttacks.Evaluate(Scope, moved, Start.AddMinutes(2)));
        Assert.Equal(original["entity_key"]!.ToString(), next["entity_key"]!.ToString());
        var other = Assert.Single(IdentityAttacks.Evaluate(Scope, Events(asrep, account: "another-synthetic-user"), Start.AddMinutes(2)));
        Assert.NotEqual(original["entity_key"]!.ToString(), other["entity_key"]!.ToString());
    }

    [Theory]
    [InlineData(false, "ru", "1) Выясните у владельца учётной записи, запускал ли он проверку. 2) Если нет — смените её пароль. 3) Смените пароли служебных учётных записей из списка; задайте им длинные пароли.")]
    [InlineData(false, "en", "1) Ask the account owner whether they ran a check. 2) If not, change the account password. 3) Change the passwords of the service accounts in the list; set long passwords for them.")]
    [InlineData(true, "ru", "1) Снимите у учётной записи флаг «Без предварительной проверки подлинности Kerberos». 2) Смените её пароль.")]
    [InlineData(true, "en", "1) Clear the account option \"Do not require Kerberos preauthentication\". 2) Change its password.")]
    public void NextStepsMatchCatalog(bool asrep, string language, string expected)
    {
        var finding = new JsonObject { ["rule_code"] = asrep ? "semantic.qw.asrep-roasting" : "semantic.qw.kerberoasting" };
        var queue = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language);
        Assert.Equal(expected, queue["next_text"]!.ToString());
        Assert.Equal(expected, HomePresentation.Finding(finding, language)["next_step"]!.ToString());
    }

    [Theory]
    [InlineData("ru", "Для synthetic-user выдан билет без предварительной проверки в 2026-11-13T08:00:00Z.")]
    [InlineData("en", "A ticket for synthetic-user was issued without pre-authentication at 2026-11-13T08:00:00Z.")]
    public void MissingClientAddressOmitsOnlyTheClientClause(string language, string expected)
    {
        var finding = new JsonObject { ["rule_code"] = "semantic.qw.asrep-roasting",
            ["presentation_facts"] = new JsonObject { ["account"] = "synthetic-user", ["time"] = "2026-11-13T08:00:00Z" } };
        Assert.Equal(expected, ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language)["what_happened"]!.ToString());
    }

    [Theory]
    [InlineData("TicketEncryptionType", "0x12")]
    [InlineData("Status", "0x6")]
    public void KerberoastingRequiresSuccessfulRc4Tickets(string field, string value)
    {
        var rows = Events(false); foreach (var row in rows) row.Fields![field] = value;
        Assert.Empty(IdentityAttacks.Evaluate(Scope, rows, Start.AddMinutes(2)));
        Assert.Empty(IdentityAttacks.Evaluate(Scope, Events(false).Take(4).ToArray(), Start.AddMinutes(2)));
    }

    [Theory]
    [InlineData("PreAuthType", "2")]
    [InlineData("Status", "0x6")]
    [InlineData("PreAuthType", null)]
    public void AsrepRequiresSuccessfulIssueWithoutPreauthentication(string field, string? value)
    {
        var rows = Events(true); rows[0].Fields![field] = value;
        Assert.Empty(IdentityAttacks.Evaluate(Scope, rows, Start.AddMinutes(2)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativePublicationReplaysIdempotentlyAndRejectsChangedProof(bool asrep)
    {
        var events = Events(asrep);
        var sql = new DetectionProducerTests.Sql { Native = events.Select(r => DetectionTests.Native(r)).ToList() };
        var source = new JsonObject { ["scope"] = Scope.Document };
        var ct = TestContext.Current.CancellationToken;
        Assert.Equal(1, await DetectionProducer.RunIdentity(sql, source, Start.AddMinutes(1), ct));
        Assert.Equal(1, await DetectionProducer.RunIdentity(sql, source, Start.AddMinutes(1), ct));
        Assert.Single(sql.Signals); Assert.Single(sql.Jobs);
        sql.Native.AddRange(Events(asrep, 20).Select(r => DetectionTests.Native(r)));
        Assert.Equal(1, await DetectionProducer.RunIdentity(sql, source, Start.AddMinutes(2), ct));
        var updated = sql.Signals.Values.Last();
        Assert.Equal(sql.Signals.Values.First()["entity_key"]!.ToString(), updated["entity_key"]!.ToString());
        sql.Native[^1]["source_xml"] = sql.Native[^1]["source_xml"]!.ToString().Replace(
            asrep ? ">0</Data>" : "0x17", asrep ? ">2</Data>" : "0x12", StringComparison.Ordinal);
        await Assert.ThrowsAsync<DetectionFailure>(() => DetectionProducer.VerifyIdentity(sql, updated, ct));
    }

    [Theory]
    [InlineData(false, "ru", "Учётная запись запросила билеты многих служб", "example.test\\synthetic-user запросила билеты 10 служб за 1 мин с 192.0.2.8.")]
    [InlineData(false, "en", "An account requested tickets for many services", "example.test\\synthetic-user requested tickets for 10 services in 1 min from 192.0.2.8.")]
    [InlineData(true, "ru", "Запрошен билет учётной записи без проверки пароля", "Для example.test\\synthetic-user выдан билет без предварительной проверки, запрос с 192.0.2.8 в 2026-11-13T08:00:00Z.")]
    [InlineData(true, "en", "Ticket requested for an account without pre-authentication", "A ticket for example.test\\synthetic-user was issued without pre-authentication, requested from 192.0.2.8 at 2026-11-13T08:00:00Z.")]
    public void QueueAndHomeUseCatalogWordingAndDetectionFacts(bool asrep, string language, string title, string what)
    {
        var signal = Assert.Single(IdentityAttacks.Evaluate(Scope, Events(asrep), Start.AddMinutes(2)));
        var finding = new JsonObject { ["id"] = 1, ["rule_code"] = "semantic." + signal["rule_id"]!.ToString(),
            ["title"] = "Saved title", ["occurrence_count"] = 2, ["evidence_count"] = asrep ? 2 : 20,
            ["last_seen_utc"] = "2026-11-13T08:01:00Z", ["presentation_facts"] = new JsonObject {
                ["account"] = "example.test\\synthetic-user", ["source"] = "192.0.2.8", ["count"] = asrep ? 1 : 10,
                ["minutes"] = 1, ["time"] = "2026-11-13T08:00:00Z", ["computer"] = "dc.example.test" } };
        var queue = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language);
        Assert.Equal(title, queue["title"]!.ToString()); Assert.Equal(what, queue["what_happened"]!.ToString());
        var home = HomePresentation.Finding(finding, language);
        Assert.Equal(title, home["title"]!.ToString()); Assert.Equal(what, home["what"]!.ToString());
        var restricted = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue", fields: ["security"]), language);
        Assert.DoesNotContain("synthetic-user", restricted.ToJsonString()); Assert.DoesNotContain("192.0.2.8", restricted.ToJsonString());
    }

    sealed class Connections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => pg.OpenAsync(ct, "adlog_user");
    }

    [Fact]
    public async Task LinkedProofReachesQueueAndHomeAndOnlyNewEvidenceIncreasesRepeatCount()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        var pg = fixture.Pg;
        await using var db = await pg.OpenAsync(ct);
        long domain = await EventShortReadPostgresTests.SeedRecorderAsync(db, ct);
        await using(var removed = new NpgsqlCommand(
            "select to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null", db))
            Assert.Equal(true, await removed.ExecuteScalarAsync(ct));
        foreach (bool asrep in new[] { false, true }) {
            var events = Events(asrep);
            var signal = Assert.Single(IdentityAttacks.Evaluate(Scope, events, Start.AddMinutes(2)));
            string rule = "semantic." + signal["rule_id"]!.ToString();
            long id;
            await using (var tx = await db.BeginTransactionAsync(ct)) {
                var session = new SemanticSession(db, tx);
                object?[] insert = [rule, rule, "Saved title", "high", 1m, "2026-11-13T08:00:00Z", "2026-11-13T08:00:00Z",
                    null, null, null, "", "", ""];
                id = (await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding7, ct, insert))[0]!.Number("id");
                Assert.Empty(await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding7, ct, insert));
                // Three series exceed the detail preview's 20 rows. Service cardinality stays ten.
                for (int batch = 0; batch < 3; batch++) {
                    foreach (var row in Events(asrep, batch * 20))
                        await CopyEvidence(session, id, domain, row, asrep, null, ct);
                    int count = (batch + 1) * events.Length;
                    object?[] update = ["Saved title", "high", 1m, "2026-11-13T08:00:00Z", "2026-11-13T08:00:49Z",
                        null, null, null, "", "", "", count, (long)count, id, null];
                    await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding12, ct, update);
                    await session.QueryAsync(SemanticRiskSql.publish_enabled_scenario_finding12, ct, update);
                    var stored = (await session.QueryAsync("select repeat_count,evidence_count from findings where id=$1", ct, id))[0]!;
                    Assert.Equal(batch, stored.Number("repeat_count")); Assert.Equal(count, stored.Number("evidence_count"));
                }
                Assert.Equal(1, (await session.QueryAsync("select count(*) as count from findings where rule_code=$1", ct, rule))[0]!.Number("count"));
                await tx.CommitAsync(ct);
            }
            await using (var readDb = await pg.OpenAsync(ct, "adlog_user")) {
                await using var tx = await readDb.BeginTransactionAsync(ct);
                var finding = new JsonObject { ["id"] = id, ["rule_code"] = rule, ["occurrence_count"] = 3 };
                await ProblemRepository.AttachKerberosFacts(tx, [finding], ct);
                var homeRows = await new HomeSummaryRepository(new Connections(pg)).ReadAsync(
                    "select id,rule_code from findings where id=@id", new Dictionary<string, object?> { ["id"] = id }, ct);
                foreach (string language in new[] { "ru", "en" }) {
                    var queue = ProblemPresentation.Finding(finding, ProblemLifecycleTests.Access("security.queue"), language);
                    var home = HomePresentation.Finding(Assert.Single(homeRows), language);
                    string expected = asrep ? language == "ru"
                        ? "Для example.test\\synthetic-user выдан билет без предварительной проверки, запрос с 192.0.2.8 в 2026-11-13T08:00:40Z."
                        : "A ticket for example.test\\synthetic-user was issued without pre-authentication, requested from 192.0.2.8 at 2026-11-13T08:00:40Z."
                        : language == "ru" ? "example.test\\synthetic-user запросила билеты 10 служб за 1 мин с 192.0.2.8."
                        : "example.test\\synthetic-user requested tickets for 10 services in 1 min from 192.0.2.8.";
                    Assert.Equal(expected, queue["what_happened"]!.ToString()); Assert.Equal(expected, home["what"]!.ToString());
                }
            }
            await using (var tx = await db.BeginTransactionAsync(ct)) {
                var session = new SemanticSession(db, tx);
                foreach (var row in Events(asrep, 60))
                    await CopyEvidence(session, id, domain, row, asrep, "198.51.100.8", ct);
                await tx.CommitAsync(ct);
            }
            var latest = Assert.Single(await new HomeSummaryRepository(new Connections(pg)).ReadAsync(
                "select rule_code,jsonb_build_object('id',id) as representative from findings where id=@id", new Dictionary<string, object?> { ["id"] = id }, ct));
            Assert.Equal("198.51.100.8", latest["presentation_facts"]!["source"]!.ToString());
            Assert.Equal(1, latest["presentation_facts"]!.Number("minutes"));
            if (!asrep) Assert.Equal(10, latest["presentation_facts"]!.Number("count"));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static Task<JsonArray> CopyEvidence(SemanticSession session, long finding, long domain,
        DetectionRow evidence, bool asrep, string? client, CancellationToken ct)
    {
        long eventId = long.Parse(evidence.Ref.NativeId) + (asrep ? 1000 : 0);
        var fields = evidence.Fields!.ToDictionary(item => item.Key, item => item.Value!.GetValue<string>(), StringComparer.Ordinal);
        if (client is not null) fields["IpAddress"] = client;
        // The current queue and home readers resolve the retained copy after hot retention.
        var (_, projection, row) = EventShortReadPostgresTests.Event(eventId, evidence.EventId,
            evidence.At, domain, fields: fields);
        return session.QueryAsync("""
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,target,source,
                computer,method,outcome,fields,source_sha256,evidence_role,event_record_id)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'semantic_scenario',$2)
            """, ct, finding, row.EventId, row.Time, row.Kind, row.DomainId, row.Actor, row.Target, row.Source,
            row.Computer, JsonNode.Parse(row.Method), JsonNode.Parse(row.Outcome), JsonSerializer.SerializeToNode(row.Fields),
            Convert.FromHexString(projection.IdentityHash));
    }
}
