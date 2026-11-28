using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class SecurityProblemsV2Tests
{
    [Theory]
    [InlineData("ru", 1, "1 адрес", "1 попытка", "1 учётная запись")]
    [InlineData("ru", 2, "2 адреса", "2 попытки", "2 учётные записи")]
    [InlineData("ru", 5, "5 адресов", "5 попыток", "5 учётных записей")]
    [InlineData("ru", 21, "21 адрес", "21 попытка", "21 учётная запись")]
    [InlineData("en", 1, "1 address", "1 attempt", "1 account")]
    [InlineData("en", 2, "2 addresses", "2 attempts", "2 accounts")]
    [InlineData("en", 5, "5 addresses", "5 attempts", "5 accounts")]
    [InlineData("en", 21, "21 addresses", "21 attempts", "21 accounts")]
    public void PasswordTitlesAndFactsUseLocalizedNumberForms(string language, int count, string addresses, string attempts, string accounts)
    {
        var brute = new JsonObject {
            ["rule_code"] = "semantic.qw.password-brute-force",
            ["presentation_facts"] = new JsonObject { ["version"] = 1, ["attempts"] = count,
                ["address_count"] = count, ["account"] = "synthetic-user" }
        };
        var spray = new JsonObject {
            ["rule_code"] = "semantic.qw.password-spray",
            ["presentation_facts"] = new JsonObject { ["version"] = 1, ["attempts"] = count,
                ["account_count"] = count, ["source"] = "192.0.2.10" }
        };
        string Message(JsonObject row, string suffix) =>
            ProblemPresentation.RuleMessage(row, suffix, language)["text"]!.ToString();
        Assert.EndsWith($"{addresses} · {attempts}", Message(brute, "title"));
        Assert.EndsWith($"{accounts} · {attempts}", Message(spray, "title"));

        var sprayFacts = spray["presentation_facts"]!.AsObject();
        sprayFacts.Remove("version");
        sprayFacts["count"] = count;
        sprayFacts["time"] = "2026-11-13T08:00:00Z";
        Assert.Contains(language == "ru" && count % 10 == 1 ? $"{count} учётную запись" : accounts, Message(spray, "what"));
    }

    [Theory]
    [InlineData("en", "Sign-in attempts from 192.0.2.28 against 18 accounts · 2,002 attempts",
        "Password guessing against test-user · 21 addresses · 111,890 attempts")]
    [InlineData("ru", "Попытки входа с адреса 192.0.2.28 · 18 учётных записей · 2\u00a0002 попытки",
        "Подбор пароля к учётной записи test-user · 21 адрес · 111\u00a0890 попыток")]
    public void QueueTitlesUsePublishedTotalsInsteadOfRetainedEvidence(string language, string sprayTitle, string bruteTitle)
    {
        foreach (bool spray in new[] { true, false })
        {
            int attempts = spray ? 2002 : 111890;
            var raw = new JsonObject {
                ["id"] = 1, ["deferred_until"] = null, ["evidence_count"] = 50,
                ["rule_code"] = spray ? "semantic.qw.password-spray" : "semantic.qw.password-brute-force",
                ["presentation_facts"] = new JsonObject { ["version"] = 1, ["attempts"] = attempts,
                    ["source"] = "192.0.2.28", ["account"] = "test-user", ["account_count"] = 18, ["address_count"] = 21,
                    ["accounts"] = new JsonArray("test-account-one", "test-account-two"),
                    ["addresses"] = new JsonArray("198.51.100.10", "198.51.100.11") }
            };
            var queue = ProblemPresentation.Finding(raw, Access, language, queue: true, includeDescription: false);
            Assert.Equal(spray ? sprayTitle : bruteTitle, (string?)queue["title_text"]);
            Assert.Equal(attempts, (int?)queue["queue_attack"]!["event_count"]);
            Assert.Equal(21, (int?)queue["queue_attack"]!["address_count"]);
            var restricted = Sli.Server.Tests.Problems.ProblemLifecycleTests.Access("security.queue", fields: ["security"]);
            var limited = ProblemPresentation.Finding(raw, restricted, language, queue: true, includeDescription: false);
            Assert.DoesNotContain("test-user", (string)limited["title_text"]!);
            Assert.DoesNotContain("192.0.2.28", (string)limited["title_text"]!);
            Assert.Null(limited["queue_attack"]!["address_count"]);

            raw["presentation_facts"]!.AsObject().Remove("version");
            var legacy = ProblemPresentation.Finding(raw, Access, language, queue: true, includeDescription: false);
            Assert.Null(legacy["queue_attack"]!["event_count"]);
        }
    }

    [Theory]
    [InlineData("ru")]
    [InlineData("en")]
    public void PasswordFactsRespectQueueAndHomeFieldAccess(string language)
    {
        var raw = new JsonObject {
            ["id"] = 1, ["rule_code"] = "semantic.qw.password-spray",
            ["presentation_facts"] = new JsonObject { ["account"] = "identity-marker", ["source"] = "technical-marker",
                ["actor"] = "identity-marker", ["computer"] = "identity-marker", ["count"] = 15,
                ["time"] = "2026-11-13T08:00:40+00:00", ["password_success"] = true }
        };
        var restricted = Sli.Server.Tests.Problems.ProblemLifecycleTests.Access("security.queue", fields: ["security"]);
        var queue = ProblemPresentation.Finding(raw, restricted, language, queue: true, includeDescription: true);
        var home = HomePresentation.Finding(raw, language, identity: false, technical: false);
        foreach (var view in new[] { queue, home }) {
            Assert.DoesNotContain("identity-marker", view.ToJsonString());
            Assert.DoesNotContain("technical-marker", view.ToJsonString());
        }
        Assert.Equal(language == "ru" ? "После перебора паролей вход удался" : "Sign-in succeeded after password guessing", home["title"]!.ToString());
        raw["presentation_facts"]!["version"] = 1;
        raw["presentation_facts"]!["reported_domains"] = new JsonArray(JsonValue.Create("reported-domain-marker"));
        Assert.DoesNotContain("reported-domain-marker", ProblemPresentation.Finding(raw, restricted, language, queue: true, includeDescription: true).ToJsonString());
        Assert.Contains("reported-domain-marker", ProblemPresentation.Finding(raw, Access, language, queue: true, includeDescription: true)["what_happened"]!.ToString());
    }

    [Theory]
    [InlineData("brute", false, 10)]
    [InlineData("brute", false, 25)]
    [InlineData("spray", false, 15)]
    [InlineData("spray", true, 15)]
    public async Task PasswordSeriesShowCatalogFactsInQueueAndHomeWithoutDuplicateRows(string kind, bool success, int attempts)
    {
        var scope = new PasswordScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "synthetic", "generation", "");
        var start = DateTimeOffset.Parse("2026-11-13T08:00:00Z");
        var rule = new PasswordRule(scope, kind);
        PasswordNative Native(int id, int seconds, string account, int eventId) {
            var at = start.AddSeconds(seconds);
            string status = eventId == 4624 ? "0x0" : eventId == 4771 ? "0x18" : "0xc000006a";
            string xml = $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID><TimeCreated SystemTime='{PasswordJson.Stamp(at)}'/></System><EventData><Data Name='TargetUserName'>{account}</Data><Data Name='TargetDomainName'>example.test</Data><Data Name='IpAddress'>192.0.2.10</Data><Data Name='Status'>{status}</Data><Data Name='LogonType'>3</Data></EventData></Event>";
            return PasswordNative.Parse(scope, id, new('a', 64), eventId, at, xml);
        }
        var failures = Enumerable.Range(1, attempts).Select(i => Native(i, i - 1, kind == "brute" ? "user" : "user" + i, i % 2 == 0 ? 4771 : 4625)).ToArray();
        var first = rule.Advance(new(), failures, start.AddSeconds(150));
        var emission = Assert.Single(first.Emissions);
        var events = failures;
        if (success) {
            var signedIn = Native(100, 40, "user1", 4624);
            var continuation = rule.Advance(first.State, [signedIn], start.AddSeconds(170), first.Emissions, failures);
            var update = Assert.Single(continuation.Emissions);
            var signal = PasswordSignal.Create(rule, update, Assert.Single(update.Contexts(emission.Id)), start.AddSeconds(160), failures.Append(signedIn), first.Emissions);
            Assert.Equal("critical", signal["effective_severity"]!.ToString());
            events = failures.Append(signedIn).ToArray();
        }
        await using var pg = await Pg.Start();
        await pg.Sql("""
            delete from findings_active;
            insert into findings_active(id,rule_code,target,source,first_seen_utc,last_seen_utc,evidence_count,severity)
            values(1,'semantic.qw.password-brute-force','example.test\user','192.0.2.10','2026-11-13T08:00:00Z','2026-11-13T08:00:30Z',0,'high');
            """);
        await using (var command = new NpgsqlCommand("update findings_active set rule_code=@rule,severity=@severity where id=1", pg.Db)) {
            command.Parameters.AddWithValue("rule", "semantic." + rule.Id);
            command.Parameters.AddWithValue("severity", success ? "critical" : "high");
            await command.ExecuteNonQueryAsync(Ct);
        }
        async Task AddEvents(IEnumerable<PasswordNative> native) {
            foreach (var e in native) {
                var xml = System.Xml.Linq.XElement.Parse(e.SourceXml);
                string account = xml.Descendants(xml.Name.Namespace + "Data").Single(d => (string?)d.Attribute("Name") == "TargetUserName").Value;
                await using var command = new NpgsqlCommand("""
                    insert into finding_event_details337(finding_id,event_db_id,event_id,time_created_utc,target_user_name,target_domain_name,ip_address,domain_id)
                    values(1,@id,@event,@at,@account,'example.test','192.0.2.10',7);
                    update findings_active set evidence_count=evidence_count+1 where id=1;
                    """, pg.Db);
                command.Parameters.AddWithValue("id", e.Witness.NativeId); command.Parameters.AddWithValue("event", e.EventId);
                command.Parameters.AddWithValue("at", e.Witness.At); command.Parameters.AddWithValue("account", account);
                await command.ExecuteNonQueryAsync(Ct);
            }
        }
        await AddEvents(events);
        var query = new FindingQuery(null, null, null, null, null, null, null, [7], 50, false) {
            Compact = true, PageQueue = true, GroupQueue = true, Population = "open"
        };
        foreach (string language in new[] { "ru", "en" }) {
            var raw = Assert.Single((await pg.Repository.FindingsAsync(query, Access, Ct))["items"]!.AsArray())!.AsObject();
            var view = ProblemPresentation.Finding(raw, Access, language);
            string title = success ? language == "ru" ? "После перебора паролей вход удался" : "Sign-in succeeded after password guessing"
                : kind == "brute" ? language == "ru" ? "Подбор пароля к учётной записи" : "Password guessing against an account"
                : language == "ru" ? "Попытки входа с одного адреса под разными учётными записями" : "Sign-in attempts across multiple accounts";
            string what = success ? language == "ru" ? "user1 вошла с 192.0.2.10 в 2026-11-13T08:00:40+00:00 после 15 неудачных попыток с этого же адреса." : "user1 signed in from 192.0.2.10 at 2026-11-13T08:00:40+00:00 after 15 failed attempts from the same source."
                : kind == "brute" ? language == "ru" ? $"К учётной записи user {attempts} неудачных входов с 192.0.2.10 с 2026-11-13T08:00:00+00:00." : $"{attempts} failed sign-ins to user from 192.0.2.10 since 2026-11-13T08:00:00+00:00."
                : language == "ru" ? "С 192.0.2.10 неудачные входы в 15 учётных записей с 2026-11-13T08:00:00+00:00." : "Failed sign-ins to 15 accounts from 192.0.2.10 since 2026-11-13T08:00:00+00:00.";
            Assert.Equal(title, view["title"]!.ToString()); Assert.Equal(what, view["summary"]!.ToString());
            string next = success ? language == "ru" ? "1) Немедленно смените пароль учётной записи. 2) Завершите её сеансы. 3) Проверьте в «Изменениях в домене», что она делала после входа." : "1) Change the account password immediately. 2) End its sessions. 3) Check Domain changes for its actions after the sign-in."
                : kind == "brute" ? language == "ru" ? "1) Проверьте, не сам ли пользователь ошибается (смена пароля, старое устройство). 2) Если источник чужой — закройте его на сетевом экране. 3) Смените пароль учётной записи." : "1) Check whether the user is making mistakes (a password change or an old device). 2) If the source is unfamiliar, block it on the firewall. 3) Change the account password."
                : language == "ru" ? "1) Закройте источник на сетевом экране. 2) Откройте список затронутых учётных записей и проверьте, не было ли успешного входа с того же адреса." : "1) Block the source on the firewall. 2) Open the list of affected accounts and check for a successful sign-in from the same address.";
            Assert.Equal(next, view["recommended_action"]!.ToString());
            var homeRow = Assert.Single(await pg.Rows(HomeDecisionSql.Groups(true), ("ids", new long[] { 7 }), ("from", null), ("to", null), ("since", null)))!.AsObject();
            var home = HomePresentation.Finding(homeRow, language);
            Assert.Equal(title, home["title"]!.ToString()); Assert.Equal(what, home["what"]!.ToString());
            Assert.Equal(next, home["next_step"]!.ToString());
        }
        var repeated = failures.Select(e => Native((int)e.Witness.NativeId + 200, (int)e.Witness.NativeId + 60, kind == "brute" ? "user" : "user" + e.Witness.NativeId, e.EventId)).ToArray();
        var repeat = rule.Advance(first.State, repeated, start.AddSeconds(220), first.Emissions, failures);
        Assert.Equal(emission.EpisodeKey, Assert.Single(repeat.Emissions).EpisodeKey);
        await AddEvents(repeated);
        var again = Assert.Single((await pg.Repository.FindingsAsync(query, Access, Ct))["items"]!.AsArray())!;
        Assert.Equal(failures.Length + repeated.Length, again["occurrence_count"]!.GetValue<long>());
        var repeatedHome = Assert.Single(await pg.Rows(HomeDecisionSql.Groups(true), ("ids", new long[] { 7 }), ("from", null), ("to", null), ("since", null)))!;
        Assert.Equal(again["occurrence_count"]!.GetValue<long>(), repeatedHome["occurrence_count"]!.GetValue<long>());
    }
}
