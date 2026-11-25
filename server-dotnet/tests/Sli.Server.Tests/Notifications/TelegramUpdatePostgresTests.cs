using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System.Threading.Channels;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
using Sli.Server.Problems;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public sealed class TelegramUpdatePostgresTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task WorkerDiscoversPrivateChatsAndUsesTheirSavedLanguage()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct, throughVersion: 393);
        var migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/394_notification_language.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, Ct);
        var problemAccounts = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/395_problem_account_identity.sql");
        var database = new Factory(fixture);
        await NotificationLanguages.RememberInterfaceAsync(database, 1, "en", Ct);

        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_notification_login"));
        await worker.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_notification_worker", Ct);
        await using var harness = new NotificationHarness();
        var admin = new NotificationAdministration(new NotificationAdministrationRepository(database, harness.Recipients), harness.Client, harness.Recipients);
        var principal = new Principal("session", 1, "admin", "platform-owner");
        var bot = new Bot();
        var settings = new TelegramBotSettings("https://sli.invalid/app", "1:synthetic", "http://proxy.invalid:8080", []);
        var job = new NotificationJob(Guid.NewGuid(), Guid.NewGuid(), 1, "test_problem", Guid.NewGuid(), 1, 1,
            Guid.NewGuid(), DateTime.UtcNow, null, "live", 0);
        var problem = await SeedAlertAsync(fixture, job, Ct);
        await fixture.Pg.ApplyFileAsync(problemAccounts, null, Ct);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var loop = TelegramUpdateWorker.PollOwnedAsync(worker, settings, () => Volatile.Read(ref settings), bot, stop.Token);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            var ct = deadline.Token;
            Assert.Null(await bot.Polls.Reader.ReadAsync(ct));
            await bot.Updates.Writer.WriteAsync(Message(1, 123, "/start"), ct);
            Assert.Equal(2L, await bot.Polls.Reader.ReadAsync(ct));
            Assert.Empty(bot.Replies);
            var choices = await admin.TelegramAsync(principal, "chats", new(), ct);
            var choice = Assert.Single(choices["chats"]!.AsArray())!.AsObject();
            Assert.Equal("Synthetic chat", choice["name"]!.ToString());
            Assert.Null(choice["id"]);
            Assert.Empty(harness.Bot.Calls);

            // Bind the observed chat as setup does, then let the next poll see the new mapping.
            await harness.Client.RequestAsync("bind", 1, new() { ["choice"] = choice["choice"]!.DeepClone() }, ct);
            var config = JsonNode.Parse(harness.Files.Read("telegram.json"))!.AsObject();
            Assert.Equal("123", config["recipients"]!["1"]!.ToString());
            Volatile.Write(ref settings, settings with { Recipients = new() { [1] = 123 } });

            await bot.Updates.Writer.WriteAsync(Message(2, 123, "/language"), ct);
            Assert.Equal(3L, await bot.Polls.Reader.ReadAsync(ct));
            var keyboard = Assert.Single(bot.Replies);
            Assert.Equal("sendMessage", keyboard.Method);
            Assert.Equal("Choose the language for alerts.", keyboard.Body["text"]!.ToString());
            var buttons = keyboard.Body["reply_markup"]!["inline_keyboard"]![0]!.AsArray();
            Assert.Equal("English", buttons[0]!["text"]!.ToString());
            Assert.Equal("Русский", buttons[1]!["text"]!.ToString());

            await bot.Updates.Writer.WriteAsync(Callback(3, 234, buttons[1]!["callback_data"]!.ToString()), ct);
            Assert.Equal(4L, await bot.Polls.Reader.ReadAsync(ct));
            Assert.Single(bot.Replies);
            await bot.Updates.Writer.WriteAsync(Callback(4, 123, buttons[1]!["callback_data"]!.ToString()), ct);
            Assert.Equal(5L, await bot.Polls.Reader.ReadAsync(ct));
            Assert.Equal("answerCallbackQuery", bot.Replies[1].Method);

            await using var delivery = new NpgsqlConnection(fixture.Dsn("sli_notification_login"));
            await delivery.OpenAsync(ct);
            await PostCollectionPostgres.Sql(delivery, "set role adlog_notification_worker", ct);
            await using var tx = await delivery.BeginTransactionAsync(ct);
            var telegram = new TelegramSettings(settings.BaseUrl, "123", settings.Token, settings.Proxy);
            var alert = await NotificationAlert.FormatAsync(delivery, tx, job, settings.BaseUrl, null, telegram, ct);
            Assert.StartsWith("Проверочное сообщение SLI: оповещения работают.", alert);
            var mail = await NotificationAlert.FormatAsync(delivery, tx, job, settings.BaseUrl, null, null, ct);
            Assert.StartsWith("SLI test message: alerts work.", mail);

            var access = ProblemLifecycleTests.Access("security.queue", fields: ["security", "identity_basic", "technical"]);
            var finding = await NotificationAlert.FormatAsync(delivery, tx, problem, settings.BaseUrl, access, telegram, ct);
            Assert.StartsWith("Средняя · Подбирают пароль к учётной записи\n", finding);
            Assert.Contains("Источник: 192.0.2.10", finding);
            Assert.Contains("Впервые: 22.11 03:00", finding);
            Assert.EndsWith("/app/report/security.problems?id=42", finding);
            await Assert.ThrowsAsync<FormatException>(() =>
                NotificationAlert.FormatAsync(delivery, tx, problem with { Lease = Guid.NewGuid() }, settings.BaseUrl, access, telegram, ct));
        }
        finally
        {
            stop.Cancel();
            try { await loop; }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(problemAccounts, ".rollback.sql"), null, Ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, Ct);
        await fixture.Pg.ApplyFileAsync(migration, null, Ct);
    }

    [Fact]
    public async Task GroupedProblemTelegramPayloadOpensItsExactProblem()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        var database = new Factory(fixture);
        await NotificationLanguages.RememberInterfaceAsync(database, 1, "ru", Ct);
        var job = new NotificationJob(Guid.NewGuid(), Guid.NewGuid(), 1, "test_problem", Guid.NewGuid(), 1, 1,
            Guid.NewGuid(), new DateTime(2026, 11, 21, 20, 0, 15, DateTimeKind.Utc), null, "live", 0);
        var problem = await SeedAlertAsync(fixture, job, Ct, evidenceCount: 2);

        // A delimiter lets this exercise Telegram's language lookup without a bot identifier or credential.
        var settings = new TelegramSettings("https://sli.invalid/app", "123", ":", "");
        Assert.Empty(TelegramSettingsReader.BotId(settings.Token));
        await using var delivery = new NpgsqlConnection(fixture.Dsn("sli_notification_login"));
        await delivery.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(delivery, "set role adlog_notification_worker", Ct);
        var access = ProblemLifecycleTests.Access("security.queue", fields: ["security", "identity_basic", "technical"]);
        string message;
        await using (var tx = await delivery.BeginTransactionAsync(Ct))
        {
            message = await NotificationAlert.FormatAsync(delivery, tx, problem, settings.BaseUrl, access, settings, Ct);
            await tx.CommitAsync(Ct);
        }

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var receiver = builder.Build();
        var captured = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        receiver.MapPost("/capture", async (HttpContext request) =>
        {
            var body = (await JsonNode.ParseAsync(request.Request.Body, cancellationToken: request.RequestAborted))!.AsObject();
            captured.SetResult(body);
            return Results.Json(new { ok = true, result = new { message_id = 1 } });
        });
        await receiver.StartAsync(Ct);
        var endpoint = new Uri(new Uri(receiver.Urls.Single()), "/capture");
        using var redirect = new LoopbackSender(endpoint);
        var sender = new TelegramSender(redirect, new TelegramRequestState());
        Assert.Equal("accepted", (await sender.SendAsync(settings, message, Ct)).Code);
        var payload = await captured.Task.WaitAsync(TimeSpan.FromSeconds(5), Ct);
        await receiver.StopAsync(Ct);

        Assert.Equal("123", payload["chat_id"]!.GetValue<string>());
        Assert.Null(payload["parse_mode"]);
        string text = payload["text"]!.GetValue<string>();
        Assert.Equal(message, text);
        string[] lines = text.Split('\n');
        const string title = "Подбирают пароль к учётной записи";
        Assert.EndsWith(" · " + title, lines[0]);
        Assert.Contains("Administrator", lines[1]);
        Assert.Contains("192.0.2.10", lines[1]);
        Assert.Contains("Впервые: 22.11 03:00", lines[1]);

        var link = new Uri(lines[^1]);
        Assert.Equal("https://sli.invalid/app/report/security.problems?id=42", link.AbsoluteUri);
        var parameters = QueryHelpers.ParseQuery(link.Query);
        Assert.Equal("42", parameters["id"].ToString());
        const string appReport = "/app/report/";
        Assert.StartsWith(appReport, link.AbsolutePath);
        string report = link.AbsolutePath[appReport.Length..];
        var definition = new ReportDefinitionRegistry().Get(report)!;
        var repository = new ProblemRepository(database, TimeProvider.System);
        var evidence = new SecurityProblemEvidence(new SemanticDatabase(database));
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), definition,
            nativeReader: new SecurityProblemsReader(repository, evidence));
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("ru");
        string route = "/api/v2/reports/" + report + "/data";
        using var response = await host.Client.GetAsync(route + link.Query, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var row = Assert.Single((await ReportFixture.Body(response))["items"]!.AsArray())!.AsObject();
        Assert.Equal("42", row["id"]!.ToString());
        Assert.Equal(title, row["title_text"]!.ToString());

        using var wrong = await host.Client.GetAsync(route + "?id=43", Ct);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Empty((await ReportFixture.Body(wrong))["items"]!.AsArray());

        var protocol = new JsonObject
        {
            ["first_seen_utc"] = "2026-11-21T20:00:15Z",
            ["server_timezone"] = "Asia/Bangkok",
            ["grouped_evidence_count"] = 2,
            ["payload"] = payload,
            ["report_request"] = route + link.Query,
            ["report_status"] = (int)response.StatusCode,
            ["problem_id"] = row["id"]!.DeepClone(),
            ["problem_title"] = row["title_text"]!.DeepClone(),
            ["wrong_id_items"] = 0,
        };
        var output = Environment.GetEnvironmentVariable("SLI_P3_PROOF_JSON");
        if (output is not null)
            await File.WriteAllTextAsync(output, protocol.ToJsonString(new JsonSerializerOptions(JsonSerializerOptions.Default)
                { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, WriteIndented = true }), Ct);
    }

    private sealed class LoopbackSender(Uri endpoint) : DelegatingHandler(new HttpClientHandler
        { AllowAutoRedirect = false, UseProxy = false }), IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(this, disposeHandler: false);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal(new Uri("https://api.telegram.org/bot:/sendMessage"), request.RequestUri);
            Assert.True(endpoint.IsLoopback);
            request.RequestUri = endpoint;
            return base.SendAsync(request, ct);
        }
    }

    private static async Task<NotificationJob> SeedAlertAsync(SqlPostgresFixture fixture, NotificationJob test, CancellationToken ct, int evidenceCount = 1)
    {
        var problem = test with { Kind = "semantic_finding", Severity = "high" };
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using var seed = new NpgsqlCommand("""
            insert into public.platform_settings(key,value,updated_by) values('server.timezone','Asia/Bangkok','synthetic')
                on conflict(key) do update set value=excluded.value;
            insert into findings(id,fingerprint,rule_code,title,status,severity,source,actor,target,evidence_count,first_seen_utc,last_seen_utc)
                values(42,'semantic:'||repeat('a',64),'semantic.qw.password-brute-force','Synthetic finding','new','high',
                    'semantic-production','synthetic-actor','Administrator',@count,'2026-11-21T20:00:15Z','2026-11-21T20:00:15Z');
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
                select 42,n,'2026-11-21T20:00:15Z'::timestamptz+(n-1)*interval '1 second',4625,id,'Administrator','dc01.example.test',
                    '{"$principals":{"TargetUserName":"Administrator","IpAddress":"192.0.2.10"}}',
                    '{}','{}',sha256(convert_to('synthetic event '||n,'UTF8')),'primary'
                from domains cross join generate_series(1,@count) as copies(n) where fqdn='example.test';
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,
                    strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
                values(@object,'qw.password-brute-force','control_gap',sha256('identity'::bytea),sha256('scenario'::bytea),
                    'synthetic','{}',300,'Synthetic scenario','Synthetic scenario',now(),now(),'high');
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-alert',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,
                    coverage_status,reason,observed_at_utc,source_reference)
                values(@object,sha256('observation'::bytea),'synthetic','synthetic','unknown','Synthetic alert',now(),'synthetic');
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,
                    source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
                values(@object,'synthetic-alert',1,'control_health',@object,@object::text,'enabled',sha256('job'::bytea),'completed',now());
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,
                    display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
                values(@object,@object,'enabled','high',1,1,false,'low',1,'unknown',1);
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
                values(@object,42,@object,'semantic:'||repeat('a',64),@count);
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                values(@subscription,1,1,'telegram',true);
            insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,
                    channel,state,lease_token,lease_until,object_severity,publication_scenario_id)
                values(@job,@subscription,1,'semantic_finding',@object,1,'telegram','sending',@lease,now()+interval '1 minute','high',@object);
            """, db);
        seed.Parameters.AddWithValue("count", evidenceCount);
        seed.Parameters.AddWithValue("object", problem.ObjectId);
        seed.Parameters.AddWithValue("subscription", problem.Subscription);
        seed.Parameters.AddWithValue("job", problem.Id);
        seed.Parameters.AddWithValue("lease", problem.Lease);
        await seed.ExecuteNonQueryAsync(ct);
        return problem;
    }

    private static JsonObject Message(long updateId, long chatId, string text) => new()
    {
        ["update_id"] = updateId,
        ["message"] = new JsonObject
        {
            ["chat"] = new JsonObject { ["id"] = chatId, ["type"] = "private", ["first_name"] = "Synthetic chat" },
            ["date"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["text"] = text
        }
    };

    private static JsonObject Callback(long updateId, long chatId, string data) => new()
    {
        ["update_id"] = updateId,
        ["callback_query"] = new JsonObject
        {
            ["id"] = "synthetic-callback",
            ["from"] = new JsonObject { ["id"] = chatId },
            ["message"] = Message(updateId, chatId, "")["message"]!.DeepClone(),
            ["data"] = data
        }
    };

    private sealed class Bot : INotificationSetupBot
    {
        internal Channel<JsonObject> Updates { get; } = Channel.CreateUnbounded<JsonObject>();
        internal Channel<long?> Polls { get; } = Channel.CreateUnbounded<long?>();
        internal List<(string Method, JsonObject Body)> Replies { get; } = [];

        public async Task<JsonNode> RequestAsync(string token, string method, JsonObject values, string proxy, CancellationToken ct)
        {
            Assert.Equal("http://proxy.invalid:8080", proxy);
            if (method == "getUpdates")
            {
                await Polls.Writer.WriteAsync(values["offset"]?.GetValue<long>(), ct);
                return new JsonArray(await Updates.Reader.ReadAsync(ct));
            }
            Replies.Add((method, values));
            return JsonValue.Create(true);
        }
    }

    private sealed class Factory(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }
}
