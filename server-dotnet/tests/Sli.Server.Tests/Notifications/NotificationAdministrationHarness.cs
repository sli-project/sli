using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Notifications;
using Sli.Server.Problems;

namespace Sli.Server.Tests.Notifications;

internal sealed class NotificationMemoryFiles : INotificationSetupFiles
{
    public Dictionary<string, byte[]> Values = new();
    public List<string> Writes = new();
    public string? FailOn;
    public bool Exists(string name) => Values.ContainsKey(name);
    public byte[] Read(string name) => Values.TryGetValue(name, out var bytes) && bytes.Length <= 65536 ? bytes.ToArray() : throw new IOException();
    public void Publish(string name, byte[] bytes) { Writes.Add(name); if (name == FailOn) throw new IOException(); Values[name] = bytes.ToArray(); }
    public void Remove(string name) { Writes.Add("remove:" + name); Values.Remove(name); }
}
internal sealed class NotificationBotStub : INotificationSetupBot
{
    public List<string> Calls = new(); public string? Error;
    public Task<JsonNode> RequestAsync(string token, string method, JsonObject values, string proxy, CancellationToken ct)
    {
        Calls.Add(method); if (Error is not null) throw NotificationException.Setup(Error);
        if (method != "getMe") throw new InvalidOperationException();
        return Task.FromResult(JsonNode.Parse("{\"is_bot\":true,\"first_name\":\"Synthetic bot\"}")!);
    }
}
internal sealed class NotificationSetupStub(NotificationSetupService service) : INotificationSetupClient
{
    public List<string> Calls = new(); public string? Error;
    public async Task<JsonObject> RequestAsync(string action, long user, JsonObject values, CancellationToken ct)
    {
        Calls.Add(action); if (Error is not null) throw NotificationException.Setup(Error);
        var body = values.DeepClone().AsObject(); body["action"] = action; body["user_id"] = user;
        return await service.HandleAsync(body, ct);
    }
}
internal sealed class NotificationRecipientsStub : INotificationRecipientAccess
{
    public HashSet<long> Denied = new(); public List<long> Checked = new();
    public Task RequireAsync(long user, CancellationToken ct) { Checked.Add(user); if (Denied.Contains(user)) throw new NotificationException("notifications_access_denied", 403); return Task.CompletedTask; }
}
internal sealed class NotificationRepositoryStub : INotificationAdministrationRepository
{
    public JsonArray DiscoveredChats = new(new JsonObject { ["id"] = 123L, ["name"] = "Synthetic" });
    public Task<JsonArray> DiscoveredTelegramChatsAsync(string generation, CancellationToken ct) =>
        Task.FromResult(DiscoveredChats.DeepClone().AsArray());
    public const string SubscriptionId = "00000000-0000-0000-0000-000000000007";
    public const string JobId = "00000000-0000-0000-0000-000000000008";
    public readonly List<string> Operations = new();
    public bool Throw; public bool Enabled = true; public long Revision = 1;
    public JsonArray Subscriptions = JsonNode.Parse("""
        [{"id":"00000000-0000-0000-0000-000000000007","owner_user_id":7,"recipient_user_id":7,"channel":"telegram","enabled":true,"revision":1,"updated_at":"2026-01-01T00:00:00Z"}]
        """)!.AsArray();
    public JsonObject Channel(string kind) => new() { ["kind"] = kind, ["enabled"] = Enabled, ["revision"] = Revision,
        ["tls_mode"] = "tls", ["secret_ref"] = NotificationInput.SecretRefs[kind], ["state"] = "not_configured", ["updated_at"] = "2026-01-01T00:00:00Z" };
    private void Read(string op) { Operations.Add(op); if (Throw) throw new IOException("synthetic private diagnostic"); }
    public Task<JsonArray> ChannelsAsync(CancellationToken ct) { Read("channels"); return Task.FromResult(new JsonArray(Channel("smtp"), Channel("telegram"))); }
    public Task<JsonArray> SubscriptionsAsync(CancellationToken ct) { Read("subscriptions"); return Task.FromResult(Subscriptions.DeepClone().AsArray()); }
    public Task<JsonObject> WorkspaceAsync(Principal actor, NotificationWorkspaceQuery query, ProblemAccess? problems, bool configure, string language, CancellationToken ct)
    {
        Read("workspace"); return Task.FromResult(new JsonObject { ["channels"] = new JsonArray(Channel("smtp"), Channel("telegram")), ["subscriptions"] = Subscriptions.DeepClone(),
            ["counts"] = JsonNode.Parse("{\"total\":0,\"accepted\":0,\"errors\":0,\"waiting\":0,\"other\":0,\"new_count\":null}"), ["items"] = new JsonArray(),
            ["has_more"] = false, ["next_cursor"] = null, ["previous_login_at"] = null, ["can_configure"] = configure });
    }
    public Task<JsonObject> UpdateChannelAsync(Principal actor, string kind, JsonObject body, CancellationToken ct)
    { Read("channel:update"); if (body["revision"]!.GetValue<long>() != Revision) throw new NotificationException("notification_channel_revision_conflict", 409); Revision++; Enabled = body["enabled"]!.GetValue<bool>(); return Task.FromResult(Channel(kind)); }
    public Task<JsonObject> SaveSubscriptionAsync(Principal actor, string? id, JsonObject body, CancellationToken ct, bool channelAudit = false)
    {
        Read(channelAudit ? "channel:subscription:save" : "subscription:save");
        var item = body.DeepClone().AsObject(); item["owner_user_id"] = actor.Id; item["id"] = id ?? Guid.NewGuid().ToString(); item["revision"] = 2L; item["updated_at"] = "2026-01-01T00:00:00Z";
        return Task.FromResult(item);
    }
    public Task<JsonObject> EnqueueAsync(Principal actor, string id, Guid problem, CancellationToken ct, bool channelAudit = false)
    {
        Read(channelAudit ? "channel:test:enqueue" : "test:enqueue"); return Task.FromResult(new JsonObject { ["id"] = JobId, ["state"] = "pending", ["subscription_id"] = id, ["object_id"] = problem.ToString(),
            ["channel"] = "telegram", ["attempts"] = 0, ["result_code"] = null, ["created_at"] = "2026-01-01T00:00:00Z", ["updated_at"] = "2026-01-01T00:00:00Z", ["delivery_reason"] = "live", ["delay_minutes"] = 0 });
    }
    public Task AuditSetupAsync(Principal actor, string kind, string op, string phase, CancellationToken ct) { Read(kind + ":" + op + ":" + phase); return Task.CompletedTask; }
    public Task TelegramChannelAsync(Principal actor, bool enabled, string op, string phase, CancellationToken ct) { Read("telegram:" + op + ":" + phase); Enabled = enabled; Revision++; return Task.CompletedTask; }
    public Task<JsonObject?> LatestTelegramTestAsync(long user, CancellationToken ct) { Read("test:latest"); return Task.FromResult<JsonObject?>(null); }
    public Task<JsonObject> SmtpStatusAsync(Func<JsonObject, Task<JsonObject>> read, CancellationToken ct) { Read("smtp:status:locked"); return read(Channel("smtp")); }
    public async Task<long> SmtpSaveAsync(Principal actor, JsonObject metadata, Func<Task> bind, Func<long, Task> publish, CancellationToken ct)
    {
        Read("smtp:save:reserve"); if (metadata["revision"]!.GetValue<long>() != Revision) throw NotificationException.Setup("smtp_setup_conflict");
        Enabled = false; Revision++; await bind(); await publish(Revision); Enabled = metadata["enabled"]!.GetValue<bool>(); Read("smtp:save:completed"); return Revision;
    }
}
internal sealed class NotificationHarness : IAsyncDisposable
{
    public NotificationMemoryFiles Files = new(); public NotificationBotStub Bot = new(); public NotificationRepositoryStub Repository = new(); public NotificationRecipientsStub Recipients = new();
    public NotificationSetupService Service; public NotificationSetupStub Client;
    public Principal Principal = new("session", 7, "admin", "synthetic");
    public string Scope = "{\"kind\":\"all\"}"; public bool Reports = true, Deliveries = true, Configure = true, GlobalCapability = true, Queue = true;
    public bool Authenticated = true;
    private IHost? host; private HttpClient? http;
    public NotificationHarness()
    { Files.Values["notification_telegram_token"] = Encoding.UTF8.GetBytes("1:synthetic"); Service = new(Files, Bot, "https://sli.invalid"); Client = new(Service); }
    private sealed class Auth(NotificationHarness harness) : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(Microsoft.AspNetCore.Http.HttpContext c, CancellationToken ct) => ValueTask.FromResult(harness.Authenticated ? AuthenticationResult.Success(harness.Principal) : AuthenticationResult.Denied(401, "authentication_required")); }
    private sealed class Facts(NotificationHarness harness) : IAccessFactsRepository
    { public Task<AccessFacts> LoadAsync(Principal actor, CancellationToken ct) => Task.FromResult(harness.Access()); }
    private AccessFacts Access()
    {
        static JsonElement J(string text) => JsonDocument.Parse(text).RootElement.Clone();
        string[] keys = ["notifications.channels", "notifications.deliveries", "security.queue"];
        var definitions = keys.Select(key => J(JsonSerializer.Serialize(new { report_key = key, version = 1, dataset_version = 1, definition_json = new { actions = new[] { "view", "configure_channel" } }, actions_json = new[] { "view", "configure_channel" }, fields_json = new[] { new { category = key == "security.queue" ? "security" : "technical" } } }))).ToArray();
        var assignments = keys.Where(k => Reports && (k != "notifications.deliveries" || Deliveries) && (k != "security.queue" || Queue)).Select(k => J(JsonSerializer.Serialize(new
        { report_key = k, effect = "allow", allowed_actions = Configure ? new[] { "view", "configure_channel" } : ["view"], field_categories = new[] { k == "security.queue" ? "security" : "technical" }, scope_json = J(Scope) }))).ToArray();
        var capabilities = new[] { "access.manage", "field.technical", "field.security" }.Select(k => J(JsonSerializer.Serialize(new
        { capability_key = k, effect = "allow", scope_json = J(k == "access.manage" && !GlobalCapability ? "{\"kind\":\"domain\",\"ids\":[1]}" : "{\"kind\":\"all\"}") }))).ToArray();
        return new(false, Principal.Role, [], [], capabilities, [], [], assignments, definitions);
    }
    public async Task<HttpResponseMessage> Request(string method, string path, string? body = null, string? origin = null)
    {
        if (host is null)
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
            host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
            {
                s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
                s.AddSingleton<IPrincipalAuthenticator>(new Auth(this)); s.AddSingleton<IAccessFactsRepository>(new Facts(this));
                s.AddSingleton<INotificationAdministrationRepository>(Repository); s.AddSingleton<INotificationRecipientAccess>(Recipients); s.AddSingleton<INotificationSetupClient>(Client); s.AddScoped<NotificationAdministration>();
            }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapNotificationAdministration(); e.MapFallback(c => { c.Response.StatusCode = 501; return Task.CompletedTask; }); }); })).StartAsync();
            http = host.GetTestClient(); http.BaseAddress = new Uri("https://sli.invalid");
        }
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        if (origin is not null) request.Headers.Add("Origin", origin);
        return await http!.SendAsync(request, Xunit.TestContext.Current.CancellationToken);
    }
    public async ValueTask DisposeAsync() { http?.Dispose(); if (host is not null) { await host.StopAsync(); host.Dispose(); } }
}
