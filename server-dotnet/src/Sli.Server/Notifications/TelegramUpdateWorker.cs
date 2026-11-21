using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Problems;

namespace Sli.Server.Notifications;

internal sealed class TelegramUpdateWorker(NotificationDatabase database, ILogger<TelegramUpdateWorker> logger) : BackgroundService
{
    private readonly NotificationSetupBot bot = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var retry = TimeSpan.FromSeconds(3);
            try { await PollAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (NotificationException e) when (e.Code == "telegram_setup_rate_limited") { retry = TimeSpan.FromMinutes(1); }
            catch { logger.LogWarning("telegram_updates_unavailable"); }
            await Task.Delay(retry, stoppingToken);
        }
    }

    private async Task PollAsync(CancellationToken ct)
    {
        var settings = ReadSettings();
        if (settings is null) return;
        await using var db = await database.OpenAsync(ct);
        await using var claim = new NpgsqlCommand("select pg_try_advisory_lock(hashtextextended('sli.telegram.get_updates',0))", db);
        if (await claim.ExecuteScalarAsync(ct) is not true) return;
        try { await PollOwnedAsync(db, settings, ReadSettings, bot, ct); }
        finally
        {
            if (db.State == System.Data.ConnectionState.Open)
            {
                await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtextextended('sli.telegram.get_updates',0))", db);
                await release.ExecuteScalarAsync(CancellationToken.None);
            }
        }
    }

    internal static async Task PollOwnedAsync(NpgsqlConnection db, TelegramBotSettings settings,
        Func<TelegramBotSettings?> readSettings, INotificationSetupBot bot, CancellationToken ct)
    {
        string generation = TelegramSettingsReader.BotGeneration(settings.Token);
        long? offset = null;
        var lastUpdate = DateTimeOffset.UtcNow;
        var nextPrune = DateTimeOffset.MinValue;
        while (!ct.IsCancellationRequested)
        {
            var latest = readSettings();
            if (latest is null || TelegramSettingsReader.BotGeneration(latest.Token) != generation) return;
            var now = DateTimeOffset.UtcNow;
            if (now >= nextPrune)
            {
                await using var prune = new NpgsqlCommand("delete from public.telegram_discovered_chats where seen_at < now() - interval '10 minutes'", db);
                await prune.ExecuteNonQueryAsync(ct);
                nextPrune = now.AddMinutes(1);
            }
            if (now - lastUpdate >= TimeSpan.FromDays(1)) offset = null;
            var values = new JsonObject { ["timeout"] = 10, ["limit"] = 1, ["allowed_updates"] = new JsonArray("message", "callback_query") };
            if (offset is {} next) values["offset"] = next;
            var updates = (JsonArray)await bot.RequestAsync(latest.Token, "getUpdates", values, latest.Proxy, ct);
            foreach (var update in updates.OfType<JsonObject>())
            {
                if (Number(update["update_id"]) is not long id || id < 0 || id == long.MaxValue) continue;
                // Resolve bindings again after the long poll so a changed destination cannot receive a reply.
                var current = readSettings();
                if (current is null || TelegramSettingsReader.BotGeneration(current.Token) != generation) return;
                await HandleAsync(db, update, current, generation, bot, ct);
                lastUpdate = DateTimeOffset.UtcNow;
                offset = Math.Max(offset ?? 0, id + 1);
            }
        }
    }

    private static TelegramBotSettings? ReadSettings()
    {
        try { return TelegramSettingsReader.ReadBot(Environment.GetEnvironmentVariable, TelegramWorker.ReadBounded); }
        catch (Exception e) when (e is IOException or FormatException or ArgumentException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException)
        { return null; }
    }

    private static async Task RememberChatAsync(NpgsqlConnection db, string generation, long chat, string name, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into public.telegram_discovered_chats(bot_generation,chat_id,chat_name,seen_at)
            values(@generation,@chat,@name,statement_timestamp())
            on conflict(bot_generation,chat_id) do update set chat_name=excluded.chat_name,seen_at=excluded.seen_at
            """, db);
        command.Parameters.AddWithValue("generation", generation);
        command.Parameters.AddWithValue("chat", chat);
        command.Parameters.AddWithValue("name", name);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static long? Number(JsonNode? node) => node is JsonValue value && value.TryGetValue<long>(out long number) ? number : null;
    private static string? Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static async Task HandleAsync(NpgsqlConnection db, JsonObject update, TelegramBotSettings settings,
        string generation, INotificationSetupBot bot, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var callback = update["callback_query"] as JsonObject;
        var message = (callback is null ? update["message"] : callback["message"]) as JsonObject;
        if (message?["chat"] is not JsonObject chat || Text(chat["type"]) != "private" ||
            Number(chat["id"]) is not long chatId || chatId is <1 or >9999999999999999) return;

        string command = (Text(message["text"]) ?? "").Split(' ', 2)[0];
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (callback is null && command == "/start" && Number(message["date"]) is long sent && sent >= now - 600 && sent <= now)
        {
            string name = NotificationMessage.Line(Text(chat["first_name"]) ?? Text(chat["username"]) ?? "", 128);
            await RememberChatAsync(db, generation, chatId, name.Length > 0 ? name : "Telegram", ct);
        }
        long user = settings.Recipients.Where(binding => binding.Value == chatId).Select(binding => binding.Key).Order().FirstOrDefault();
        if (user <= 0) return;
        string M(string key, string locale) => ProblemJson.Text(ProblemPresentation.Message("notifications.bot." + key, locale)["text"]);
        async Task ReplyAsync(string method, JsonObject body)
        {
            try { await bot.RequestAsync(settings.Token, method, body, settings.Proxy, ct); }
            catch (NotificationException) { /* Reply failure does not undo a saved language. */ }
        }
        if (callback is not null)
        {
            if (callback["from"] is not JsonObject from || Number(from["id"]) != chatId ||
                Text(callback["id"]) is not { Length: >0 and <=128 } callbackId ||
                Text(callback["data"]) is not ("sli:language:en" or "sli:language:ru")) return;
            string chosen = Text(callback["data"])![^2..];
            await NotificationLanguages.SetChatAsync(db, TelegramSettingsReader.BotId(settings.Token), chatId, chosen, ct);
            await ReplyAsync("answerCallbackQuery", new() { ["callback_query_id"] = callbackId, ["text"] = M("saved", chosen) });
            return;
        }
        if (command is not ("/start" or "/help" or "/language")) return;
        string locale = await NotificationLanguages.ReadAsync(db, null, user,
            new(settings.BaseUrl, chatId.ToString(CultureInfo.InvariantCulture), settings.Token, settings.Proxy), ct);
        var reply = new JsonObject { ["chat_id"] = chatId, ["text"] = M(command == "/language" ? "choose" : "help", locale), ["protect_content"] = true };
        if (command == "/language")
            reply["reply_markup"] = new JsonObject { ["inline_keyboard"] = new JsonArray(new JsonArray(
                new JsonObject { ["text"] = "English", ["callback_data"] = "sli:language:en" },
                new JsonObject { ["text"] = "Русский", ["callback_data"] = "sli:language:ru" })) };
        await ReplyAsync("sendMessage", reply);
    }
}
