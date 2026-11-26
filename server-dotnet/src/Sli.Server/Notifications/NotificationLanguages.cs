using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Notifications;

internal static class NotificationLanguages
{
    private const string ServerDefault = "en";

    internal static async Task RememberInterfaceAsync(IPostgresConnectionFactory database, long userId, string language, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into public.user_interface_languages(user_id,language) values(@user,@language)
            on conflict(user_id) do update set language=excluded.language
            where user_interface_languages.language<>excluded.language
            """, db);
        command.Parameters.AddWithValue("user", userId);
        command.Parameters.AddWithValue("language", language);
        await command.ExecuteNonQueryAsync(ct);
    }

    internal static async Task<string> ReadAsync(NpgsqlConnection db, NpgsqlTransaction? tx, long userId, TelegramSettings? telegram, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select coalesce(
                (select language from public.telegram_chat_languages where bot_id=@bot and chat_id=@chat),
                (select language from public.user_interface_languages where user_id=@user))
            """, db, tx);
        command.Parameters.AddWithValue("user", userId);
        command.Parameters.AddWithValue("bot", NpgsqlDbType.Text, telegram is null ? DBNull.Value : TelegramSettingsReader.BotId(telegram.Token));
        command.Parameters.AddWithValue("chat", NpgsqlDbType.Bigint, telegram is null ? DBNull.Value : long.Parse(telegram.Chat, System.Globalization.CultureInfo.InvariantCulture));
        return await command.ExecuteScalarAsync(ct) as string ?? ServerDefault;
    }

    internal static async Task SetChatAsync(NpgsqlConnection db, string botId, long chatId, string language, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into public.telegram_chat_languages(bot_id,chat_id,language) values(@bot,@chat,@language)
            on conflict(bot_id,chat_id) do update set language=excluded.language
            """, db);
        command.Parameters.AddWithValue("bot", botId);
        command.Parameters.AddWithValue("chat", chatId);
        command.Parameters.AddWithValue("language", language);
        await command.ExecuteNonQueryAsync(ct);
    }
}
