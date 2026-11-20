using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Auth.Lifecycle.Security;

public sealed class AccountThrottle : IAccountThrottle
{
    public static string AccountKey(string username)
    {
        // Python str.strip additionally includes the four ASCII information separators.
        int start = 0, end = username.Length;
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        while (start < end && Space(username[start])) start++;
        while (end > start && Space(username[end - 1])) end--;
        var runes = username[start..end].EnumerateRunes().ToArray();
        var normalized = new StringBuilder();
        for (int i = 0; i < runes.Length; i++)
        {
            if (runes[i].Value == 0x130) normalized.Append("i\u0307"); // Unicode full lowercase expansion.
            else if (runes[i].Value == 0x3a3 && HasCased(runes, i, -1) && !HasCased(runes, i, 1))
                normalized.Append('\u03c2'); // Unicode Final_Sigma context used by Python lower().
            else normalized.Append(Rune.ToLowerInvariant(runes[i]).ToString());
        }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalized.ToString())));
    }

    private static bool HasCased(Rune[] text, int index, int direction)
    {
        for (int i = index + direction; i >= 0 && i < text.Length; i += direction)
        {
            var category = Rune.GetUnicodeCategory(text[i]);
            if (category is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark
                or UnicodeCategory.Format or UnicodeCategory.ModifierLetter or UnicodeCategory.ModifierSymbol
                || text[i].Value is 0x27 or 0x2e or 0x3a or 0xb7 or 0x387 or 0x55f or 0x5f4
                    or 0x2018 or 0x2019 or 0x2024 or 0x2027 or 0xfe13 or 0xfe52 or 0xfe55 or 0xff07 or 0xff0e or 0xff1a)
                continue;
            return category is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
                || text[i].Value is 0xaa or 0xba or >= 0x2160 and <= 0x217f or >= 0x24b6 and <= 0x24e9
                    or >= 0x1f130 and <= 0x1f149 or >= 0x1f150 and <= 0x1f169 or >= 0x1f170 and <= 0x1f189;
        }
        return false;
    }

    public static long AdvisoryKey(string accountKey) => BinaryPrimitives.ReadInt64BigEndian(
        SHA256.HashData(Encoding.UTF8.GetBytes("login:" + accountKey)));

    public async Task<IAccountAttempt> BeginAsync(NpgsqlTransaction transaction, string username, CancellationToken ct)
    {
        var connection = transaction.Connection ?? throw new InvalidOperationException("account_attempt_transaction_required");
        string key = AccountKey(username);
        await using (var command = new NpgsqlCommand("select pg_try_advisory_xact_lock($1)", connection, transaction))
        {
            command.Parameters.AddWithValue(AdvisoryKey(key));
            if (await command.ExecuteScalarAsync(ct) is not true) throw new LoginThrottledException(1);
        }
        DateTime now;
        await using (var command = new NpgsqlCommand("select clock_timestamp()", connection, transaction))
            now = (DateTime)(await command.ExecuteScalarAsync(ct))!;
        int failures = 0;
        DateTime started = now;
        await using (var command = new NpgsqlCommand("select failures,window_started_at,blocked_until from auth_login_throttle where account_key=$1 for update", connection, transaction))
        {
            command.Parameters.AddWithValue(key);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                if (!reader.IsDBNull(2) && reader.GetDateTime(2) > now)
                    throw new LoginThrottledException((int)Math.Ceiling((reader.GetDateTime(2) - now).TotalSeconds));
                if (reader.GetDateTime(1) > now.AddSeconds(-900))
                {
                    failures = reader.GetInt32(0);
                    started = reader.GetDateTime(1);
                }
            }
        }
        return new AccountAttempt(transaction, key, now, started, failures);
    }

    private sealed class AccountAttempt(NpgsqlTransaction transaction, string key, DateTime now,
        DateTime started, int failures) : IAccountAttempt
    {
        private bool completed;
        private NpgsqlCommand Command(string sql)
        {
            if (completed) throw new InvalidOperationException("account_attempt_already_completed");
            return new(sql, transaction.Connection ?? throw new InvalidOperationException("account_attempt_transaction_required"), transaction);
        }

        public async Task FailAsync(CancellationToken ct)
        {
            int next = Math.Min(failures + 1, 9);
            int delay = next >= 5 ? Math.Min(300, 30 * (1 << (next - 5))) : 0;
            await using (var command = Command("""
                insert into auth_login_throttle(account_key,failures,window_started_at,blocked_until)
                values($1,$2,$3,$4) on conflict(account_key) do update set failures=excluded.failures,
                window_started_at=excluded.window_started_at,blocked_until=excluded.blocked_until
                """))
            {
                command.Parameters.AddWithValue(key);
                command.Parameters.AddWithValue(next);
                command.Parameters.AddWithValue(started);
                command.Parameters.AddWithValue(NpgsqlDbType.TimestampTz, delay == 0 ? DBNull.Value : now.AddSeconds(delay));
                await command.ExecuteNonQueryAsync(ct);
            }
            await using (var command = Command("""
                delete from auth_login_throttle where account_key in (
                select account_key from auth_login_throttle where window_started_at < $1
                and (blocked_until is null or blocked_until <= $2)
                order by window_started_at limit 64 for update skip locked)
                """))
            {
                command.Parameters.AddWithValue(now.AddSeconds(-900));
                command.Parameters.AddWithValue(now);
                await command.ExecuteNonQueryAsync(ct);
            }
            completed = true;
        }

        public async Task SucceedAsync(CancellationToken ct)
        {
            await using var command = Command("delete from auth_login_throttle where account_key=$1");
            command.Parameters.AddWithValue(key);
            await command.ExecuteNonQueryAsync(ct);
            completed = true;
        }

        public ValueTask DisposeAsync() { completed = true; return ValueTask.CompletedTask; }
    }
}
