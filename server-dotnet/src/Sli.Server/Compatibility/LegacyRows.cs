using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Compatibility;

public interface ILegacyRows
{
    Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct);
    Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string,string> parameters, CancellationToken ct);
    Task<Dictionary<long,JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct);
}

internal sealed class PostgresLegacyRows(IPostgresConnectionFactory connections) : ILegacyRows, IDisposable
{
    public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string,string> parameters, CancellationToken ct)
        => throw new LegacyInputException("module_disabled", 503);
    public Task<Dictionary<long,JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct)
        => throw new LegacyInputException("module_disabled", 503);
    public void Dispose() { }
    public async Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct)
    {
        // Zero lets the shared dashboard flight follow its owner cancellation
        // instead of imposing a query deadline. Existing callers keep their policy.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeoutMs > 0) deadline.CancelAfter(timeoutMs + 1500);
        try
        {
            await using var db = await connections.OpenAsync(deadline.Token);
            await using var tx = await db.BeginTransactionAsync(deadline.Token);
            if (timeoutMs > 0)
            {
                await using var limits = new NpgsqlCommand("select set_config('statement_timeout',@timeout,true),set_config('lock_timeout','1000',true)", db, tx);
                limits.Parameters.AddWithValue("timeout", timeoutMs.ToString(CultureInfo.InvariantCulture));
                await limits.ExecuteNonQueryAsync(deadline.Token);
            }
            await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = timeoutMs > 0 ? (timeoutMs + 999) / 1000 + 1 : 0 };
            for (int i = 0; i < parameters.Count; i++) command.Parameters.AddWithValue("p" + i, parameters[i]);
            await using var reader = await command.ExecuteReaderAsync(deadline.Token);
            var result = new JsonArray();
            while (await reader.ReadAsync(deadline.Token))
            {
                var row = new JsonObject();
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    object value = reader.GetValue(i);
                    row[reader.GetName(i)] = value switch
                    {
                        DBNull => null,
                        DateTime time => time.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffK", CultureInfo.InvariantCulture),
                        DateTimeOffset time => time.ToString("O", CultureInfo.InvariantCulture),
                        byte[] bytes => "\\x" + Convert.ToHexStringLower(bytes),
                        _ => JsonSerializer.SerializeToNode(value)
                    };
                }
                result.Add(row);
            }
            await reader.DisposeAsync(); await tx.CommitAsync(deadline.Token);
            return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("report_read_timeout"); }
    }
}

// SQL fragments and column names come exclusively from code. Host values are
// always parameters, including LIKE patterns and keyset cursor components.
internal sealed class LegacySql
{
    internal readonly List<object> Parameters = [];
    internal readonly List<string> Conditions = [];
    internal string Bind(object value) { string name = "@p" + Parameters.Count; Parameters.Add(value); return name; }
    internal void Equal(string column, string? value, bool folded = false)
    { if (value is not null) Conditions.Add(folded ? $"lower(coalesce({column},''))=lower({Bind(value)})" : $"{column}={Bind(value)}"); }
    internal string Where => Conditions.Count == 0 ? "" : " where " + string.Join(" and ", Conditions);
    internal string Account(string raw, params string[] columns)
    {
        string[] values = new[] { raw, raw.Contains('\\') ? raw.Split('\\')[^1] : raw, raw.Contains('@') ? raw.Split('@')[0] : raw }
            .Select(s => s.Trim().ToLowerInvariant()).Where(s => s.Length > 0).Distinct().ToArray();
        if (values.Length == 0) return "false";
        bool prefix = raw.Length >= 3 && !raw.All(char.IsDigit) && !raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && !raw.Replace(".", "").All(char.IsDigit);
        return "(" + string.Join(" or ", columns.Select(c => "(" + string.Join(" or ", values.SelectMany(v => prefix
            ? new[] { $"lower(coalesce({c},''))={Bind(v)}", $"lower(coalesce({c},'')) like {Bind(v + "%")}" }
            : new[] { $"lower(coalesce({c},''))={Bind(v)}" })) + ")")) + ")";
    }
    internal void Like(string value, params string[] columns) => Conditions.Add("(" + string.Join(" or ", columns.Select(c => $"lower(coalesce({c},'')) like lower({Bind("%" + value + "%")})")) + ")");
    internal void Common(LegacyQuery query)
    {
        Equal("e.channel", query.Text("channel")); Equal("e.provider_name", query.Text("provider"), true);
        foreach (var (key, column) in new[] { ("subject", "e.subject_user_name"), ("target", "e.target_user_name") })
            if (query.Text(key) is {} account) Conditions.Add(Account(account, column));
        if (query.Filters["servers"] is JsonArray { Count: > 0 } servers) Conditions.Add("s.hostname in (" + string.Join(",", servers.Select(s => Bind(s!.ToString()))) + ")");
        if (query.Filters["event_ids"] is JsonArray { Count: > 0 } ids) Conditions.Add("e.event_id in (" + string.Join(",", ids.Select(s => Bind(int.Parse(s!.ToString(), CultureInfo.InvariantCulture)))) + ")");
        foreach (var (key, op) in new[] { ("time_from", ">="), ("time_to", "<") })
            if (query.Text(key) is {} time) Conditions.Add($"e.time_created_utc {op} {Bind(time)}::timestamptz");
    }
}


