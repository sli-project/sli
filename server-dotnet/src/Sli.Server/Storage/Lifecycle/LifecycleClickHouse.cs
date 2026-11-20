using System.Globalization;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class LifecycleClickHouse(HttpClient client, Uri endpoint, AuthenticationHeaderValue? auth = null, bool unbounded = false, bool processLifetime = false)
{
    internal LifecycleClickHouse ForProcessLifetime() => processLifetime ? this : new(client, endpoint, auth, unbounded, processLifetime: true);
    internal async Task<List<JsonObject>> RowsAsync(string sql, CancellationToken ct, Dictionary<string, string>? parameters = null)
    {
        var result = new List<JsonObject>();
        await foreach (var row in StreamRowsAsync(sql, ct, parameters)) {
            if (result.Count >= 100000) throw new LifecycleBlocked("history_response_too_large");
            result.Add(row);
        }
        return result;
    }
    internal async IAsyncEnumerable<JsonObject> StreamRowsAsync(string sql, [EnumeratorCancellation] CancellationToken ct,
        Dictionary<string, string>? parameters = null, Dictionary<string, string>? settings = null)
    {
        await using var rows = StreamRowsCoreAsync(sql, ct, parameters, settings).GetAsyncEnumerator(ct);
        while (true) {
            bool hasNext;
            try { hasNext = await rows.MoveNextAsync(); }
            catch (Exception error) when (error is HttpRequestException or IOException || error is OperationCanceledException && !ct.IsCancellationRequested)
            { throw new LifecycleBlocked("history_clickhouse_unavailable"); }
            if (!hasNext) yield break;
            yield return rows.Current;
        }
    }
    async IAsyncEnumerable<JsonObject> StreamRowsCoreAsync(string sql, [EnumeratorCancellation] CancellationToken ct,
        Dictionary<string, string>? parameters, Dictionary<string, string>? settings)
    {
        if (!Regex.IsMatch(sql, @"\bFORMAT\s+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) sql = sql.TrimEnd().TrimEnd(';') + " FORMAT JSONEachRow";
        using var request = Request(sql, true, parameters, settings);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        RequireSuccess(response);
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var line = new MemoryStream();
        byte[] buffer = new byte[8192]; long bytes = 0; int count;
        while ((count = await stream.ReadAsync(buffer, ct)) != 0) {
            ct.ThrowIfCancellationRequested();
            bytes += count;
            if (bytes > LifecycleJson.MaxBytes) throw new LifecycleBlocked("history_response_too_large");
            int start = 0;
            for (int i = 0; i < count; i++) {
                if (buffer[i] != (byte)'\n') continue;
                line.Write(buffer, start, i - start);
                if (ParseLine(line) is { } row) yield return row;
                line.SetLength(0); start = i + 1;
            }
            line.Write(buffer, start, count - start);
        }
        if (ParseLine(line) is { } last) yield return last;
    }
    static JsonObject? ParseLine(MemoryStream bytes)
    {
        string line = new UTF8Encoding(false, true).GetString(bytes.GetBuffer(), 0, (int)bytes.Length);
        return string.IsNullOrWhiteSpace(line) ? null : JsonNode.Parse(line) as JsonObject ?? throw new LifecycleBlocked("history_json_invalid");
    }
    internal Task<string> ExecuteAsync(string sql, CancellationToken ct, Dictionary<string, string>? parameters = null) => SendAsync(sql, false, ct, parameters);
    internal async Task InsertAsync(string table, IReadOnlyList<JsonObject> rows, CancellationToken ct)
    {
        if (rows.Count == 0) return;
        if (!Tables.Contains(table)) throw new ArgumentException("history_table_invalid");
        string body = "INSERT INTO " + table + " FORMAT JSONEachRow\n" + string.Join('\n', rows.Select(LifecycleJson.Canonical));
        if (Encoding.UTF8.GetByteCount(body) > LifecycleJson.MaxBytes) throw new LifecycleBlocked("history_request_too_large");
        await SendAsync(body, false, ct);
    }
    static readonly HashSet<string> Tables = [FileAuditHistory.Table];
    HttpRequestMessage Request(string sql, bool read, Dictionary<string, string>? parameters, Dictionary<string, string>? settings = null)
    {
        if (Encoding.UTF8.GetByteCount(sql) > LifecycleJson.MaxBytes) throw new LifecycleBlocked("history_request_too_large");
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not ("http" or "https") || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
            throw new ArgumentException("history_endpoint_invalid");
        var query = new List<string> { "max_execution_time=0" };
        if (read) query.Add("readonly=1");
        if (settings is not null) query.AddRange(settings.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        if (parameters is not null) query.AddRange(parameters.Select(p => "param_" + Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        var request = new HttpRequestMessage(HttpMethod.Post, new UriBuilder(endpoint) { Query = string.Join('&', query) }.Uri) { Content = new StringContent(sql, Encoding.UTF8, "text/plain") };
        if (auth is not null) request.Headers.Authorization = auth;
        return request;
    }
    async Task<string> SendAsync(string sql, bool read, CancellationToken ct, Dictionary<string, string>? parameters)
    {
        using var request = Request(sql, read, parameters);
        try {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            RequireSuccess(response);
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var bytes = new MemoryStream(); byte[] buffer = new byte[8192]; int n;
            while ((n = await stream.ReadAsync(buffer, ct)) != 0) {
                if (bytes.Length + n > LifecycleJson.MaxBytes) throw new LifecycleBlocked("history_response_too_large"); bytes.Write(buffer, 0, n);
            }
            return new UTF8Encoding(false, true).GetString(bytes.ToArray());
        }
        catch (Exception error) when (error is HttpRequestException or IOException || error is OperationCanceledException && !ct.IsCancellationRequested)
        { throw new LifecycleBlocked("history_clickhouse_unavailable"); }
    }
    static void RequireSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode) throw new LifecycleBlocked((int)response.StatusCode is 429 or 502 or 503 or 504
            ? "history_clickhouse_unavailable" : $"ClickHouse HTTP {(int)response.StatusCode}:request_failed");
    }
    internal Task<string> SendAsync(string sql, bool read, CancellationToken ct) => SendAsync(sql, read, ct, null);
    internal static string Ids(IEnumerable<long> ids) => string.Join(',', ids.Select(n => n > 0 ? n.ToString(CultureInfo.InvariantCulture) : throw new ArgumentException("history_id_invalid")));
    // HTTP Array(String) parameters use ClickHouse quoted literals, not JSON.
    // Escape backslashes as well as quotes so host data cannot end a value.
    internal static string StringArray(IEnumerable<string> values) => "[" + string.Join(',', values.Select(value =>
        "'" + string.Concat(value.Select(c => c switch {
            '\\' => "\\\\", '\'' => "\\'", '\0' => "\\0", '\n' => "\\n", '\r' => "\\r",
            '\t' => "\\t", '\b' => "\\b", '\f' => "\\f", _ => c.ToString()
        })) + "'")) + "]";
}
