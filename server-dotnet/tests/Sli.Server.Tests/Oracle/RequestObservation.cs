using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Tests.Oracle;

// Test infrastructure only. The control connection belongs to a fresh cluster created
// by SqlPostgresFixture; it never borrows runtime credentials or widens runtime ACLs.
internal sealed class RequestObservation(SqlPostgresFixture fixture, long[] sessions, long[] keys)
{
    internal static readonly string[] InsertOnlyTables =
        ["public.sli_ad_credential_audit", "public.sli_agent_gpo_plan_audit", "public.storage_v2_shadow_results"];
    internal sealed record Fingerprint(long Rows, string Sha256);
    internal sealed record Snapshot(DateTime ClockStart, DateTime ClockEnd, JsonObject Auth,
        SortedDictionary<string, Fingerprint> Tables);
    internal sealed record HttpResult(int Status, string BodyBase64, KeyValuePair<string, string[]>[] Headers,
        string[] Normalizations);
    internal sealed record Observation(string CaseId, string Kind, Snapshot Before, Snapshot After, HttpResult? Http);

    internal async Task<Snapshot> SnapshotAsync(CancellationToken ct)
    {
        await using var db = await fixture.Pg.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        async Task<object?> Scalar(string sql)
        {
            await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
            return await command.ExecuteScalarAsync(ct);
        }
        await Scalar("set transaction read only");
        DateTime start = (DateTime)(await Scalar("select clock_timestamp()"))!;
        var auth = new JsonObject();
        foreach (var (table, ids, fields) in new[] {
            ("auth_sessions", sessions, "id,user_id,expires_at,revoked_at,last_used_at"),
            ("auth_api_keys", keys, "id,role,is_active,expires_at,revoked_at,last_used_at") })
        {
            await using var command = new NpgsqlCommand($"select coalesce(jsonb_agg(to_jsonb(m) order by id),'[]'::jsonb)::text from (select {fields} from public.{table} where id=any(@ids)) m", db, tx) { CommandTimeout = 0 };
            command.Parameters.AddWithValue("ids", ids);
            var rows = JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsArray();
            if (rows.Count != ids.Distinct().Count()) throw new InvalidOperationException("Observed auth identity is missing.");
            auth[table] = rows;
        }
        // Discover all application base tables, including tables invisible to the
        // runtime's SELECT role and non-public plugin schemas. No silent omissions.
        var tables = new List<(string Schema, string Name)>();
        await using (var command = new NpgsqlCommand("""
            select n.nspname,c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
            where c.relkind in ('r','p') and n.nspname <> 'information_schema'
              and n.nspname !~ '^pg_' order by n.nspname,c.relname
            """, db, tx) { CommandTimeout = 0 })
        await using (var reader = await command.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) tables.Add((reader.GetString(0), reader.GetString(1)));
        var fingerprints = new SortedDictionary<string, Fingerprint>(StringComparer.Ordinal);
        using var identifiers = new NpgsqlCommandBuilder();
        foreach (var (schema, table) in tables)
        {
            string expression = "to_jsonb(t)";
            long[]? ids = schema != "public" ? null : table == "auth_sessions" ? sessions : table == "auth_api_keys" ? keys : null;
            // Only last_used of explicitly observed identities is measured separately.
            // Other auth rows and every other auth column remain in the fingerprint.
            if (ids is not null) expression = "case when t.id=any(@ids) then to_jsonb(t)-'last_used_at' else to_jsonb(t) end";
            string sql = $"select digest from (select encode(sha256(convert_to(({expression})::text,'UTF8')),'hex') as digest from {identifiers.QuoteIdentifier(schema)}.{identifiers.QuoteIdentifier(table)} t) hashes order by digest collate \"C\"";
            await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
            if (ids is not null) command.Parameters.AddWithValue("ids", ids);
            fingerprints.Add(schema + "." + table, await HashRows(command, ct));
        }
        foreach (string required in InsertOnlyTables)
            if (!fingerprints.ContainsKey(required)) throw new InvalidOperationException("Missing INSERT-only control coverage: " + required);
        // Bind role attributes, memberships and schema/table/column/function ACLs.
        // pg_roles projection deliberately omits passwords, even their masked form.
        await using (var command = new NpgsqlCommand("""
            select value from (
              select 'role:'||row(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconfig)::text value from pg_roles
              union all select 'member:'||to_jsonb(m)::text from pg_auth_members m
              union all select 'schema:'||row(oid,nspname,nspowner,nspacl)::text from pg_namespace where nspname !~ '^pg_'
              union all select 'relation:'||row(oid,relnamespace,relname,relowner,relacl,relrowsecurity,relforcerowsecurity)::text from pg_class where relnamespace in (select oid from pg_namespace where nspname !~ '^pg_' and nspname<>'information_schema')
              union all select 'column:'||row(attrelid,attnum,attacl)::text from pg_attribute where attacl is not null
              union all select 'function:'||row(oid,pronamespace,proname,proowner,proacl,prosecdef,proconfig)::text from pg_proc where pronamespace in (select oid from pg_namespace where nspname !~ '^pg_' and nspname<>'information_schema')
            ) metadata order by value collate "C"
            """, db, tx) { CommandTimeout = 0 })
            fingerprints.Add("$privileges", await HashRows(command, ct));
        DateTime end = (DateTime)(await Scalar("select clock_timestamp()"))!;
        await tx.CommitAsync(ct);
        return new(start, end, auth, fingerprints);
    }

    private static async Task<Fingerprint> HashRows(NpgsqlCommand command, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long count = 0;
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            // Length framing avoids ambiguous concatenation for catalog metadata.
            byte[] bytes = Encoding.UTF8.GetBytes(reader.GetString(0));
            hash.AppendData(Encoding.ASCII.GetBytes(bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":"));
            hash.AppendData(bytes); count++;
        }
        return new(count, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    internal async Task<Observation> RequestAsync(string caseId, HttpClient client, HttpRequestMessage request, CancellationToken ct)
    {
        var before = await SnapshotAsync(ct);
        using var response = await client.SendAsync(request, ct);
        var http = await NormalizeAsync(response, ct);
        var after = await SnapshotAsync(ct);
        return new(caseId, "http", before, after, http);
    }

    internal async Task<Observation> ActionAsync(string caseId, Func<Task> action, CancellationToken ct)
    {
        var before = await SnapshotAsync(ct);
        await action();
        return new(caseId, "controlled_action", before, await SnapshotAsync(ct), null);
    }

    internal static async Task<HttpResult> NormalizeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        byte[] body = await response.Content.ReadAsByteArrayAsync(ct);
        var normalizations = new List<string> { "headers.Date", "headers.Server" };
        // Only the documented top-level error correlation ID is variable. Preserve
        // arbitrary/non-JSON response bytes exactly, with no truncation or decoding loss.
        if (response.Content.Headers.ContentType?.MediaType == "application/json")
        {
            JsonNode? node;
            try { node = JsonNode.Parse(body); }
            catch (System.Text.Json.JsonException) { node = null; }
            if (node is JsonObject obj && obj["internal_error_id"] is JsonValue)
            {
                obj["internal_error_id"] = "$internal_error_id";
                body = Encoding.UTF8.GetBytes(obj.ToJsonString());
                normalizations.Add("body.internal_error_id");
            }
        }
        var headers = response.Headers.Concat(response.Content.Headers).Concat(response.TrailingHeaders)
            .Where(h => !h.Key.Equals("Date", StringComparison.OrdinalIgnoreCase) && !h.Key.Equals("Server", StringComparison.OrdinalIgnoreCase))
            .Select(h => KeyValuePair.Create(h.Key.ToLowerInvariant(), h.Value.ToArray())).ToArray();
        return new((int)response.StatusCode, Convert.ToBase64String(body), headers, normalizations.ToArray());
    }
}
