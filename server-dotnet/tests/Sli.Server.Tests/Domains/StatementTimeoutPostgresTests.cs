using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class StatementTimeoutPostgresTests(ITestOutputHelper output)
{
    // Fault injection is confined to this fixture's disposable PG18 cluster.
    // pg_sleep does not raise an exception: the real server timer must cancel
    // the unchanged authentication UPDATE. Neither locks nor client cancel are used.
    [Fact]
    public async Task Actual57014ReturnsSafeHttpErrorAndRollsBackAuthWrite()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = new SqlPostgresFixture();
        string clusterRoot = fixture.Pg.Root;
        bool loggingConfigured = false;
        try
        {
            await fixture.StartAsync(ct);
            await using var admin = await fixture.Pg.OpenAsync(ct);
            Assert.Equal(18, Convert.ToInt32(await Scalar(admin, "show server_version_num", ct)) / 10000);
            await PostCollectionPostgres.Sql(admin, "alter system set log_error_verbosity='verbose'", ct);
            loggingConfigured = true;
            await PostCollectionPostgres.Sql(admin, "select pg_reload_conf()", ct);
            string token = await fixture.SeedOwnerAsync(ct);
            var settings = new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")) {
                CommandTimeout = 0, Options = "-c statement_timeout=1000 -c lock_timeout=100"
            };
            string root = PostCollectionPostgres.Repository();
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(b => b
                .ConfigureLogging(l => l.ClearProviders())
                .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                    ["ConnectionStrings:Sli"] = settings.ConnectionString,
                    ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                    ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(clusterRoot, "app-data"),
                    ["Sli:LogDirectory"] = Path.Combine(clusterRoot, "app-logs"),
                    ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:OwnerSetup"] = "0"
                })));
            host.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));
            host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) {
                BaseAddress = new Uri(address), Timeout = Timeout.InfiniteTimeSpan
            };
            client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
            client.DefaultRequestHeaders.Add("Accept-Language", "en");

            foreach (string runtime in new[] { "dotnet" })
            {
                Task<JsonObject> Request() => Http(client, ct);
                async Task<JsonObject> Observe(string phase, bool fault)
                {
                    var before = await Snapshot(admin, ct);
                    string logBefore = await fixture.Pg.DiagnosticsAsync(ct);
                    var response = await Request();
                    var after = await Snapshot(admin, ct);
                    var changed = before.Tables.Keys.Union(after.Tables.Keys)
                        .Where(k => before.Tables.GetValueOrDefault(k) != after.Tables.GetValueOrDefault(k)).ToArray();
                    output.WriteLine(JsonSerializer.Serialize(new {
                        runtime, phase, request = "GET /api/v1/domains", response,
                        before = Summary(before), after = Summary(after),
                        deltas = changed.ToDictionary(k => k, k => new { before = before.Tables.GetValueOrDefault(k), after = after.Tables.GetValueOrDefault(k) })
                    }));
                    Assert.Equal(fault ? 503 : 200, response["status"]!.GetValue<int>());
                    if (fault)
                    {
                        Assert.Empty(changed);
                        Assert.Equal(before.LastUsed, after.LastUsed);
                        string log = (await fixture.Pg.DiagnosticsAsync(ct))[logBefore.Length..];
                        output.WriteLine(log);
                        Assert.Contains("57014", log);
                        Assert.Contains("canceling statement due to statement timeout", log);
                        Assert.Contains("pg_sleep", log);
                        Assert.Contains("update auth_sessions", log.ToLowerInvariant());
                        Assert.DoesNotContain("55P03", log);
                        Assert.DoesNotContain("due to user request", log);
                        Assert.DoesNotContain("lock timeout", log);
                        string body = Encoding.UTF8.GetString(Convert.FromBase64String(response["body_base64"]!.GetValue<string>()));
                        var json = JsonNode.Parse(body)!;
                        Assert.Equal("report_read_timeout", json["error"]!.GetValue<string>());
                        Assert.Equal("unavailable", json["state"]!.GetValue<string>());
                        var headers = response["headers"]!.AsArray();
                        string Header(string name) => headers.Single(h => string.Equals(h![0]!.GetValue<string>(), name, StringComparison.OrdinalIgnoreCase))![1]!.GetValue<string>();
                        Assert.Equal(Convert.FromBase64String(response["body_base64"]!.GetValue<string>()).Length.ToString(), Header("Content-Length"));
                        Assert.Equal("nosniff", Header("X-Content-Type-Options"));
                        Assert.Equal("no-store, max-age=0", Header("Cache-Control"));

                    }
                    else
                    {
                        Assert.Equal(new[] { "public.auth_sessions" }, changed);
                        Assert.NotEqual(before.LastUsed, after.LastUsed);
                    }
                    return response;
                }
                // Separate controlled mutation from each HTTP observation. The
                // fresh process/request really authenticates; no cached principal.
                await PostCollectionPostgres.Sql(admin, "update auth_sessions set last_used_at=null", ct);
                await Observe("healthy", false);
                await PostCollectionPostgres.Sql(admin, "update auth_sessions set last_used_at=null", ct);
                string originalSettings = (string)(await Scalar(admin, "select coalesce(jsonb_agg(to_jsonb(s) order by setdatabase,setrole)::text,'[]') from pg_db_role_setting s", ct))!;
                Assert.Equal(0L, await Scalar(admin, "select count(*) from pg_proc where proname='q500_statement_timeout'", ct));
                try
                {
                    await PostCollectionPostgres.Sql(admin, """
                        create function public.q500_statement_timeout() returns trigger language plpgsql as $$
                        begin perform pg_catalog.pg_sleep(10); return new; end $$;
                        create trigger q500_statement_timeout before update on public.auth_sessions
                        for each row execute function public.q500_statement_timeout();
                        """, ct);
                    await Observe("statement_timeout", true);
                }
                finally
                {
                    await PostCollectionPostgres.Sql(admin, "drop trigger if exists q500_statement_timeout on public.auth_sessions; drop function if exists public.q500_statement_timeout()", CancellationToken.None);
                }
                Assert.Equal(0L, await Scalar(admin, "select count(*) from pg_trigger where tgname='q500_statement_timeout'", ct));
                Assert.Equal(0L, await Scalar(admin, "select count(*) from pg_proc where proname='q500_statement_timeout'", ct));
                Assert.Equal(originalSettings, await Scalar(admin, "select coalesce(jsonb_agg(to_jsonb(s) order by setdatabase,setrole)::text,'[]') from pg_db_role_setting s", ct));
                await Observe("recovered", false);
                Assert.Equal(0L, await Scalar(admin, "select count(*) from pg_stat_activity where usename='adlog_user' and pid<>pg_backend_pid() and (state='active' or xact_start is not null)", ct));
                output.WriteLine(runtime + ": trigger/function removed, role/database settings unchanged, no active runtime transaction");
            }
        }
        finally
        {
            try
            {
                if (loggingConfigured)
                {
                    await using var cleanup = await fixture.Pg.OpenAsync(CancellationToken.None);
                    await PostCollectionPostgres.Sql(cleanup, "alter system reset log_error_verbosity", CancellationToken.None);
                    await PostCollectionPostgres.Sql(cleanup, "select pg_reload_conf()", CancellationToken.None);
                    Assert.Equal(0L, await Scalar(cleanup, "select count(*) from pg_file_settings where name='log_error_verbosity'", CancellationToken.None));
                    output.WriteLine("cleanup: diagnostic logging setting restored");
                }
            }
            finally
            {
                await fixture.DisposeAsync();
                Assert.False(Directory.Exists(clusterRoot));
                output.WriteLine("cleanup: owned PostgreSQL stopped and unique cluster directory removed");
            }
        }
    }

    private sealed record DatabaseSnapshot(DateTime Clock, Dictionary<string, string> Tables, string LastUsed);
    private static object Summary(DatabaseSnapshot snapshot) => new {
        snapshot.Clock, snapshot.LastUsed, relations = snapshot.Tables.Count,
        sha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot.Tables))))
    };
    private static async Task<DatabaseSnapshot> Snapshot(NpgsqlConnection db, CancellationToken ct)
    {
        var names = new List<(string Schema, string Table, bool Sequence)>();
        await using (var list = new NpgsqlCommand("""
            select n.nspname,c.relname,c.relkind='S' from pg_class c join pg_namespace n on n.oid=c.relnamespace
            where c.relkind in ('r','p','S') and n.nspname not in ('pg_catalog','information_schema')
              and n.nspname not like 'pg_toast%' order by 1,2
            """, db))
        await using (var rows = await list.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) names.Add((rows.GetString(0), rows.GetString(1), rows.GetBoolean(2)));
        var tables = new Dictionary<string, string>();
        using var quote = new NpgsqlCommandBuilder();
        foreach (var (schema, table, sequence) in names)
        {
            string name = quote.QuoteIdentifier(schema) + "." + quote.QuoteIdentifier(table);
            tables[schema + "." + table] = (string)(await Scalar(db,
                sequence ? $"select last_value::text||':'||is_called::text from {name}" :
                $"select count(*)::text||':'||md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' order by to_jsonb(t)::text),'')) from {name} t", ct))!;
        }
        return new((DateTime)(await Scalar(db, "select clock_timestamp()", ct))!, tables,
            (string)(await Scalar(db, "select coalesce(jsonb_agg(last_used_at order by id)::text,'[]') from auth_sessions", ct))!);
    }

    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, db); return await command.ExecuteScalarAsync(ct); }

    private static async Task<JsonObject> Http(HttpClient client, CancellationToken ct)
    {
        using var response = await client.GetAsync("/api/v1/domains", ct);
        var headers = new JsonArray();
        foreach (var header in response.Headers.Concat(response.Content.Headers))
            foreach (string value in header.Value) headers.Add(new JsonArray(header.Key, value));
        return new JsonObject {
            ["status"] = (int)response.StatusCode, ["reason"] = response.ReasonPhrase,
            ["version"] = response.Version.ToString(), ["headers"] = headers,
            ["body_base64"] = Convert.ToBase64String(await response.Content.ReadAsByteArrayAsync(ct))
        };
    }


}
