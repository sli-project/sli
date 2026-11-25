using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Sli.Server.Vpn;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests;

public sealed class ReadSqlPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Workstation_computer_names_follow_reference_sources_and_bounded_xml_fallback()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString);
        await db.OpenAsync(ct);
        // Only the display-name reader's relations; the canonical runtime schema is exercised below.
        await PostCollectionPostgres.Sql(db, """
            create table sli_agents(id uuid,assigned_modules jsonb,registration_host_name text);
            create table sli_agent_audit(id bigint,target text,actor text,action text);
            create table sli_agent_group_approval_links(enrollment_token_id uuid,request_id bigint);
            create table sli_agent_group_requests(id bigint,computer_version_id bigint);
            create table ad_context_entity_versions(id bigint,attributes_json jsonb);
            create schema sli_plugin_workstations;
            create table sli_plugin_workstations.observations(id text,agent_key text,family text,observed_at timestamptz,source_xml text);
            insert into sli_agents values('00000000-0000-4000-8000-000000000001','[]',null);
            insert into sli_agent_audit values(1,'00000000-0000-4000-8000-000000000001','enrollment:00000000-0000-4000-8000-000000000002','issue');
            insert into sli_agent_group_approval_links values('00000000-0000-4000-8000-000000000002',1);
            insert into sli_agent_group_requests values(1,1);
            insert into ad_context_entity_versions values(1,'{}');
            """, ct);
        var readNames = typeof(Sli.Server.Workstations.WorkstationReports)
            .GetMethod("Names", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!
            .CreateDelegate<Func<NpgsqlConnection, string[], CancellationToken, Task<Dictionary<string, JsonObject>>>>();
        const string key = "00000000-0000-4000-8000-000000000001";
        static string Xml(string name) => "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Computer>" + name + "</Computer></System></Event>";
        async Task Check(string? enrolled, string? registered, string modules, string[] xml, string? expected, string source)
        {
            await using var seed = new NpgsqlCommand("""
                update sli_agents set registration_host_name=@registered,assigned_modules=@modules::jsonb;
                update ad_context_entity_versions set attributes_json=jsonb_build_object('attributes',jsonb_build_object('dns_host_name',@enrolled));
                delete from sli_plugin_workstations.observations;
                insert into sli_plugin_workstations.observations
                select n::text,@agent,(array['logons','processes','usb','protection'])[n],now(),source_xml
                from unnest(@xml::text[]) with ordinality input(source_xml,n);
                """, db);
            seed.Parameters.AddWithValue("registered", NpgsqlTypes.NpgsqlDbType.Text, (object?)registered ?? DBNull.Value);
            seed.Parameters.AddWithValue("enrolled", NpgsqlTypes.NpgsqlDbType.Text, (object?)enrolled ?? DBNull.Value);
            seed.Parameters.AddWithValue("modules", modules); seed.Parameters.AddWithValue("agent", key); seed.Parameters.AddWithValue("xml", xml);
            await seed.ExecuteNonQueryAsync(ct);
            var names = await readNames(db, [key], ct);
            Assert.Equal(expected, names[key]["name"]?.GetValue<string>());
            Assert.Equal(source, names[key]["source"]?.GetValue<string>());
        }
        const string module = """[{"module_id":"sli.workstations","config":{"source_name":"module.example.test"}}]""";
        await Check("ad.example.test", "registered.example.test", module, [Xml("event.example.test")], "ad.example.test", "ad_enrollment");
        await Check(null, "registered.example.test", module, [Xml("event.example.test")], "registered.example.test", "agent_reported");
        await Check(null, "unknown", module, [Xml("event.example.test")], "module.example.test", "module_config");
        await Check(null, "192.0.2.1", "[]", [Xml("event.example.test"), Xml("EVENT.example.test")], "event.example.test", "event_reported");
        await Check(null, null, "[]", [Xml("first.example.test"), Xml("second.example.test")], null, "unknown");
        await Check(null, null, "[]", ["<!DOCTYPE Event><Event/>", Xml("fallback.example.test")], "fallback.example.test", "event_reported");
        await Check(null, null, "[]", ["<Event>", Xml("fallback.example.test")], "fallback.example.test", "event_reported");
        await Check(null, null, "[]", [Xml("oversized.example.test") + new string(' ', 1048576)], null, "unknown");
        await Check("\u001c", null, "[]", [Xml("fallback.example.test")], "fallback.example.test", "event_reported");
        await Check(null, null, """[{"module_id":"sli.workstations","config":"invalid"}]""", [Xml("fallback.example.test")], "fallback.example.test", "event_reported");
        await Check(null, null, """[{"module_id":"sli.workstations","config":{"source_name":"urn:uuid:00000000-0000-4000-8000-000000000001"}}]""", [Xml("fallback.example.test")], "fallback.example.test", "event_reported");
        await Check(null, null, "[]", [], null, "unknown");
    }

    [Fact]
    public void Sql_helpers_reject_covariant_arrays_but_accept_explicit_array_parameters()
    {
        using var db = new NpgsqlConnection();
        foreach (string[] values in new[] { Array.Empty<string>(), new[] { "fixture" }, new[] { "fixture", "other" } })
        {
            Assert.Throws<ArgumentException>(() => Sli.Server.Workstations.Ws.Command(db, "select @p0", values));
            using var command = Sli.Server.Workstations.Ws.Command(db, "select @p0", (object)values);
            Assert.Same(values, Assert.Single(command.Parameters.Cast<NpgsqlParameter>()).Value);
        }
    }

    internal static void AssertReactDeclaration(JsonObject declaration, string key)
    {
        void Strings(JsonObject row, params string[] names)
        { foreach (string name in names) Assert.True(row[name]?.GetValueKind() == System.Text.Json.JsonValueKind.String, key + "." + name + " must be a string"); }
        void Options(JsonNode node)
        { foreach (var item in Assert.IsType<JsonArray>(node)) Strings(Assert.IsType<JsonObject>(item), "value", "label"); }
        void Columns(JsonNode node)
        {
            foreach (var item in Assert.IsType<JsonArray>(node))
            {
                var column = Assert.IsType<JsonObject>(item); Strings(column, "key", "label", "kind", "path");
                Assert.Contains(column["kind"]!.ToString(), new[] { "text", "number", "datetime", "date", "boolean", "code", "list", "state" });
            }
        }
        void Links(JsonNode node)
        { foreach (var item in Assert.IsType<JsonArray>(node)) Strings(Assert.IsType<JsonObject>(item), "label", "href"); }
        Assert.Equal(key, declaration["key"]?.ToString());
        foreach (string name in new[] { "params", "columns", "views", "presets", "row_links" })
            Assert.True(declaration[name] is JsonArray, key + "." + name + " must be an array");
        Strings(declaration, "section", "title", "description", "archetype", "row_key");
        foreach (var item in declaration["params"]!.AsArray())
        {
            var param = Assert.IsType<JsonObject>(item); Strings(param, "key", "label", "kind");
            Assert.False(string.IsNullOrEmpty(param["key"]?.ToString()), key);
            Assert.Contains(param["kind"]?.ToString(), new[] { "period", "text", "int", "choice", "multichoice", "domain" });
            if (param["options"] is {} options) Options(options);
            if (param["default"] is {} value) Assert.True(value.GetValueKind() is System.Text.Json.JsonValueKind.String or System.Text.Json.JsonValueKind.Number);
        }
        Assert.IsAssignableFrom<JsonValue>(declaration["export"]);
        Assert.IsType<bool>(declaration["export"]!.GetValue<bool>());
        Assert.IsType<JsonObject>(declaration["limits"]);
        Assert.True(declaration["limits"]!["default"]!.GetValue<int>() > 0); Assert.True(declaration["limits"]!["max"]!.GetValue<int>() >= declaration["limits"]!["default"]!.GetValue<int>());
        Assert.False(string.IsNullOrEmpty(declaration["row_key"]?.ToString()), key);
        Columns(declaration["columns"]!); Links(declaration["row_links"]!);
        foreach (var item in declaration["views"]!.AsArray())
        {
            var view = Assert.IsType<JsonObject>(item); Strings(view, "key", "kind"); Assert.Contains(view["kind"]!.ToString(), new[] { "table", "chart", "custom" });
            if (view["columns"] is {} columns) Columns(columns);
        }
        foreach (var item in declaration["presets"]!.AsArray())
        {
            var preset = Assert.IsType<JsonObject>(item); Strings(preset, "label");
            foreach (var pair in Assert.IsType<JsonObject>(preset["params"])) Assert.Equal(System.Text.Json.JsonValueKind.String, pair.Value!.GetValueKind());
        }
        if (declaration["detail"] is JsonObject detail)
        { Strings(detail, "kind", "title", "key"); Assert.Contains(detail["kind"]!.ToString(), new[] { "sub", "inline" }); Columns(detail["columns"]!); Links(detail["row_links"]!); }
        else Assert.Contains(declaration["detail"]?.ToString(), new[] { "fields", "none" });
        if (declaration["filter_options"] is JsonObject filters) foreach (var pair in filters) Options(pair.Value!);
    }

    private static string Repository([System.Runtime.CompilerServices.CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../.."));
    [Fact]
    public async Task Every_registered_GET_executes_against_the_canonical_schema_as_adlog_user()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var pg = fixture.Pg;
        await using var admin = await pg.OpenAsync(ct);
        string root = Repository();
        string token = await fixture.SeedOwnerAsync(ct);
        var shortRows = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, shortRows, ct);
        var shortEventId = Assert.Single(shortRows).EventId;
        // Let the real semantic worker register source metadata for password coverage.
        await using (var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")))
        {
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
            await using var discover = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            Assert.IsType<string>(await discover.ExecuteScalarAsync(ct));
        }

        await PostCollectionPostgres.Sql(admin, """
            insert into servers(id,domain_id,hostname,fqdn) select 1,id,'fixture','fixture.example.test' from domains where fqdn='example.test';
            insert into platform_settings(key,value,updated_by) values('reports.domain_fqdn','example.test','synthetic') on conflict(key) do update set value=excluded.value;
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            select ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
                   ('00000000-0000-4000-9000-'||lpad(n::text,12,'0'))::uuid,
                   repeat(n::text,64),'[{"module_id":"sli.workstations","config":{}}]'::jsonb
            from generate_series(1,2) n;
            insert into sli_plugin_workstations.station_inventory(station_id,agent_key,station_type,metadata)
            select 'fixture-station-'||n,'00000000-0000-4000-8000-'||lpad(n::text,12,'0'),
                   'workstation','{"display_name":"fixture.example.test"}'::jsonb from generate_series(1,2) n;
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            select encode(sha256(convert_to(family||n::text,'UTF8')),'hex'),
                   '00000000-0000-4000-8000-'||lpad(n::text,12,'0'),n,family,4624,now()-interval '1 minute',
                   '{"facts":{"storage_evidence":true},"quality":{}}'::jsonb,repeat('a',64),
                   '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Computer>fixture.example.test</Computer></System></Event>'
            from generate_series(1,2) n cross join (values('logons'),('usb'),('processes'),('protection')) families(family);
            """, ct);
        var runtime = new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Username = "adlog_user" };
        // Exercise the batched home label SQL even when this fixture has no findings.
        await using (var identityDb = new NpgsqlConnection(runtime.ConnectionString))
        {
            await identityDb.OpenAsync(ct);
            await using var labels = new NpgsqlCommand(Sli.Server.Domains.HomeDecisionSummary.IdentitySql,identityDb);
            labels.Parameters.AddWithValue("requests", "[{\"request_index\":0,\"finding\":1,\"sid\":\"s-1-5-21-100000001-200000002-300000003-1001\"}]");
            await using var result = await labels.ExecuteReaderAsync(ct);
            Assert.False(await result.ReadAsync(ct));
        }
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .ConfigureLogging(l => l.ClearProviders())
            .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = runtime.ConnectionString, ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(pg.Root, "app-data"), ["Sli:LogDirectory"] = Path.Combine(pg.Root, "app-logs"),
                ["Sli:Storage:HistoryReadMode"] = "disabled",
                ["Sli:Storage:ArchiveRoot"] = Path.Combine(pg.Root, "archive"),
                ["Sli:OwnerSetup"] = "0", ["Sli:HttpRatePerMinute"] = "5000", ["urls"] = "http://127.0.0.1:0"
            })));
        host.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));
        host.StartServer();
        string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) { BaseAddress = new Uri(address) };
        client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
        using (var scope = host.Services.CreateScope())
        {
            Assert.IsType<PostgresConnectionFactory>(scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>());
            await using var db = await scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var check = new NpgsqlCommand("select current_user,rolsuper,rolcreaterole,rolbypassrls,has_schema_privilege(current_user,'public','CREATE'),rolinherit,rolcreatedb,rolreplication from pg_roles where rolname=current_user", db);
            await using var row = await check.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct)); Assert.Equal("adlog_user", row.GetString(0));
            for (int i = 1; i < 8; i++) Assert.False(row.GetBoolean(i));
        }
        var routes = host.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Where(e => e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains("GET") == true)
            .Select(e => e.RoutePattern.RawText!).Distinct().Order().ToArray();
        Assert.NotEmpty(routes);
        var definitions = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json")))!.AsArray();
        var reportKeys = definitions.Select(d => d!["key"]!.GetValue<string>()).ToArray();
        Assert.NotEmpty(reportKeys);
        Assert.Equal(reportKeys.Order(), host.Services.GetRequiredService<Sli.Server.Access.IReportCatalogProvider>().Capture().Rules.Select(r => r.RegistryKey).Order());
        var storedKeys = new List<string>();
        await using (var keys = new NpgsqlCommand("select distinct report_key from report_registry_v4 where status='published' order by report_key", admin))
        await using (var rows = await keys.ExecuteReaderAsync(ct))
            while (await rows.ReadAsync(ct)) storedKeys.Add(rows.GetString(0));
        long domainId;
        await using (var domain = new NpgsqlCommand("select id from domains where fqdn='example.test'", admin)) domainId = Convert.ToInt64(await domain.ExecuteScalarAsync(ct));
        await using var owner = new NpgsqlCommand("select id from auth_users where username='platform-owner'", admin);
        long ownerId = Convert.ToInt64(await owner.ExecuteScalarAsync(ct));
        using var readScope = host.Services.CreateScope();
        var facts = await readScope.ServiceProvider.GetRequiredService<IAccessFactsRepository>()
            .LoadAsync(new Principal("session", ownerId, "admin", "platform-owner"), ct);
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var workstationReader = readScope.ServiceProvider.GetRequiredService<IWorkstationReports>();
        var registry = new Sli.Server.Reporting.V2.ReportDefinitionRegistry();
        foreach (string key in reportKeys)
        {
            string reportPath = "/api/v2/reports/" + key;
            bool retired = WorkstationReportContract.Keys.Contains(key) && key != "workstations.overview"
                || key is "vpn.accounts" or "vpn.connections";
            using var declarationResponse = await client.GetAsync(reportPath, ct);
            JsonObject declaration;
            if (retired)
            {
                await AssertModuleDisabled(declarationResponse, ct);
                declaration = key.StartsWith("workstations.", StringComparison.Ordinal)
                    ? WorkstationReportContract.Declaration(key)
                    : registry.Get(key)!.Declaration;
            }
            else
            {
                Assert.Equal(HttpStatusCode.OK, declarationResponse.StatusCode);
                declaration = JsonNode.Parse(await declarationResponse.Content.ReadAsStringAsync(ct))!.AsObject();
            }
            AssertReactDeclaration(declaration, key);
            var parameters = new List<string>();
            foreach (var param in declaration["params"]!.AsArray().OfType<JsonObject>())
            {
                string name = param["key"]!.ToString();
                string? value = param["kind"]?.ToString() == "domain" ? domainId.ToString(System.Globalization.CultureInfo.InvariantCulture) : param["default"]?.ToString();
                // These standalone stations have no inferred AD-domain association.
                if (key == "workstations.overview" && name == "domain") value = null;
                if (!string.IsNullOrEmpty(value)) parameters.Add(Uri.EscapeDataString(name) + "=" + Uri.EscapeDataString(value));
            }
            string query = string.Join('&', parameters);
            using var dataResponse = await client.GetAsync(reportPath + "/data?" + query, ct);
            JsonObject data;
            if (retired)
            {
                await AssertModuleDisabled(dataResponse, ct);
                if (!key.StartsWith("workstations.", StringComparison.Ordinal)) continue;

                WorkstationReportContract.Admit(access, key);
                var request = WorkstationReportContract.Parse(key, new QueryCollection(QueryHelpers.ParseQuery(query)));
                data = await workstationReader.ReadAsync(request, facts, access, ct);
            }
            else
            {
                string body = await dataResponse.Content.ReadAsStringAsync(ct);
                Assert.True(dataResponse.StatusCode == HttpStatusCode.OK, key + ": " + body);
                data = JsonNode.Parse(body)!.AsObject();
            }
            string dataText = data.ToJsonString();
            Assert.Equal("sli.report-result.v2", data["contract_id"]?.ToString());
            Assert.False(data["state"]?.ToString() == "error" && data["state_details"]?["reason"]?.ToString() == "report_reader_unavailable", key + ": " + dataText);
            if (key == "workstations.overview")
            {
                Assert.Equal("ok", data["state"]?.ToString());
                Assert.Equal(2, data["items"]!.AsArray().Count);
                Assert.All(data["items"]!.AsArray(), item => {
                    Assert.Equal("disabled", item!["collection_state"]?.ToString());
                    Assert.False(item["journal_available"]!.GetValue<bool>());
                });
            }
            else if (key.StartsWith("workstations.", StringComparison.Ordinal))
            {
                Assert.True(data["state"]?.ToString() == "partial", key + ": " + dataText);
                Assert.True(Assert.IsType<JsonArray>(data["items"]).Count > 0, key + ": " + dataText);
                if (key != "workstations.overview")
                {
                    Assert.Equal(2, data["items"]!.AsArray().Count);
                    Assert.Contains(data["limitations"]!.AsArray(), item => item?["code"]?.ToString() == "coverage_unverified"
                        && item["text"]!.GetValue<string>().Contains("USB-события не доказывают чтение или копирование файлов."));
                    Assert.All(data["items"]!.AsArray(), item => {
                        Assert.Equal("fixture.example.test", item!["host_name"]?.ToString());
                        Assert.Equal("event_reported", item["host_name_source"]?.ToString());
                    });
                }
            }
        }
        await AssertWorkstationReportOrderAsync(workstationReader, facts, access, admin, ct);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (string route in routes.Append("/api/v1/domains"))
        {
            foreach (string key in route.Contains("{key}") ? route.StartsWith("/api/v1/") ? storedKeys.ToArray() : reportKeys : ["events.journal"])
            {
                string path = Regex.Replace(route, @"\{[^}]+\}", m => m.Value switch {
                    "{hostname}" => "fixture.example.test", "{objectType}" => "ad_user", "{key}" => key,
                    _ when route.StartsWith("/api/plugins/") => "sli.ad/settings",
                    _ when route.StartsWith("/api/v1/ui/plugins/") && m.Value.Contains("tail") => "sli.ad/descriptor",
                    _ when route.StartsWith("/api/v1/ui/plugins/") && m.Value == "{id}" => "sli.ad",
                    _ when route.StartsWith("/api/v1/ui/plugins/") && m.Value == "{hash}" => new string('a', 64),
                    _ when route.StartsWith("/api/v1/ui/plugins/") => "entry.js",
                    _ when m.Value.Contains("objectPath") => "ad_user/1",
                    _ when route.StartsWith("/api/findings/") => "1/risk-audit",
                    _ when route.StartsWith("/api/v1/investigations/") && m.Value.Contains("tail") => "evidence",
                    _ when (key is "workstations.usb" or "workstations.processes" ||
                            route.StartsWith("/api/v2/reports/workstations.usb/rows/", StringComparison.Ordinal) ||
                            route.StartsWith("/api/v2/reports/workstations.processes/rows/", StringComparison.Ordinal)) &&
                           route.EndsWith("/detail", StringComparison.Ordinal) => new string('1', 64),
                    _ => "1"
                });
                if (path == "/api/v1/events/batch") path += "?event_db_id=" + shortEventId;
                if (path == "/api/events/details") path += "?event_db_id=" + shortEventId;
                if (path == "/api/v1/admin/agent-onboarding") path += "?token_id=00000000-0000-4000-8000-000000000001";
                if (path is "/api/v1/admin/agents/file-audit" or "/api/v1/admin/agents/sequence-recovery") path += "?agent_id=00000000-0000-4000-8000-000000000001";
                if (path.EndsWith("/vpn-sessions")) path += "?time_from=2026-11-05T00:00:00Z&time_to=2026-11-06T00:00:00Z";
                if (Sli.Server.Ad.AdReportEndpoints.Routes.Contains(path) && !path.EndsWith("sources")) path += "?domain_id=" + domainId;
                paths.Add(path);
            }
        }
        var failures = new List<string>(); var statuses = new SortedDictionary<int, int>(); int count = 0;
        using var securityDeclarationResponse = await client.GetAsync("/api/v2/reports/security.events.chains", ct);
        Assert.Equal(HttpStatusCode.OK, securityDeclarationResponse.StatusCode);
        var securityDeclaration = JsonNode.Parse(await securityDeclarationResponse.Content.ReadAsStringAsync(ct))!;
        foreach (var view in securityDeclaration["views"]!.AsArray())
            foreach (string action in new[] { "data", "export.csv" })
                paths.Add("/api/v2/reports/security.events.chains/" + action + "?domain=" + domainId + "&period=24h&tab=" + Uri.EscapeDataString(view!["key"]!.ToString()));
        foreach (string path in paths.Order())
        {
            try
            {
                using var response = await client.GetAsync(path, ct);
                string body = await response.Content.ReadAsStringAsync(ct);
                int status = (int)response.StatusCode;
                statuses[status] = statuses.GetValueOrDefault(status) + 1;
                string? errorCode = response.Content.Headers.ContentType?.MediaType == "application/json" ? (JsonNode.Parse(body) as JsonObject)?["error"]?.ToString() : null;
                output.WriteLine($"GET {path}: {status} {errorCode}");
                if (path is "/api/role-views" or "/api/v2/reports/events.journal/export.csv" or "/api/v2/reports/security.events.chains/export.csv"
                    || path.StartsWith("/api/v2/reports/security.events.chains/", StringComparison.Ordinal) && path.Contains("&tab=", StringComparison.Ordinal))
                    if (status != 200) failures.Add($"{path}: expected working read, got {status} {body}");
                bool retired = RetiredModulePath(path);
                if (retired && (response.StatusCode != HttpStatusCode.ServiceUnavailable || errorCode != "module_disabled"))
                    failures.Add($"{path}: expected 503 module_disabled, got {status} {errorCode}");
                if (response.StatusCode is HttpStatusCode.InternalServerError or HttpStatusCode.NotImplemented)
                    failures.Add($"{path}: {(int)response.StatusCode} {body}");
                if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    string? expected = path switch {
                        "/api/v1/operations/administrative-activity" => "administrative_activity_reader_runtime_disabled",
                        "/" or "/app" or "/app/1" => "react_ui_not_built",
                        _ when retired => "module_disabled",
                        _ => null
                    };
                    // Do not let a generic 503 conceal another broken PG query/adapter.
                    if (string.IsNullOrWhiteSpace(errorCode) || errorCode != expected)
                        failures.Add($"{path}: unexpected 503 {errorCode}");
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { failures.Add(path + ": " + error); }
            count++;
        }
        output.WriteLine($"Checked {count} GET requests from {routes.Length + 1} route patterns");
        output.WriteLine("HTTP totals: " + string.Join(", ", statuses.Select(p => $"{p.Key}={p.Value}")));
        string diagnostics = await pg.DiagnosticsAsync(ct);
        var errors = Regex.Matches(diagnostics, @"(?m)^.*(?:ERROR:|ОШИБКА:).*$").Select(m => m.Value).ToArray();
        if (errors.Length > 0) failures.Add("PostgreSQL errors:\n" + diagnostics);
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }
    // S6 preserves ACLs on these disabled routes and retires the old readers
    // (632c2a593, 22df767c1, 7a0cb3264). Event detail stays on the short store.
    private static bool RetiredModulePath(string path)
    {
        const string vpnAudit = "/api/v1/reports/vpn.audit/";
        if (path.StartsWith(vpnAudit, StringComparison.Ordinal))
            return VpnEndpoints.Operations.Contains(path[vpnAudit.Length..]);

        const string reports = "/api/v2/reports/";
        if (path.StartsWith(reports, StringComparison.Ordinal))
        {
            string[] parts = path[reports.Length..].Split('/', 2);
            string key = parts[0], action = parts.Length == 1 ? "" : parts[1];
            bool detail = action.EndsWith("/detail", StringComparison.Ordinal);
            if (key is "vpn.accounts" or "vpn.connections")
                return action is "" or "data" or "export.csv" || detail;
            if (WorkstationReportContract.Keys.Contains(key) && key != "workstations.overview")
                return action is "" or "data" || (detail && key is not ("workstations.logons" or "workstations.protection"));
        }

        return path is "/api/ai/prompt-preview" or "/api/ai/redaction-preview" or "/api/ai/runs" or
            "/api/entities/details" or "/api/entities/summary" or
            "/api/events/search" or "/api/events/search/deep" or "/api/events/summary" or "/api/events/timeline" or
            "/api/security/events-monitor" or "/api/v1/investigation-cases" or "/api/v1/investigations" or
            "/reports/ai-analysis.html" or "/reports/ai-prompt-preview.html" or "/reports/ai-redaction-preview.html" or
            "/reports/ai-reports.html" or "/reports/security-events-monitor.csv" ||
            path.StartsWith("/api/v1/investigations/", StringComparison.Ordinal);
    }

    private static async Task AssertModuleDisabled(HttpResponseMessage response, CancellationToken ct)
    {
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!;
        Assert.Equal("module_disabled", body["error"]!.GetValue<string>());
        Assert.Equal("disabled", body["state"]!.GetValue<string>());
    }

    private static async Task AssertWorkstationReportOrderAsync(IWorkstationReports reader, AccessFacts facts,
        AccessDecision access, NpgsqlConnection admin, CancellationToken ct)
    {
        const string agent = "00000000-0000-4000-8000-000000000001";
        await PostCollectionPostgres.Sql(admin, """
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            select repeat(n::text,64),'00000000-0000-4000-8000-000000000001',1,'logons',4624,
                (array['2026-11-03','2026-10-31','2026-10-31','2026-11-03','2026-10-30'])[n]::timestamptz,
                '{"facts":{},"quality":{}}'::jsonb,repeat('a',64),
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Computer>fixture.example.test</Computer></System></Event>'
            from generate_series(1,5) n;
            """, ct);
        // Each family needs distinct immutable IDs; deliberately keep source times out of order.
        await PostCollectionPostgres.Sql(admin, """
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            select 'a'||substr(id,2),agent_key,entity_id,'processes',4688,observed_at,observation,observation_sha256,source_xml
            from sli_plugin_workstations.observations where family='logons' and id in (repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),repeat('5',64));
            """, ct);
        foreach (string family in new[] { "logons", "processes" })
        {
            string? cursor = null; var ids = new List<string>(); var days = new List<int>();
            for (int page = 0; page < 3; page++)
            {
                string key = "workstations." + family;
                string query = "agent_key=" + agent
                    + "&period=custom&from=2026-10-30T00%3A00%3A00Z&to=2026-11-04T00%3A00%3A00Z&limit=2"
                    + (cursor is null ? "" : "&cursor=" + cursor);
                WorkstationReportContract.Admit(access, key);
                var request = WorkstationReportContract.Parse(key, new QueryCollection(QueryHelpers.ParseQuery(query)));
                var result = await reader.ReadAsync(request, facts, access, ct);
                Assert.Equal("partial", result["state"]?.ToString());
                var items = result["items"]!.AsArray(); Assert.Equal(page < 2 ? 2 : 1, items.Count);
                foreach (var item in items)
                {
                    ids.Add(item!["id"]!.GetValue<string>());
                    days.Add(DateTimeOffset.Parse(item["observed_at"]!.GetValue<string>()).Day);
                    Assert.Equal("fixture.example.test", item["host_name"]?.ToString());
                }
                Assert.Equal(page < 2, result["has_more"]!.GetValue<bool>());
                cursor = result["next_cursor"]?.GetValue<string>();
                Assert.Equal(page < 2 ? ids[^1] : null, cursor);
                Assert.Contains(result["limitations"]!.AsArray(), item => item?["code"]?.ToString() == "coverage_unverified"
                    && item["text"]!.GetValue<string>().Contains("USB-события не доказывают чтение или копирование файлов."));
            }
            Assert.Equal(Enumerable.Range(1,5).Select(n => (family == "processes" ? "a" : n.ToString()) + new string((char)('0' + n),63)), ids);
            Assert.Equal(new[] { 3, 31, 31, 3, 30 }, days);
        }
    }
}
