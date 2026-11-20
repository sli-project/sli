using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class WorkerSqlPostgresTests
{
    [Fact]
    public async Task Post_collection_imports_dc_and_marks_disabled_modules_with_rendered_unit_environment()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        string root = SqlPostgresFixture.Repository();
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await SeedInstalledPackets(db, root, fixture.Pg.Root, ct);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
            ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "ADLOG_DATA_DIR")
        }).Build();
        var queries = new OperationsQueries(new PostgresConnectionFactory(configuration));
        var agents = await queries.ReadAsync(OperationsSql.Agents, ct);
        var requested = new JsonArray(agents.OfType<JsonObject>().Select(a => (JsonNode)new JsonObject {
            ["agent_id"] = a["id"]!.DeepClone(), ["module_id"] = a["assigned_modules"]![0]!["module_id"]!.DeepClone(),
            ["revision"] = "1", ["channel"] = "Security", ["snapshot"] = false
        }).ToArray());
        await queries.ReadAsync(OperationsSql.Streams, ct, ("requested", requested.ToJsonString()));
        var render = ProcessInfo(Environment.GetEnvironmentVariable("SLI_TEST_PYTHON") ?? (OperatingSystem.IsWindows()
            ? "python" : "python3"), root);
        render.ArgumentList.Add("-B"); render.ArgumentList.Add("-c");
        render.ArgumentList.Add("from deploy.linux import native_runtime as n; import json; n.clickhouse.configured_mode=lambda: 'native'; print(json.dumps(n.dotnet_units('synthetic',dict(profiles=['light'],radius_pilot=False,bind='192.0.2.1',health_url='https://192.0.2.1:8443/api/health/ready'))))");
        var rendered = await RunProcess(render, ct); Assert.Equal(0, rendered.Exit);
        string unit = JsonNode.Parse(rendered.Out)!["sli-dotnet-post-collection.service"]!.GetValue<string>();
        var info = ProcessInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", root);
        info.ArgumentList.Add(typeof(Program).Assembly.Location); info.ArgumentList.Add("post-collection-worker"); info.ArgumentList.Add("--once");
        string credentials = Path.Combine(fixture.Pg.Root, "credentials"); Directory.CreateDirectory(credentials);
        var loaded = Regex.Matches(unit, @"(?m)^LoadCredential=([^:]+):").Select(m => m.Groups[1].Value).ToHashSet();
        Assert.Equal(new[] { "context_password", "runtime_password", "storage_password" }, loaded.Order());
        foreach (string name in loaded) await File.WriteAllTextAsync(Path.Combine(credentials, name), "synthetic-test-password\n", ct);
        foreach (Match setting in Regex.Matches(unit, "(?m)^Environment=\"([^=]+)=(.*)\"$"))
        {
            string key = setting.Groups[1].Value, value = setting.Groups[2].Value;
            if (value.StartsWith("%d/", StringComparison.Ordinal)) { Assert.Contains(value[3..], loaded); value = Path.Combine(credentials, value[3..]); }
            else if (key.EndsWith("_DSN", StringComparison.Ordinal)) {
                string role = Regex.Match(value, @"user=([^ ]+)").Groups[1].Value;
                var target = new NpgsqlConnectionStringBuilder(fixture.Dsn(role));
                value = $"host={target.Host} port={target.Port} dbname={target.Database} user={role}";
            }
            else if (key == "Sli__EventCatalogPath") value = Path.Combine(root, "config/event_catalog.json");
            // The installed lock belongs to /var/lib/sli; this test owns only its disposable cluster.
            else if (key == "ADLOG_POSTGRES_IMPORT_QUEUE_LOCK") value = Path.Combine(fixture.Pg.Root, "postgres-import.queue.lock");
            else if (key is "ADLOG_DATA_DIR" or "ADLOG_LOG_DIR" or "SLI_PLUGIN_RUNTIME_DIR" or "SLI_PLUGIN_LOCK_DIR") {
                value = Path.Combine(fixture.Pg.Root, key); Directory.CreateDirectory(value);
                if (key == "SLI_PLUGIN_LOCK_DIR") foreach (string plugin in new[] { "sli.ad", "sli.file-audit" })
                    await File.WriteAllTextAsync(Path.Combine(value, plugin + ".json"), "{}", ct);
            }
            info.Environment[key] = value;
        }
        Assert.DoesNotContain("ConnectionStrings__Sli", info.Environment.Keys);
        Assert.DoesNotContain("ADLOG_PG_ADMIN_USER", info.Environment.Keys);
        string? catalog = info.Environment.TryGetValue("Sli__EventCatalogPath", out var configuredCatalog) ? configuredCatalog : null;
        Assert.NotNull(catalog);
        info.Environment.Remove("Sli__EventCatalogPath");
        var unavailable = await RunProcess(info, ct);
        Assert.Contains("agent_storage_unavailable", unavailable.Out);
        info.Environment["Sli__EventCatalogPath"] = catalog;
        var result = await RunProcess(info, ct);
        output.WriteLine(result.Out + result.Error); Assert.Equal(0, result.Exit);
        Assert.DoesNotContain("_failed", result.Error);
        long eventId;
        await using (var check = new NpgsqlCommand("""
            select (select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is null),
                   (select count(*) from sli_agent_packet_quarantine),
                   (select array_agg(envelope->>'module_id' order by envelope->>'module_id')
                    from sli_agent_packet_inbox where imported_at is null and module_disabled_at is not null),
                   (select count(*) from sli_plugin_workstations.observations),
                   (select count(*) from sli_plugin_file_audit.observations),
                   to_regclass('public.events_v2_core') is null;
            select event_id,event_kind,event_record_id from event_hot;
            """, db)) {
            await using var r = await check.ExecuteReaderAsync(ct);
            Assert.True(await r.ReadAsync(ct));
            Assert.Equal(0L, r.GetInt64(0));
            Assert.Equal(0L, r.GetInt64(1));
            Assert.Equal(new[] { "sli.file-audit", "sli.workstations" }, r.GetFieldValue<string[]>(2));
            Assert.Equal(0L, r.GetInt64(3));
            Assert.Equal(0L, r.GetInt64(4));
            Assert.True(r.GetBoolean(5));
            Assert.True(await r.NextResultAsync(ct));
            Assert.True(await r.ReadAsync(ct));
            eventId = r.GetInt64(0);
            Assert.Equal(4624, r.GetInt32(1));
            Assert.Equal(1L, r.GetInt64(2));
            Assert.False(await r.ReadAsync(ct));
        }
        // The worker's cycle fact remains in PostgreSQL; its process observation
        // correctly reports that this --once invocation has now exited.
        var durable = await queries.ReadAsync("select status,phase from runtime_worker_heartbeats where worker_name='post_collection'", ct);
        Assert.Equal("idle", Assert.Single(durable)!["status"]!.ToString());
        using (var host = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(b => b
            .ConfigureLogging(l => l.ClearProviders())
            .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                ["Sli:AgentMtlsCaFile"] = "", ["Sli:TrustedProxies"] = "",
                ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = configuration["Sli:DataDirectory"],
                ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:OwnerSetup"] = "0"
            })))) {
            using var client = host.CreateClient();
            client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + await fixture.SeedOwnerAsync(ct));
            foreach (string suffix in new[] { "?view=readiness", "" }) {
                using var response = await client.GetAsync("/api/v1/operations/overview" + suffix, ct);
                response.EnsureSuccessStatusCode();
                var overview = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!;
                Assert.Null(overview["agent_collection"]?["diagnostics"]);
                var checks = overview["agent_collection"]!["items"]!.AsArray()
                    .SelectMany(a => a!["modules"]!.AsArray())
                    .Where(m => m!["module_id"]!.ToString() == "sli.windows.ad-dc")
                    .SelectMany(m => m!["channels"]!.AsArray())
                    .Where(c => c!["last_packet_at"] is not null).ToArray();
                Assert.NotEmpty(checks);
                foreach (var channel in checks) { Assert.NotNull(channel!["last_import_at"]); Assert.NotNull(channel["import_lag_seconds"]); Assert.NotEqual("unknown", channel["state"]!.ToString()); }
                var worker = Assert.Single(overview["workers"]!["items"]!.AsArray(), w => w!["worker_name"]!.ToString() == "post_collection")!;
                Assert.Equal("disabled", worker["state"]!.ToString()); Assert.Equal("stopped", worker["status"]!.ToString()); Assert.NotNull(worker["heartbeat_at"]);
            }
        }
        // Re-read acknowledged evidence: exact-source replay must remain idempotent.
        await PostCollectionPostgres.Sql(db, "update sli_agent_packet_inbox set imported_at=null where envelope->>'module_id'='sli.windows.ad-dc'", ct);
        result = await RunProcess(info, ct); Assert.Equal(0, result.Exit);
        await using (var check = new NpgsqlCommand("""
            select (select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is null),
                   (select count(*) from sli_agent_packet_inbox where imported_at is null and module_disabled_at is not null),
                   array_agg(event_id) from event_hot
            """, db)) {
            await using var rows = await check.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(0L, rows.GetInt64(0));
            Assert.Equal(2L, rows.GetInt64(1));
            Assert.Equal(new[] { eventId }, rows.GetFieldValue<long[]>(2));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Notification_cycle_is_observed_without_granting_heartbeat_table_access()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        string root = SqlPostgresFixture.Repository(), data = Path.Combine(fixture.Pg.Root, "notification-data");
        var info = ProcessInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", root);
        info.ArgumentList.Add(typeof(Program).Assembly.Location); info.ArgumentList.Add("notification-delivery-worker"); info.ArgumentList.Add("--once");
        info.Environment["ADLOG_PG_DSN"] = fixture.Dsn("sli_notification_login");
        info.Environment["ADLOG_DATA_DIR"] = data;
        info.Environment["SLI_NOTIFICATION_STATUS_FILE"] = Path.Combine(fixture.Pg.Root, "notification-cycle.json");
        var result = await RunProcess(info, ct); Assert.Equal(0, result.Exit); Assert.DoesNotContain("notification_delivery_cycle_failed", result.Out);
        Assert.True(File.Exists(info.Environment["SLI_NOTIFICATION_STATUS_FILE"]));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"), ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = data
        }).Build();
        var queries = new OperationsQueries(new PostgresConnectionFactory(config));
        var operations = new OperationsService(queries, new(config), new(), new(), TimeProvider.System);
        var worker = Assert.Single((await operations.WorkersAsync(ct))["items"]!.AsArray(), w => (string?)w?["worker_name"] == "notification_delivery")!;
        Assert.Equal("disabled", (string?)worker["state"]); Assert.Equal("stopped", (string?)worker["status"]);
        Assert.Equal("native_process_heartbeat", (string?)worker["observation_source"]);
        var privileges = await queries.ReadAsync("select has_table_privilege('adlog_notification_worker','runtime_worker_heartbeats','INSERT') as can_write", ct);
        Assert.False((bool)Assert.Single(privileges)!["can_write"]!);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task SeedInstalledPackets(NpgsqlConnection db, string root, string archive, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into servers(id,domain_id,hostname,fqdn,role)
              select 1,id,'fixture-dc','fixture-dc.example.test','domain_controller' from domains where fqdn='example.test';
            insert into log_sources(name) values('Security') on conflict do nothing;
            update plugin_installations_v1 set package_lifecycle='registered',desired_activation='enabled_manual'
              where plugin_id in ('sli.ad','sli.file-audit','sli.workstations');
            """, ct);
        DateTime now = new(DateTime.UtcNow.Ticks / 10 * 10, DateTimeKind.Utc);
        var auth = new DirectRuntimeRecord("v2", "storage-v2-fresh-bootstrap/v1", new string('a',64), archive,
            new JsonObject { ["kind"]="fresh-event-store", ["version"]=1 }, "synthetic-test", now, now.AddHours(1), null, "");
        await using (var command = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,archive_root,evidence,authorized_by,authorized_at,expires_at)
            values(@route,@authority,@preflight,@digest,@archive,@evidence,'synthetic-test',@at,@expires)
            """, db)) {
            command.Parameters.AddWithValue("route",auth.Route); command.Parameters.AddWithValue("authority",auth.Authority);
            command.Parameters.AddWithValue("preflight",auth.PreflightDigest); command.Parameters.AddWithValue("digest",DirectRuntimeAuthorization.Digest(auth));
            command.Parameters.AddWithValue("archive",archive); command.Parameters.AddWithValue("evidence",NpgsqlDbType.Jsonb,auth.Evidence.ToJsonString());
            command.Parameters.AddWithValue("at",now); command.Parameters.AddWithValue("expires",auth.ExpiresAt); await command.ExecuteNonQueryAsync(ct);
        }
        async Task Store(Guid agent, Guid host, string module, JsonObject body, JsonObject envelope, JsonArray assignments, string channel, string source, int sequence = 1)
        {
            Guid packet = Guid.Parse(envelope["packet_id"]!.GetValue<string>());
            var rows = new JsonArray(body["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
            await using var command = new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint,status,assigned_modules) values(@agent,@host,repeat('a',64),'active',@assigned) on conflict do nothing;
                insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                  select @agent,@module,@host::text,@source,@channel,'1.0.0','1' where @module<>'sli.file-audit' on conflict do nothing;
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                  values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}');
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@body,@rows)
                """, db);
            command.Parameters.AddWithValue("agent",agent); command.Parameters.AddWithValue("host",host); command.Parameters.AddWithValue("module",module);
            command.Parameters.AddWithValue("channel",channel); command.Parameters.AddWithValue("source",source); command.Parameters.AddWithValue("sequence",(long)sequence);
            command.Parameters.AddWithValue("packet",packet); command.Parameters.AddWithValue("hash",Packets.Digest(envelope));
            foreach (var (name,node) in new (string,JsonNode)[] { ("assigned",assignments),("envelope",envelope),("body",body),("rows",rows) })
                command.Parameters.AddWithValue(name,NpgsqlDbType.Jsonb,CanonicalJson.Serialize(node));
            await command.ExecuteNonQueryAsync(ct);
        }
        Guid dc = Guid.NewGuid(), dcHost = Guid.NewGuid();
        var ad = JsonNode.Parse(File.ReadAllText(Path.Combine(root,"agent-dotnet/tests/vectors/ad-dc-scenarios.json")))!.AsArray()
            .Single(x=>x!["name"]!.GetValue<string>()=="security-initial-window-all")!;
        var adStep = ad["steps"]![0]!; var expected = adStep["expected"]!;
        string Rebind(string value) => value.Replace(ad["host_id"]!.GetValue<string>(),dcHost.ToString("D"));
        var dcBody = JsonNode.Parse(Rebind(expected["payload_canonical"]!.GetValue<string>()))!.AsObject();
        string xml = $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>fixture-dc</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        dcBody["header"]!["source"]="fixture-dc"; dcBody["records"]![0]!["payload"]=EventXml.Parse(xml,"fixture-dc","","Security");
        var dcEnvelope = new Envelope(Guid.NewGuid().ToString(),dc.ToString(),dcHost.ToString(),"sli.windows.ad-dc","1.0.0","1","ad-dc",dcHost.ToString(),1,
            Cursor.FromJson(JsonNode.Parse(Rebind(expected["cursor_before"]!.ToJsonString()))),Cursor.FromJson(JsonNode.Parse(Rebind(expected["cursor_after"]!.ToJsonString()))),
            CollectionPacket.Contract,Packets.Digest(dcBody),1,CanonicalJson.Length(dcBody),adStep["now"]!.GetValue<string>(),"not_proven",0,0).ToJson();
        await Store(dc,dcHost,"sli.windows.ad-dc",dcBody,dcEnvelope,new JsonArray(new JsonObject { ["module_id"]="sli.windows.ad-dc",["enabled"]=true }),"ad-dc","fixture-dc");

        Guid file = Guid.NewGuid();
        var vector = JsonNode.Parse(File.ReadAllText(Path.Combine(root,"agent-dotnet/tests/vectors/file-audit-scenarios.json")))!.AsArray()
            .Single(x=>x!["name"]!.GetValue<string>()=="events-restart-filter")!;
        var step = vector["steps"]![0]!;
        var fileBody = JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
        var policy = vector["config"]!.DeepClone().AsObject(); policy["source_name"]=fileBody["header"]!["source"]!.DeepClone();
        // This server is independently bound, so its masked context belongs to this stream too.
        await using (var server = new NpgsqlCommand("insert into servers(id,domain_id,hostname,fqdn,role) select 2,id,@name,'file.example.test','file_server' from domains where fqdn='example.test'",db)) {
            server.Parameters.AddWithValue("name",policy["source_name"]!.GetValue<string>()); await server.ExecuteNonQueryAsync(ct);
        }
        Guid host = Guid.Parse(vector["host_id"]!.GetValue<string>());
        var fileEnvelope = new Envelope(Guid.NewGuid().ToString(),file.ToString(),host.ToString(),"sli.file-audit","1.0.0","1","Security",fileBody["header"]!["generation"]!.GetValue<string>(),1,
            Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),CollectionPacket.Contract,Packets.Digest(fileBody),fileBody["records"]!.AsArray().Count,
            CanonicalJson.Length(fileBody),step["now"]!.GetValue<string>(),step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),0).ToJson();
        AgentFileAuditValidator.Validate(Envelope.Parse(fileEnvelope),fileBody,FileAuditPolicy.Parse(policy),host);
        await Store(file,host,"sli.file-audit",fileBody,fileEnvelope,new JsonArray(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=policy }),"Security",fileBody["header"]!["source"]!.GetValue<string>());

        Guid ws = Guid.NewGuid(), wsHost = Guid.NewGuid();
        var station = JsonNode.Parse(File.ReadAllText(Path.Combine(root,"server-dotnet/tests/Sli.Server.Tests/Agents/M4/workstation-1102.json")))!["packet"]!.DeepClone().AsObject();
        station["header"]!["source"]=wsHost.ToString(); station["records"]![0]!["payload"]!["computer_name"]=wsHost.ToString();
        var unknown = station["records"]![0]!.DeepClone(); unknown["record_id"]=8;
        unknown["payload"]=EventXml.Parse(station["records"]![0]!["payload"]!["xml"]!.GetValue<string>().Replace("<EventID>1102</EventID>","<EventID>9999</EventID>").Replace("<EventRecordID>7</EventRecordID>","<EventRecordID>8</EventRecordID>"),wsHost.ToString(),"","Security");
        station["records"]!.AsArray().Add(unknown); station["header"]!["record_id_range"]!["last"]=8;
        var wsEnvelope = new JsonObject { ["agent_id"]=ws.ToString(),["packet_id"]=Guid.NewGuid().ToString(),["module_id"]="sli.workstations",["source_instance_id"]=wsHost.ToString(),["payload_sha256"]=Packets.Digest(station) };
        await Store(ws,wsHost,"sli.workstations",station,wsEnvelope,new JsonArray(new JsonObject { ["module_id"]="sli.workstations",["enabled"]=true }),"Security",wsHost.ToString());
    }

}
