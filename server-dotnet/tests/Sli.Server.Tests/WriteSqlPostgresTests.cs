using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Notifications;
using Sli.Server.Operations;
using Sli.Server.Agents.Certificates;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Domains;
using Sli.Server.Tests.Operations;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests;

public sealed class WriteSqlPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Semantic_review_lock_survives_migration_308_rollback_and_reapply()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 308);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await AssertSemanticReviewRightsAsync(db, ct);

        string migration = MigrationDirectory.Read(308).Single(m => m.Version == 308).Path;
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using (var predecessor = new NpgsqlCommand("""
            select (select max(version) from schema_migrations)=307
                and to_regprocedure('public.lock_semantic_review_scenario_v308(uuid)') is null
            """, db)) Assert.Equal(true, await predecessor.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await AssertSemanticReviewRightsAsync(db, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Every_registered_mutation_executes_on_canonical_schema_as_adlog_user()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        string token = await fixture.SeedOwnerAsync(ct), root = SqlPostgresFixture.Repository();
        using var certificates = new Certificates();
        string trust = Path.Combine(fixture.Pg.Root, "synthetic-ca.txt");
        await File.WriteAllTextAsync(trust, certificates.Root.ExportCertificatePem() + "\n" + certificates.Issuer.ExportCertificatePem(), ct);
        const string consoleHost = "agents.example.test";
        string serverCertificatePath = Path.Combine(fixture.Pg.Root, "synthetic-server.crt");
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var serverRequest = new CertificateRequest($"CN={consoleHost}", serverKey, HashAlgorithmName.SHA256);
        var serverSan = new SubjectAlternativeNameBuilder();
        serverSan.AddDnsName(consoleHost);
        serverRequest.CertificateExtensions.Add(serverSan.Build());
        using var serverCertificate = serverRequest.Create(certificates.Root, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        await File.WriteAllTextAsync(serverCertificatePath, serverCertificate.ExportCertificatePem(), ct);
        string installer = Path.Combine(fixture.Pg.Root, "synthetic-agent.msi");
        await File.WriteAllTextAsync(installer, "synthetic package bytes", ct);
        using var transportTrust = new Sli.Server.Hosting.AgentTlsTrust(trust);
        var package = AgentPackageTests.Fixture()["cases"]!.AsArray().First(c => c!["error"] is null)!;
        string updateTrust = Path.Combine(fixture.Pg.Root, "synthetic-package-trust.json");
        await File.WriteAllTextAsync(updateTrust, package["trust"]!.ToString(), ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        // SqlPostgresFixture verifies the baseline and the complete installed ledger.
        await AssertSemanticReviewRightsAsync(admin, ct);
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(admin, ct, eventKinds: [4625]);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        long eventId = Assert.Single(events).EventId;
        await using var seed = new NpgsqlCommand("""
            insert into auth_users(username,password_hash,role) values('sql-viewer','synthetic-unusable-hash','viewer');
            insert into investigations(title,created_by,public_id) values('Synthetic case','session:1','00000000-0000-4000-8000-000000000001');
            insert into sli_agents(id,host_id,key_fingerprint) values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002',repeat('a',64));
            insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values('00000000-0000-4000-8000-000000000001','a',repeat('a',64),now()-interval '1 hour',now()+interval '1 day');
            insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,first_seen_utc,last_seen_utc,source_core_sha256)
            select 1,t.id,'synthetic-sql-user','Synthetic SQL user',d.id,now(),now(),sha256('synthetic-user'::bytea) from storage_v2_entity_type t cross join domains d where t.value='ad_user' and d.fqdn='example.test';
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status,completed_at)
            select '00000000-0000-4000-8000-000000000001','sli.ad','1',id,'full',now(),sha256('synthetic-bundle'::bytea),'completed',now() from domains where fqdn='example.test';
            insert into ad_context_sections(run_id,section_name,status,record_count) values('00000000-0000-4000-8000-000000000001','directory_accounts','complete',2);
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(1,'directory_accounts',now(),now(),sha256('synthetic-user'::bytea),'{"identity":{"kind":"ad_user","object_sid":"S-1-5-21-100000001-200000002-300000003-1001","object_guid":"00000000-0000-4000-8000-000000000001"},"attributes":{"enabled":true}}','00000000-0000-4000-8000-000000000001');
            insert into semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
            values('00000000-0000-4000-8000-000000000001','synthetic-sql','control_gap',sha256('identity'::bytea),sha256('scenario'::bytea),'synthetic','{}',300,'Synthetic scenario','Synthetic SQL review',now(),now(),'low');
            insert into findings(id,fingerprint,rule_code,title,severity,source) values(1,'semantic:'||repeat('a',64),'synthetic-sql','Synthetic SQL finding','low','semantic-production');
            insert into finding_evidence(finding_id,event_id) values(1,@event_id);
            insert into findings(id,fingerprint,rule_code,title,severity,source) values(2,'synthetic-link','synthetic-sql','Synthetic linked finding','low','semantic-production');
            insert into finding_evidence(finding_id,event_id) values(2,@event_id);
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values('synthetic-sql',1,'control_health','disabled','{}',sha256('{}'::bytea));
            insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
            values('00000000-0000-4000-8000-000000000001',sha256('synthetic-observation'::bytea),'synthetic','synthetic','unknown','Synthetic SQL observation',now(),'synthetic');
            insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,evaluation_mode,idempotency_key,evaluation_status,completed_at)
            values('00000000-0000-4000-8000-000000000001','synthetic-sql',1,'control_health','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001','enabled',sha256('synthetic-job'::bytea),'completed',now());
            insert into semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,coverage_status,evaluation_ms)
            values('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001','enabled','low',1,1,false,'low',1,'unknown',1);
            insert into semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            values('00000000-0000-4000-8000-000000000001',1,'00000000-0000-4000-8000-000000000001','semantic:'||repeat('a',64),1);
            insert into storage_v2_entity_type(value) values('ad_computer') on conflict(value) do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 2,t.id,'synthetic-sql-computer','Synthetic SQL computer',d.id,sha256('synthetic-computer'::bytea) from storage_v2_entity_type t cross join domains d where t.value='ad_computer' and d.fqdn='example.test';
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(2,'directory_accounts',now(),now(),sha256('synthetic-computer'::bytea),'{"identity":{"kind":"ad_computer"},"attributes":{"enabled":true,"distinguished_name":"CN=fixture,OU=Computers,DC=example,DC=test"}}','00000000-0000-4000-8000-000000000001');
            """, admin);
        seed.Parameters.AddWithValue("event_id", eventId);
        await seed.ExecuteNonQueryAsync(ct);
        using var backupSettingsSocket = new BackupSettingsEndpointTests.SocketExchange(
            """{"ok":true,"enabled":true,"path":"/mnt/synthetic-backup","revision":"r1","storage_status":"ready"}""" + "\n");
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(b => b
            .UseTestServer()
            .ConfigureLogging(l => l.ClearProviders())
            .ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"), ["Sli:AgentMtlsCaFile"] = trust, ["Sli:TrustedProxies"] = "",
                ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1",
                ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "app-data"), ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "app-logs"),
                ["Sli:AgentUpdateTrustFile"] = updateTrust,
                ["Sli:AgentServerCaFile"] = trust, ["Sli:AgentInstallerPath"] = installer,
                ["Kestrel:Certificates:Default:Path"] = serverCertificatePath,
                ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:Storage:ArchiveRoot"] = Path.Combine(fixture.Pg.Root, "archive"),
                ["Sli:OwnerSetup"] = "0", ["Sli:HttpRatePerMinute"] = "5000", ["urls"] = "http://127.0.0.1:0"
            }))
            .ConfigureServices(s => {
                s.RemoveAll<INotificationSetupClient>(); s.AddSingleton<INotificationSetupClient, SetupTransport>(); s.RemoveAll<AgentIssuingCa>(); s.AddSingleton(certificates.Ca);
                s.RemoveAll<BackupSettingsClient>();
                s.AddSingleton(new BackupSettingsClient(_ => ValueTask.FromResult<Stream>(backupSettingsSocket)));
                s.AddSingleton(transportTrust);
            }));
        // TestServer replaces only the transport. Schannel credentials are not
        // available in the Windows sandbox; CA/identity validation stays real.
        static void RawTarget(HttpContext c) => c.Features.Get<IHttpRequestFeature>()!.RawTarget = c.Request.Path + c.Request.QueryString;
        using var client = new HttpClient(host.Server.CreateHandler(RawTarget)) { BaseAddress = new Uri("https://localhost") };
        client.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
        var failures = new List<string>(); var exercised = new List<(string Method, string Path)>();
        async Task<JsonNode?> Check(string path, object body, int expected = 200, string method = "POST", string? error = null, HttpClient? asClient = null, HttpContent? content = null)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path) { Content = content ?? new StringContent(System.Text.Json.JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json") };
            using var response = await (asClient ?? client).SendAsync(request, ct);
            string raw = await response.Content.ReadAsStringAsync(ct); JsonNode? json = null;
            try { json = JsonNode.Parse(raw); } catch (System.Text.Json.JsonException) { }
            string? actualError = (json as JsonObject)?["error"]?.ToString();
            output.WriteLine($"{method} {path}: {(int)response.StatusCode} {actualError}");
            exercised.Add((method, path.Split('?')[0]));
            if ((int)response.StatusCode != expected || error is not null && actualError != error)
                failures.Add($"{method} {path}: expected {expected} {error}, got {(int)response.StatusCode} {actualError}");
            return json;
        }
        await Check("/api/auth/users", new { username = "sql-created", password = "synthetic-password-A1!", role = "viewer" }, 201);
        await Check("/api/auth/users/2", new { role = "operator", is_active = true });
        await Check("/api/auth/users/2/password", new { password = "synthetic-password-B2!" });
        await Check("/api/auth/login", new { username = "sql-created", password = "synthetic-password-A1!" });
        await Check("/api/auth/bootstrap", new { code = "synthetic", password = "synthetic-password-A1!" }, 404, error: "not_found");
        await Check("/api/test/sli-v4/session", new { }, 404, error: "not_found");
        var key = await Check("/api/auth/api-keys", new { label = "sql-fixture", role = "viewer" }, 201);
        await Check("/api/auth/api-keys/" + (key?["item"]?["id"]?.ToString() ?? "1") + "/revoke", new { });
        await Check("/api/v1/access/assignments", new { subject_type = "user", subject_id = 2, report_key = "events.explorer", business_reason = "Synthetic SQL contract", scope = new { kind = "all" }, field_categories = new[] { "security" }, allowed_actions = new[] { "view" } }, 201);
        await Check("/api/v1/access/package-assignments", new { subject_type = "user", subject_id = 2, package_key = "security_analyst", business_reason = "Synthetic SQL contract" }, 201);
        await Check("/api/v1/reports/events.explorer/preference", new { pinned = true });
        await Check("/api/v1/access/report-requests", new { report_key = "events.explorer", business_reason = "Synthetic SQL contract", scope = new { kind = "all" }, valid_until = DateTimeOffset.UtcNow.AddDays(1) }, 400, error: "report_already_accessible");
        await Check("/api/v1/access/report-requests/1/decision", new { decision = "reject", decision_reason = "Synthetic SQL contract" }, 400, error: "access_request_not_pending");
        await Check("/api/v1/setup/domains", new { fqdn = "new.example.test", netbios_name = "NEW" }, 201);
        await Check("/api/v1/setup/domains/example.test", new { netbios_name = "EXAMPLE" });
        await Check("/api/v1/setup/domain-controllers", new { hostname = "dc.example.test", domain = "example.test" }, 201);
        await Check("/api/v1/setup/domain-controllers/dc.example.test", new { enabled = false });
        await Check("/api/v1/platform-settings/ad.inactivity_days", new { value = "30" });
        client.DefaultRequestHeaders.Add("Origin", "https://localhost");
        var regularBackup = await Check("/api/v1/admin/backup-settings",
            new { enabled = true, path = "/mnt/synthetic-backup", revision = "0" }, method: "PUT");
        client.DefaultRequestHeaders.Remove("Origin");
        Assert.Equal("r1", regularBackup?["revision"]?.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"action":"set","enabled":true,"path":"/mnt/synthetic-backup","revision":"0"}"""),
            JsonNode.Parse(backupSettingsSocket.Outgoing.ToArray())));
        await Check("/api/plugins/sli.ad/settings", new { key = "ad.password_max_age_days", value = 30 }, method: "PUT");
        await Check("/api/v1/plugins/sli.ad", new { enabled = true, expected_revision = 1 });
        var definition = new { report_key = "studio.sql", name = "SQL report", owner = "fixture", purpose = "SQL contract", dataset_key = "entities.v2", fields = new[] { "id", "display_name" }, actions = new[] { "view" }, status = "published" };
        await Check("/api/v1/reports/builder/preview", definition);
        await Check("/api/v1/reports/definitions", definition, 201);
        await Check("/api/v1/reports/definitions/studio.sql/visibility", new { discoverable = true, requestable = true });
        await Check("/api/v1/reports/definitions", new { report_key = "studio.sql", name = "SQL draft", owner = "fixture", purpose = "SQL contract", dataset_key = "entities.v2", fields = new[] { "id", "display_name" }, actions = new[] { "view" }, status = "draft" }, 201);
        await Check("/api/v1/reports/definitions/studio.sql/versions/2/publish", new { });
        await Check("/api/v1/reports/definitions/studio.sql/retire", new { });
        await Check("/api/v1/investigations", new { title = "Synthetic SQL case" }, 503, error: "module_disabled");
        var watchBody = new JsonObject { ["entity_id"] = 1, ["owner"] = "fixture", ["reason"] = "Synthetic SQL watch", ["expires_at"] = DateTimeOffset.UtcNow.AddDays(1), ["active"] = true, ["revision"] = 0 };
        var watch = await Check("/api/v1/watch", watchBody);
        watchBody["revision"] = 1;
        await Check("/api/v1/watch/" + (watch?["item"]?["id"]?.ToString() ?? watch?["id"]?.ToString() ?? "00000000-0000-4000-8000-000000000001"), watchBody);
        var decoyBody = new JsonObject { ["kind"] = "account", ["identity"] = new JsonObject { ["domain_id"] = 1, ["entity_id"] = 1, ["sid"] = "S-1-5-21-100000001-200000002-300000003-1001", ["guid"] = "00000000-0000-4000-8000-000000000001" }, ["owner"] = "fixture", ["reason"] = "Synthetic SQL decoy", ["active"] = false, ["revision"] = 0 };
        var decoy = await Check("/api/v1/decoys", decoyBody); decoyBody["revision"] = 1;
        await Check("/api/v1/decoys/" + (decoy?["item"]?["id"]?.ToString() ?? decoy?["id"]?.ToString() ?? "00000000-0000-4000-8000-000000000001"), decoyBody);
        const string investigation = "/api/v1/investigations/00000000-0000-4000-8000-000000000001";
        await Check(investigation + "/notes", new { body = "Synthetic SQL note" }, 503, error: "module_disabled");
        await Check(investigation + "/status", new { status = "active" }, 503, error: "module_disabled");
        await Check(investigation + "/owner", new { owner = "fixture" }, 503, error: "module_disabled");
        await Check(investigation + "/events", new { event_db_id = eventId }, 503, error: "module_disabled");
        await Check(investigation + "/events/remove", new { event_db_id = eventId }, 503, error: "module_disabled");
        await Check("/api/v1/platform-settings/semantic-control", new { action = "create_suppression", semantic_type = "sql.fixture", domain_id = 1, scope_kind = "bucket", scope_value = "unknown", reason = "Synthetic SQL suppression", expires_at = DateTimeOffset.UtcNow.AddDays(1) });
        await Check("/api/v1/semantic/scenarios/00000000-0000-4000-8000-000000000001/review", new { verdict = "confirmed_security", review_confidence = "high", rationale = "Synthetic SQL review", review_request_id = "00000000-0000-4000-8000-000000000002" }, 201);
        var search = await Check("/api/v1/event-search/query", new { contract_version = "evsearch.v1" });
        string execution = search?["execution_id"]?.ToString() ?? "missing";
        await Check("/api/v1/event-search/page", new { execution_id = execution });
        await Check("/api/v1/event-search/summary", new { execution_id = execution, blocks = new[] { "totals" } });
        await Check("/api/v1/event-search/members", new { execution_id = execution, group_key = "missing" }, 422);
        await Check("/api/v1/source-onboarding/preflight", new { hostname = "source.example.test", source_kind = "domain_controller" });
        await Check("/api/jobs/collect", new { servers = new[] { "fixture.example.test" }, hours = 1, max_events_per_channel = 1 }, 503, error: "module_disabled");
        await Check("/api/jobs/analyze", new { servers = new[] { "fixture.example.test" }, hours = 1, max_events_per_channel = 1 }, 503, error: "module_disabled");
        const string agent = "00000000-0000-4000-8000-000000000001";
        var archive = new ByteArrayContent(Convert.FromBase64String(package["archive"]!.ToString())); archive.Headers.ContentType = new("application/zip");
        var upload = await Check("/api/v1/admin/agent-packages", new { }, content: archive);
        string packageHash = upload?["sha256"]?.ToString() ?? new string('a',64);
        var fileConfig = JsonNode.Parse("""{"source_name":"file.example.test","roots":[{"collection_scope_id":"sql-scope","path":"C:\\sql-data","share_name":"Synthetic","important":false,"sacl":{"trustee_sids":["S-1-1-0"],"inherit_files":true,"inherit_directories":true}}]}""")!;
        using var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string agentHost = "00000000-0000-4000-8000-000000000004";
        var csr = new CertificateRequest("CN=" + agentHost, agentKey, HashAlgorithmName.SHA256).CreateSigningRequestPem();
        var agentToken = await Check("/api/v1/admin/agent-tokens", new { host_id = agentHost, key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(agentKey.ExportSubjectPublicKeyInfo())) });
        var registered = await Check("/api/v1/agent/enroll", new { token = agentToken?["token"]?.ToString(), csr_pem = csr, reported_hostname = "agent.example.test" });
        using var issuedCertificate = X509Certificate2.CreateFromPem(registered!["certificate_pem"]!.ToString());
        using var certificate = issuedCertificate.CopyWithPrivateKey(agentKey);
        using var agentClient = new HttpClient(host.Server.CreateHandler(c => { RawTarget(c); c.Connection.ClientCertificate = certificate; })) { BaseAddress = client.BaseAddress };
        await Check("/api/v1/agent/renew", new { csr_pem = csr }, asClient: agentClient);
        var runtimePolicy = await Check("/api/v1/admin/agents/modules", new { agent_id = registered["agent_id"]!.ToString(), module_id = "sli.workstations", enabled = false, config = new { } });
        long agentRevision = runtimePolicy!["policy_revision"]!.GetValue<long>();
        await Check("/api/v1/agent/policy-report", new { applied_policy_revision = agentRevision, collection_state = "active" }, asClient: agentClient);
        await Check("/api/v1/agent/windows-audit-report", new { windows_audit = new { policy_revision = agentRevision, management_state = "disabled", command_line_enabled = false, families = new { } } }, asClient: agentClient);
        await Check("/api/v1/admin/agents/update-policy", new { agent_id = registered["agent_id"]!.ToString(), sha256 = packageHash });
        await Check("/api/v1/agent/update-result", new { sha256 = packageHash, status = "rejected", reason = "agent_update_download_failed", version = "1.0.0" }, asClient: agentClient);
        await Check("/api/v1/admin/agents/file-audit", new { agent_id = registered["agent_id"]!.ToString(), expected_revision = agentRevision, config = fileConfig,
            command = new { contract_id = "sli.file-audit.audit-command.v1", command_id = "sql-agent-file", action = "check", policy_revision = (agentRevision+1).ToString(), collection_scope_ids = new[] { "sql-scope" } } });
        var checkReport = new { contract_id = "sli.file-audit.audit-result.v1", command_id = "sql-agent-file",
            policy_revision = (agentRevision + 1).ToString(), action = "check", observed_at_utc = DateTimeOffset.UtcNow,
            scopes = new[] { new { collection_scope_id = "sql-scope", state = "failed", reason_code = "unknown", required_masks = new { }, actual_masks = new { } } },
            snapshots = Array.Empty<object>(), ownership_remaining = false };
        var reportAck = await Check("/api/v1/agent/file-audit-report", checkReport, asClient: agentClient);
        if (reportAck?["status"]?.GetValue<string>() != "accepted")
            failures.Add("File Audit check did not return an accepted receipt");
        await Check("/api/v1/agent/file-audit-report", checkReport with { command_id = "sql-unrequested-file" },
            400, error: "file_audit_result_invalid", asClient: agentClient);
        await using (var checkBoundary = new NpgsqlCommand("""
            select not public.file_permissions_allowed405(@agent,@revision,'sql-scope',false)
                and (select count(*) from sli_plugin_file_audit.audit_receipts
                     where agent_id=@agent and command_id='sql-agent-file' and action='check'
                         and collection_scope_id='sql-scope' and state='failed')=1
                and not exists (select 1 from sli_plugin_file_audit.audit_receipts
                                where agent_id=@agent and command_id='sql-unrequested-file')
            """, admin))
        {
            checkBoundary.Parameters.AddWithValue("agent", Guid.Parse(registered["agent_id"]!.ToString()));
            checkBoundary.Parameters.AddWithValue("revision", checkReport.policy_revision);
            if (await checkBoundary.ExecuteScalarAsync(ct) is not true)
                failures.Add("File Audit check receipt or event admission did not match the current command");
        }
        object Heartbeat(long sequence, string before) => Packets.Make(new EcdsaPacketSigner(agentKey), registered["agent_id"]!.ToString(), sequence,
            new Sample("sli.heartbeat", agentHost, "heartbeat", agentHost, new Cursor("record_id", before), new Cursor("record_id", sequence.ToString()),
                new JsonObject { ["contract"] = "sli.heartbeat.v1", ["status"] = "alive" }), DateTimeOffset.UtcNow).ToJson();
        await Check("/api/v1/agent/packets", Heartbeat(1, ""), asClient: agentClient);
        await Check("/api/v1/agent/packets", Heartbeat(3, "1"), asClient: agentClient);
        var recovery = await client.GetFromJsonAsync<JsonObject>("/api/v1/admin/agents/sequence-recovery?agent_id=" + registered["agent_id"], ct);
        var preview = recovery!["recovery_preview"];
        await Check("/api/v1/admin/agents/sequence-recovery", new { agent_id = registered["agent_id"]!.ToString(), observation_ids = preview?["observation_ids"]?.DeepClone(), preview_token = preview?["preview_token"]?.ToString(), confirm_loss = true });
        var replacementToken = await Check("/api/v1/admin/agent-tokens", new { host_id = "00000000-0000-4000-8000-000000000005", replacement_for = registered["agent_id"]!.ToString(), key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(agentKey.ExportSubjectPublicKeyInfo())) });
        string replacementCsr = new CertificateRequest("CN=00000000-0000-4000-8000-000000000005", agentKey, HashAlgorithmName.SHA256).CreateSigningRequestPem();
        var replacement = await Check("/api/v1/agent/enroll", new { token = replacementToken?["token"]?.ToString(), csr_pem = replacementCsr, reported_hostname = "agent.example.test" });
        await Check("/api/v1/admin/agents/replace", new { old_agent_id = registered["agent_id"]!.ToString(), new_agent_id = replacement?["agent_id"]?.ToString(), phase = "prepare", confirm = true });
        var removal = await Check("/api/v1/agent/uninstall", new { }, asClient: agentClient);
        await Check("/api/v1/agent/removal-result", new { command_id = removal?["agent_removal"]?["command_id"]?.ToString(), state = "state_cleaned", reason = (string?)null }, asClient: agentClient);
        var enrollment = await Check("/api/v1/admin/agent-tokens", new { host_id = agent, key_fingerprint = new string('a',64) });
        await Check("/api/v1/admin/agent-tokens/revoke", new { id = enrollment?["id"]?.ToString() ?? agent });
        var consoleToken = await Check("/api/v1/admin/agent-console-tokens", new { host_limit = 2, server_url = $"https://{consoleHost}" });
        string consoleTokenId = consoleToken?["id"]?.ToString() ?? agent;
        await Check("/api/v1/admin/agent-console-tokens/revoke", new { id = consoleTokenId });
        await Check("/api/v1/admin/agents/rights-probe", new { agent_id = agent });
        await Check("/api/v1/admin/agents/policy", new { agent_id = agent, expected_revision = 1, collection_policy = new { state = "paused" } });
        await Check("/api/v1/admin/agents/modules", new { agent_id = agent, module_id = "sli.workstations", enabled = false, config = new { } });
        var template = await Check("/api/v1/admin/agent-templates", new { assigned_modules = Array.Empty<object>(), collection_policy = new { state = "active" }, expected_version = 0 });
        var group = await Check("/api/v1/admin/agent-group-tokens", new { domain_id = 1, max_uses = 1 });
        var filter = new { group_id = group?["group_id"]?.ToString() ?? agent, token_id = group?["id"]?.ToString() ?? agent };
        using var groupKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string groupHost = "00000000-0000-4000-8000-000000000006";
        var submitted = await Check("/api/v1/agent/group-enroll", new { token = group?["token"]?.ToString(), host_id = groupHost, csr_pem = new CertificateRequest("CN=" + groupHost, groupKey, HashAlgorithmName.SHA256).CreateSigningRequestPem(), computer_entity_id = 2 });
        await Check("/api/v1/admin/agent-group-requests", filter);
        var binding = new { request_id = submitted?["request_id"]?.ToString() ?? agent, host_id = groupHost, instance_name = (string?)null, key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(groupKey.ExportSubjectPublicKeyInfo())), computer_entity_id = 2 };
        await Check("/api/v1/admin/agent-group-requests/approve", new { filter, evidence = new[] { binding } });
        await Check("/api/v1/admin/agent-onboarding/approve", new { token_id = filter.token_id, template_id = template?["id"]?.ToString() ?? agent, template_version = 1, mode = "selected", request_ids = new[] { binding.request_id }, evidence = new[] { binding } });
        await Check("/api/v1/admin/agent-group-tokens/revoke", new { id = filter.token_id });
        await Check("/api/v1/admin/agents/update-policy", new { agent_id = agent, sha256 = (string?)null });
        var wave = await Check("/api/v1/admin/agent-update-waves", new { agent_ids = new[] { agent }, sha256 = packageHash, batch_size = 1, error_threshold = 0 });
        await Check("/api/v1/admin/agent-update-waves/stop", new { wave_id = wave?["wave_id"]?.ToString() ?? wave?["id"]?.ToString() ?? agent });
        long fileRevision;
        await using (var version = new NpgsqlCommand("select policy_revision from sli_agents where id='00000000-0000-4000-8000-000000000001'", admin)) fileRevision = Convert.ToInt64(await version.ExecuteScalarAsync(ct));
        await Check("/api/v1/admin/agents/file-audit", new { agent_id = agent, expected_revision = fileRevision, config = fileConfig, command = new { contract_id = "sli.file-audit.audit-command.v1", command_id = "sql-file-command", action = "check", policy_revision = (fileRevision+1).ToString(), collection_scope_ids = new[] { "sql-scope" } } });
        await Check("/api/v1/admin/agents/revoke", new { agent_id = agent, serial = "a" });
        await Check("/api/v1/admin/agents/disable", new { agent_id = agent });
        await Check("/api/v1/admin/agents/remove", new { operation_id = agent, agent_ids = new[] { agent } });
        await Check("/api/v1/admin/agent-deployment-directory", new { });
        await Check("/api/v1/ad-operation-credentials", new { domain_id = 1, label = "Synthetic SQL credential", username = "fixture@example.test", password = "synthetic-password" }, 403);
        foreach (string action in new[] { "check", "replace-password", "delete" }) {
            var body = new JsonObject { ["credential_id"] = agent, ["credential_revision"] = 1 };
            if (action == "replace-password") body["password"] = "synthetic-password";
            await Check("/api/v1/ad-operation-credentials/" + action, body, 403);
        }
        await Check("/api/v1/agent-deployment/gpo/credentials", new { domain_id = 1, computer_entity_ids = new[] { 2 } }, 403);
        await Check("/api/v1/agent-deployment/gpo/preview", new { domain_id = 1, computer_entity_ids = new[] { 2 }, credential_id = agent, credential_revision = 1 }, 403);
        await Check("/api/v1/agent-deployment/gpo/confirm", new { plan_id = agent, plan_sha256 = new string('a',64), acknowledged = true, credential_id = agent, credential_revision = 1 }, 404);
        await Check("/api/v1/agent-deployment/gpo/cancel", new { plan_id = agent, plan_sha256 = new string('a',64) }, 404);
        await Check("/api/findings/1/status", new { status = "active", status_reason = "Synthetic SQL decision" });
        const string queueDecisions = "/api/findings/queue-decisions";
        await Check(queueDecisions, new { ids = new[] { 1, 2 }, state = "closed", classification = "fixed" }, 404, error: "not_found");
        using (var unchanged = new NpgsqlCommand("select status from findings where id=1", admin))
            Assert.Equal("active", await unchanged.ExecuteScalarAsync(ct));
        var queueDecision = await Check(queueDecisions, new { ids = new[] { 1 }, state = "closed", classification = "fixed", comment = "Synthetic queue decision" });
        Assert.Equal(1, (int?)queueDecision?["changed"]);
        using (var audit = new NpgsqlCommand("""
            select h.old_status, h.new_status, a.details_json->'decision'->>'comment'
            from finding_status_history h
            join access_audit_v4 a on a.target_type='finding' and a.target_key=h.finding_id::text
            join auth_users u on u.id=a.actor_id and u.username=h.changed_by
            where h.finding_id=1 and a.action='finding_queue_decision' and a.outcome='ok'
              and a.actor_type='session' and u.username='platform-owner'
              and h.old_status=a.details_json->>'from' and h.new_status=a.details_json->>'to'
            """, admin))
        await using (var decisionHistory = await audit.ExecuteReaderAsync(ct))
        {
            Assert.True(await decisionHistory.ReadAsync(ct));
            Assert.Equal("active", decisionHistory.GetString(0));
            Assert.Equal("closed", decisionHistory.GetString(1));
            Assert.Equal("Synthetic queue decision", decisionHistory.GetString(2));
            Assert.False(await decisionHistory.ReadAsync(ct));
        }
        await Check("/api/findings/1/risk-acceptance", new { action = "create", responsible_user_id = 1, reason = "Synthetic SQL acceptance", expires_at = DateTimeOffset.UtcNow.AddDays(1) });
        await Check(investigation + "/findings", new { finding_id = 1 }, 503, error: "module_disabled");
        await Check("/api/v1/investigations/from-finding", new { finding_id = 2 }, 503, error: "module_disabled");
        await Check(investigation + "/evidence-refs", new { source_domain_id = 1, evidence_kind = "vpn_accounting_session", reference_id = "radius-session-row:" + new string('a',64) }, 503, error: "module_disabled");
        const string channels = "/api/v1/notification-channels";
        await Check(channels + "/smtp", new { enabled = true, tls_mode = "starttls", secret_ref = "SLI_NOTIFY_SMTP_PASSWORD", revision = 1 });
        await Check(channels + "/smtp/setup/status", new { });
        await Check(channels + "/smtp/setup/save", new { host = "mail.example.test", port = 587, username = "fixture", sender = "sender@example.test", password = "synthetic-password", recipients = new[] { new { user_id = 1, mailbox = "recipient@example.test" } }, revision = 2, tls_mode = "starttls", enabled = true });
        await Check(channels + "/telegram/setup/status", new { });
        await Check(channels + "/telegram/setup/token", new { token = "1:synthetic" });
        await Check(channels + "/telegram/setup/chats", new { });
        await Check(channels + "/telegram/setup/bind", new { choice = "synthetic" });
        await Check(channels + "/telegram/setup/test", new { });
        var subscription = await Check("/api/v1/notification-subscriptions", new { recipient_user_id = 2, channel = "smtp", enabled = true });
        string subscriptionId = subscription?["item"]?["id"]?.ToString() ?? agent;
        await Check("/api/v1/notification-subscriptions/" + subscriptionId, new { recipient_user_id = 2, channel = "smtp", enabled = true, revision = 1 });
        await Check("/api/v1/notification-subscriptions/" + subscriptionId + "/test", new { problem_id = agent });
        var scheduleBody = new JsonObject { ["report_key"] = "security.problems", ["filters"] = new JsonObject(), ["timezone"] = "UTC", ["local_time"] = "09:00", ["weekday"] = null, ["period_days"] = 1, ["language"] = "en", ["enabled"] = true, ["subscription_ids"] = new JsonArray(subscriptionId) };
        var schedule = await Check("/api/v1/notification-subscriptions/schedules", scheduleBody);
        scheduleBody["revision"] = 1;
        await Check("/api/v1/notification-subscriptions/schedules/" + (schedule?["item"]?["id"]?.ToString() ?? agent), scheduleBody);
        Guid replacedId = Guid.Parse("00000000-0000-4000-8000-000000000091");
        Guid currentId = Guid.Parse("00000000-0000-4000-8000-000000000092");
        await using (var registrations = new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role,is_active)
                select id,'restore-dc.example.test','restore-dc.example.test','domain_controller',true
                from domains where fqdn='example.test';
            insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,status) values
                (@replaced,'00000000-0000-4000-8000-000000000191',repeat('d',64),'restore-dc.example.test','replaced'),
                (@current,'00000000-0000-4000-8000-000000000192',repeat('e',64),'restore-dc.example.test','active');
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
                select id,'sli.windows.ad-dc',host_id::text,'restore-dc.example.test','ad-dc','1.0.0','1'
                from sli_agents where id in (@replaced,@current);
            insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after)
                values(@replaced,'91',repeat('d',64),now()-interval '1 hour',now()+interval '1 day');
            """, admin))
        {
            registrations.Parameters.AddWithValue("replaced", replacedId);
            registrations.Parameters.AddWithValue("current", currentId);
            await registrations.ExecuteNonQueryAsync(ct);
        }
        var restored = await Check("/api/v1/admin/agents/restore", new { agent_id = replacedId, current_agent_id = currentId });
        if (restored?["status"]?.GetValue<string>() != "active") failures.Add("The previous DC registration was not activated");
        await using (var state = new NpgsqlCommand("""
            select count(*) from sli_agents where (id=@replaced and status='active') or (id=@current and status='replaced')
            """, admin))
        {
            state.Parameters.AddWithValue("replaced", replacedId);
            state.Parameters.AddWithValue("current", currentId);
            if (await state.ExecuteScalarAsync(ct) is not 2L) failures.Add("DC registration statuses were not exchanged");
        }
        // Finish writes with the original owner session before testing first login.
        await Check("/api/auth/logout", new { });
        client.DefaultRequestHeaders.Remove("Cookie");

        const string initialPassword = "synthetic-initial-password-A1!";
        const string replacementPassword = "synthetic-replacement-password-B2!";
        await using (var pending = new NpgsqlCommand(
            "update auth_users set password_hash=@hash where username='platform-owner'", admin))
        {
            pending.Parameters.AddWithValue("hash", InitialAdminPassword.HashPrefix + new PasswordCodec().Hash(initialPassword));
            await pending.ExecuteNonQueryAsync(ct);
        }
        using var initialLogin = new StringContent(
            System.Text.Json.JsonSerializer.Serialize(new { username = "platform-owner", password = initialPassword }),
            System.Text.Encoding.UTF8, "application/json");
        using (var login = await client.PostAsync("/api/auth/login", initialLogin, ct))
        {
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var body = await login.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct);
            Assert.True(body?["password_change_required"]?.GetValue<bool>() is true);
            client.DefaultRequestHeaders.Add("Cookie", Assert.Single(login.Headers.GetValues("Set-Cookie")).Split(';')[0]);
        }
        var changed = await Check("/api/auth/change-initial-password",
            new { password = replacementPassword, repeat = replacementPassword });
        Assert.True(changed?["authenticated"]?.GetValue<bool>() is true);
        client.DefaultRequestHeaders.Remove("Cookie");
        var signedIn = await Check("/api/auth/login", new { username = "platform-owner", password = replacementPassword });
        Assert.Equal("platform-owner", signedIn?["principal"]?["username"]?.GetValue<string>());

        var routes = host.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? []).Where(m => m is "POST" or "PUT" or "DELETE").Select(m => (Method: m, Pattern: e.RoutePattern.RawText!))).Distinct().ToArray();
        foreach (var route in routes)
        {
            var matcher = new TemplateMatcher(TemplateParser.Parse(route.Pattern), new RouteValueDictionary());
            if (!exercised.Any(e => e.Method == route.Method && matcher.TryMatch(e.Path, new RouteValueDictionary()))) failures.Add("Uncovered registry action: " + route);
        }
        output.WriteLine($"Checked {exercised.Count} actions from {routes.Length} registered method/route patterns");
        string diagnostics = await fixture.Pg.DiagnosticsAsync(ct);
        if (Regex.IsMatch(diagnostics, @"(?m)^.*(?:ERROR:|FATAL:|ОШИБКА:).*$")) failures.Add(diagnostics);
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    private static async Task AssertSemanticReviewRightsAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var privilege = new NpgsqlCommand("""
            select has_function_privilege('adlog_user','public.lock_semantic_review_scenario_v308(uuid)','EXECUTE')
                and not has_table_privilege('adlog_user','semantic_security_scenarios','UPDATE')
                and not exists(select 1 from pg_attribute where attrelid='semantic_security_scenarios'::regclass
                    and attnum>0 and not attisdropped and has_column_privilege('adlog_user',attrelid,attname,'UPDATE'))
            """, db);
        Assert.Equal(true, await privilege.ExecuteScalarAsync(ct));
    }

    // Only the Unix-socket/network boundary is substituted. All channel,
    // subscription, schedule, queue, authorization and audit SQL stays real.
    private sealed class SetupTransport : INotificationSetupClient
    {
        private static readonly string TelegramGeneration = new('a', 64);

        public Task<JsonObject> RequestAsync(string action, long user, JsonObject values, CancellationToken ct) => Task.FromResult(action switch {
            "status" => new JsonObject { ["secret_set"] = true, ["chat_bound"] = true, ["chat_name"] = "Synthetic", ["proxy_url"] = "" },
            "smtp_status" => new JsonObject { ["host"] = "mail.example.test", ["port"] = 587, ["username"] = "fixture", ["sender"] = "sender@example.test", ["recipients"] = new JsonObject { ["1"] = "recipient@example.test" }, ["secret_set"] = true, ["needs_save"] = false },
            "smtp_save" => new JsonObject { ["secret_set"] = true, ["needs_save"] = false },
            "chat_generation" => new JsonObject { ["generation"] = TelegramGeneration },
            "chats" when values["generation"]?.GetValue<string>() == TelegramGeneration && values["observations"] is JsonArray
                => new JsonObject { ["chats"] = new JsonArray(new JsonObject { ["choice"] = "synthetic", ["name"] = "Synthetic" }) },
            "chats" => throw new InvalidOperationException("Expected a generation and chat observations"),
            _ => new JsonObject { ["status"] = "ok" }
        });
    }

    internal sealed class Certificates : IDisposable
    {
        internal X509Certificate2 Root, Issuer;
        internal AgentIssuingCa Ca;
        private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal Certificates()
        {
            static CertificateRequest Request(string name, ECDsa key, int depth) {
                var r = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
                r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, depth, true));
                r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true)); return r;
            }
            Root = Request("Synthetic SQL root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
            using var issuer = Request("Synthetic SQL issuer", issuerKey, 0).Create(Root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
            Issuer = issuer.CopyWithPrivateKey(issuerKey); Ca = new(Root, Issuer);
        }
        public void Dispose() { Ca.Dispose(); rootKey.Dispose(); issuerKey.Dispose(); }
    }
}
