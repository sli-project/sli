using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed class FileAuditRestorePostgresTests(ITestOutputHelper output)
{
    private const string Control = "/api/v1/admin/agents/file-audit";
    private const string AgentReport = "/api/v1/agent/file-audit-report";
    private const string AgentIdentity = "/api/v1/agent/identity";
    private const string Intake = "/api/v1/agent/packets";
    private const string Scope = "scope:files";

    [Fact]
    public async Task Applied_file_scope_can_be_checked_and_restored_without_widening_admission()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 414);
        using var environment = new SemanticProducerPostgresTests.Admission(mode: null);
        environment.Set("SLI_PLUGIN_RUNTIME_DIR", null);
        environment.Set("SLI_PLUGIN_LOCK_DIR", null);
        var token = await fixture.SeedOwnerAsync(ct);
        var agentId = AdDcImportPerformanceTests.Agent;
        var hostId = AdDcImportPerformanceTests.Host;
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=synthetic.example.test", key, HashAlgorithmName.SHA256);
        using var peer = certificates.Ca.Issue(request, agentId, hostId);
        var trustPath = Path.Combine(fixture.Pg.Root, "synthetic-agent-trust.pem");
        await File.WriteAllTextAsync(trustPath,
            certificates.Root.ExportCertificatePem() + "\n" + certificates.Issuer.ExportCertificatePem(), ct);
        environment.Set("ConnectionStrings__Sli", fixture.Dsn("adlog_user"));
        environment.Set("Sli__AgentMtlsCaFile", trustPath);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await AdDcImportPerformanceTests.SeedAsync(owner, fixture.Pg.Root, peer, ct,
            Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())));
        await using (var manage = new NpgsqlCommand("""
            update public.sli_agents set collection_policy=jsonb_set(collection_policy,'{manage_windows_audit}','true')
            where id=@agent
            """, owner))
        {
            manage.Parameters.AddWithValue("agent", agentId);
            await manage.ExecuteNonQueryAsync(ct);
        }

        var settings = new Dictionary<string, string?> {
            ["Sli:TrustedProxies"] = "",
            ["Sli:AuthRequired"] = "1",
            ["Sli:AllowUnauthenticated"] = "0",
            ["Sli:OwnerSetup"] = "0",
            ["Sli:ProjectRoot"] = PostCollectionPostgres.Repository(),
            ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "data-runtime"),
            ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "logs-runtime"),
            ["Sli:Storage:ArchiveRoot"] = fixture.Pg.Root,
            ["Sli:Storage:HistoryReadMode"] = "primary",
            ["urls"] = "http://127.0.0.1:0"
        };
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder
            .UseTestServer()
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings))
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureServices(services => {
                services.RemoveAll<IHostedService>();
                services.AddSingleton(certificates.Ca);
            }));
        HttpClient Client(X509Certificate2? cert = null) => new(host.Server.CreateHandler(context => {
            context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString;
            context.Connection.ClientCertificate = cert;
        })) { BaseAddress = new Uri("https://localhost") };
        using var admin = Client();
        admin.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + token);
        using var agent = Client(peer);

        var (envelope, filePacket, policy) = AgentFileAuditValidatorTests.ActionPacket("permissions", 4670);
        var now = Iso8601.Truncate(DateTimeOffset.UtcNow);
        var signer = new EcdsaPacketSigner(key);
        string statusPath = Control + "?agent_id=" + agentId;

        async Task<JsonObject> Queue(string action, string commandId, long currentRevision)
        {
            var command = new JsonObject {
                ["contract_id"] = "sli.file-audit.audit-command.v1", ["command_id"] = commandId, ["action"] = action,
                ["policy_revision"] = (currentRevision + 1).ToString(CultureInfo.InvariantCulture),
                ["collection_scope_ids"] = new JsonArray(Scope)
            };
            var body = new JsonObject {
                ["agent_id"] = agentId.ToString(), ["expected_revision"] = currentRevision,
                ["config"] = policy.Value.DeepClone(), ["command"] = command
            };
            if (action == "apply")
            {
                body["enabled"] = true;
                body["activate_collection"] = true;
            }
            using var response = await Post(admin, Control, body, ct);
            var result = await Read(response, HttpStatusCode.OK, ct);
            Assert.Equal(commandId, result["command_id"]!.ToString());
            Assert.Equal("pending", result["state"]!.ToString());
            return command;
        }

        JsonObject SignedFile(string revision, string scope)
        {
            var payload = (JsonObject)filePacket.DeepClone();
            var source = hostId.ToString("D");
            payload["header"]!["generation"] = source;
            payload["header"]!["observed_at_utc"] = Iso8601.Format(now);
            payload["context"]!["policy_revision"] = revision;
            payload["records"]![0]!["payload"]!["collection_scope_id"] = scope;
            var after = JsonNode.Parse(envelope.CursorAfter.Token)!.AsObject();
            after["generation"] = source;
            return Packets.Make(signer, agentId.ToString(), 1,
                new Sample("sli.file-audit", source, "Security", source,
                    envelope.CursorBefore, new Cursor("bookmark", after.ToJsonString()), payload, PolicyRevision: revision,
                    ContinuityState: "not_proven", FilteredCount: 0, LostCount: 0), now).ToJson();
        }

        async Task<JsonObject> SendPacket(JsonObject data)
        {
            using var response = await Post(agent, Intake, data, ct);
            return await Read(response, HttpStatusCode.OK, ct);
        }

        async Task Confirm(JsonObject report)
        {
            using var response = await Post(agent, AgentReport, report, ct);
            Assert.Equal("accepted", (await Read(response, HttpStatusCode.OK, ct))["status"]!.ToString());
        }

        async Task AssertSavedCommand(JsonObject command)
        {
            using var response = await admin.GetAsync(Control + "/catalog?agent_id=" + agentId, ct);
            var catalog = await Read(response, HttpStatusCode.OK, ct);
            var saved = Assert.IsType<JsonObject>(catalog["saved_command"]);
            foreach (string field in new[] { "command_id", "action", "policy_revision", "collection_scope_ids" })
                Assert.True(JsonNode.DeepEquals(command[field], saved[field]), $"Catalog returned a different {field}");
            Assert.Equal(Scope, catalog["saved_selection"]!["collection_scope_id"]!.GetValue<string>());
            Assert.Equal(@"C:\Files", catalog["saved_selection"]!["path"]!.GetValue<string>());
            var reportKey = JsonNode.Parse(catalog["saved_report_share_key"]!.GetValue<string>())!.AsArray();
            Assert.Equal(new[] { agentId.ToString("D"), hostId.ToString("D"), Scope },
                reportKey.Select(value => value!.GetValue<string>()).ToArray());

            using var receipt = await admin.GetAsync(statusPath, ct);
            var status = await Read(receipt, HttpStatusCode.OK, ct);
            Assert.Equal(command["command_id"]!.GetValue<string>(), status["command"]!["command_id"]!.GetValue<string>());
            Assert.Equal("verified", status["state"]!.GetValue<string>());
        }

        var initial = await agent.GetFromJsonAsync<JsonObject>(AgentIdentity, ct);
        var adAssignment = initial!["assigned_modules"]!.AsArray().Single(
            item => item?["module_id"]?.ToString() == "sli.windows.ad-dc")!.DeepClone();
        var applied = await Queue("apply", "synthetic-apply", initial["policy_revision"]!.GetValue<long>());
        var applyRevision = applied["policy_revision"]!.ToString();
        Assert.Equal("module_disabled", (await SendPacket(SignedFile(applyRevision, Scope)))["error_code"]!.ToString());
        var appliedReport = Report(policy, applied, now);
        await Confirm(appliedReport);
        await AssertSavedCommand(applied);
        // Continue from a native apply written before the server stored its origin separately.
        await using (var legacyApply = new NpgsqlCommand("""
            update public.sli_agents set file_audit=file_audit-'permissions_restore_origin' where id=@agent
            """, owner))
        {
            legacyApply.Parameters.AddWithValue("agent", agentId);
            Assert.Equal(1, await legacyApply.ExecuteNonQueryAsync(ct));
        }
        var otherScope = await SendPacket(SignedFile(applyRevision, "scope:other"));
        var fileReceipt = await SendPacket(SignedFile(applyRevision, Scope));

        var recheck = await Queue("check", "synthetic-recheck", long.Parse(applyRevision, CultureInfo.InvariantCulture));
        var beforeRestore = await agent.GetFromJsonAsync<JsonObject>(AgentIdentity, ct);
        Assert.Equal("module_disabled", (await SendPacket(SignedFile(applyRevision, Scope)))["error_code"]!.ToString());
        var recheckReport = Report(policy, recheck, now.AddSeconds(1));
        using var checkedReport = await Post(agent, AgentReport, recheckReport, ct);
        output.WriteLine($"Repeat check report HTTP {(int)checkedReport.StatusCode}");
        await AssertSavedCommand(recheck);

        var restore = await Queue("restore", "synthetic-restore", beforeRestore!["policy_revision"]!.GetValue<long>());
        var restoreReport = Report(policy, restore, now.AddSeconds(2));
        await Confirm(restoreReport);
        await Confirm(restoreReport);
        Assert.Equal("accepted", (await Read(checkedReport, HttpStatusCode.OK, ct))["status"]!.ToString());
        Assert.Equal("agent_file_audit_packet_invalid", otherScope["error_code"]!.ToString());
        Assert.True(fileReceipt["status"]!.ToString() == "committed", fileReceipt.ToJsonString());
        var restored = await admin.GetFromJsonAsync<JsonObject>(statusPath, ct);
        Assert.Equal("synthetic-restore", restored!["command"]!["command_id"]!.ToString());
        Assert.Equal("verified", restored["state"]!.ToString());
        Assert.NotNull(restored["reported_at"]);
        Assert.Equal("verified", restored["scopes"]![Scope]!["state"]!.ToString());
        Assert.False(restored["may_own_audit"]!.GetValue<bool>());

        var reapplied = await Queue("apply", "synthetic-pending-apply",
            long.Parse(restore["policy_revision"]!.ToString(), CultureInfo.InvariantCulture));
        var nextCheck = await Queue("check", "synthetic-pending-check",
            long.Parse(reapplied["policy_revision"]!.ToString(), CultureInfo.InvariantCulture));
        var lastCheck = await Queue("check", "synthetic-later-check",
            long.Parse(nextCheck["policy_revision"]!.ToString(), CultureInfo.InvariantCulture));
        var nextRestore = await Queue("restore", "synthetic-next-restore",
            long.Parse(lastCheck["policy_revision"]!.ToString(), CultureInfo.InvariantCulture));
        var lateApply = Report(policy, reapplied, now.AddSeconds(3));
        var lateCheck = Report(policy, nextCheck, now.AddSeconds(4));
        var unrelated = (JsonObject)lateCheck.DeepClone();
        unrelated["command_id"] = "synthetic-unrequested";
        using (var refused = await Post(agent, AgentReport, unrelated, ct))
            Assert.Equal("file_audit_result_invalid", (await Read(refused, HttpStatusCode.BadRequest, ct))["error"]!.ToString());
        var otherReportScope = (JsonObject)lateCheck.DeepClone();
        otherReportScope["scopes"]![0]!["collection_scope_id"] = "scope:other";
        using (var refused = await Post(agent, AgentReport, otherReportScope, ct))
            Assert.Equal("file_audit_result_invalid", (await Read(refused, HttpStatusCode.BadRequest, ct))["error"]!.ToString());
        await Confirm(lateApply);
        await Confirm(lateCheck);
        var pending = await admin.GetFromJsonAsync<JsonObject>(statusPath, ct);
        Assert.Equal("synthetic-next-restore", pending!["command"]!["command_id"]!.ToString());
        Assert.Equal("pending", pending["state"]!.ToString());
        Assert.True(pending["may_own_audit"]!.GetValue<bool>());
        var ad = AgentPacketReportPostgresTests.CaptureSample(now, AdDcImportPerformanceTests.Source, hostId);
        var adReceipt = await SendPacket(Packets.Make(signer, agentId.ToString(), 1, ad, now).ToJson());
        Assert.True(adReceipt["status"]!.ToString() == "committed", adReceipt.ToJsonString());
        await Confirm(Report(policy, nextRestore, now.AddSeconds(5)));

        var final = await agent.GetFromJsonAsync<JsonObject>(AgentIdentity, ct);
        Assert.True(JsonNode.DeepEquals(adAssignment, final!["assigned_modules"]!.AsArray().Single(
            item => item?["module_id"]?.ToString() == "sli.windows.ad-dc")));
        await using var receipt = new NpgsqlCommand("""
            select (select count(*) from public.sli_agent_receipts where packet_id=@packet)=1
                and (select count(*) from sli_plugin_file_audit.audit_receipts where agent_id=@agent
                     and command_id in ('synthetic-apply','synthetic-recheck','synthetic-restore','synthetic-next-restore'))=4
                and not exists (select 1 from sli_plugin_file_audit.audit_receipts where agent_id=@agent
                                and command_id in ('synthetic-pending-apply','synthetic-pending-check'))
            """, owner);
        receipt.Parameters.AddWithValue("packet", Guid.Parse(fileReceipt["packet_id"]!.ToString()));
        receipt.Parameters.AddWithValue("agent", agentId);
        Assert.Equal(true, await receipt.ExecuteScalarAsync(ct));
    }

    private static async Task<HttpResponseMessage> Post(HttpClient client, string path, JsonObject body, CancellationToken ct)
    {
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        return await client.PostAsync(path, content, ct);
    }

    private static async Task<JsonObject> Read(HttpResponseMessage response, HttpStatusCode expected, CancellationToken ct)
    {
        string body = await response.Content.ReadAsStringAsync(ct);
        Assert.True(response.StatusCode == expected, $"Expected HTTP {(int)expected}, got {(int)response.StatusCode} {body}");
        return JsonNode.Parse(body)!.AsObject();
    }

    private static JsonObject Report(FileAuditPolicy policy, JsonObject command, DateTimeOffset observed)
    {
        var time = Iso8601.Format(observed);
        var commandId = command["command_id"]!.ToString();
        var revision = command["policy_revision"]!.ToString();
        var action = command["action"]!.ToString();
        var masks = new JsonObject(policy.RequiredMasks().Select(mask =>
            new KeyValuePair<string, JsonNode?>(mask.Key, JsonValue.Create(mask.Value))));
        var snapshot = new JsonObject {
            ["contract_id"] = "sli.file-audit.inventory.v1", ["collection_scope_id"] = Scope,
            ["policy_revision"] = revision, ["observed_at_utc"] = time,
            ["scan_id"] = AuthAudit.Uuid5(commandId + time).ToString(), ["page_number"] = 0,
            ["has_more"] = false, ["completeness"] = "complete", ["unread_objects"] = 0,
            ["share"] = new JsonObject { ["name"] = "Files", ["path"] = @"C:\Files", ["dacl"] = "", ["complete"] = true },
            ["local_groups"] = new JsonObject { ["complete"] = true, ["groups"] = new JsonArray() },
            ["objects"] = new JsonArray(new JsonObject { ["path"] = @"C:\Files", ["object_id"] = "fixture",
                ["object_type"] = "directory", ["owner_sid"] = "S-1-5-18", ["dacl"] = "", ["sacl"] = "",
                ["sacl_protected"] = false, ["sacl_missing"] = false })
        };
        string digest = Packets.Digest(snapshot);
        snapshot["snapshot_sha256"] = digest;
        snapshot["snapshot_id"] = AuthAudit.Uuid5(commandId + digest).ToString();
        return new JsonObject {
            ["contract_id"] = "sli.file-audit.audit-result.v1", ["command_id"] = commandId,
            ["action"] = action, ["policy_revision"] = revision, ["observed_at_utc"] = time,
            ["ownership_remaining"] = action == "apply",
            ["snapshots"] = new JsonArray(snapshot),
            ["scopes"] = new JsonArray(new JsonObject { ["collection_scope_id"] = Scope, ["state"] = "verified",
                ["reason_code"] = "ok", ["required_masks"] = masks, ["actual_masks"] = masks.DeepClone() })
        };
    }
}
