using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Deployment;
using Xunit;
using static Sli.Server.Tests.AgentDeploymentFixture;

namespace Sli.Server.Tests;

public sealed class AgentDeploymentTests
{
    [Theory]
    [InlineData(System.Runtime.InteropServices.Architecture.X64, 0x20000)]
    [InlineData(System.Runtime.InteropServices.Architecture.Arm64, 0x8000)]
    public void Master_key_open_uses_architecture_specific_nofollow(System.Runtime.InteropServices.Architecture architecture, int nofollow)
    {
        Assert.Equal(nofollow | 0x800 | 0x80000, AdCredentialSecrets.OpenFlags(architecture));
    }
    private const string Directory = AgentDeploymentFixture.Directory;
    private const string Gpo = AgentDeploymentFixture.Gpo;
    public static TheoryData<string, bool> Routes => new()
    {
        { Credentials, false }, { Credentials, true }, { Credentials + "/check", true },
        { Credentials + "/replace-password", true }, { Credentials + "/delete", true },
        { Directory, true }, { Gpo + "credentials", true }, { Gpo + "preview", true }, { Gpo + "confirm", true }, { Gpo + "cancel", true }
    };
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteRejectsUnauthenticatedAndInvalidInput(string route, bool mutation)
    {
        await using var f = new AgentDeploymentFixture();
        var denied = await f.Send(route, mutation ? new() : null, actor: "anonymous");
        Assert.Equal(401, denied.Status); Assert.Equal(0, f.Data.Opens);
        var bad = mutation ? await f.Send(route, new() { ["unexpected"] = true }) : await f.Send(route, query: "?unexpected=1");
        Assert.Equal(400, bad.Status);
        string expected = route == Directory ? "invalid_group_enrollment_scope" : route.StartsWith(Gpo) ? route.EndsWith("confirm") || route.EndsWith("cancel") ? "gpo_confirmation_invalid" : "gpo_selection_invalid" : "ad_credential_request_invalid";
        Assert.Equal(expected, bad.Body["error"]!.GetValue<string>());
        Assert.Empty(f.Data.Audits); Assert.Empty(f.Data.Credentials); Assert.Empty(f.Data.Plans);
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteRejectsMissingAuthority(string route, bool mutation)
    {
        await using var f = new AgentDeploymentFixture();
        JsonObject? body = null;
        if (mutation)
        {
            if (route == Credentials) body = new() { ["domain_id"] = 1, ["label"] = "synthetic", ["username"] = "user", ["password"] = "synthetic" };
            else if (route.StartsWith(Credentials)) body = new() { ["credential_id"] = Guid.NewGuid().ToString(), ["credential_revision"] = 1 };
            else if (route == Directory) body = new();
            else if (route.EndsWith("confirm") || route.EndsWith("cancel"))
            {
                var credential = await f.Create(); var plan = await f.Preview(credential);
                body = Finish(plan, route.EndsWith("confirm") ? credential : null);
            }
            else
            {
                body = Selection();
                if (route.EndsWith("preview")) { body["credential_id"] = Guid.NewGuid().ToString(); body["credential_revision"] = 1; }
            }
            if (route.EndsWith("replace-password")) body["password"] = "synthetic";
        }
        int before = f.Data.Commits;
        f.Data.Granted = false; f.Data.DeploymentGranted = false;
        var denied = await f.Send(route, body, owner: false);
        Assert.Equal(403, denied.Status);
        if (route == Directory) Assert.Equal(before, f.Data.Commits);
        else
        {
            Assert.Equal(before + 1, f.Data.Commits);
            var audit = f.Data.Audits.Last(); Assert.Equal("denied", audit["action"]!.GetValue<string>());
            Assert.Equal(route.StartsWith(Gpo) ? "gpo_deployment_denied" : "ad_operations_denied", denied.Body["error"]!.GetValue<string>());
            if (route.StartsWith(Credentials)) { Assert.Null(audit["domain"]); Assert.Null(audit["id"]); }
        }
    }
    [Fact]
    public async Task CredentialsCreateListRotateCheckDeleteMatchPublicContractAndAudit()
    {
        await using var f = new AgentDeploymentFixture();
        var created = await f.Create(); string id = created["credential_id"]!.GetValue<string>();
        Assert.Equal("synthetic", created["label"]!.GetValue<string>()); Assert.Equal("operator@example.test", created["username"]!.GetValue<string>());
        Assert.Equal("saved", created["password_status"]!.GetValue<string>()); Assert.Equal(1, created["credential_revision"]!.GetValue<long>());
        Assert.Equal("2026-11-05 01:02:03+00:00", created["created_at"]!.GetValue<string>());
        Assert.Empty(created["usages"]!.AsArray()); AssertNoSecrets(created);
        var listed = await f.Send(Credentials); Assert.Equal(200, listed.Status);
        Assert.Single(listed.Body["items"]!.AsArray()); Assert.True(listed.Body["key_status"]!["available"]!.GetValue<bool>());
        Assert.False(listed.Body["write_enabled"]!.GetValue<bool>()); AssertNoSecrets(listed.Body);
        Assert.DoesNotContain(f.Data.Sql, sql => sql.Contains("envelope") && sql.Contains("where domain_id=any"));
        AssertPassword(f, id, "synthetic password");
        var rotate = Revision(created); rotate["password"] = "synthetic rotated";
        var changed = await f.Send(Credentials + "/replace-password", rotate); Assert.Equal(200, changed.Status);
        Assert.Equal(2, changed.Body["credential_revision"]!.GetValue<long>()); AssertNoSecrets(changed.Body); AssertPassword(f, id, "synthetic rotated");
        var stale = await f.Send(Credentials + "/delete", Revision(created)); Assert.Equal(409, stale.Status); Assert.Equal("ad_credential_revision_conflict", stale.Body["error"]!.GetValue<string>());
        var check = await f.Send(Credentials + "/check", Revision(changed.Body)); Assert.Equal(409, check.Status); Assert.Equal("ad_check_transport_unavailable", check.Body["error"]!.GetValue<string>());
        Assert.Equal("not_checked", f.Data.Credentials[id]["check_status"]!.GetValue<string>());
        var deleted = await f.Send(Credentials + "/delete", Revision(changed.Body)); Assert.Equal(200, deleted.Status); Assert.Equal("deleted", deleted.Body["status"]!.GetValue<string>()); Assert.False(deleted.Body["write_enabled"]!.GetValue<bool>());
        Assert.Empty(f.Data.Credentials);
        Assert.Equal(new[] { "created", "password_replaced", "check_blocked", "deleted" }, f.Data.Audits.Select(x => x["action"]!.GetValue<string>()));
        Assert.DoesNotContain("synthetic", JsonSerializer(f.Data.Audits));
    }
    [Fact]
    public async Task DirectoryReturnsAcceptedDomainsOusAndScopedComputers()
    {
        await using var f = new AgentDeploymentFixture();
        var domains = await f.Send(Directory, new()); Assert.Equal(200, domains.Status); Assert.Single(domains.Body["domains"]!.AsArray());
        f.Data.AccessManager = true;
        Assert.Equal(200, (await f.Send(Directory, new(), owner: false)).Status);
        var directory = await f.Send(Directory, Selection()); Assert.Equal(200, directory.Status);
        Assert.Single(directory.Body["computers"]!.AsArray()); Assert.Single(directory.Body["ous"]!.AsArray()); Assert.False(directory.Body["has_more"]!.GetValue<bool>());
        Assert.Equal(20, directory.Body["computers"]![0]!["id"]!.GetValue<long>());
        Assert.Contains(f.Data.Sql, sql => sql.Contains("interval '24 hours'") && sql.Contains("limit 10001"));
        f.Data.Directory[1]["record"]!["attributes"]!["distinguished_name"] = "CN=Synthetic,OU=Other,DC=example,DC=test";
        Assert.Empty((await f.Send(Directory, Selection())).Body["computers"]!.AsArray());
        f.Data.Directory[1]["record"]!["attributes"]!["enabled"] = false;
        Assert.Empty((await f.Send(Directory, new() { ["domain_id"] = 1 })).Body["computers"]!.AsArray());
    }
    [Fact]
    public async Task GpoOptionsPreviewConfirmAndCancelPersistBoundIntentions()
    {
        await using var f = new AgentDeploymentFixture(); var credential = await f.Create();
        var options = await f.Send(Gpo + "credentials", Selection()); Assert.Equal(200, options.Status);
        Assert.True(options.Body["items"]![0]!["eligible"]!.GetValue<bool>()); Assert.Null(options.Body["selected_credential_id"]); AssertNoSecrets(options.Body);
        var plan = await f.Preview(credential); Assert.False(plan["write_enabled"]!.GetValue<bool>()); Assert.Equal(604800, plan["token_ttl_seconds"]!.GetValue<int>());
        Assert.Single(plan["targets"]!.AsArray()); Assert.Single(plan["ous"]!.AsArray()); AssertNoSecrets(plan);
        Assert.InRange(DateTimeOffset.Parse(plan["expires_at"]!.GetValue<string>()) - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
        string id = plan["plan_id"]!.GetValue<string>(); var persisted = f.Data.Plans[id];
        // Python json.dumps(sort_keys=True,separators=(",",":")) source vectors.
        Assert.Equal("0349d4e05392c591db8ec1e4fa3d9467c7df0e14328e49a87877930cbc13f99e", persisted["snapshot"]!["targets"]![0]!["identity_sha256"]!.GetValue<string>());
        Assert.Equal("3a80b3580dd6fdb21d7446c7411f655409871994604862bc10617146eb7df21a", plan["credential_binding"]!["authorization_sha256"]!.GetValue<string>());
        Assert.Equal(20, persisted["selection"]!["computer_entity_ids"]![0]!.GetValue<long>());
        Assert.Equal(plan["plan_sha256"]!.GetValue<string>(), AgentGpoPlans.Hash(persisted["snapshot"]!));
        var confirm = await f.Send(Gpo + "confirm", Finish(plan, credential)); Assert.Equal(200, confirm.Status); Assert.Equal("confirmed", confirm.Body["status"]!.GetValue<string>());
        Assert.Equal("confirmed", f.Data.Plans[id]["status"]!.GetValue<string>()); Assert.False(confirm.Body["write_enabled"]!.GetValue<bool>());
        var repeated = await f.Send(Gpo + "confirm", Finish(plan, credential)); Assert.Equal(409, repeated.Status); Assert.Equal("gpo_plan_unavailable", repeated.Body["error"]!.GetValue<string>());
        var remembered = await f.Send(Gpo + "credentials", Selection()); Assert.Equal(credential["credential_id"]!.GetValue<string>(), remembered.Body["selected_credential_id"]!.GetValue<string>());
        var next = await f.Preview(credential); var cancel = await f.Send(Gpo + "cancel", Finish(next)); Assert.Equal(200, cancel.Status); Assert.Equal("cancelled", cancel.Body["status"]!.GetValue<string>());
        int audits = f.Data.Audits.Count; Assert.Equal(200, (await f.Send(Gpo + "cancel", Finish(next))).Status); Assert.Equal(audits, f.Data.Audits.Count);
        Assert.Contains(f.Data.Audits, x => x["action"]!.GetValue<string>() == "confirmed" && x["certificate"]!.GetValue<string>() == new string('b', 64));
        Assert.DoesNotContain("Synthetic", JsonSerializer(f.Data.Audits));
    }
    [Theory]
    [InlineData("scope", "gpo_plan_drift")]
    [InlineData("recipient", "gpo_plan_drift")]
    [InlineData("credential", "gpo_credential_changed")]
    [InlineData("identity", "gpo_plan_drift")]
    [InlineData("expired", "gpo_plan_unavailable")]
    [InlineData("deadline", "gpo_plan_unavailable")]
    [InlineData("hash", "gpo_plan_mismatch")]
    [InlineData("foreign", "gpo_plan_unavailable")]
    public async Task ConfirmationRechecksRevisionEvidenceRecipientActorAndDeadline(string mutation, string error)
    {
        await using var f = new AgentDeploymentFixture(); var credential = await f.Create(); var plan = await f.Preview(credential);
        string id = plan["plan_id"]!.GetValue<string>(); var body = Finish(plan, credential);
        switch (mutation)
        {
            case "scope": f.Data.ScopeRevision++; break;
            case "recipient": f.Data.RecipientRevision++; break;
            case "credential": f.Data.Credentials[credential["credential_id"]!.GetValue<string>()]["credential_revision"] = 2; break;
            case "identity": f.Data.Directory[1]["record"]!["identity"]!["object_sid"] = "S-1-5-21-1-2-3-1001"; break;
            case "expired": f.Data.Plans[id]["expires_at"] = DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O"); break;
            case "deadline": f.Data.ExpireOnUpdate = true; break;
            case "hash": body["plan_sha256"] = new string('0', 64); break;
            case "foreign": f.Data.Plans[id]["actor"] = "session:2"; break;
        }
        var denied = await f.Send(Gpo + "confirm", body); Assert.Equal(mutation == "foreign" ? 404 : 409, denied.Status); Assert.Equal(error, denied.Body["error"]!.GetValue<string>());
        Assert.Equal("preview", f.Data.Plans[id]["status"]!.GetValue<string>()); Assert.Null(f.Data.Last);
        Assert.Equal("denied", f.Data.Audits.Last()["action"]!.GetValue<string>());
    }
    [Fact]
    public async Task AdScopeIsIndependentOfOwnershipAndDoesNotExposeForeignCredentials()
    {
        await using var f = new AgentDeploymentFixture(); var created = await f.Create(); string id = created["credential_id"]!.GetValue<string>();
        f.Data.Credentials[id]["ou_entity_ids"] = new JsonArray(999);
        Assert.Empty((await f.Send(Credentials)).Body["items"]!.AsArray());
        var denial = await f.Send(Credentials + "/delete", Revision(created)); Assert.Equal(403, denial.Status);
        Assert.Null(f.Data.Audits.Last()["domain"]); Assert.Null(f.Data.Audits.Last()["id"]);
        f.Data.Granted = false;
        Assert.Equal(403, (await f.Send(Credentials, owner: true)).Status);
        foreach (string actor in new[] { "api_key", "other" })
        {
            Assert.Equal(403, (await f.Send(Credentials, actor: actor)).Status);
            Assert.Equal("gpo_session_required", (await f.Send(Gpo + "preview", Selection(), actor: actor)).Body["error"]!.GetValue<string>());
        }
    }
    [Theory]
    [InlineData("dc", "gpo_target_excluded")]
    [InlineData("sid", "gpo_identity_unavailable")]
    [InlineData("empty", "gpo_selection_empty")]
    [InlineData("package", "gpo_package_unavailable")]
    [InlineData("recipient", "gpo_recipient_unavailable")]
    [InlineData("key", "ad_master_key_not_configured")]
    public async Task PreviewFailsClosedAndAuditsUnavailableDependencies(string cause, string error)
    {
        await using var f = new AgentDeploymentFixture(); var credential = await f.Create();
        switch (cause)
        {
            case "dc": f.Data.Directory[1]["record"]!["attributes"]!["user_account_control"] = 8192; break;
            case "sid": f.Data.Directory[1]["record"]!["identity"]!["object_sid"] = "bad"; break;
            case "empty": f.Data.Directory.RemoveAt(1); break;
            case "package": f.Data.Package = new() { ["version"] = "../bad" }; break;
            case "recipient": f.Data.RecipientReady = false; break;
            case "key": f.Secrets.Error = "ad_master_key_not_configured"; break;
        }
        var selection = Selection(); foreach (var (k, v) in Revision(credential)) selection[k] = v?.DeepClone();
        var result = await f.Send(Gpo + "preview", selection); Assert.Equal(409, result.Status); Assert.Equal(error, result.Body["error"]!.GetValue<string>());
        Assert.Empty(f.Data.Plans); Assert.Equal(error, f.Data.Audits.Last()["result"]!.GetValue<string>());
    }
    [Fact]
    public async Task TlsOriginParserAndCommitFailuresCannotReleaseResults()
    {
        await using var f = new AgentDeploymentFixture();
        var tls = await f.Send(Credentials, new(), scheme: "http"); Assert.Equal(401, tls.Status); Assert.Equal("agent_tls_required", tls.Body["error"]!.GetValue<string>()); Assert.Equal(0, f.Data.Opens);
        var origin = await f.Send(Gpo + "preview", Selection(), origin: "https://other.example"); Assert.Equal(403, origin.Status); Assert.Equal(0, f.Data.Opens);
        Assert.Equal(400, (await f.Send(Gpo + "preview", new(), raw: "{")).Status);
        Assert.Equal(413, (await f.Send(Gpo + "preview", new(), raw: "{\"x\":\"" + new string('x', 65536) + "\"}")).Status);
        f.Data.FailAudit = true;
        var failed = await f.Send(Credentials, new() { ["domain_id"] = 1, ["label"] = "synthetic", ["username"] = "user", ["password"] = "synthetic" });
        Assert.Equal(503, failed.Status); Assert.Equal("agent_service_unavailable", failed.Body["error"]!.GetValue<string>()); Assert.Empty(f.Data.Credentials); Assert.Empty(f.Data.Audits);
        f.Data.FailAudit = false; f.Data.FailCommit = true;
        Assert.Equal(503, (await f.Send(Credentials, new() { ["domain_id"] = 1, ["label"] = "synthetic", ["username"] = "user", ["password"] = "synthetic" })).Status);
        Assert.Empty(f.Data.Credentials); Assert.Empty(f.Data.Audits);
    }
    [Fact]
    public async Task AllTenMethodsAreRegistered()
    {
        var builder = WebApplication.CreateBuilder(); await using var app = builder.Build(); app.MapAgentDeploymentEndpoints();
        var endpoints = ((IEndpointRouteBuilder)app).DataSources.SelectMany(x => x.Endpoints).OfType<RouteEndpoint>().ToArray(); Assert.Equal(10, endpoints.Length);
        foreach (var row in Routes)
        {
            string route = row.Data.Item1; string method = row.Data.Item2 ? "POST" : "GET";
            Assert.Single(endpoints, e => e.RoutePattern.RawText == route && e.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains(method));
        }
    }
    [Theory]
    [InlineData("user@example.test", true)] [InlineData("EXAMPLE\\user", true)] [InlineData("user@@example.test", false)]
    [InlineData("EXAMPLE\\user@other.test", false)] [InlineData("a;command@example.test", false)] [InlineData("a\u200b@example.test", false)]
    public void UsernameValidationMatchesSource(string username, bool valid)
    {
        if (valid) AdOperationCredentials.ValidateUsername(username);
        else Assert.Equal("ad_credential_request_invalid", Assert.Throws<AgentControlException>(() => AdOperationCredentials.ValidateUsername(username)).Message);
    }
    [Fact]
    public void SelectionRejectsBooleanIdsEmptyListsAndFloatRevisionsAtCredentialBinding()
    {
        foreach (string json in new[] { "{\"domain_id\":true,\"ou_entity_ids\":[1]}", "{\"domain_id\":1,\"ou_entity_ids\":[false]}", "{\"domain_id\":1,\"ou_entity_ids\":[]}", "{\"domain_id\":1,\"ou_entity_ids\":null}" })
            Assert.Throws<AgentControlException>(() => AgentGpoPlans.Selection(JsonNode.Parse(json)!.AsObject(), false));
        Assert.False(AdOperationCredentials.Integer(JsonNode.Parse("1.0"), out _));
        Assert.Equal("ad_master_key_invalid", Assert.Throws<AgentControlException>(() => AdCredentialSecrets.Decode(new string(' ', 44))).Message);
        Assert.Throws<AgentControlException>(() => AdCredentialSecrets.Decode(Convert.ToBase64String(new byte[31])));
    }
    [Theory]
    [InlineData("password", "ad_password_invalid", 400)]
    [InlineData("username", "ad_credential_request_invalid", 400)]
    [InlineData("label", "agent_service_unavailable", 503)]
    public async Task LoneSurrogateInputPreservesValidationAndStorageErrors(string field, string error, int status)
    {
        await using var f = new AgentDeploymentFixture();
        string raw = "{\"domain_id\":1,\"label\":\"synthetic\",\"username\":\"user\",\"password\":\"synthetic\",\"" + field + "\":\"\\ud800\"}";
        var response = await f.Send(Credentials, new(), raw: raw);
        Assert.Equal(status, response.Status); Assert.Equal(error, response.Body["error"]!.GetValue<string>());
        Assert.Empty(f.Data.Credentials); Assert.Empty(f.Data.Audits);
    }
    private static string JsonSerializer(object value) => System.Text.Json.JsonSerializer.Serialize(value);
    private static void AssertNoSecrets(JsonObject value)
    {
        string text = value.ToJsonString(); foreach (string field in new[] { "\"password\":", "\"envelope\":", "\"ciphertext\":", "\"wrapped_dek\":" }) Assert.DoesNotContain(field, text);
    }
    private static void AssertPassword(AgentDeploymentFixture f, string id, string expected)
    {
        var row = f.Data.Credentials[id]; var envelope = row["envelope"]!;
        byte[] Decode(string field) => Convert.FromBase64String(envelope[field]!.GetValue<string>());
        byte[] Aad(string purpose) => Encoding.ASCII.GetBytes("{\"credential_id\":\"" + id + "\",\"credential_revision\":" + row["credential_revision"] + ",\"domain_id\":1,\"format_version\":1,\"installation_id\":\"" + Installation + "\",\"purpose\":\"" + purpose + "\"}");
        byte[] wrapped = Decode("wrapped_dek"), dek = new byte[32]; using var master = new AesGcm(f.Secrets.Bytes, 16);
        master.Decrypt(Decode("wrap_nonce"), wrapped.AsSpan(0, 32), wrapped.AsSpan(32), dek, Aad("dek").Concat("1"u8.ToArray()).ToArray());
        byte[] ciphertext = Decode("ciphertext"), clear = new byte[ciphertext.Length - 16]; using var aes = new AesGcm(dek, 16);
        aes.Decrypt(Decode("nonce"), ciphertext.AsSpan(0, clear.Length), ciphertext.AsSpan(clear.Length), clear, Aad("password")); Assert.Equal(expected, Encoding.UTF8.GetString(clear));
        byte[] wrong = Aad("password"); wrong[1] ^= 1;
        Assert.Throws<AuthenticationTagMismatchException>(() => aes.Decrypt(Decode("nonce"), ciphertext.AsSpan(0, clear.Length), ciphertext.AsSpan(clear.Length), clear, wrong));
    }
}
