using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;

namespace Sli.Server.Agents.Deployment;

internal sealed class AdOperationCredentials(IAgentDeploymentDatabase db, IAdCredentialSecrets secrets)
{
    private const string Metadata = "credential_id,domain_id,label,username,credential_revision,created_by,created_at,updated_by,updated_at,check_status,checked_at";
    internal async Task<Dictionary<long, long[]>> Scopes(string actor, CancellationToken ct)
    {
        if (!AgentControlJson.Matches(actor, @"\Asession:[1-9][0-9]*\z")) await Deny(actor, ct);
        var rows = await db.Rows("select public.sli_ad_operations_scopes(@actor) as scopes", ct, ("actor", actor));
        var scopes = (rows[0]["scopes"] as JsonArray ?? []).OfType<JsonObject>().ToDictionary(x => Long(x, "domain_id"), x => Ids(x["ou_entity_ids"]));
        if (scopes.Count == 0) await Deny(actor, ct);
        return scopes;
    }
    private async Task Deny(string actor, CancellationToken ct)
    {
        await Audit(actor, null, "denied", ct, result: "ad_operations_denied");
        throw new AgentDeploymentRejection("ad_operations_denied");
    }
    private Task Audit(string actor, long? domain, string action, CancellationToken ct, Guid? id = null, long? revision = null, string result = "ok")
        => db.Execute("insert into sli_ad_credential_audit(actor,domain_id,credential_id,credential_revision,action,result) values(@actor,@domain::bigint,@id::uuid,@revision::bigint,@action,@result)", ct,
            ("actor", actor), ("domain", domain), ("id", id), ("revision", revision), ("action", action), ("result", result));
    internal async Task<JsonObject> List(string actor, CancellationToken ct)
    {
        var scopes = await Scopes(actor, ct);
        long[] domains = scopes.Keys.Order().ToArray();
        var names = await db.Rows("select id,fqdn from domains where id=any(@domains) order by id", ct, ("domains", domains));
        var rows = await db.Rows($"select {Metadata},ou_entity_ids from sli_ad_operation_credentials where domain_id=any(@domains) order by created_at,credential_id", ct, ("domains", domains));
        return new() { ["items"] = new JsonArray(rows.Where(x => Ids(x["ou_entity_ids"]).All(scopes[Long(x, "domain_id")].Contains)).Select(x => (JsonNode)Public(x)).ToArray()),
            ["domains"] = new JsonArray(names.Select(x => (JsonNode)x).ToArray()), ["key_status"] = AdCredentialSecrets.Status(secrets), ["write_enabled"] = false };
    }
    internal async Task<JsonObject> Record(JsonNode? id, string actor, CancellationToken ct)
    {
        Guid credential = InputId(id);
        var scopes = await Scopes(actor, ct);
        var rows = await db.Rows("select * from sli_ad_operation_credentials where credential_id=@id for update", ct, ("id", credential));
        var row = rows.FirstOrDefault();
        if (row is null || !scopes.TryGetValue(Long(row, "domain_id"), out var allowed) || !Ids(row["ou_entity_ids"]).All(allowed.Contains)) await Deny(actor, ct);
        return row!;
    }
    internal async Task<JsonObject> Create(JsonObject body, string actor, CancellationToken ct)
    {
        Request(body, "domain_id", "label", "username", "password");
        long domain = AgentGroupInput.Positive(body["domain_id"]);
        var scopes = await Scopes(actor, ct);
        if (!scopes.ContainsKey(domain)) await Deny(actor, ct);
        string? label = AgentGroupInput.Text(body["label"]);
        if (label is null || AgentControlJson.Strip(label).EnumerateRunes().Count() is < 1 or > 128 || label.Any(c => c < 32)) Invalid();
        var names = await db.Rows("select fqdn from domains where id=@domain", ct, ("domain", domain));
        if (names.Count == 0) Invalid();
        string? username = InputText(body["username"]);
        if (username is not null && !username.Contains('\\') && !username.Contains('@')) username += "@" + Text(names[0], "fqdn");
        ValidateUsername(username);
        byte[] key = secrets.ReadKey();
        try
        {
            var installations = await db.Rows("select installation_id from sli_ad_credential_installation where singleton=true", ct);
            if (installations.Count == 0) throw new AgentControlException("ad_credential_installation_unavailable", 409);
            Guid id = Guid.NewGuid();
            var context = new JsonObject { ["installation_id"] = Text(installations[0], "installation_id"), ["credential_id"] = id.ToString(), ["domain_id"] = domain, ["credential_revision"] = 1 };
            var envelope = AdCredentialSecrets.Encrypt(body["password"], context, key);
            var rows = await db.Rows($"insert into sli_ad_operation_credentials(credential_id,installation_id,domain_id,ou_entity_ids,label,username,envelope,created_by,updated_by) values(@id,@installation,@domain,@ous,@label,@username,@envelope::jsonb,@actor,@actor) returning {Metadata}", ct,
                ("id", id), ("installation", Guid.Parse(Text(context, "installation_id"))), ("domain", domain), ("ous", scopes[domain].Distinct().Order().ToArray()),
                ("label", AgentControlJson.Strip(label!)), ("username", username), ("envelope", envelope.ToJsonString()), ("actor", actor));
            await Audit(actor, domain, "created", ct, id, 1);
            return Public(rows[0]);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    internal async Task<JsonObject> Change(string action, JsonObject body, string actor, CancellationToken ct)
    {
        Request(body, action == "replace-password" ? ["credential_id", "credential_revision", "password"] : ["credential_id", "credential_revision"]);
        var row = await Record(body["credential_id"], actor, ct);
        long revision = Long(row, "credential_revision");
        if (!Integer(body["credential_revision"], out long expected) || expected != revision) throw new AgentControlException("ad_credential_revision_conflict", 409);
        Guid id = Guid.Parse(Text(row, "credential_id"));
        long domain = Long(row, "domain_id");
        if (action == "check")
        {
            byte[] key = secrets.ReadKey(); CryptographicOperations.ZeroMemory(key);
            await Audit(actor, domain, "check_blocked", ct, id, revision, "ad_check_transport_unavailable");
            throw new AgentDeploymentRejection("ad_check_transport_unavailable", 409);
        }
        if (action == "delete")
        {
            await db.Execute("delete from sli_ad_operation_credentials where credential_id=@id", ct, ("id", id));
            await Audit(actor, domain, "deleted", ct, id, revision);
            return new() { ["credential_id"] = id.ToString(), ["status"] = "deleted", ["write_enabled"] = false };
        }
        revision = checked(revision + 1);
        var context = new JsonObject { ["installation_id"] = Text(row, "installation_id"), ["credential_id"] = id.ToString(), ["domain_id"] = domain, ["credential_revision"] = revision };
        var envelope = AdCredentialSecrets.Encrypt(body["password"], context, secrets.ReadKey());
        var rows = await db.Rows($"update sli_ad_operation_credentials set envelope=@envelope::jsonb,credential_revision=@revision,updated_by=@actor,updated_at=clock_timestamp(),check_status='not_checked',checked_at=null where credential_id=@id returning {Metadata}", ct,
            ("envelope", envelope.ToJsonString()), ("revision", revision), ("actor", actor), ("id", id));
        await Audit(actor, domain, "password_replaced", ct, id, revision);
        return Public(rows[0]);
    }
    internal static long Long(JsonObject row, string name) => row[name]!.GetValue<long>();
    internal static string Text(JsonObject row, string name) => row[name]!.GetValue<string>();
    internal static string? InputText(JsonNode? node)
    {
        try { return AgentGroupInput.Text(node); }
        catch (InvalidOperationException) { return null; }
    }
    internal static Guid InputId(JsonNode? node)
    {
        try { return AgentGroupInput.Id(node); }
        catch (InvalidOperationException) { throw new AgentControlException("invalid_agent_identity"); }
    }
    internal static long[] Ids(JsonNode? value) => value!.AsArray().Select(x => x!.GetValue<long>()).ToArray();
    internal static bool Integer(JsonNode? node, out long value)
    {
        value = 0;
        return node?.GetValueKind() == JsonValueKind.Number && JsonSerializer.SerializeToElement(node).TryGetInt64(out value);
    }
    private static void Request(JsonObject body, params string[] fields) { if (!AgentGroupInput.Shape(body, fields)) Invalid(); }
    private static void Invalid() => throw new AgentControlException("ad_credential_request_invalid");
    internal static void ValidateUsername(string? value)
    {
        if (value is null || value.EnumerateRunes().Count() is < 1 or > 1024 || value.Any(c => char.IsWhiteSpace(c) || c is >= '\x1c' and <= '\x1f')
            || value.EnumerateRunes().Any(c => System.Text.Rune.GetUnicodeCategory(c) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned)
            || value.Any(c => "/:\"<>|?*;=,[]".Contains(c))) Invalid();
        string[] parts = value!.Contains('\\') && !value.Contains('@') ? value.Split('\\') : !value.Contains('\\') ? value.Split('@') : [];
        if (parts.Length != 2 || parts.Any(x => x is "" or "." or "..")) Invalid();
    }
    private static JsonObject Public(JsonObject row)
    {
        var result = new JsonObject();
        foreach (string field in Metadata.Split(',')) result[field] = row[field]?.DeepClone();
        foreach (string field in new[] { "created_at", "updated_at", "checked_at" })
            if (result[field] is not null) result[field] = AgentControlJson.Stamp(DateTimeOffset.Parse(Text(result, field), CultureInfo.InvariantCulture));
        result["password_status"] = "saved"; result["usages"] = new JsonArray();
        return result;
    }
}
