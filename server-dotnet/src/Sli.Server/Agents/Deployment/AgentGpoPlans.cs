using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;
using static Sli.Server.Agents.Deployment.AdOperationCredentials;

namespace Sli.Server.Agents.Deployment;

internal sealed class AgentGpoPlans(IAgentDeploymentDatabase db, AdOperationCredentials credentials, AgentDeploymentDirectory directory, IAdCredentialSecrets secrets)
{
    private async Task Audit(string actor, long? domain, string action, CancellationToken ct, Guid? plan = null, string result = "ok", JsonObject? binding = null, DateTimeOffset? expires = null)
    {
        await db.Execute("insert into sli_agent_gpo_plan_audit(actor,domain_id,action,plan_id,result,credential_id,credential_revision,recipient_agent_id,recipient_certificate_sha256,expires_at) values(@actor,@domain::bigint,@action,@plan::uuid,@result,@credential::uuid,@revision::bigint,@agent::uuid,@certificate,@expires::timestamptz)", ct,
            ("actor", actor), ("domain", domain), ("action", action), ("plan", plan), ("result", result),
            ("credential", binding is null ? null : Guid.Parse(Text(binding, "credential_id"))), ("revision", binding is null ? null : Long(binding, "credential_revision")),
            ("agent", binding is null ? null : Guid.Parse(binding["recipient"]!["agent_id"]!.GetValue<string>())),
            ("certificate", binding?["recipient"]?["certificate_sha256"]?.GetValue<string>()), ("expires", expires));
    }
    private async Task Reject(string actor, long? domain, string code, CancellationToken ct, int status = 403, Guid? plan = null)
    {
        await Audit(actor, domain, "denied", ct, plan, code);
        throw new AgentDeploymentRejection(code, status);
    }
    private async Task<(JsonObject Scope, long[] Allowed)> Scope(string actor, long domain, string action, CancellationToken ct)
    {
        var row = (await db.Rows("select public.sli_agent_gpo_plan_scope(@actor,@domain,@action) as scope", ct, ("actor", actor), ("domain", domain), ("action", action)))[0];
        if (row["scope"] is not JsonObject scope || scope.Count == 0) { await Reject(actor, domain, "gpo_deployment_denied", ct); throw new InvalidOperationException(); }
        if (scope["revision"] is null || Long(scope, "revision") == 0) await Reject(actor, domain, "gpo_scope_unavailable", ct, 409);
        var ad = await credentials.Scopes(actor, ct);
        if (!ad.TryGetValue(domain, out var adOus) || adOus.Length == 0) await Reject(actor, domain, "ad_operations_denied", ct);
        long[] allowed = Ids(scope["grant_ou_entity_ids"]).Intersect(Ids(scope["ou_entity_ids"])).Intersect(adOus!).Order().ToArray();
        if (allowed.Length == 0) await Reject(actor, domain, "gpo_deployment_denied", ct);
        return (scope, allowed);
    }
    private async Task<JsonNode?> Recipient(long domain, CancellationToken ct)
        => (await db.Rows("select public.sli_gpo_plan_recipient(@domain) as recipient", ct, ("domain", domain)))[0]["recipient"]?.DeepClone();
    private async Task<JsonObject> Bind(string actor, long domain, JsonObject selection, CancellationToken ct)
    {
        var row = await credentials.Record(selection["credential_id"], actor, ct);
        if (Long(row, "domain_id") != domain || !Integer(selection["credential_revision"], out long revision) || revision <= 0 || Long(row, "credential_revision") != revision
            || !Ids(selection["ou_entity_ids"]).All(Ids(row["ou_entity_ids"]).Contains)) throw new AgentControlException("gpo_credential_changed", 409);
        if (Text(row, "check_status") != "not_checked") throw new AgentControlException("gpo_credential_unavailable", 409);
        byte[] key = secrets.ReadKey(); CryptographicOperations.ZeroMemory(key);
        var recipient = await Recipient(domain, ct);
        if (recipient is null) throw new AgentControlException("gpo_recipient_unavailable", 409);
        var scopes = await credentials.Scopes(actor, ct);
        if (!scopes.TryGetValue(domain, out var allowed) || allowed.Length == 0) throw new AgentControlException("ad_operations_denied", 403);
        var authorization = new JsonObject { ["operator_ous"] = Array(allowed.Order()), ["credential_ous"] = Array(Ids(row["ou_entity_ids"]).Order()),
            ["check_status"] = row["check_status"]!.DeepClone(), ["checked_at"] = row["checked_at"] is null ? "None" : AgentControlJson.Stamp(DateTimeOffset.Parse(Text(row, "checked_at"), CultureInfo.InvariantCulture)) };
        return new() { ["credential_id"] = row["credential_id"]!.DeepClone(), ["credential_revision"] = revision,
            ["authorization_sha256"] = Hash(authorization), ["recipient"] = recipient };
    }
    internal async Task<JsonObject> Options(JsonObject body, string actor, CancellationToken ct)
    {
        var (domain, selection) = Selection(body, false);
        try { await Snapshot(actor, domain, selection, "preview", ct); }
        catch (AgentControlException e) { await Reject(actor, domain, e.Message, ct, e.Status); }
        var records = (await credentials.List(actor, ct))["items"]!.AsArray().OfType<JsonObject>().Where(x => Long(x, "domain_id") == domain).ToArray();
        var rows = await db.Rows("select credential_id,credential_revision,ou_entity_ids from sli_ad_operation_credentials where domain_id=@domain", ct, ("domain", domain));
        var scopes = rows.ToDictionary(x => Text(x, "credential_id"));
        var recipient = await Recipient(domain, ct);
        bool ready = AdCredentialSecrets.Status(secrets)["available"]!.GetValue<bool>();
        var last = (await db.Rows("select credential_id,credential_revision from sli_gpo_plan_last_credentials where actor=@actor and domain_id=@domain", ct, ("actor", actor), ("domain", domain))).FirstOrDefault();
        var items = new JsonArray(); string? selected = null;
        foreach (var record in records)
        {
            var item = new JsonObject();
            foreach (string field in new[] { "credential_id", "credential_revision", "label", "username", "check_status" }) item[field] = record[field]?.DeepClone();
            bool eligible = ready && recipient is not null && scopes.TryGetValue(Text(item, "credential_id"), out var saved)
                && Long(saved, "credential_revision") == Long(item, "credential_revision") && Ids(selection["ou_entity_ids"]).All(Ids(saved["ou_entity_ids"]).Contains)
                && Text(item, "check_status") == "not_checked";
            item["eligible"] = eligible;
            if (last is not null && eligible && Text(last, "credential_id") == Text(item, "credential_id") && Long(last, "credential_revision") == Long(item, "credential_revision")) selected = Text(item, "credential_id");
            items.Add(item);
        }
        return new() { ["items"] = items, ["selected_credential_id"] = selected, ["write_enabled"] = false };
    }
    private async Task<(JsonObject Snapshot, JsonArray Names)> Snapshot(string actor, long domain, JsonObject selection, string action, CancellationToken ct)
    {
        var (scope, allowed) = await Scope(actor, domain, action, ct);
        long[] ous = Ids(selection["ou_entity_ids"]); if (ous.Length == 0) ous = allowed;
        if (!ous.All(allowed.Contains)) await Reject(actor, domain, "gpo_deployment_denied", ct);
        var units = new Dictionary<long, (long Version, string[] Dn)>();
        foreach (long ou in ous) { var found = await directory.Resolve(ou, domain, true, ct); units[ou] = (found.Version, found.Dn); }
        if (units.Values.Any(x => x.Dn.Contains("ou=domain controllers"))) await Reject(actor, domain, "gpo_target_excluded", ct, 409);
        var ids = Ids(selection["computer_entity_ids"]).ToList();
        if (ids.Count == 0)
        {
            var rows = await db.Rows("select e.id as entity_id,v.id as version_id,v.attributes_json as record " + AgentDeploymentDirectory.CurrentDirectory + " and v.source_section='directory_accounts' order by e.id", ct, ("domain", domain));
            foreach (var row in rows)
            {
                if (AgentGroupInput.Text(row["record"]?["identity"]?["kind"]) != "ad_computer" || row["record"]?["attributes"]?["enabled"]?.GetValueKind() != System.Text.Json.JsonValueKind.True) continue;
                var dn = AgentGroupDirectory.Record(row["record"], false);
                if (!units.Values.Any(x => AgentGroupDirectory.Within(dn, x.Dn))) continue;
                ids.Add(Long(row, "entity_id"));
                if (ids.Count > 1000) throw new AgentControlException("gpo_target_limit", 409);
            }
        }
        if (ids.Count == 0) throw new AgentControlException("gpo_selection_empty", 409);
        var targets = new JsonArray(); var names = new JsonArray(); var used = new HashSet<long>(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (long id in ids)
        {
            var (version, dn, _) = await directory.Resolve(id, domain, false, ct);
            long[] matches = units.Where(x => AgentGroupDirectory.Within(dn, x.Value.Dn)).Select(x => x.Key).ToArray();
            if (matches.Length == 0) await Reject(actor, domain, "gpo_deployment_denied", ct);
            used.UnionWith(matches);
            var record = (await db.Rows("select attributes_json from ad_context_entity_versions where id=@version", ct, ("version", version)))[0]["attributes_json"]!;
            var attrs = record["attributes"]!; var identity = record["identity"]!;
            if (!Integer(attrs["user_account_control"], out long uac) || (uac & 8192) != 0 || dn.Contains("ou=domain controllers")) await Reject(actor, domain, "gpo_target_excluded", ct, 409);
            string guid = AgentGroupInput.Id(identity["object_guid"]).ToString(); string? sid = AgentGroupInput.Text(identity["object_sid"]);
            if (!AgentControlJson.Matches(sid, @"\AS-1-5-21-\d+-\d+-\d+-\d+\z") || guid == Guid.Empty.ToString() || !seen.Add(guid) || !seen.Add(sid!)) throw new AgentControlException("gpo_identity_unavailable", 409);
            targets.Add(new JsonObject { ["entity_id"] = id, ["version_id"] = version, ["identity_sha256"] = Hash(new JsonArray(JsonValue.Create(guid), JsonValue.Create(sid), new JsonArray(dn.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()))) });
            names.Add(new JsonObject { ["entity_id"] = id, ["name"] = (AgentGroupInput.Text(attrs["display_name"]) is { Length: > 0 } ? attrs["display_name"] : attrs["distinguished_name"])!.DeepClone() });
        }
        selection["ou_entity_ids"] = Array(used.Order());
        return (new JsonObject { ["domain_id"] = domain, ["ou_versions"] = new JsonArray(used.Order().Select(x => (JsonNode)new JsonArray(JsonValue.Create(x), JsonValue.Create(units[x].Version))).ToArray()),
            ["targets"] = targets, ["scope_revision"] = scope["revision"]!.DeepClone(), ["grant_ou_entity_ids"] = Array(Ids(scope["grant_ou_entity_ids"]).Order()),
            ["grant_permissions"] = new JsonArray(scope["grant_permissions"]!.AsArray().Select(x => x!.GetValue<string>()).Order(StringComparer.Ordinal).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
            ["evidence_sha256"] = scope["evidence_sha256"]!.DeepClone(), ["package"] = Package(scope["package"]) }, names);
    }
    private async Task<(JsonObject Snapshot, JsonArray Names)> CheckedSnapshot(string actor, long domain, JsonObject selection, string action, CancellationToken ct, Guid? plan = null)
    {
        try
        {
            var result = await Snapshot(actor, domain, selection, action, ct);
            result.Snapshot["credential_binding"] = await Bind(actor, domain, selection, ct);
            return result;
        }
        catch (AgentControlException e) { await Reject(actor, domain, e.Message, ct, e.Status, plan); throw; }
    }
    internal async Task<JsonObject> Preview(JsonObject body, string actor, CancellationToken ct)
    {
        var (domain, selection) = Selection(body, true);
        var (snapshot, names) = await CheckedSnapshot(actor, domain, selection, "preview", ct);
        selection["computer_entity_ids"] = Array(snapshot["targets"]!.AsArray().Select(x => x!["entity_id"]!.GetValue<long>()));
        Guid plan = Guid.NewGuid(); DateTimeOffset expires = AgentControlJson.Now().AddMinutes(10); string digest = Hash(snapshot);
        await db.Execute("insert into sli_agent_gpo_plans(id,actor,domain_id,selection,snapshot,plan_sha256,expires_at) values(@id,@actor,@domain,@selection::jsonb,@snapshot::jsonb,@digest,@expires)", ct,
            ("id", plan), ("actor", actor), ("domain", domain), ("selection", selection.ToJsonString()), ("snapshot", snapshot.ToJsonString()), ("digest", digest), ("expires", expires));
        await Audit(actor, domain, "preview", ct, plan, binding: snapshot["credential_binding"]!.AsObject(), expires: expires);
        string domainName = Text((await db.Rows("select fqdn from domains where id=@domain", ct, ("domain", domain)))[0], "fqdn");
        var rows = await db.Rows("select e.id as entity_id,v.attributes_json as record from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id where e.id=any(@ous) and e.domain_id=@domain and v.valid_to_utc is null and v.source_section='domain_posture' order by e.id", ct, ("ous", Ids(selection["ou_entity_ids"])), ("domain", domain));
        return new() { ["plan_id"] = plan.ToString(), ["plan_sha256"] = digest, ["domain_id"] = domain, ["domain_name"] = domainName, ["expires_at"] = AgentControlJson.Stamp(expires, true),
            ["targets"] = names, ["ou_entity_ids"] = selection["ou_entity_ids"]!.DeepClone(), ["ous"] = new JsonArray(rows.Select(x => (JsonNode)new JsonObject { ["entity_id"] = x["entity_id"]!.DeepClone(), ["name"] = x["record"]!["attributes"]!["distinguished_name"]!.DeepClone() }).ToArray()),
            ["package"] = snapshot["package"]!.DeepClone(), ["credential_binding"] = snapshot["credential_binding"]!.DeepClone(), ["write_enabled"] = false, ["token_ttl_seconds"] = 604800 };
    }
    internal async Task<JsonObject> Finish(JsonObject body, string actor, bool cancel, CancellationToken ct)
    {
        string[] fields = cancel ? ["plan_id", "plan_sha256"] : ["plan_id", "plan_sha256", "acknowledged", "credential_id", "credential_revision"];
        if (!AgentGroupInput.Shape(body, fields) || !cancel && body["acknowledged"]?.GetValueKind() != System.Text.Json.JsonValueKind.True) throw new AgentControlException("gpo_confirmation_invalid");
        Guid plan = InputId(body["plan_id"]);
        var row = (await db.Rows("select * from sli_agent_gpo_plans where id=@id for update", ct, ("id", plan))).FirstOrDefault();
        if (row is null || Text(row, "actor") != actor) { await Reject(actor, null, "gpo_plan_unavailable", ct, 404); throw new InvalidOperationException(); }
        long domain = Long(row, "domain_id"); await Scope(actor, domain, cancel ? "preview" : "apply", ct);
        if (InputText(body["plan_sha256"]) != Text(row, "plan_sha256")) await Reject(actor, domain, "gpo_plan_mismatch", ct, 409, plan);
        var binding = row["snapshot"]?["credential_binding"] as JsonObject;
        if (!cancel && (binding is null || InputText(body["credential_id"]) != Text(binding, "credential_id") || !Integer(body["credential_revision"], out long revision) || revision != Long(binding, "credential_revision")))
            await Reject(actor, domain, "gpo_credential_changed", ct, 409, plan);
        string desired = cancel ? "cancelled" : "confirmed";
        var result = new JsonObject { ["plan_id"] = plan.ToString(), ["status"] = desired, ["write_enabled"] = false };
        if (cancel && Text(row, "status") == desired) return result;
        DateTimeOffset expires = DateTimeOffset.Parse(Text(row, "expires_at"), CultureInfo.InvariantCulture);
        if (Text(row, "status") != "preview" || expires <= AgentControlJson.Now()) await Reject(actor, domain, "gpo_plan_unavailable", ct, 409, plan);
        if (!cancel)
        {
            var (snapshot, _) = await CheckedSnapshot(actor, domain, row["selection"]!.AsObject(), "apply", ct, plan);
            if (Hash(snapshot) != Text(row, "plan_sha256")) await Reject(actor, domain, "gpo_plan_drift", ct, 409, plan);
        }
        var changed = await db.Rows("update sli_agent_gpo_plans set status=@status,finished_at=clock_timestamp() where id=@id and status='preview' and expires_at>clock_timestamp() returning id", ct, ("status", desired), ("id", plan));
        if (changed.Count == 0) await Reject(actor, domain, "gpo_plan_unavailable", ct, 409, plan);
        if (!cancel) await db.Execute("insert into sli_gpo_plan_last_credentials(actor,domain_id,credential_id,credential_revision) values(@actor,@domain,@credential,@revision) on conflict(actor,domain_id) do update set credential_id=excluded.credential_id,credential_revision=excluded.credential_revision", ct,
            ("actor", actor), ("domain", domain), ("credential", Guid.Parse(Text(binding!, "credential_id"))), ("revision", Long(binding!, "credential_revision")));
        await Audit(actor, domain, desired, ct, plan, binding: binding, expires: expires);
        return result;
    }
    internal static (long Domain, JsonObject Selection) Selection(JsonObject body, bool credential)
    {
        if (!AgentGroupInput.Allowed(body, "domain_id", "ou_entity_ids", "computer_entity_ids", "credential_id", "credential_revision")
            || credential && (!body.ContainsKey("credential_id") || !body.ContainsKey("credential_revision"))
            || !credential && (body.ContainsKey("credential_id") || body.ContainsKey("credential_revision"))) throw new AgentControlException("gpo_selection_invalid");
        long domain = AgentGroupInput.Positive(body["domain_id"]);
        var ous = body.ContainsKey("ou_entity_ids") ? body["ou_entity_ids"] : new JsonArray();
        var computers = body.ContainsKey("computer_entity_ids") ? body["computer_entity_ids"] : new JsonArray();
        if (ous is not JsonArray oa || computers is not JsonArray ca || oa.Count == 0 && ca.Count == 0) throw new AgentControlException("gpo_selection_invalid");
        static long[] Parse(JsonArray values, int maximum) { if (values.Count > maximum) throw new AgentControlException("gpo_selection_invalid"); return values.Select(AgentGroupInput.Positive).Distinct().Order().ToArray(); }
        var selection = new JsonObject { ["ou_entity_ids"] = Array(Parse(oa, 128)), ["computer_entity_ids"] = Array(Parse(ca, 1000)) };
        if (credential) { selection["credential_id"] = InputId(body["credential_id"]).ToString(); selection["credential_revision"] = body["credential_revision"]?.DeepClone(); }
        return (domain, selection);
    }
    internal static JsonObject Package(JsonNode? node)
    {
        if (node is JsonObject { Count: 0 } empty) return (JsonObject)empty.DeepClone();
        if (node is not JsonObject value || !new[] { "version", "sha256", "size_bytes", "signature" }.All(value.ContainsKey)
            || !AgentGroupInput.Allowed(value, "version", "sha256", "size_bytes", "signature", "signer_sha256")
            || !AgentControlJson.Matches(AgentGroupInput.Text(value["version"]), @"\A[A-Za-z0-9_.+-]{1,64}\z")
            || !AgentControlJson.Matches(AgentGroupInput.Text(value["sha256"]), @"\A[0-9a-f]{64}\z")
            || !Integer(value["size_bytes"], out long size) || size <= 0 || AgentGroupInput.Text(value["signature"]) is not ("valid" or "invalid" or "unavailable")
            || value.ContainsKey("signer_sha256") && !AgentControlJson.Matches(AgentGroupInput.Text(value["signer_sha256"]), @"\A[0-9a-f]{64}\z")) throw new AgentControlException("gpo_package_unavailable", 409);
        return (JsonObject)value.DeepClone();
    }
    internal static string Hash(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(value)));
    private static JsonArray Array(IEnumerable<long> values) => new(values.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
}
