using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Workspace;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService(IInstallationDatabase database, InstallationPackages packages, IConfiguration? configuration = null)
{
    static string Text(JsonNode? n) => InstallationPackages.Text(n);
    static string Field(JsonObject body, string name) => AuthJsonBody.CredentialString(JsonSerializer.SerializeToElement(body), name);
    static JsonObject? First(JsonArray rows) => rows.FirstOrDefault() as JsonObject;
    static JsonArray Copy(JsonArray rows) => rows.DeepClone().AsArray();
    static bool Bool(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    static long Number(JsonNode? n) => n is JsonValue v && v.TryGetValue<long>(out long l) ? l
        : n is JsonValue i && i.TryGetValue<int>(out int number) ? number : 0;
    static JsonObject Item(JsonObject value) => new() { ["item"] = value };
    public async Task<JsonNode> DispatchAsync(string method, string path, JsonObject body, Principal actor, string? address, bool canManage, CancellationToken ct,
        AccessFacts? facts = null)
    {
        bool get = method == "GET";
        if (path == "/api/v1/setup/status" && get) return await SetupStatusAsync(ct);
        if (path == "/api/v1/setup/domains" && get) return new JsonObject { ["items"] = await DomainsAsync(ct) };
        if (path.StartsWith("/api/v1/setup/domains", StringComparison.Ordinal) && !get)
            return Item(await DomainWriteAsync(path, body, actor, address, ct));
        if (path == "/api/v1/setup/domain-controllers" && get) return await ControllersAsync(ct);
        if (path.StartsWith("/api/v1/setup/domain-controllers", StringComparison.Ordinal) && !get)
            return Item(await ControllerWriteAsync(path, body, actor, address, ct));
        if (path == "/api/v1/platform-settings" && get) return new JsonObject { ["items"] = await SettingsAsync(ct) };
        if (path.StartsWith("/api/v1/platform-settings/", StringComparison.Ordinal) && !get)
        {
            string key = Uri.UnescapeDataString(path["/api/v1/platform-settings/".Length..]).Trim('/');
            await SettingWriteAsync(key, Field(body, "value"), actor, address, null, ct);
            return Item((await SettingsAsync(ct)).OfType<JsonObject>().Single(s => Text(s["key"]) == key).DeepClone().AsObject());
        }
        if (path.StartsWith("/api/plugins/", StringComparison.Ordinal) && path.EndsWith("/settings", StringComparison.Ordinal))
        {
            string id = path.Substring("/api/plugins/".Length, Math.Max(0, path.Length - "/api/plugins/".Length - "/settings".Length));
            var metadata = packages.Settings(id);
            if (get) return await PluginSettingsAsync(id, metadata, ct);
            try
            {
                if (!InstallationPackages.Keys(body, "key", "value")) throw new InstallationException("invalid_plugin_setting_value");
                string key = Text(body["key"]);
                var schema = metadata["settings"]!.AsObject();
                if (schema["properties"]?[key] is not JsonObject node) throw new InstallationException("invalid_plugin_setting_value");
                InstallationPackages.Shape(new JsonObject { [key] = body["value"]?.DeepClone() }, schema);
                string encoded = body["value"] is JsonValue value && value.TryGetValue<string>(out var s) ? s : body["value"]?.ToJsonString() ?? "null";
                var result = await SettingWriteAsync(key, encoded, actor, address, id, ct);
                return new JsonObject { ["plugin_id"] = id, ["key"] = key, ["value"] = Typed(Text(result["value"]), node) };
            }
            catch (InstallationException e) when (e.Status == 400) { throw new InstallationException("invalid_plugin_setting_value"); }
        }
        if (path == "/api/v1/plugins" && get)
            return new JsonObject { ["items"] = await PluginStatesAsync(NavigationRegistry.PreviewEnabled(configuration), facts, ct),
                ["can_manage"] = canManage, ["mutation_api_enabled"] = true };
        if (path.StartsWith("/api/v1/plugins/", StringComparison.Ordinal) && !get)
            return Item(await ToggleAsync(Uri.UnescapeDataString(path["/api/v1/plugins/".Length..]), body, actor, ct));
        if (path == "/api/v1/operations/plugins" && get) return await PluginCatalogAsync(ct);
        if (path.StartsWith("/api/v1/operations/plugins/", StringComparison.Ordinal) && get)
        {
            string id = PythonText.Strip(Uri.UnescapeDataString(path["/api/v1/operations/plugins/".Length..]));
            if (id.Length is 0 or > 128) throw new InstallationException("invalid_plugin_id");
            var catalog = await PluginCatalogAsync(ct);
            var item = catalog["items"]!.AsArray().OfType<JsonObject>().FirstOrDefault(i => Text(i["plugin_id"]) == id)
                ?? throw new InstallationException("plugin_not_found", 404);
            return new JsonObject { ["contract_id"] = catalog["contract_id"]!.DeepClone(), ["status"] = catalog["status"]!.DeepClone(),
                ["read_only"] = true, ["mutation_api_enabled"] = true, ["item"] = item.DeepClone() };
        }
        throw new InstallationException("not_found", 404);
    }

    public Task<JsonArray> DomainsAsync(CancellationToken ct) => database.ReadAsync(s => s.QueryAsync("""
        select d.fqdn,d.netbios_name,d.is_archived,f.name as forest,
               (select max(observed_at_utc)::text from ad_context_runs where domain_id=d.id) as observed_at_utc,
               (select count(*) from servers where domain_id=d.id) as server_count
        from domains d join forests f on f.id=d.forest_id order by d.fqdn
        """, ct), ct);

    async Task<JsonObject> DomainWriteAsync(string path, JsonObject body, Principal actor, string? address, CancellationToken ct)
    {
        bool add = path == "/api/v1/setup/domains";
        string fqdn = InstallationSettings.Dns(add ? Field(body, "fqdn") : Uri.UnescapeDataString(path["/api/v1/setup/domains/".Length..]).Trim('/'));
        bool archive = !add && body.ContainsKey("is_archived");
        if (archive && !InstallationPackages.Keys(body, "is_archived")) throw new InstallationException("domain_archive_update_fields_invalid");
        if (archive && (body["is_archived"] is not JsonValue b || !b.TryGetValue<bool>(out _))) throw new InstallationException("domain_archive_must_be_boolean");
        string? netbios = archive ? null : InstallationSettings.Netbios(Field(body, "netbios_name"));
        string forest = add && PythonText.Strip(Field(body, "forest")).Length > 0 ? InstallationSettings.Dns(Field(body, "forest")) : fqdn;
        return await database.WriteAsync(async s =>
        {
            await s.QueryAsync("select pg_advisory_xact_lock(hashtext('ad_log_setup_domains'))", ct);
            var current = First(await s.QueryAsync(archive
                ? "select is_archived from domains where lower(fqdn)=@p0 for update"
                : "select netbios_name,is_archived from domains where lower(fqdn)=@p0 for update", ct, fqdn));
            if (add && current is not null) throw new InstallationException("domain_already_exists", 409);
            if (!add && current is null) throw new InstallationException("domain_not_found", 404);
            if (netbios is not null && First(await s.QueryAsync("select 1 as found from domains where upper(netbios_name)=@p0 and lower(fqdn)<>@p1", ct, netbios, fqdn)) is not null)
                throw new InstallationException("netbios_already_exists", 409);
            JsonObject result;
            if (add)
            {
                long forestId = Number(First(await s.QueryAsync("insert into forests(name) values(@p0) on conflict(name) do update set name=excluded.name returning id", ct, forest))?["id"]);
                if (forestId == 0) throw new InvalidOperationException("forest_insert_failed");
                await s.QueryAsync("insert into domains(forest_id,fqdn,netbios_name) values(@p0,@p1,@p2)", ct, forestId, fqdn, netbios);
                result = new() { ["fqdn"] = fqdn, ["netbios_name"] = netbios, ["forest"] = forest, ["server_count"] = 0 };
            }
            else if (archive)
            {
                await s.QueryAsync("update domains set is_archived=@p0 where lower(fqdn)=@p1", ct, Bool(body["is_archived"]), fqdn);
                result = new() { ["fqdn"] = fqdn, ["is_archived"] = Bool(body["is_archived"]), ["previous_is_archived"] = current!["is_archived"]?.DeepClone() };
            }
            else
            {
                await s.QueryAsync("update domains set netbios_name=@p0 where lower(fqdn)=@p1", ct, netbios, fqdn);
                result = new() { ["fqdn"] = fqdn, ["netbios_name"] = netbios, ["previous_netbios_name"] = current!["netbios_name"]?.DeepClone() };
            }
            var details = result.DeepClone().AsObject(); details.Remove("fqdn");
            if (add) details["previous_netbios_name"] = null;
            await AuditAsync(s, actor, add ? "setup_domain_add" : "setup_domain_update", "ad_domain", fqdn, details, address, ct);
            return result;
        }, ct);
    }
    public async Task<JsonObject> ControllersAsync(CancellationToken ct)
    {
        using var admission = Admission("sli.ad");
        JsonArray rows;
        try { rows = await database.ReadAsync(s => s.QueryAsync("""
            select t.hostname,t.connect_address,d.fqdn as domain,t.enabled,'db'::text as source,
                   (t.owner_confirmed_ip is not null) as dns_readback
            from domain_controller_targets t left join domains d on d.id=t.domain_id order by lower(t.hostname)
            """, ct), ct); }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException) { rows = new(); }
        if (rows.Count > 0) return new() { ["source"] = "db", ["items"] = rows };
        var file = FileTargets();
        return new() { ["source"] = file.Count > 0 ? "file" : "none", ["items"] = new JsonArray(file.Select(t => (JsonNode)new JsonObject {
            ["hostname"] = t!["hostname"]!.DeepClone(), ["connect_address"] = t["connect_address"]!.DeepClone(), ["domain"] = null,
            ["enabled"] = true, ["source"] = "file", ["dns_readback"] = Text(t["owner_confirmed_ip"]).Length > 0 }).ToArray()) };
    }
    IDisposable Admission(string id) => InstallationAdmission.Enter(id, packages);
    static string Hostname(string value) => PythonText.Strip(value).Trim('.').TrimStart('\\').Split('.')[0];
    static string ConnectAddress(string value)
    {
        string clean = PythonText.Strip(value).TrimStart('\\').TrimEnd('.');
        if (IpLiteral(clean) || !InstallationPackages.Match(clean, "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"))
            throw new InstallationException("connect_address_must_be_fqdn");
        return clean;
    }
    static bool IpLiteral(string value)
    {
        if (value.Contains(':')) return IPAddress.TryParse(value, out _);
        string[] octets = value.Split('.');
        return octets.Length == 4 && octets.All(p => InstallationPackages.Match(p, "0|[1-9][0-9]{0,2}") && int.Parse(p) <= 255);
    }
    JsonArray FileTargets()
    {
        string path = Path.Combine(packages.ConfigRoot, "domain_controllers.json");
        JsonObject file;
        try { file = JsonNode.Parse(File.ReadAllText(path))!.AsObject(); }
        catch (Exception e) when (e is IOException or JsonException) { return new(); }
        var rows = new JsonArray();
        foreach (var item in file["domain_controllers"] as JsonArray ?? new())
        {
            string raw = item is JsonValue ? Text(item) : Text(item?["hostname"] ?? item?["name"]);
            string hostname = Hostname(raw);
            if (hostname.Length == 0 || rows.Any(r => Text(r?["hostname"]).Equals(hostname, StringComparison.OrdinalIgnoreCase))) continue;
            string address = item is JsonValue ? hostname : Text(item?["connect_address"] ?? item?["address"] ?? item?["ip"] ?? JsonValue.Create(hostname));
            string ip = item is JsonValue ? "" : PythonText.Strip(Text(item?["owner_confirmed_ip"]));
            if (ip.Length > 0 && !IpLiteral(ip)) throw new InstallationException("domain_controllers_file_invalid");
            if (ip.Length > 0) ip = IPAddress.Parse(ip).ToString();
            rows.Add(new JsonObject { ["hostname"] = hostname, ["connect_address"] = ConnectAddress(address), ["owner_confirmed_ip"] = ip.Length > 0 ? ip : null });
        }
        return rows;
    }
    async Task<JsonObject> ControllerWriteAsync(string path, JsonObject body, Principal actor, string? remote, CancellationToken ct)
    {
        using var admission = Admission("sli.ad");
        bool add = path == "/api/v1/setup/domain-controllers";
        string actorName = ActorName(actor, true);
        if (!add && (body["enabled"] is not JsonValue b || !b.TryGetValue<bool>(out _))) throw new InstallationException("enabled_must_be_boolean");
        string address = add ? InstallationSettings.Dns(ConnectAddress(Field(body, "hostname"))) : "";
        string host = Hostname(add ? address : Uri.UnescapeDataString(path["/api/v1/setup/domain-controllers/".Length..]).Trim('/'));
        if (host.Length == 0) throw new InstallationException("hostname_required");
        string domain = add ? InstallationSettings.Dns(Field(body, "domain")) : "";
        var fileTargets = add ? FileTargets() : new JsonArray();
        return await database.WriteAsync(async s =>
        {
            await s.QueryAsync("select pg_advisory_xact_lock(hashtext('ad_log_setup_domain_controllers'))", ct);
            JsonObject result;
            int imported = 0;
            if (add)
            {
                var domainRow = First(await s.QueryAsync("select id from domains where lower(fqdn)=@p0", ct, domain)) ?? throw new InstallationException("domain_not_found", 404);
                var taken = (await s.QueryAsync("select lower(hostname) as key from domain_controller_targets", ct)).Select(r => Text(r?["key"])).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (taken.Count == 0 && fileTargets.Count > 0)
                {
                    var domains = await s.QueryAsync("select id,lower(fqdn) as fqdn from domains", ct);
                    foreach (var target in fileTargets.OfType<JsonObject>())
                    {
                        string targetHost = Text(target["hostname"]), targetAddress = Text(target["connect_address"]);
                        var matched = domains.OfType<JsonObject>().Where(d => targetAddress.EndsWith("." + Text(d["fqdn"]), StringComparison.OrdinalIgnoreCase)).OrderByDescending(d => Text(d["fqdn"]).Length).FirstOrDefault();
                        await s.QueryAsync("""
                            insert into domain_controller_targets(hostname,connect_address,domain_id,owner_confirmed_ip,enabled,source,created_by,updated_by)
                            values(@p0,@p1,nullif(@p2,0),@p3::inet,true,'file_import',@p4,@p4)
                            """, ct, targetHost, targetAddress, Number(matched?["id"]), Text(target["owner_confirmed_ip"]) is { Length: > 0 } ip ? ip : null, actorName);
                        taken.Add(targetHost); imported++;
                    }
                }
                if (taken.Contains(host)) throw new InstallationException("domain_controller_already_exists", 409);
                await s.QueryAsync("""
                    insert into domain_controller_targets(hostname,connect_address,domain_id,enabled,source,created_by,updated_by)
                    values(@p0,@p1,@p2,true,'interface',@p3,@p3)
                    """, ct, host, address, Number(domainRow["id"]), actorName);
                result = new() { ["hostname"] = host, ["connect_address"] = address, ["domain"] = domain, ["enabled"] = true, ["source"] = "db", ["dns_readback"] = false };
            }
            else
            {
                var current = First(await s.QueryAsync("select hostname,enabled from domain_controller_targets where lower(hostname)=@p0", ct, host.ToLowerInvariant()))
                    ?? throw new InstallationException("domain_controller_not_found", 404);
                await s.QueryAsync("update domain_controller_targets set enabled=@p0,updated_by=@p1,updated_at=now() where lower(hostname)=@p2", ct, Bool(body["enabled"]), actorName, host.ToLowerInvariant());
                result = new() { ["hostname"] = current["hostname"]!.DeepClone(), ["enabled"] = Bool(body["enabled"]), ["previous_enabled"] = Bool(current["enabled"]) };
            }
            var details = result.DeepClone().AsObject(); details.Remove("hostname"); if (add) details["imported_from_file"] = imported;
            await AuditAsync(s, actor, add ? "setup_dc_add" : "setup_dc_update", "domain_controller", Text(result["hostname"]), details, remote, ct);
            return result;
        }, ct);
    }
    static string ActorName(Principal actor, bool fallback = false)
    {
        string name = PythonText.Strip(actor.Username ?? (fallback ? actor.Type + ":" + actor.Id : ""));
        name = string.Concat(name.EnumerateRunes().Take(256).Select(r => r.ToString()));
        if (name.Length == 0) throw new InstallationException("actor_required");
        return name;
    }
    static Task<JsonArray> AuditAsync(IInstallationSession s, Principal actor, string action, string target, string key, JsonObject details, string? remote, CancellationToken ct) => s.QueryAsync("""
        insert into access_audit_v4(actor_type,actor_id,action,target_type,target_key,outcome,details_json,remote_address)
        values(@p0,@p1,@p2,@p3,@p4,'ok',@p5::jsonb,@p6) returning id,created_at
        """, ct, actor.Type, actor.Id, action, target, key, InstallationSettings.Json(details), remote);
}
