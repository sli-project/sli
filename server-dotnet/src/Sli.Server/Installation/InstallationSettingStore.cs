using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Auth;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService
{
    public async Task<string> GetSettingAsync(string key, CancellationToken ct)
    {
        var setting = await ResolveAsync(key, ct);
        if (Text(setting["source"]) == "not_configured")
            throw new InstallationException(key == "reports.domain_fqdn" ? "report_domain_not_configured" : "setting_not_configured", 503);
        return Text(setting["value"]);
    }

    public async Task<string> ReportDomainAsync(CancellationToken ct)
    {
        string? configured;
        try { configured = await GetSettingAsync("reports.domain_fqdn", ct); }
        catch (InstallationException e) when (e.Message == "report_domain_not_configured") { configured = null; }
        try { return await EffectiveDomainAsync(configured ?? "", ct) ?? throw new InstallationException("report_domain_not_configured", 503); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is not InstallationException || e.Message != "report_domain_not_configured")
        { throw new InstallationException("report_domain_not_configured", 503); }
    }

    async Task<JsonObject> ResolveAsync(string key, CancellationToken ct)
    {
        var spec = InstallationSettings.Specs[key];
        JsonObject? row;
        try { row = await database.ReadAsync(async s => First(await s.QueryAsync("select value,updated_by,updated_at::text from platform_settings where key=@p0", ct, key)), ct); }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException) { row = null; }
        string environment = Text(spec["environment"]);
        string? raw = row is not null ? Text(row["value"]) : environment.Length > 0 ? Environment.GetEnvironmentVariable(environment)?.Trim() : null;
        string source = row is not null ? "database" : !string.IsNullOrEmpty(raw) ? "environment" : spec.ContainsKey("default") ? "default" : "not_configured";
        if (source == "default") raw = Text(spec["default"]);
        string value = source == "not_configured" ? "" : InstallationSettings.Normalize(key, raw ?? "");
        return new() { ["key"] = key, ["label"] = spec["label"]?.DeepClone(), ["description"] = spec["description"]?.DeepClone(),
            ["value"] = value, ["source"] = source, ["environment"] = environment,
            ["updated_by"] = row?["updated_by"]?.DeepClone(), ["updated_at"] = row?["updated_at"]?.DeepClone(), ["stored_value"] = row?["value"]?.DeepClone() };
    }
    public async Task<JsonArray> SettingsAsync(CancellationToken ct)
    {
        var items = new JsonArray();
        foreach (string key in InstallationSettings.Specs.Keys)
        {
            var item = await ResolveAsync(key, ct); item.Remove("stored_value"); items.Add(item);
        }
        var report = items.OfType<JsonObject>().Single(i => Text(i["key"]) == "reports.domain_fqdn");
        try
        {
            string? effective = await EffectiveDomainAsync(Text(report["value"]), ct);
            report["effective_value"] = effective;
            report["effective_state"] = effective is null ? "unknown" : "available";
        }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException)
        { report["effective_value"] = null; report["effective_state"] = "unavailable"; }
        return items;
    }
    async Task<string?> EffectiveDomainAsync(string configured, CancellationToken ct) => await database.ReadAsync(async s =>
    {
        if (configured.Length > 0)
        {
            var current = First(await s.QueryAsync("select is_archived from domains where lower(fqdn)=@p0", ct, configured));
            if (current is not null && !Bool(current["is_archived"])) return configured;
        }
        var chosen = First(await s.QueryAsync("""
            select d.fqdn from domains d join lateral (
                select max(observed_at_utc) as observed_at_utc from ad_context_runs where domain_id=d.id and status='completed'
            ) observed on true where not d.is_archived and observed.observed_at_utc<=now()
            order by observed.observed_at_utc desc,d.id limit 1
            """, ct));
        return chosen is null ? null : InstallationSettings.Dns(Text(chosen["fqdn"]));
    }, ct);

    async Task<JsonObject> PluginSettingsAsync(string id, JsonObject metadata, CancellationToken ct)
    {
        var values = new JsonObject(); var sources = new JsonObject();
        foreach (var entry in metadata["settings"]!["properties"]!.AsObject())
        {
            var resolved = await ResolveAsync(entry.Key, ct);
            values[entry.Key] = Typed(Text(resolved["stored_value"] ?? resolved["value"]), entry.Value!.AsObject());
            sources[entry.Key] = resolved["source"]!.DeepClone();
        }
        return new() { ["plugin_id"] = id, ["schema"] = metadata["settings"]!.DeepClone(), ["values"] = values, ["sources"] = sources, ["rules"] = metadata["rules"]!.DeepClone() };
    }
    static JsonNode? Typed(string value, JsonObject node)
    {
        if (value.Length == 0) return null;
        bool text = node["type"] is JsonArray types ? types.Any(t => Text(t) == "string") : Text(node["type"]) == "string";
        return text ? JsonValue.Create(value) : JsonNode.Parse(value);
    }
    async Task<JsonObject> SettingWriteAsync(string key, string raw, Principal actor, string? address, string? pluginId, CancellationToken ct)
    {
        string normalized = InstallationSettings.Normalize(key, raw);
        string actorName = ActorName(actor);
        string? previous = Text((await ResolveAsync(key, ct))["value"]);
        if (previous.Length == 0) previous = null;
        return await database.WriteAsync(async s =>
        {
            if (key is "workstations.logon_policy" or "ad.service_account_exceptions")
            {
                await s.QueryAsync("select pg_advisory_xact_lock(hashtext(@p0))", ct, key);
                var stored = First(await s.QueryAsync("select value from platform_settings where key=@p0 for update", ct, key));
                previous = stored is null ? null : Text(stored["value"]);
                if (key == "workstations.logon_policy") InstallationSettings.CheckPolicyVersion(normalized, previous);
                else { previous ??= "[]"; normalized = InstallationSettings.AttributeExceptions(normalized, previous, actorName); }
            }
            if (key == "reports.domain_fqdn" && First(await s.QueryAsync("select id from domains where lower(fqdn)=@p0", ct, normalized)) is null)
                throw new InstallationException("report_domain_not_registered");
            await s.QueryAsync("""
                insert into platform_settings(key,value,updated_by,updated_at) values(@p0,@p1,@p2,now())
                on conflict(key) do update set value=excluded.value,updated_by=excluded.updated_by,updated_at=now()
                """, ct, key, normalized, actorName);
            var details = pluginId is null ? new JsonObject { ["previous"] = previous, ["value"] = normalized }
                : new JsonObject { ["plugin_id"] = pluginId, ["key"] = key };
            await AuditAsync(s, actor, "platform_setting_update", "platform_setting", key, details, address, ct);
            return new JsonObject { ["key"] = key, ["previous"] = previous, ["value"] = normalized };
        }, ct);
    }
}
