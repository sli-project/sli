using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Agents.Control;

public static class AgentPolicyStore
{
    public static JsonElement NormalizeCollectionPolicy(JsonElement value)
    {
        var defaults = JsonNode.Parse("""
            {"state":"active","interval_seconds":60,"batch_size":32,"rate_limit_per_minute":120,"spool_max_bytes":67108864,"manage_windows_audit":false,"audit_process_command_line":false}
            """)!.AsObject();
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Any(p => !defaults.ContainsKey(p.Name) && p.Name != "manage_domain_root_sacl")
            || value.TryGetProperty("manage_domain_root_sacl", out var root) && root.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new AgentControlException("invalid_agent_collection_policy");
        foreach (var property in value.EnumerateObject()) defaults[property.Name] = JsonNode.Parse(property.Value.GetRawText());
        var control = AgentControlJson.Element(defaults);
        if (AgentControlJson.String(control.GetProperty("state")) is not ("active" or "paused" or "drain")
            || new[] { "manage_windows_audit", "audit_process_command_line" }.Any(k => control.GetProperty(k).ValueKind is not (JsonValueKind.True or JsonValueKind.False))) throw new AgentControlException("invalid_agent_collection_policy");
        foreach ((string key, long min, long max) in new[] { ("interval_seconds", 1L, 86400L), ("batch_size", 1L, 128L), ("rate_limit_per_minute", 1L, 10000L), ("spool_max_bytes", 65536L, 1073741824L) })
        {
            var n = control.GetProperty(key);
            if (n.ValueKind != JsonValueKind.Number || !n.TryGetInt64(out long integer) || integer < min || integer > max) throw new AgentControlException("invalid_agent_collection_policy");
        }
        return control;
    }

    // Caller owns the connection/transaction and publication. Enrollment remains
    // the sole default/template producer and may reuse this source history store.
    public static async Task SnapshotAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, long revision, JsonElement modules, JsonElement control, CancellationToken ct)
    {
        var normalized = NormalizeCollectionPolicy(control);
        await using var query = new NpgsqlCommand("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(@agent,@revision,@modules::jsonb,@control::jsonb) on conflict(agent_id,revision) do nothing", db, tx);
        query.Parameters.AddWithValue("agent", agent); query.Parameters.AddWithValue("revision", revision);
        query.Parameters.AddWithValue("modules", modules.GetRawText()); query.Parameters.AddWithValue("control", normalized.GetRawText()); await query.ExecuteNonQueryAsync(ct);
    }
}
