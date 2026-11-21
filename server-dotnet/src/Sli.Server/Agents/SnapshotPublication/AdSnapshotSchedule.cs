using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdSnapshotSchedule
{
    internal const string SettingKey = "server.timezone";
    internal const string UseHost = "host";

    internal static TimeZoneInfo? FindIanaZone(string id)
    {
        if (id == "UTC") return TimeZoneInfo.Utc;
        if (id.Length is 0 or > 100 || id.StartsWith("posix/", StringComparison.Ordinal)
            || id.StartsWith("right/", StringComparison.Ordinal)
            || !TimeZoneInfo.TryFindSystemTimeZoneById(id, out var zone) || !zone.HasIanaId) return null;
        return zone;
    }

    internal static string HostZone
    {
        get
        {
            var local = TimeZoneInfo.Local;
            if (FindIanaZone(local.Id) is not null) return local.Id;
            return TimeZoneInfo.TryConvertWindowsIdToIanaId(local.Id, out var iana) ? iana : "UTC";
        }
    }

    internal static async Task<string> ReadZoneAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var read = new NpgsqlCommand("select value from platform_settings where key=@key", db, tx);
        read.Parameters.AddWithValue("key", SettingKey);
        return await read.ExecuteScalarAsync(ct) is string id && FindIanaZone(id) is not null ? id : HostZone;
    }

    // Authentication already holds this agent's row lock. Retain the previous
    // signed policy so in-flight packets still resolve their capture revision.
    internal static async Task RefreshAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonObject agent, CancellationToken ct)
    {
        var modules = agent["assigned_modules"]!.AsArray();
        var snapshots = modules.OfType<JsonObject>().Where(item => item["enabled"]?.GetValue<bool>() == true
            && item["module_id"]?.GetValue<string>() is SnapshotPolicy.Ad or SnapshotPolicy.Gpo).ToArray();
        if (snapshots.Length == 0) return;

        Guid id = Guid.Parse(agent["id"]!.GetValue<string>());
        string timezone = await ReadZoneAsync(db, tx, ct);
        var managed = new HashSet<string>(StringComparer.Ordinal);
        await using (var read = new NpgsqlCommand("select module_id from sli_agent_snapshot_bindings where agent_id=@id and enabled and follow_server_timezone", db, tx))
        {
            read.Parameters.AddWithValue("id", id);
            await using var rows = await read.ExecuteReaderAsync(ct);
            while (await rows.ReadAsync(ct)) managed.Add(rows.GetString(0));
        }
        var changes = snapshots.Where(item => managed.Contains(item["module_id"]!.GetValue<string>())
            && item["config"]!["schedule"]!["timezone"]!.GetValue<string>() != timezone).ToArray();
        if (changes.Length == 0) return;

        long current = agent["policy_revision"]!.GetValue<long>();
        long revision = AgentModuleAssignmentRules.NextRevision(current, current);
        var control = AgentControlJson.Element(agent["collection_policy"]!);
        await AgentManagementService.LockImportAsync(db, tx, id, ct);
        await AgentPolicyStore.SnapshotAsync(db, tx, id, current, AgentControlJson.Element(modules), control, ct);
        foreach (var item in changes)
        {
            string module = item["module_id"]!.GetValue<string>();
            var config = item["config"]!.AsObject();
            config["schedule"]!["timezone"] = timezone;
            config["policy_revision"] = revision.ToString(CultureInfo.InvariantCulture);
            await AgentSnapshotAssignment.ValidateAsync(db, tx, id, module, config, true, ct);
            await AgentSnapshotAssignment.PublishAsync(db, tx, id, module, config, true, ct, followServerTimezone:true);
        }
        await AgentPolicyStore.SnapshotAsync(db, tx, id, revision, AgentControlJson.Element(modules), control, ct);
        await using var write = new NpgsqlCommand("update sli_agents set assigned_modules=@modules::jsonb,policy_revision=@revision where id=@id", db, tx);
        write.Parameters.AddWithValue("id", id);
        write.Parameters.AddWithValue("modules", modules.ToJsonString());
        write.Parameters.AddWithValue("revision", revision);
        await write.ExecuteNonQueryAsync(ct);
        agent["policy_revision"] = revision;
    }
}
