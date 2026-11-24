using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Agents.Ingress;

internal sealed record WorkstationJournalScope(long ServerId, long DomainId, string Computer, string Alias, JsonObject Config);

internal static class WorkstationJournalAdmission
{
    internal static readonly int[] EventIds = [1102, 4624, 4625, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045];

    internal static async Task<bool> AvailableAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select to_regprocedure('public.workstation_journal_scope412(uuid,text,text)') is not null", db, tx);
        return await query.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task<bool> PluginEnabledAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select public.workstation_runtime_enabled_v376()", db, tx);
        return await query.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task<bool> SetAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, bool enabled, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select public.set_workstation_journal_grant412(@agent,@enabled)", db, tx);
        query.Parameters.AddWithValue("agent", agent);
        query.Parameters.AddWithValue("enabled", enabled);
        return await query.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task<WorkstationJournalScope?> ReadAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent,
        string? source, string? revision, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select server_id,domain_id,computer,alias,config::text from public.workstation_journal_scope412(@agent,@source,@revision)", db, tx);
        query.Parameters.AddWithValue("agent", agent);
        query.Parameters.AddWithValue("source", NpgsqlDbType.Text, (object?)source ?? DBNull.Value);
        query.Parameters.AddWithValue("revision", NpgsqlDbType.Text, (object?)revision ?? DBNull.Value);
        await using var scope = await query.ExecuteReaderAsync(ct);
        return await scope.ReadAsync(ct)
            ? new(scope.GetInt64(0), scope.GetInt64(1), scope.GetString(2), scope.GetString(3), JsonNode.Parse(scope.GetString(4))!.AsObject())
            : null;
    }

    internal static void RestrictConfig(JsonObject config)
    {
        var requested = config["allow_event_ids"] as JsonArray;
        config["allow_event_ids"] = new JsonArray(EventIds.Where(id => requested is null || requested.Any(value => value!.GetValue<int>() == id))
            .Select(id => (JsonNode?)JsonValue.Create(id)).ToArray());
        config["families"]!["processes"] = false;
        config["families"]!["usb"] = false;
    }

    internal static bool MatchesRows(WorkstationJournalScope scope, JsonArray rows) => rows.All(row =>
        row?["event_id"] is JsonValue kind && kind.TryGetValue<int>(out int id) && EventIds.Contains(id)
        && row["machine_name"] is JsonValue machine && machine.TryGetValue<string>(out var name)
        && (string.Equals(name, scope.Computer, StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, scope.Alias, StringComparison.OrdinalIgnoreCase)));
}
