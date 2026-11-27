using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;

namespace Sli.Server.Agents.Ingress;

internal sealed record WorkstationJournalScope(long ServerId, long DomainId, string Computer, string Alias, JsonObject Config, bool InstallerScope);

internal static class WorkstationJournalAdmission
{
    internal static readonly int[] PreviousEventIds = [1102, 4624, 4625, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045];
    internal static readonly int[] EventIds = [1102, 4624, 4625, 4688, 4698, 4732, 4733, 5001, 5010, 5012, 6416, 7036, 7040, 7045];
    internal const string InstallerDomain = "workstations.invalid";

    internal static async Task<bool> ExpandedAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("select to_regprocedure('public.workstation_package_approved459(uuid)') is not null", db, tx);
        return await query.ExecuteScalarAsync(ct) is true;
    }

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
        await using var query = new NpgsqlCommand("""
            select s.server_id,s.domain_id,s.computer,s.alias,s.config::text,
                   exists(select 1 from public.domains d where d.id=s.domain_id and d.fqdn=@installer_domain and d.is_archived)
            from public.workstation_journal_scope412(@agent,@source,@revision) s
            """, db, tx);
        query.Parameters.AddWithValue("agent", agent);
        query.Parameters.AddWithValue("source", NpgsqlDbType.Text, (object?)source ?? DBNull.Value);
        query.Parameters.AddWithValue("revision", NpgsqlDbType.Text, (object?)revision ?? DBNull.Value);
        query.Parameters.AddWithValue("installer_domain", InstallerDomain);
        await using var scope = await query.ExecuteReaderAsync(ct);
        return await scope.ReadAsync(ct)
            ? new(scope.GetInt64(0), scope.GetInt64(1), scope.GetString(2), scope.GetString(3), JsonNode.Parse(scope.GetString(4))!.AsObject(), scope.GetBoolean(5))
            : null;
    }

    internal static bool SupportsConfig(JsonObject config, int[]? eventIds = null) =>
        config["allow_event_ids"] is JsonArray requested
        && requested.All(value => value is JsonValue item && item.TryGetValue<int>(out int id) && (eventIds ?? EventIds).Contains(id));

    internal static bool MatchesRows(WorkstationJournalScope scope, JsonArray rows) => rows.All(row =>
        row?["event_id"] is JsonValue kind && kind.TryGetValue<int>(out int id) && EventIds.Contains(id)
        && row["machine_name"] is JsonValue machine && machine.TryGetValue<string>(out var name)
        && (string.Equals(name, scope.Computer, StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, scope.Alias, StringComparison.OrdinalIgnoreCase)
            || scope.InstallerScope && name.IndexOf('.') is > 0 and var separator
                && string.Equals(name[..separator], scope.Alias, StringComparison.OrdinalIgnoreCase))
        && (id is not (4688 or 6416) || BoundedFields(row.AsObject(), id)));

    private static bool BoundedFields(JsonObject row, int id)
    {
        XNamespace ns = EventXml.Namespace;
        var native = EventXml.ParseBounded(row["xml"]!.GetValue<string>());
        return native.Descendants(ns + "EventData").Elements(ns + "Data")
            .Where(field => id == 6416 || field.Attribute("Name")?.Value == "CommandLine")
            .All(field => Encoding.UTF8.GetByteCount(field.Value) <= (id == 6416
                ? WorkstationsModule.DeviceFieldMaxBytes : WorkstationsModule.ProcessCommandLineMaxBytes));
    }
}
