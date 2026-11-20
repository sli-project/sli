using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access.Administration;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
namespace Sli.Server.Reporting.V2;

public interface IReportV2Metadata
{
    Task<string?> PreferredDomainAsync(CancellationToken ct);
    Task<JsonObject?> PluginAsync(string reportKey, CancellationToken ct);
}
public sealed class ReportV2Metadata(IPostgresConnectionFactory connections) : IReportV2Metadata
{
    public async Task<string?> PreferredDomainAsync(CancellationToken ct)
    {
        string? value;
        try
        {
            await using var connection = await connections.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select value from platform_settings where key='reports.domain_fqdn'", connection) { CommandTimeout = 0 };
            value = await command.ExecuteScalarAsync(ct) as string;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; } // Source setting has no environment fallback.
        if (value is null) return null;
        value = AssignmentValidation.Strip(value).ToLowerInvariant();
        if (value.Length > 253 || !Regex.IsMatch(value, @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z")) throw new ReportRequestException("value_must_be_dns_name");
        return value;
    }
    public async Task<JsonObject?> PluginAsync(string reportKey, CancellationToken ct)
    {
        if (reportKey is not ("vpn.accounts" or "vpn.connections")) return null;
        string state = "unknown"; bool readOnly = true;
        try
        {
            await using var connection = await connections.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select installed,enabled from public.read_plugin_states_v1() where plugin_id='sli.remote-access'", connection) { CommandTimeout = 0 };
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                state = !reader.GetBoolean(0) ? "not_installed" : reader.GetBoolean(1) ? "enabled" : "disabled";
                readOnly = state != "enabled";
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { } // Observing collection state must not hide retained rows.
        return new() { ["plugin_id"] = "sli.remote-access", ["state"] = state, ["read_only"] = readOnly };
    }
    public static DomainItem? ChooseDomain(IEnumerable<DomainItem> domains, string? preferred, DateTimeOffset? now = null)
    {
        var eligible = domains.Where(d => !d.IsArchived).ToArray();
        var configured = eligible.FirstOrDefault(d => preferred is not null && string.Equals(d.DisplayName, preferred, StringComparison.OrdinalIgnoreCase));
        if (configured is not null) return configured;
        return eligible.Select(d => (Domain: d, Raw: d.Freshness.DefaultObservedAtUtc))
            .Where(d => d.Raw is not null && Regex.IsMatch(d.Raw, @"(?:Z|[+-]\d{2}:?\d{2})$") && DateTimeOffset.TryParse(d.Raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp) && stamp <= (now ?? DateTimeOffset.UtcNow))
            .OrderByDescending(d => DateTimeOffset.Parse(d.Raw!, CultureInfo.InvariantCulture)).ThenBy(d => d.Domain.Id).Select(d => d.Domain).FirstOrDefault();
    }
    internal static void Annotate(JsonObject payload, JsonObject? plugin)
    {
        if (plugin is null) return;
        payload["plugin"] = plugin.DeepClone();
        if (plugin.Text("state") == "disabled" && payload.Text("state") == "empty" && payload["items"] is not JsonArray { Count: > 0 })
        {
            payload["state"] = "unavailable"; payload["reason"] = "not_collected";
            if (payload["coverage"] is JsonObject coverage && coverage.Text("state") == "empty") { coverage["state"] = "unavailable"; coverage["reason"] = "not_collected"; }
        }
    }
}
