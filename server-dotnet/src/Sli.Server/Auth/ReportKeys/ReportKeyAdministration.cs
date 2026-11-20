using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Sli.Server.Auth.ReportKeys;

public sealed record IssueReportKeyCommand(string Label, long DomainId, int Hours, string[] FileAgentIds, string[] WorkstationAgentIds, bool WorkstationsOnly);
public sealed record ReportKeyIssueResult(long Id, DateTimeOffset ExpiresAt, long DomainId, string Token);
public sealed class ReportKeyException(string code) : Exception(code);
public static class ReportKeyTime
{
    public static string Format(DateTimeOffset value) => value.ToString(value.Ticks % TimeSpan.TicksPerSecond == 0
        ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", System.Globalization.CultureInfo.InvariantCulture);
}
public interface IReportKeyAdministration { Task<ReportKeyIssueResult> IssueAsync(IssueReportKeyCommand command, CancellationToken ct); }

public static class ReportKeyServices
{
    public static IServiceCollection AddReportKeyServices(this IServiceCollection services)
    {
        services.TryAddScoped<IReportKeyAdministration, ReportKeyAdministration>();
        services.TryAddScoped<IExactEventAuthorization, ExactEventAuthorization>();
        return services;
    }
}

public sealed class ReportKeyAdministration(IPostgresConnectionFactory connections, IUserAdministration users,
    IApiKeyAdministration keys, IReportAssignmentWriter assignments) : IReportKeyAdministration
{
    private const string Reason = "Expiring read-only report verification";
    private static readonly string[] Core = ["events.explorer", "ad.state", "ad.gpo.v2", "security.queue", "security.events.chains", "ad.users.v2", "ad.computers.v6", "vpn.audit"];
    private static readonly string[] File = ["file-audit.overview", "file-audit.actions", "file-audit.mass-operations", "file-audit.permission-changes", "file-audit.access-denials", "file-audit.out-of-hours", "file-audit.permissions", "file-audit.audit-state"];
    private static readonly string[] Workstations = ["workstations.logons", "workstations.processes", "workstations.usb", "workstations.protection"];
    private static readonly UserAdministrationActor Actor = new("local_operator", null, null!);

    public async Task<ReportKeyIssueResult> IssueAsync(IssueReportKeyCommand command, CancellationToken ct)
    {
        if (command.DomainId < 1 || command.Hours is < 1 or > 168 || command.WorkstationsOnly && (command.WorkstationAgentIds.Length == 0 || command.FileAgentIds.Length != 0))
            throw new ReportKeyException("report_key_parameters_invalid");
        string label = UserAdministrationService.Strip(command.Label);
        if (label.Length == 0 || label.EnumerateRunes().Take(121).Count() > 120) throw new ReportKeyException("api_key_label_required");
        var now = DateTimeOffset.UtcNow;
        DateTimeOffset expiry = new DateTimeOffset(now.Ticks - now.Ticks % 10, TimeSpan.Zero).AddHours(command.Hours);
        var reports = (command.WorkstationsOnly ? Array.Empty<string>() : Core)
            .Concat(command.FileAgentIds.Length > 0 ? File : []).Concat(command.WorkstationAgentIds.Length > 0 ? Workstations : []).ToArray();
        var domainScope = JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { command.DomainId } });
        var scopes = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var definitions = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        await using (var connection = await connections.OpenAsync(ct))
        {
            await using var domain = new NpgsqlCommand("select 1 from domains where id=@id", connection);
            domain.Parameters.AddWithValue("id", command.DomainId);
            if (await domain.ExecuteScalarAsync(ct) is null) throw new ReportKeyException("report_key_domain_not_found");
            foreach (string key in command.WorkstationsOnly ? [] : Core) scopes[key] = domainScope;
            if (command.FileAgentIds.Length > 0)
            {
                var scope = await ResolveAgents(connection, command.FileAgentIds, command.DomainId, true, ct);
                foreach (string key in File) scopes[key] = scope;
            }
            if (command.WorkstationAgentIds.Length > 0)
            {
                var scope = await ResolveAgents(connection, command.WorkstationAgentIds, command.DomainId, false, ct);
                foreach (string key in Workstations) scopes[key] = scope;
            }
            await using var query = new NpgsqlCommand("select report_key,definition_json from report_registry_v4 where report_key=any(@keys) and status='published'", connection);
            query.Parameters.AddWithValue("keys", reports);
            await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) { using var json = JsonDocument.Parse(reader.GetString(1)); definitions[reader.GetString(0)] = json.RootElement.Clone(); }
        }
        if (!reports.ToHashSet(StringComparer.Ordinal).SetEquals(definitions.Keys)) throw new ReportKeyException("report_key_reports_not_published");
        var subject = await users.CreateAsync(new("report-key-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12)),
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)), "viewer", true), Actor, ct);
        long subjectId = subject.GetProperty("id").GetInt64();
        try
        {
            var required = definitions.Values.SelectMany(d => d.Get("required_capabilities").Strings()).ToHashSet(StringComparer.Ordinal);
            required.Add("evidence.exact");
            if (command.FileAgentIds.Length > 0) required.Add("file-audit.view");
            var caps = required.Concat(definitions.Values.SelectMany(d => d.Get("field_categories").Strings()).Select(f => "field." + f)).ToHashSet(StringComparer.Ordinal);
            if (definitions.ContainsKey("vpn.audit")) caps.Add("vpn.sessions.view");
            await WriteCapabilities(subjectId, command.DomainId, expiry, required, caps, domainScope, ct);
            foreach (var pair in definitions)
            {
                var payload = JsonSerializer.SerializeToElement(new { subject_type = "user", subject_id = subjectId, report_key = pair.Key,
                    scope = scopes[pair.Key], field_categories = pair.Value.Get("field_categories").Strings(), allowed_actions = new[] { "view" },
                    source_type = "temporary", valid_until = ReportKeyTime.Format(expiry), business_reason = Reason });
                await assignments.CreateAsync(new(payload), new("local_operator", null), null, ct);
            }
            var key = await keys.IssueAsync(new(label, "viewer", expiry, new(subjectId, command.DomainId, reports)), Actor, ct);
            return new(key.Item.GetProperty("id").GetInt64(), expiry, command.DomainId, key.Token);
        }
        catch
        {
            await users.UpdateAsync(new(subjectId, null, false), Actor, CancellationToken.None);
            throw;
        }
    }

    private async Task WriteCapabilities(long subject, long domain, DateTimeOffset expiry, HashSet<string> required,
        HashSet<string> caps, JsonElement domainScope, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        var found = new Dictionary<string, long>();
        await using (var query = new NpgsqlCommand("select id,capability_key from access_capabilities where capability_key=any(@caps)", connection, tx))
        {
            query.Parameters.AddWithValue("caps", caps.ToArray()); await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) found[reader.GetString(1)] = reader.GetInt64(0);
        }
        if (!caps.SetEquals(found.Keys)) throw new ReportKeyException("report_key_capabilities_missing");
        foreach (var pair in found)
        {
            await using var insert = new NpgsqlCommand("insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,valid_until,source_type,business_reason,created_by) values('user',@subject,@cap,'allow',@scope::jsonb,@expiry,'temporary',@reason,null)", connection, tx);
            insert.Parameters.AddWithValue("subject", subject); insert.Parameters.AddWithValue("cap", pair.Value);
            insert.Parameters.AddWithValue("scope", required.Contains(pair.Key) && pair.Key != "vpn.sessions.view" ? "{\"kind\":\"all\"}" : domainScope.GetRawText());
            insert.Parameters.AddWithValue("expiry", expiry); insert.Parameters.AddWithValue("reason", Reason); await insert.ExecuteNonQueryAsync(ct);
        }
        await AssignmentAudit.AppendEventAsync(tx, new("local_operator", null), "report_key_capabilities_created", "user", subject,
            "ad_domain", domain.ToString(System.Globalization.CultureInfo.InvariantCulture), Reason,
            new { capabilities = caps.Order(StringComparer.Ordinal), valid_until = ReportKeyTime.Format(expiry) }, null, ct);
        await tx.CommitAsync(ct);
    }

    private static async Task<JsonElement> ResolveAgents(NpgsqlConnection connection, string[] requested, long domain, bool file, CancellationToken ct)
    {
        if (requested.Any(id => !Guid.TryParse(id, out _))) throw new ReportKeyException(file ? "report_key_file_agents_invalid" : "report_key_workstation_agents_invalid");
        Guid[] ids = requested.Select(Guid.Parse).Distinct().ToArray();
        if (ids.Length is < 1 or > 100) throw new ReportKeyException(file ? "report_key_file_agents_invalid" : "report_key_workstation_agents_invalid");
        string sql = file ? """
            select distinct a.id,a.host_id from sli_agents a join sli_agent_module_bindings b on b.agent_id=a.id
            join servers s on lower(s.hostname)=lower(b.source_name) where a.id=any(@ids) and a.status='active' and s.domain_id=@domain
            and b.module_id='sli.windows.ad-dc' and s.is_active and exists(select 1 from jsonb_array_elements(a.assigned_modules) m where m->>'module_id'='sli.file-audit' and m->>'enabled'='true')
            """ : """
            select a.id,a.host_id from sli_agents a where a.id=any(@ids) and a.status='active'
            and exists(select 1 from jsonb_array_elements(a.assigned_modules) m where m->>'module_id'='sli.workstations' and m->>'enabled'='true')
            """;
        await using var query = new NpgsqlCommand(sql, connection);
        query.Parameters.AddWithValue("ids", ids); query.Parameters.AddWithValue("domain", domain);
        var found = new HashSet<Guid>(); var sources = new HashSet<string>(StringComparer.Ordinal);
        await using var reader = await query.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) { found.Add(reader.GetGuid(0)); sources.Add(reader.GetGuid(1).ToString()); }
        if (!found.SetEquals(ids)) throw new ReportKeyException(file ? "report_key_file_agent_domain_mismatch" : "report_key_workstation_agent_not_assigned");
        return JsonSerializer.SerializeToElement(new { mode = "restricted", clauses = new[] { new { plugin_ids = new[] { file ? "sli.file-audit" : "sli.workstations" }, source_instance_ids = sources.Order(StringComparer.Ordinal).ToArray() } } });
    }
}
