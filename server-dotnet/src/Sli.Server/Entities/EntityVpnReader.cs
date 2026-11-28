using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
using Sli.Agent.Protocol;

namespace Sli.Server.Entities;

public sealed partial class EntityReader
{
    public async Task<JsonObject> Vpn(JsonObject entity, EntityReadOptions options, CapabilityDecisionSet caps, AccessDecision access, CancellationToken ct)
    {
        long id = Number(entity, "id"), domain = entity["domain_id"] is null ? 0 : Number(entity, "domain_id");
        if (domain <= 0) throw new EntityInputException("entity_vpn_domain_invalid");
        if (options.Limit is < 1 or > 100) throw new EntityInputException("entity_vpn_limit_invalid");
        var start = DateTimeOffset.Parse(options.From!, CultureInfo.InvariantCulture); var end = DateTimeOffset.Parse(options.To!, CultureInfo.InvariantCulture);
        if (end - start > TimeSpan.FromDays(31)) throw new EntityInputException("entity_vpn_period_too_wide");

        string? root = new FileAuditHookAdmission(services.GetRequiredService<IHostEnvironment>()).PackageRoot();
        if (root is null) throw new InvalidOperationException("plugin_not_installed");
        using var admission = AgentAssignmentPluginAdmission.Enter("sli.remote-access", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        foreach (var (path, expected) in new[] { ("config/plugin_packages/v3/sli.remote-access.json", "c5dae5b2aca19e0351e8a2f12e834586ef553234b60a5960a732a8604374a426"), ("config/plugin_settings_schema/sli.remote-access.settings.json", "df07b6b2693f8728886c53652a9830d4e715b7fa1a8a6332028e83864e4181ed") })
        {
            string file = Path.Combine(root, path); if (!File.Exists(file)) throw new InvalidOperationException("plugin_not_installed");
            using var input = File.OpenRead(file); if (input.Length > 16 * 1024 * 1024) throw new InvalidDataException("plugin_manifest_invalid");
            string actual = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(CanonicalJson.ToBytes(JsonNode.Parse(input))));
            if (actual != expected) throw new InvalidOperationException("plugin_generation_unavailable");
        }
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[new("domain", domain)]];
        bool report = ResourceAccessDecisions.ReportAction(access, "vpn.audit", "view", groups).Allowed;
        JsonObject Branch(string name, string capability)
        {
            var decision = ResourceAccessDecisions.Capability(caps, capability, groups);
            return new() { ["branch"] = name, ["state"] = report && decision.Allowed ? "available" : "not_authorized", ["reason"] = report ? decision.Reason : "vpn_report_scope_required", ["dataset_or_resource_group"] = "vpn.sessions", ["required_capability"] = capability };
        }
        var sessions = Branch("sessions", "vpn.sessions.view"); var evidence = Branch("session_evidence", "vpn.session.evidence.read");
        var result = new JsonObject { ["contract_id"] = "sli.entity-vpn-sessions.v1", ["entity_id"] = id, ["source_domain_id"] = domain,
            ["branches"] = new JsonObject { ["sessions"] = sessions, ["session_evidence"] = evidence },
            ["time_range"] = new JsonObject { ["from_utc"] = options.From, ["to_utc_exclusive"] = options.To },
            ["limits"] = new JsonObject { ["items"] = options.Limit, ["max_items"] = 100, ["bounded"] = true }, ["state"] = "not_authorized", ["items"] = new JsonArray(), ["has_more"] = false };
        if (Text(sessions, "state") != "available") return result;
        var rows = await Read("""
            select session_row_id,entity_id,domain_id,generation,lifecycle_state,completeness,started_at_utc,last_observed_at_utc,stopped_at_utc,duration_seconds,observation_count,anomalies,updated_at
            from radius_vpn_session_rows_v1 where entity_id=@id and domain_id=@domain and last_observed_at_utc>=@start and last_observed_at_utc<@end
            order by last_observed_at_utc desc,session_row_id desc limit @limit
            """, new() { ["id"] = (int)id, ["domain"] = (int)domain, ["start"] = start.UtcDateTime, ["end"] = end.UtcDateTime, ["limit"] = options.Limit + 1 }, ct, 5);
        var items = new JsonArray(); bool evidenceAllowed = Text(evidence, "state") == "available";
        foreach (var row in rows.OfType<JsonObject>().Take(options.Limit))
        {
            if (Number(row, "entity_id") != id || Number(row, "domain_id") != domain) throw new EntityInputException("entity_vpn_row_identity_mismatch");
            string session = Text(row, "session_row_id").Trim(); if (session.Length == 0) throw new EntityInputException("entity_vpn_session_identity_invalid");
            var item = Pick(row, "generation", "lifecycle_state", "completeness", "started_at_utc", "last_observed_at_utc", "stopped_at_utc", "duration_seconds", "observation_count", "anomalies", "updated_at");
            item["session_row_id"] = session; item["entity_id"] = id; item["source_domain_id"] = domain;
            item["generation"] ??= 0; item["observation_count"] ??= 0; item["anomalies"] ??= new JsonArray(); item["lifecycle_state"] ??= "unknown"; item["completeness"] ??= "unknown";
            item["evidence_ref"] = evidenceAllowed ? new JsonObject { ["kind"] = "vpn_accounting_session", ["source_domain_id"] = domain, ["session_row_id"] = session } : new JsonObject { ["state"] = "not_authorized" };
            items.Add(item);
        }
        result["state"] = "available"; result["items"] = items; result["has_more"] = rows.Count > options.Limit; return result;
    }
}
