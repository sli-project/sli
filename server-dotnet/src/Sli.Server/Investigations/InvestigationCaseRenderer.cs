using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Access;
using Sli.Server.Agents.Control;

namespace Sli.Server.Investigations;

public interface IInvestigationVpnEvidence
{
    bool Allowed(AccessDecision access, long domainId);
}

public sealed class InvestigationVpnEvidence(IHostEnvironment host) : IInvestigationVpnEvidence
{
    private const string Manifest = "c5dae5b2aca19e0351e8a2f12e834586ef553234b60a5960a732a8604374a426";
    private const string Settings = "df07b6b2693f8728886c53652a9830d4e715b7fa1a8a6332028e83864e4181ed";
    public bool Allowed(AccessDecision access, long domainId)
    {
        using var admission = AgentAssignmentPluginAdmission.Enter("sli.remote-access", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        var root = new DirectoryInfo(host.ContentRootPath);
        while (root is not null && !Directory.Exists(Path.Combine(root.FullName, "config", "plugin_packages", "v3"))) root = root.Parent;
        if (root is null || Fingerprint(Path.Combine(root.FullName,"config","plugin_packages","v3","sli.remote-access.json")) != Manifest ||
            Fingerprint(Path.Combine(root.FullName,"config","plugin_settings_schema","sli.remote-access.settings.json")) != Settings)
            throw new InvalidOperationException("vpn_evidence_contribution_unavailable");
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = domainId > 0 ? [[new("domain", domainId)]] : [];
        return ResourceAccessDecisions.ReportAction(access, "vpn.audit", "view", groups).Allowed &&
            access.Capabilities.DecideForResourceGroups("vpn.session.evidence.read", groups).Allowed;
    }
    private static string Fingerprint(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 16 * 1024 * 1024) throw new InvalidDataException("plugin_manifest_invalid");
        return Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(JsonNode.Parse(stream))));
    }
}

public static class InvestigationCaseRenderer
{
    public static JsonObject Render(InvestigationCaseMutationResult result, AccessDecision access, IInvestigationVpnEvidence evidence)
    {
        var row = result.Case;
        // Paged references were authorized in the same snapshot as the counts.
        // Re-running a hook here could change the response after pagination.
        if (row["evidence_page_size"] is null)
        {
            var visible = new JsonArray(); bool hidden = false;
            var decisions = new Dictionary<long, bool>();
            foreach (var node in row["evidence_refs"]!.AsArray())
            {
                var domain = node!["source_domain_id"]?.GetValue<long>() ?? 0;
                if (!decisions.TryGetValue(domain, out bool allowed)) decisions[domain] = allowed = evidence.Allowed(access, domain);
                if (allowed) visible.Add(node.DeepClone()); else hidden = true;
            }
            row["evidence_refs"] = visible;
            row["evidence_refs_state"] = hidden ? "partially_authorized" : "available";
        }
        foreach (string key in new[] { "created_at", "updated_at", "closed_at" }) NormalizeTime(row, key, true);
        foreach (string group in new[] { "events", "evidence_refs", "notes", "audit" })
            foreach (var node in (row[group] as JsonArray ?? new JsonArray()))
                foreach (string key in new[] { "added_at", "created_at" }) NormalizeTime(node!.AsObject(), key, false);
        if (row["anchor_event"] is JsonObject anchor) NormalizeTime(anchor, "added_at", false);
        row["api_version"] = "v1";
        row["case_number"] = "INV-" + row["id"]!.GetValue<long>().ToString("D7", CultureInfo.InvariantCulture);
        foreach (var key in new[] { "evidence_page_size", "events_total", "events_next_cursor", "evidence_refs_total", "evidence_refs_next_cursor", "anchor_event" }) row[key] ??= null;
        row["audit"] ??= new JsonArray();
        return row;
    }
    private static void NormalizeTime(JsonObject obj, string key, bool utc)
    {
        if (obj[key] is not JsonValue value || !value.TryGetValue<string>(out var raw)) return;
        var time = DateTimeOffset.Parse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        if (utc) time = time.ToUniversalTime();
        string format = time.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss" : "yyyy-MM-dd'T'HH:mm:ss.ffffff";
        string text = time.ToString(format, CultureInfo.InvariantCulture) + (time.Offset == TimeSpan.Zero ? "Z" : time.ToString("zzz", CultureInfo.InvariantCulture));
        obj[key] = text;
    }
}
