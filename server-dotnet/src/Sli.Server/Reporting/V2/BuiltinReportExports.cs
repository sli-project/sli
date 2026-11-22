using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Ad;

namespace Sli.Server.Reporting.V2;

// These declarations delegate export to the same readers as the v1 endpoints.
public sealed partial class BuiltinReportExports(ReportRunner runner, IAccessFactsRepository facts, IAdReportStore security, Sli.Server.Semantic.ISemanticDatabase database, IConfiguration? configuration = null)
{
    public static bool Handles(string key) => key is "events.journal" or "security.events.chains";
    public async Task<ReportExport> ExportAsync(ReportQueryContext c, CancellationToken ct)
    {
        try {
            return c.Definition.Key == "events.journal" ? await Journal(c, ct) : await Security(c, ct);
        }
        catch (ReportException e) { throw new ReportRequestException(e.Message, e.Status); }
        catch (AdInputException e) { throw new ReportRequestException(e.Message); }
    }
    async Task<ReportExport> Journal(ReportQueryContext c, CancellationToken ct)
    {
        var subject = await facts.LoadAsync(c.Principal, ct);
        var projection = JsonSerializer.SerializeToNode(AccessReadProjection.Compose(c.Principal, subject, c.Access.Capabilities, c.Access, false))!.AsObject();
        var filters = new Dictionary<string, string> { ["time_from"] = c.Params["period"]!["from_utc"]!.ToString(), ["time_to"] = c.Params["period"]!["to_utc"]!.ToString() };
        foreach (string key in new[] { "view", "q", "server" }) if (c.Params[key]?.ToString() is { Length: > 0 } value && (key != "view" || value != "all")) filters[key] = value;
        var journal = EventsJournalReader.Options(c);
        var raw = await runner.ExecuteAsync(new(c.Principal, subject, c.Access.Capabilities, projection), "events.explorer", 200, null, "export", filters, ct, journal);
        var rows = (raw["items"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
        var columns = (raw["fields"] as JsonArray ?? []).OfType<JsonObject>().Select(f => new JsonObject { ["key"] = f["key"]!.DeepClone(), ["label"] = f["label"]?.DeepClone() ?? f["key"]!.DeepClone() });
        bool truncated = raw["has_more"]?.GetValue<bool>() == true || long.TryParse((raw["filtered_count"] ?? raw["limits"]?["total_count"])?.ToString(), out long total) && total > rows.Length;
        return new(ReportCsv.FromColumns(columns, rows), rows.Length, truncated);
    }
    async Task<ReportExport> Security(ReportQueryContext c, CancellationToken ct)
    {
        var period = AdPeriod.Parse(c.Params["period"]!["from_utc"]!.ToString(), c.Params["period"]!["to_utc"]!.ToString(), "UTC", "security_events");
        if (c.Paging.Tab == "persistence-changes") return await Persistence(c, period, ct);
        var query = new QueryCollection(c.Params.Where(p => p.Value is JsonValue).ToDictionary(p => p.Key, p => new StringValues(p.Value!.ToString())));
        var filters = AdSecurity.Normalize(query);
        long? selected = c.Params["domain"] is {} domain ? long.Parse(domain.ToString(), CultureInfo.InvariantCulture) : null;
        var domains = new List<long>();
        if (selected is {} chosen) {
            if (!AdReportEndpoints.Allowed(c.Access, "security", chosen, true)) throw new ReportRequestException("report_export_not_authorized", 403);
            domains.Add(chosen);
        }
        else {
            long after = 0; int scanned = 0;
            while (true) {
                var batch = await security.DomainsAsync(after, ct); if (batch.Count == 0) break;
                scanned += batch.Count; if (scanned > 10000) throw new ReportRequestException("security_events_source_discovery_scan_limit");
                foreach (long candidate in batch) if (AdReportEndpoints.Allowed(c.Access, "security", candidate, true)) domains.Add(candidate);
                after = batch[^1]; if (batch.Count < 256) break;
            }
            if (domains.Count == 0) throw new ReportRequestException("report_export_not_authorized", 403);
        }
        var rows = new List<JsonObject>(); bool more = false; var coverage = new JsonObject(); bool available = false;
        foreach (long id in domains) {
            var raw = await security.ReadAsync(new("security", false, true, id, period, 500, filters, null), false, ct);
            if (raw["state"]?.ToString() == "not_authorized") throw new ReportRequestException("report_export_not_authorized", 403);
            rows.AddRange((raw["items"] as JsonArray ?? []).OfType<JsonObject>().Select(r => r.DeepClone().AsObject()));
            if (rows.Count > 500) {
                more = true;
                rows = rows.OrderByDescending(r => r["time_created_utc"]!.ToString(), StringComparer.Ordinal).ThenByDescending(r => long.Parse(r["event_db_id"]!.ToString(), CultureInfo.InvariantCulture)).Take(500).ToList();
            }
            more |= raw["has_more"]?.GetValue<bool>() == true; available |= raw["state"]?.ToString() == "available";
            if (raw["category_coverage"] is JsonObject categories) foreach (var (family, state) in categories) {
                int Rank(JsonNode? value) => value?["state"]?.ToString() switch { "processing_unfinished" => 3, "retained_match_present" => 2, "no_retained_match" => 1, _ => 0 };
                if (!coverage.ContainsKey(family) || Rank(state) > Rank(coverage[family])) coverage[family] = state?.DeepClone();
            }
        }
        var page = rows.OrderByDescending(r => r["time_created_utc"]!.ToString(), StringComparer.Ordinal).ThenByDescending(r => long.Parse(r["event_db_id"]!.ToString(), CultureInfo.InvariantCulture)).Take(500).ToArray();
        more |= rows.Count > 500;
        var payload = new JsonObject { ["items"] = new JsonArray(page.Select(r => (JsonNode)r).ToArray()), ["has_more"] = more,
            ["state"] = available ? "available" : "not_collected", ["category_coverage"] = coverage };
        return new(AdSecurity.Csv(payload), page.Length, more);
    }
}
