using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Domains;

internal sealed class HomeComputerReader(HomeSummaryReaders reads)
{
    internal const string Sources = """
        select snapshot.* from unnest(@ids::bigint[]) as selected(domain_id)
        cross join lateral (
            select domain_id,snapshot_uuid,source_completed_at_utc,collection_status,
                base_inventory_status,object_count,payload_json,encode(payload_sha256,'hex') as payload_sha256
            from computers_v6_source_snapshots where domain_id=selected.domain_id
            order by source_completed_at_utc desc,source_snapshot_id desc limit 1
        ) snapshot order by snapshot.domain_id
        """;
    internal async Task<JsonObject> Read(long[] ids, HomeSummaryQuery query, CancellationToken ct)
    {
        var sections = await reads.Read(HomeSummarySql.Sections, ct, ("ids", ids), ("sections", "directory_accounts"));
        var rows = (await reads.Read(HomeSummarySql.Entities, ct, ("ids", ids), ("sections", "directory_accounts")))
            .Where(r => r.Text("entity_type") == "ad_computer").ToArray();
        var coverage = HomeSummaryReaders.SectionCoverage(sections, query.Now, true);
        // The source snapshot is optional in the reference. Invalid snapshots cannot override inventory.
        IReadOnlyList<JsonObject> snapshots;
        try { snapshots = await reads.Read(Sources, ct, ("ids", ids)); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { snapshots = []; }
        var sources = new Dictionary<(long, string), (JsonObject Source, JsonObject Snapshot)>();
        foreach (var snapshot in snapshots)
        {
            try
            {
                var payload = snapshot["payload_json"] as JsonObject ?? JsonNode.Parse(snapshot.Text("payload_json") ?? "")!.AsObject();
                var canonical = Sli.Agent.Protocol.CanonicalJson.Serialize(payload, ensureAscii: false);
                if (!HomeComputerSource.Valid(payload) || Encoding.UTF8.GetByteCount(canonical) > 64 * 1024 * 1024 || payload["objects"] is not JsonArray objects || objects.Count > 250000
                    || snapshot.Text("payload_sha256") != Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
                    || snapshot.Number("object_count") != objects.Count || payload["metadata"].Number("object_count") != objects.Count
                    || payload["metadata"].Text("snapshot_id") != snapshot.Text("snapshot_uuid")
                    || payload["metadata"].Text("collection_status") != snapshot.Text("collection_status")
                    || !Guid.TryParse(payload["metadata"].Text("snapshot_id"), out _) || snapshot.Text("base_inventory_status") != "observed") continue;
                if (snapshot.Stamp("source_completed_at_utc") < query.Now.AddDays(-1)) coverage["state"] = "stale";
                foreach (var source in objects.OfType<JsonObject>())
                    sources[(snapshot.Number("domain_id"), source.Text("objectGuid")!.ToLowerInvariant())] = (source, snapshot);
                coverage["computer_snapshot_observed_at_utc"] = snapshot["source_completed_at_utc"].Copy();
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException) { /* optional invalid source */ }
        }
        var counts = new Dictionary<string, long> { ["total"] = 0, ["attention"] = 0, ["ws"] = 0, ["srv"] = 0, ["unknown"] = 0, ["disabled"] = 0, ["unknown_state"] = 0 };
        foreach (var row in rows.Take(10000))
        {
            var attrs = row["attributes"]?["attributes"] as JsonObject ?? row["attributes"] as JsonObject ?? new();
            var identity = row["attributes"]?["identity"];
            var enabled = attrs.Boolean("enabled");
            var os = attrs.Text("operating_system") ?? "";
            var version = attrs.Text("operating_system_version");
            var type = string.IsNullOrWhiteSpace(os) || os.ToLowerInvariant() is "unknown" or "неизвестно" ? "unknown"
                : os.Contains("server", StringComparison.OrdinalIgnoreCase) ? "server" : "workstation";
            var uac = attrs.Number("user_account_control");
            var delegation = attrs["user_account_control"]?.GetValueKind() == JsonValueKind.Number ? (uac & 524288) != 0 : attrs.Boolean("trusted_for_delegation") == true;
            if ((uac & 8192) != 0) type = "domain_controller";
            var observed = row.Stamp("observed_at_utc");
            var lastLogon = attrs.Stamp("last_logon_utc");
            var laps = attrs.Stamp("laps_password_expiration_utc") ?? attrs.Stamp("legacy_laps_password_expiration_utc");
            var fieldStates = attrs["computer_reference_attribute_states"] as JsonObject ?? attrs["attribute_states"] as JsonObject;
            bool error = fieldStates?.Any(p => p.Value.Text("state") is "failed" or "access_denied" or "parse_error") == true;
            bool osUnknown = string.IsNullOrEmpty(os) || fieldStates?["operating_system"].Text("state") is not ("observed" or "present");
            var guid = identity.Text("object_guid") ?? attrs.Text("object_guid");
            if (guid is not null && sources.TryGetValue((row.Number("domain_id"), guid.ToLowerInvariant()), out var overlay)
                && (observed is null || overlay.Snapshot.Stamp("source_completed_at_utc") >= observed))
            {
                var source = overlay.Source;
                enabled = source.Boolean("enabled") ?? enabled;
                os = source.Text("osName") ?? ""; version = source.Text("osVersion");
                var classified = source["classification"].Text("result") ?? source["classification"].Text("deviceType") ?? source.Text("deviceType");
                if (classified is "server" or "domain_controller" or "workstation") type = classified;
                else if (type is not ("server" or "workstation")) type = "unknown";
                uac = source.Number("userAccountControl"); if ((uac & 8192) != 0) type = "domain_controller";
                delegation = source["userAccountControl"]?.GetValueKind() == JsonValueKind.Number ? (uac & 524288) != 0 : source.Boolean("trustedForDelegation") == true;
                observed = overlay.Snapshot.Stamp("source_completed_at_utc") ?? source.Stamp("collectedAt");
                lastLogon = source.Stamp("eventLastSeen") ?? source.Stamp("exactLastLogon") ?? source.Stamp("lastLogonTimestamp");
                laps = source.Stamp("lapsPasswordExpiration") ?? source.Stamp("legacyLapsPasswordExpiration");
                error = (source["sources"] as JsonObject)?.Any(p => p.Value.Text("status") is "failed" or "access_denied" or "parse_error") == true;
                osUnknown = string.IsNullOrEmpty(os) || source["sources"]?["os"].Text("status") is not ("observed" or "present");
            }
            var attention = Unsupported(os, version, observed) || delegation
                || laps < observed || error || type == "unknown" || osUnknown
                || enabled == true && (lastLogon is null || observed is not null && Math.Floor((observed.Value - lastLogon.Value).TotalDays) > 90);
            counts["total"]++;
            if (attention) counts["attention"]++;
            if (enabled is null) counts["unknown_state"]++;
            else if (enabled == false) counts["disabled"]++;
            else counts[type == "workstation" ? "ws" : type is "server" or "domain_controller" ? "srv" : "unknown"]++;
        }
        var state = coverage.Text("state")!;
        if (state == "not_collected" && rows.Length > 0) state = "ok";
        if (rows.Length > 10000) state = "partial";
        if (state == "ok" && rows.Length == 0) state = "empty";
        if (coverage["computer_snapshot_observed_at_utc"] is not null) coverage["observed_at_utc"] = coverage["computer_snapshot_observed_at_utc"].Copy();
        return HomeSummaryReaders.Limitations(HomeSummaryReaders.Result(state, items: rows.Take(20), metrics: new[] {
            ("total", "Компьютеры в AD", "accent", (object)new { view="all" }), ("attention", "Требуют внимания", counts["attention"]>0 ? "warning" : "neutral", new { view="attention" }),
            ("ws", "Рабочие станции (вкл.)", "neutral", new { view="workstation_enabled" }), ("srv", "Серверы (вкл.)", "neutral", new { view="server_enabled" }),
            ("unknown", "Тип не определён (вкл.)", "neutral", new { view="all", type="unknown", enabled="enabled" }),
            ("disabled", "Отключены (все типы)", "neutral", new { view="all", enabled="disabled" }),
            ("unknown_state", "Состояние учётной записи не определено", "neutral", new { view="all", enabled="unknown" }) }
                .Select(m => HomeSummaryReaders.Metric(m.Item1, m.Item2, counts[m.Item1], m.Item3, m.Item4)), coverage: coverage),
            ("computers_0", "Признак «Включена в AD» показывает состояние учётной записи, а не питание или доступность устройства."),
            ("computers_1", "Последняя активность основана на приблизительном реплицируемом lastLogonTimestamp."),
            ("computers_2", "Причины источника, типа и ОС оцениваются для всех записей AD; давность активности — только для включённых учётных записей."),
            ("computers_3", "Семантические выводы показываются только по точным опубликованным связям объектов и не изменяют квалификацию AD."));
    }

    private static bool Unsupported(string os, string? version, DateTimeOffset? observed)
    {
        if (observed is null) return false;
        var name = os.ToLowerInvariant();
        if (new[] { "embedded", "iot", "ltsb" }.Any(name.Contains)) return false;
        string? end = null;
        foreach (var (marker, date) in new[] { ("windows server 2022", "2031-10-14"), ("windows server 2019", "2029-01-09"), ("windows server 2016", "2027-01-12"),
            ("windows server 2012", "2023-10-10"), ("windows server 2008", "2020-01-14"), ("windows server 2003", "2015-07-14") })
            if (name.Contains(marker)) end = date;
        var match = Regex.Match(version ?? "", @"\((\d{4,5})\)");
        _ = int.TryParse(match.Groups[1].Value, out var build);
        if (name.Contains("windows 10")) end = name.Contains("ltsc") ? build == 19044 ? "2027-01-12" : build == 17763 ? "2029-01-09" : null : "2025-10-14";
        if (name.Contains("windows 11")) end = name.Contains("ltsc") && build == 26100 ? "2029-10-09"
            : name.Contains("pro") ? build switch { 22000 => "2023-10-10", 22621 => "2024-10-08", 22631 => "2025-11-11", 26100 => "2026-10-13", 26200 => "2027-10-13", _ => null } : null;
        if (Regex.IsMatch(name, @"windows\s+7(?:\s|$)")) end = "2020-01-14";
        if (Regex.IsMatch(name, @"windows\s+8\.1(?:\s|$)")) end = "2023-01-10";
        else if (Regex.IsMatch(name, @"windows\s+8(?:\s|$)")) end = "2016-01-12";
        if (Regex.IsMatch(name, @"windows\s+vista(?:\s|$)")) end = "2017-04-11";
        return end is not null && DateOnly.FromDateTime(observed.Value.UtcDateTime) > DateOnly.Parse(end, System.Globalization.CultureInfo.InvariantCulture);
    }
}
