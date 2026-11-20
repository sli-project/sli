using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public sealed partial class OperationsService
{
    static string InventoryName(JsonNode? value) => S(value).Trim().TrimEnd('.').ToLowerInvariant();
    static HashSet<string> InventoryKeys(JsonObject row)
    {
        string hostname = InventoryName(row["hostname"]), fqdn = InventoryName(row["fqdn"]), domain = InventoryName(row["domain_fqdn"]);
        return new[] { hostname, fqdn, hostname.Split('.')[0], hostname.Length > 0 && domain.Length > 0 && !hostname.Contains('.') ? hostname + "." + domain : "" }.Where(s => s.Length > 0).ToHashSet();
    }
    internal async Task<JsonArray> SourcesAsync(CancellationToken ct)
    {
        var sources = await queries.ReadAsync(OperationsSql.Sources, ct);
        if (sources.Count == 0) return sources;
        var hostnames = sources.OfType<JsonObject>().SelectMany(InventoryKeys).Distinct().Order().ToArray();
        int limit = Math.Min(200, Math.Max(4, sources.Count * 3));
        JsonArray inventory;
        try { inventory = await queries.ReadAsync(OperationsSql.SourceInventory, ct, ("hostnames", hostnames), ("limit", limit + 1)); }
        catch (Exception) when (!ct.IsCancellationRequested) { inventory = []; }
        if (inventory.Count > limit) inventory = [];
        JsonArray targets;
        try { targets = await new DomainControllerTargets(queries, files).SourceAddressesAsync(ct); }
        catch (Exception) when (!ct.IsCancellationRequested) { targets = []; }
        foreach (var row in sources.OfType<JsonObject>())
        {
            var keys = InventoryKeys(row);
            string domain = InventoryName(row["domain_fqdn"]), hostname = InventoryName(row["hostname"]), explicitFqdn = InventoryName(row["fqdn"]);
            if (explicitFqdn.Length == 0 && hostname.Contains('.')) explicitFqdn = hostname;
            string fqdn = explicitFqdn.Length > 0 ? explicitFqdn : domain.Length > 0 ? hostname + "." + domain : "";
            var candidates = inventory.OfType<JsonObject>().Where(i => new[] { "display_key", "sam_key", "dns_key", "fqdn" }.Select(k => InventoryName(i[k])).Where(s => s.Length > 0).Any(keys.Contains)).ToArray();
            bool Compatible(JsonObject i) => !(domain.Length > 0 && InventoryName(i["domain_fqdn"]) is { Length: > 0 } d && d != domain || explicitFqdn.Length > 0 && InventoryName(i["fqdn"]) is { Length: > 0 } f && explicitFqdn != f);
            var exact = candidates.Where(i => Compatible(i) && fqdn.Length > 0 && InventoryName(i["fqdn"]) == fqdn).ToArray();
            var sameDomain = candidates.Where(i => Compatible(i) && domain.Length > 0 && InventoryName(i["domain_fqdn"]) == domain).ToArray();
            JsonObject? current = exact.Length > 0 ? exact.Length == 1 ? exact[0] : null : sameDomain.Length > 0 ? sameDomain.Length == 1 ? sameDomain[0] : null
                : candidates.Length == 1 && Compatible(candidates[0]) && !(fqdn.Length > 0 && InventoryName(candidates[0]["fqdn"]) is { Length: > 0 } cf && cf != fqdn)
                  && sources.OfType<JsonObject>().Count(s => InventoryKeys(s).Overlaps(keys)) == 1 ? candidates[0] : null;
            if (current is not null)
            {
                foreach (string key in new[] { "fqdn", "os_name", "os_version" }) if (S(row[key]).Length == 0) row[key] = Copy(current[key]);
                foreach (string key in new[] { "ip_addresses", "logical_disks", "technical_inventory_status", "technical_inventory_observed_at_utc" }) row[key] = Copy(current[key]);
                row["inventory_observed_at_utc"] = Copy(current["last_observed_at_utc"]); row["inventory_source"] = "ad_context";
            }
            var addresses = new List<string>();
            // A configured short alias may be attributed only when there is one owner.
            foreach (var target in targets.OfType<JsonObject>())
            {
                string name = InventoryName(target["hostname"]);
                var owners = sources.OfType<JsonObject>().Where(s => name.Contains('.') ? (InventoryName(s["fqdn"]) is { Length: > 0 } sf ? sf : InventoryName(s["hostname"]) + "." + InventoryName(s["domain_fqdn"])) == name : InventoryName(s["hostname"]).Split('.')[0] == name).ToArray();
                if (owners.Length == 1 && ReferenceEquals(owners[0], row) && SafeIp(target["owner_confirmed_ip"]) is {} ip) addresses.Add(ip);
            }
            addresses.AddRange((row["ip_addresses"] as JsonArray ?? []).Select(SafeIp).OfType<string>());
            row["ip_addresses"] = new JsonArray(addresses.Distinct().Select(s => JsonValue.Create(s)).ToArray());
            var disks = new JsonArray();
            foreach (var disk in (row["logical_disks"] as JsonArray ?? []).Take(64))
            {
                var parts = S(disk).Split('|');
                if (parts.Length == 3 && Regex.IsMatch(parts[0], "\\A[A-Za-z]:\\z") && long.TryParse(parts[1], out long total) && long.TryParse(parts[2], out long free) && total > 0 && free >= 0 && free <= total)
                    disks.Add(new JsonObject { ["name"] = parts[0].ToUpperInvariant(), ["total_bytes"] = total, ["free_bytes"] = free, ["free_percent"] = Math.Round(free * 100d / total, 1) });
            }
            row["disks"] = disks;
            row["disk_state"] = S(row["technical_inventory_status"]) switch { "complete" => disks.Any(d => double.Parse(S(d?["free_percent"]), System.Globalization.CultureInfo.InvariantCulture) < 15) ? "warning" : "ok", "failed" => "failed", "timeout" => "timeout", _ => "not_collected" };
        }
        return sources;
    }
    static string? SafeIp(JsonNode? value) => IPAddress.TryParse(S(value), out var ip) ? ip.ToString() : null;
    public async Task<JsonObject> SourceAsync(string hostname, CancellationToken ct)
    {
        string clean = hostname.Trim();
        if (clean.Length is 0 or > 255) throw new OperationsInputException("invalid_source_hostname");
        var matches = (await SourcesAsync(ct)).OfType<JsonObject>().Where(s => S(s["hostname"]).Trim().TrimEnd('.').Equals(clean.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length > 1) throw new OperationsInputException("ambiguous_source_hostname");
        var health = await CollectorAsync(ct);
        var channels = A((health["items"] as JsonArray ?? []).OfType<JsonObject>().Where(c => S(c["server"]).Equals(clean, StringComparison.OrdinalIgnoreCase)));
        var inventory = matches.FirstOrDefault();
        if (inventory is null && channels.Count == 0) throw new OperationsInputException("source_not_found", 404);
        string name = S(inventory?["hostname"], S(channels.FirstOrDefault()?["server"], clean));
        var source = new JsonObject { ["hostname"] = name };
        foreach (string key in new[] { "fqdn", "role", "domain_fqdn", "os_name", "os_version", "inventory_observed_at_utc", "inventory_source" }) source[key] = Copy(inventory?[key]);
        source["active"] = Copy(inventory?["is_active"]); source["site"] = Copy(inventory?["site_name"]);
        source["ip_addresses"] = Copy(inventory?["ip_addresses"]) ?? new JsonArray(); source["disks"] = Copy(inventory?["disks"]) ?? new JsonArray(); source["disk_state"] = S(inventory?["disk_state"], "not_collected");
        return new() { ["api_version"] = "v1", ["generated_at_utc"] = Generated, ["source"] = source,
            ["collection_freshness"] = OperationsCollector.Freshness(channels, Now, name), ["channels"] = channels,
            ["limitations"] = new JsonArray("IP-адрес контроллера показывается только из подтверждённого владельцем DNS-readback; адрес подключения не подменяет инвентаризацию. Дополнительные IP-адреса берутся из инвентаризации AD Context.", "Сведения о дисках показываются только после успешного ограниченного технического опроса в едином 30-минутном контуре.", "Время последней проверки канала и время последнего события показаны отдельно."), ["read_only"] = true };
    }
}
