using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Agent.Windows.SnapshotJson;

namespace Sli.Agent.Windows;

internal static class ComputerSnapshot
{
    internal static JsonObject Normalize(IEnumerable<JsonObject> records, JsonObject cfg, string observed, string queryDc, string searchBase, JsonNode? optional, Func<Guid> newId)
    {
        string[] names = ["ad", "dns", "os", "site", "last_logon_timestamp", "exact_last_logon", "dc_events"];
        var flags = cfg["expensive_flags"]!; var objects = new JsonArray();
        string FlagName(string name) => name switch { "dns" => "dns", "site" => "ad_site", "exact_last_logon" => "exact_last_logon", _ => "" };
        foreach (var record in records)
        {
            var attrs = record["attributes"]!; var identity = record["identity"]!; var guid = Text(identity["object_guid"]);
            var addresses = Rows(attrs["ip_addresses"]).Select(n => Text(n)).ToArray(); string? site = null; var sources = new JsonObject();
            foreach (var name in names)
            {
                var status = name is "ad" or "os" or "last_logon_timestamp" ? "observed" : "not_collected"; JsonNode? value = null;
                if (name is "os" or "last_logon_timestamp")
                { value = Copy(attrs[name == "os" ? "operating_system" : "last_logon_timestamp_utc"]); status = value is not null && value.ToString() != "" ? "observed" : "missing_in_source"; }
                else if (name == "exact_last_logon")
                { value = Copy(attrs["exact_last_logon_utc"]); status = Text(attrs["exact_last_logon_status"], "not_collected"); if (status == "no_record") status = "missing_in_source"; }
                else if (name == "dns" && Flag(flags["dns"]))
                { value = Array(addresses); status = Text(optional?["dns"]?["values"]?[guid]?["status"], "not_evaluated"); }
                else if (name == "site" && Flag(flags["ad_site"]))
                {
                    status = Text(optional?["ad_site"]?["status"], "not_evaluated");
                    if (status == "observed")
                    {
                        var matches = new List<(int Prefix, string Site)>();
                        foreach (var subnet in Rows(optional?["ad_site"]?["subnets"]))
                        {
                            var parts = Text(subnet["name"]).Split('/');
                            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > ip.GetAddressBytes().Length * 8) continue;
                            if (addresses.Any(a => InSubnet(IPAddress.Parse(a), ip, prefix)) && subnet["siteobject"] is not null) matches.Add((prefix, Text(subnet["siteobject"])));
                        }
                        var dn = matches.OrderBy(m => m.Prefix).ThenBy(m => m.Site, StringComparer.Ordinal).LastOrDefault().Site;
                        site = dn is { Length: >= 3 } ? dn.Split(',', 2)[0][3..] : null;
                        value = JsonValue.Create(site); status = site is not null ? "observed" : addresses.Length > 0 ? "no_record" : "not_evaluated";
                    }
                }
                else if (name != "ad" && Flag(flags[FlagName(name)])) status = "not_evaluated";
                sources[name] = new JsonObject { ["status"] = status, ["source"] = name, ["value"] = value,
                    ["observed_at"] = status is not ("not_collected" or "not_evaluated") ? observed : null, ["error"] = null, ["details"] = null };
            }
            sources["exact_last_logon"]!["details"] = new JsonObject { ["discovered_dc_count"] = Int(attrs["exact_last_logon_discovered_dc_count"]),
                ["successful_dc_count"] = Int(attrs["exact_last_logon_successful_dc_count"]), ["failed_dcs"] = Copy(attrs["exact_last_logon_failed_dcs"]) ?? new JsonArray() };
            var os = Text(attrs["operating_system"]); var isDc = (Int(attrs["user_account_control"]) & 8192) != 0;
            var type = isDc ? "domain_controller" : os.Contains("server", StringComparison.OrdinalIgnoreCase) ? "server" : os.Contains("windows", StringComparison.OrdinalIgnoreCase) ? "workstation" : "unknown";
            var build = Regex.Match(Text(attrs["operating_system_version"]), @"\((\d+)\)"); var dnValue = Text(attrs["distinguished_name"]);
            var obj = new JsonObject { ["id"] = guid, ["objectGuid"] = guid, ["deviceType"] = type,
                ["classification"] = new JsonObject { ["result"] = type, ["state"] = type == "unknown" ? "unknown" : "observed", ["source"] = isDc ? "userAccountControl" : "operatingSystem" },
                ["ipv4s"] = Array(addresses.Where(a => IPAddress.Parse(a).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)),
                ["ipv6s"] = Array(addresses.Where(a => IPAddress.Parse(a).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)),
                ["osBuild"] = build.Success ? build.Groups[1].Value : null, ["osFamily"] = os.Contains("windows", StringComparison.OrdinalIgnoreCase) ? "Windows" : "Unknown",
                ["ou"] = dnValue.Contains(',') ? dnValue.Split(',', 2)[1] : null, ["domain"] = Copy(cfg["domain_dns"]), ["adSite"] = site,
                ["eventLastSeen"] = null, ["sid"] = Copy(identity["object_sid"]), ["spns"] = Copy(attrs["service_principal_names"]) ?? new JsonArray(),
                ["roleHint"] = null, ["roleEvidence"] = new JsonArray(), ["collectedAt"] = observed, ["queryDc"] = queryDc,
                ["collectorVersion"] = "sli-agent/ad-snapshot/1", ["sources"] = sources, ["collectionErrors"] = new JsonArray() };
            foreach (var (target, source) in AdSnapshotAttributes.Schema["computer_fields"]!.AsObject()) obj[target] = Copy(attrs[Text(source)]);
            objects.Add(obj);
        }
        var stages = new JsonArray();
        foreach (var name in names)
        {
            var requested = name is "ad" or "os" or "last_logon_timestamp" || Flag(flags[FlagName(name)]);
            var status = name is "ad" or "os" or "last_logon_timestamp" ? "observed" : name == "exact_last_logon" && Flag(flags["exact_last_logon"]) ? "partial" : Flag(flags[name == "site" ? "ad_site" : name == "dns" ? "dns" : ""]) ? "not_evaluated" : "not_collected";
            if (objects.Count > 0)
            {
                var statuses = objects.Select(o => Text(o!["sources"]![name]!["status"])).Distinct().ToArray(); status = statuses.Length == 1 ? statuses[0] : "partial";
            }
            stages.Add(new JsonObject { ["name"] = name, ["status"] = status, ["requested"] = requested });
        }
        return new JsonObject { ["schema_version"] = "2.0", ["metadata"] = new JsonObject { ["snapshot_id"] = newId().ToString(), ["label"] = "SLI AD snapshot", ["started_at"] = observed, ["completed_at"] = observed,
            ["query_dc"] = queryDc, ["domain"] = Copy(cfg["domain_dns"]), ["search_base"] = searchBase, ["collection_status"] = stages.Any(s => Flag(s!["requested"]) && Text(s["status"]) != "observed") ? "partial" : "complete",
            ["object_count"] = objects.Count, ["collector_version"] = "sli-agent/ad-snapshot/1", ["sources"] = stages, ["errors"] = new JsonArray() }, ["objects"] = objects };
    }

    private static bool InSubnet(IPAddress address, IPAddress network, int prefix)
    {
        var a = address.GetAddressBytes(); var b = network.GetAddressBytes();
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
        {
            var bits = Math.Clamp(prefix - i * 8, 0, 8); var mask = (byte)(0xff << (8 - bits));
            if ((a[i] & mask) != (b[i] & mask)) return false;
        }
        return true;
    }
}
