using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Hosting;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdCoordinatorEndpoint
{
    internal static async Task ValidateAsync(string dsn, string root, string server, Func<string, string?> get, CancellationToken ct)
    {
        if (new[] { "ADLOG_DC_CONNECT_MAP", "ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP" }.Any(n => !string.IsNullOrWhiteSpace(get(n)))) throw new WorkerFailure("source_identity", "ad_source_endpoint_invalid");
        await using var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
        var targets = await ReadAsync(db, "select hostname,connect_address,owner_confirmed_ip::text,enabled from domain_controller_targets", ct);
        if (targets.Count == 0) {
            string path = Path.Combine(root, "config/domain_controllers.json");
            if (!File.Exists(path) || new FileInfo(path).Length > 1048576) throw new WorkerFailure("source_identity", "ad_source_endpoint_invalid");
            targets = new();
            foreach (var item in JsonNode.Parse(await File.ReadAllTextAsync(path, ct))!["domain_controllers"]!.AsArray()) {
                if (item is not JsonObject row) continue;
                targets.Add(new() { ["hostname"] = (row["hostname"] ?? row["name"])?.DeepClone(), ["connect_address"] = (row["connect_address"] ?? row["address"] ?? row["ip"] ?? row["hostname"])?.DeepClone(), ["owner_confirmed_ip"] = row["owner_confirmed_ip"]?.DeepClone(), ["enabled"] = true });
            }
        }
        var matches = targets.Where(t => t["enabled"]?.GetValue<bool>() == true && new[] { t.Text("hostname"), t.Text("connect_address") }.Any(n => string.Equals(n, server, StringComparison.OrdinalIgnoreCase))).ToArray();
        if (matches.Length != 1) throw new WorkerFailure("source_identity", "ad_source_endpoint_invalid");
        var target = matches[0]; string address = target.Text("connect_address") ?? "";
        if (IPAddress.TryParse(address, out _) || !address.Contains('.') || Uri.CheckHostName(address) != UriHostNameType.Dns) throw new WorkerFailure("source_identity", "ad_source_endpoint_invalid");
        if (target.Text("owner_confirmed_ip") is {} ip) {
            if (!IPAddress.TryParse(ip, out var expected) || !(await Dns.GetHostAddressesAsync(address, System.Net.Sockets.AddressFamily.InterNetwork, ct)).Contains(expected)) throw new WorkerFailure("source_identity", "ad_source_endpoint_invalid");
        }
    }
}
