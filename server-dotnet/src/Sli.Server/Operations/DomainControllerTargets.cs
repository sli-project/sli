using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Shared endpoint authority for operational reads, collection and archive target
// selection. DNS is checked only by the explicit collection/archive methods.
public sealed class DomainControllerTargets(Func<CancellationToken, Task<JsonArray>> readRows, OperationsFiles files)
{
    internal const string Query = "select hostname,connect_address,host(owner_confirmed_ip) as owner_confirmed_ip,enabled from domain_controller_targets order by lower(hostname)";
    public DomainControllerTargets(IOperationsQueries queries, OperationsFiles files) : this(ct => queries.ReadAsync(Query, ct), files) { }

    async Task<(JsonArray Rows, bool Exists)> ReadAsync(CancellationToken ct)
    {
        JsonArray? rows = null;
        try { rows = await readRows(ct); }
        catch (Exception) when (!ct.IsCancellationRequested) { }
        if (rows is { Count: > 0 }) return (A(rows.OfType<JsonObject>().Where(r => B(r["enabled"]))), true);
        var config = files.Json("config/domain_controllers.json");
        return (config?["domain_controllers"] as JsonArray ?? [], config is not null || File.Exists(files.Resolve("config/domain_controllers.json")));
    }

    void RejectOverrides()
    {
        if (files.Setting("ADLOG_DC_CONNECT_MAP").Trim().Length > 0 || files.Setting("ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP").Trim().Length > 0)
            throw new OperationsInputException("Environment DC endpoint override is not permitted");
    }

    static string Hostname(string name) => name.Trim().Trim('.').TrimStart('\\').Split('.')[0];
    static string ConnectAddress(string value)
    {
        string address = value.Trim().TrimStart('\\').TrimEnd('.');
        if (IPAddress.TryParse(address, out _))
            throw new OperationsInputException("DC connect_address must be an FQDN, not an IP literal");
        if (address.Split('.').Length < 2 || address.Split('.').Any(label => !Regex.IsMatch(label, "\\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\z")))
            throw new OperationsInputException("DC connect_address must be an FQDN");
        return address;
    }

    static JsonArray Normalize(JsonArray rows)
    {
        var result = new JsonArray(); var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in rows)
        {
            if (node is not (JsonObject or JsonValue)) continue;
            string hostname = Hostname(node is JsonObject row ? S(row["hostname"]) is { Length: > 0 } h ? h : S(row["name"]) : S(node));
            string address = node is JsonObject target
                ? new[] { "connect_address", "address", "ip" }.Select(k => S(target[k])).FirstOrDefault(s => s.Length > 0) ?? hostname
                : S(node).Trim().Trim('.').TrimStart('\\');
            address = ConnectAddress(address);
            if (hostname.Length == 0 || !seen.Add(hostname)) continue;
            var item = new JsonObject { ["hostname"] = hostname, ["connect_address"] = address };
            if (node is JsonObject o && S(o["owner_confirmed_ip"]) is { Length: > 0 } ip)
            {
                if (!IPAddress.TryParse(ip.Trim(), out var parsed)) throw new OperationsInputException("owner_confirmed_ip must be an IP literal");
                item["owner_confirmed_ip"] = parsed.ToString();
            }
            result.Add(item);
        }
        return result;
    }

    public async Task<JsonArray> ConfiguredAsync(CancellationToken ct)
    {
        RejectOverrides();
        return Normalize((await ReadAsync(ct)).Rows);
    }

    static async Task VerifyAsync(JsonObject target, CancellationToken ct, Func<string, CancellationToken, Task<IPAddress[]>>? resolver)
    {
        if (target["owner_confirmed_ip"] is null) return;
        string address = S(target["connect_address"]);
        IPAddress[] resolved;
        try { resolved = await (resolver is null ? Dns.GetHostAddressesAsync(address, ct) : resolver(address, ct)); }
        catch (Exception e) when (e is SocketException or IOException)
        { throw new OperationsInputException("DNS readback failed for configured DC endpoint " + address); }
        if (!resolved.Contains(IPAddress.Parse(S(target["owner_confirmed_ip"]))))
            throw new OperationsInputException("DNS readback mismatch for configured DC endpoint " + address);
    }

    public async Task<JsonArray> VerifyConfiguredAsync(CancellationToken ct, Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        var targets = await ConfiguredAsync(ct);
        foreach (var target in targets.OfType<JsonObject>()) await VerifyAsync(target, ct, resolver);
        return targets;
    }

    public async Task<string> ResolveAsync(string hostname, CancellationToken ct, Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        RejectOverrides();
        var (rows, exists) = await ReadAsync(ct);
        var target = Normalize(rows).OfType<JsonObject>().FirstOrDefault(t => S(t["hostname"]).Equals(Hostname(hostname), StringComparison.OrdinalIgnoreCase));
        if (target is not null) { await VerifyAsync(target, ct, resolver); return S(target["connect_address"]); }
        if (exists) throw new OperationsInputException("DC server is not configured in the endpoint contract");
        return hostname;
    }

    public async Task<IReadOnlyDictionary<string, string>> CollectionEndpointsAsync(string hostname, IEnumerable<string> channels, CancellationToken ct,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        string address = await ResolveAsync(hostname, ct, resolver);
        return channels.ToDictionary(channel => channel, _ => address, StringComparer.Ordinal);
    }

    public async Task<IReadOnlyDictionary<string, string>> ArchiveTargetsAsync(IEnumerable<string>? requested, CancellationToken ct,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        // Verify the entire shared authority before accepting even a subset.
        var configured = (await VerifyConfiguredAsync(ct, resolver)).OfType<JsonObject>().ToDictionary(t => S(t["hostname"]), StringComparer.OrdinalIgnoreCase);
        if (configured.Count == 0) throw new OperationsInputException("No configured DC FQDN endpoints resolved");
        var items = requested?.ToArray();
        if (items is null || items.Length == 0) return configured.Values.ToDictionary(t => S(t["hostname"]), t => S(t["connect_address"]));
        var targets = new Dictionary<string, string>();
        foreach (string item in items)
        {
            if (item.Trim().Length == 0) continue;
            string[] parts = item.Trim().Split('=', 2);
            if (parts.Length != 2 || parts.Any(p => p.Trim().Length == 0)) throw new OperationsInputException("Invalid --target value; expected non-empty name/address");
            if (!configured.TryGetValue(parts[0].Trim(), out var target) || !parts[1].Trim().TrimEnd('.').Equals(S(target["connect_address"]).TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                throw new OperationsInputException("Target must match its configured FQDN endpoint");
            targets[S(target["hostname"])] = S(target["connect_address"]);
        }
        if (targets.Count == 0) throw new OperationsInputException("No targets resolved");
        return targets;
    }

    internal async Task<JsonArray> SourceAddressesAsync(CancellationToken ct)
    {
        // Inventory evidence is independent of endpoint validity and DNS access.
        var result = new JsonArray();
        foreach (var row in (await ReadAsync(ct)).Rows.OfType<JsonObject>())
        {
            string hostname = S(row["hostname"]).Trim().TrimStart('\\').TrimEnd('.');
            if (hostname.Length > 0 && IPAddress.TryParse(S(row["owner_confirmed_ip"]).Trim(), out var ip))
                result.Add(new JsonObject { ["hostname"] = hostname, ["owner_confirmed_ip"] = ip.ToString() });
        }
        return result;
    }
}
