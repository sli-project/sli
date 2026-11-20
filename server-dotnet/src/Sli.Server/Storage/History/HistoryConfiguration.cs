using System.Globalization;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using Sli.Server.Hosting;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Storage.History;

// IConfiguration is the server lifetime boundary. All readers share one immutable
// snapshot, including cached failures; requests never reopen credential files.
internal sealed class HistoryConfiguration
{
    static readonly ConditionalWeakTable<IConfiguration, HistoryConfiguration> Servers = new();
    static readonly Lazy<HistoryConfiguration> Worker = new(() => Load(null, Environment.GetEnvironmentVariable));
    readonly string mode;
    readonly string? port;
    readonly Lazy<(Uri Endpoint, AuthenticationHeaderValue Auth)> transport;
    internal static HistoryConfiguration For(IConfiguration? config) => config is null ? Worker.Value
        : Servers.GetValue(config, c => Load(c, Environment.GetEnvironmentVariable));
    internal static HistoryConfiguration Load(IConfiguration? config, Func<string,string?> environment)
    {
        var values = new Dictionary<string,string?>();
        foreach (var (name, suffix) in new[] { ("Host","HOST"), ("Port","PORT"), ("User","USER"),
            ("UserFile","USER_FILE"), ("Password","PASSWORD"), ("PasswordFile","PASSWORD_FILE") })
            values["ADLOG_HISTORY_CLICKHOUSE_"+suffix] = config?["Sli:Storage:HistoryClickHouse"+name]
                ?? config?["ADLOG_HISTORY_CLICKHOUSE_"+suffix] ?? environment("ADLOG_HISTORY_CLICKHOUSE_"+suffix);
        values["ADLOG_HISTORY_READ_MODE"] = config?["Sli:Storage:HistoryReadMode"] ?? config?["ADLOG_HISTORY_READ_MODE"] ?? environment("ADLOG_HISTORY_READ_MODE");
        values["CREDENTIALS_DIRECTORY"] = config?["CREDENTIALS_DIRECTORY"] ?? environment("CREDENTIALS_DIRECTORY");
        return new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
    }
    HistoryConfiguration(IConfiguration snapshot)
    {
        mode = (snapshot["ADLOG_HISTORY_READ_MODE"] ?? "disabled").Trim().ToLowerInvariant();
        port = snapshot["ADLOG_HISTORY_CLICKHOUSE_PORT"];
        transport = new(() =>
        {
            if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out int number) || number is <1 or >65535)
                throw new EventReadConfigurationException("history_clickhouse_port_invalid");
            string host = snapshot["ADLOG_HISTORY_CLICKHOUSE_HOST"] ?? "127.0.0.1";
            if (Uri.CheckHostName(host) == UriHostNameType.Unknown)
                throw new EventReadConfigurationException("history_clickhouse_host_invalid");
            string user, password;
            try
            {
                user = (InstalledConfiguration.Secret(snapshot,"ADLOG_HISTORY_CLICKHOUSE_USER") ?? "").Trim();
                password = InstalledConfiguration.Secret(snapshot,"ADLOG_HISTORY_CLICKHOUSE_PASSWORD") ?? "";
            }
            catch (ServerConfigurationException) { throw new EventReadConfigurationException("history_clickhouse_secret_invalid"); }
            if (user.Length == 0 || password.Length == 0)
                throw new EventReadConfigurationException("history_clickhouse_credentials_missing");
            return (new UriBuilder("http",host,number).Uri,
                new AuthenticationHeaderValue("Basic",Convert.ToBase64String(Encoding.UTF8.GetBytes(user+":"+password))));
        });
    }
    internal bool HasPort => !string.IsNullOrEmpty(port);
    internal bool Primary => mode switch { "primary" => true, "disabled" => false,
        _ => throw new EventReadConfigurationException("history_read_mode_invalid") };
    internal Uri Endpoint => transport.Value.Endpoint;
    internal HttpClient CreateClient()
    {
        var auth = transport.Value.Auth;
        var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect=false,UseProxy=false }) { Timeout=Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.Authorization=auth;
        return client;
    }
}
