using System.Globalization;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;

namespace Sli.Server.Sources;

// Deliberately not records: generated ToString must never expose login values.
public sealed class AdSourceLogin(string username, string password)
{
    public string Username { get; } = username;
    public string Password { get; } = password;
    public override string ToString() => "AdSourceLogin";
}
public sealed class EventLogLogin(string server, string? user = null, string? domain = null, string? password = null)
{
    public string Server { get; } = server;
    public string? User { get; } = user;
    public string? Domain { get; } = domain;
    public string? Password { get; } = password;
    public int Flags => 0;
    public override string ToString() => "EventLogLogin";
}
public sealed record AdSourceTarget(string Hostname, string ConnectAddress);

public sealed class AdSourceAuth(Func<IReadOnlyList<AdSourceTarget>> targets, Func<string,string> resolve,
    Func<string,AdSourceLogin> credentials, IWindowsEventLog events, Func<string,string?>? environment = null)
{
    public const string Process = "process", Dpapi = "dpapi_current_user";
    public const string ModeKey = "ADLOG_AD_SOURCE_CREDENTIAL_MODE", ProfileKey = "ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE";
    private readonly Func<string,string?> env = environment ?? Environment.GetEnvironmentVariable;
    public static string ValidateMode(string mode, string backend = "auto")
    {
        if (mode is not (Process or Dpapi)) throw new CollectionSourceException("ad_source_credential_mode_invalid");
        if (mode == Dpapi && backend is not ("python" or "auto")) throw new CollectionSourceException("ad_source_backend_unsupported");
        return mode;
    }
    public string ConfiguredEndpoint(string server, string? connectAddress = null)
    {
        try {
            var matches = targets().Where(t => string.Equals(server,t.Hostname,StringComparison.OrdinalIgnoreCase) || string.Equals(server,t.ConnectAddress,StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1 || connectAddress is not null && !string.Equals(connectAddress,matches[0].ConnectAddress,StringComparison.OrdinalIgnoreCase)) throw new FormatException();
            string address = matches[0].ConnectAddress;
            if (IPAddress.TryParse(address,out _) || !address.Contains('.') || address.Split('.').Any(label => !Regex.IsMatch(label,@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z"))) throw new FormatException();
            string resolved = resolve(matches[0].Hostname);
            if (resolved != matches[0].ConnectAddress) throw new FormatException();
            return resolved;
        }
        catch { throw new CollectionSourceException("ad_source_endpoint_invalid"); }
    }
    internal static void ValidateUsername(string username)
    {
        _ = new UTF8Encoding(false,true).GetByteCount(username);
        if (username.EnumerateRunes().Count() is < 1 or > 1024 || username.EnumerateRunes().Any(c => Rune.IsWhiteSpace(c) || Rune.GetUnicodeCategory(c) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned)
            || username.IndexOfAny("/:\"<>|?*;=,[]".ToCharArray()) >= 0) throw new FormatException();
        string[] parts = username.Count(c => c == '\\') == 1 && !username.Contains('@') ? username.Split('\\')
            : username.Count(c => c == '@') == 1 && !username.Contains('\\') ? username.Split('@') : [];
        if (parts.Length != 2 || parts.Any(x => x is "" or "." or "..")) throw new FormatException();
    }
    public IEventLogSession? Open(string server, string mode = Process, bool configuredDc = false)
    {
        ValidateMode(mode);
        if (mode == Process) {
            string target = configuredDc ? ConfiguredEndpoint(server) : server.Trim();
            if (target is "" or "." || new[] { "localhost", "127.0.0.1", env("COMPUTERNAME") }.Any(x => string.Equals(x,target,StringComparison.OrdinalIgnoreCase))) return null;
            return events.Open(new(target));
        }
        // Admission must precede secret access and RPC, including profile selection.
        string endpoint = ConfiguredEndpoint(server);
        string profile = env(ProfileKey) ?? "ad";
        if (profile is not ("ad" or "vpn")) throw new CollectionSourceException("ad_source_credential_profile_invalid");
        EventLogLogin login;
        try {
            var value = credentials(profile); ValidateUsername(value.Username);
            string[] parts = value.Username.Split('\\');
            login = parts.Length == 2 ? new(endpoint,parts[1],parts[0],value.Password) : new(endpoint,value.Username,null,value.Password);
        }
        catch { throw new CollectionSourceException("ad_source_credentials_unavailable"); }
        try { return events.Open(login); }
        catch (Exception e) { throw CollectionFailurePolicy.Sanitize(e); }
    }
}
