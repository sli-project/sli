using System.Net;
using System.Text.RegularExpressions;
using Sli.Server.Hosting;

namespace Sli.Server.Auth.Lifecycle;

public sealed record AuthRequestIdentity(string Address, string Scheme, string Host);

// Mirrors the existing edge-proxy trust contract. Untrusted forwarded headers never
// participate in source admission, cookie security or same-origin decisions.
public sealed class AuthRequestPolicy
{
    private readonly System.Net.IPNetwork[] proxies;
    public bool AuthRequired { get; }
    public bool AllowInsecureHttp { get; }
    public bool SecureCookie { get; }
    public bool OwnerSetup { get; }

    public AuthRequestPolicy(IConfiguration configuration)
    {
        static bool True(string? value) => value?.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
        static string? Setting(IConfiguration c, string name, string legacy) => c["Sli:" + name] ?? Environment.GetEnvironmentVariable(legacy);
        string required = (Setting(configuration, "AuthRequired", "ADLOG_AUTH_REQUIRED") ?? "1").Trim().ToLowerInvariant();
        AuthRequired = required switch
        {
            "" or "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => throw new ServerConfigurationException("Sli:AuthRequired")
        };
        if (!AuthRequired && !True(Setting(configuration, "AllowUnauthenticated", "ADLOG_ALLOW_UNAUTHENTICATED")))
            throw new ServerConfigurationException("Sli:AllowUnauthenticated", "required");
        AllowInsecureHttp = True(Setting(configuration, "AuthAllowInsecureHttp", "ADLOG_AUTH_ALLOW_INSECURE_HTTP"));
        SecureCookie = True(Setting(configuration, "AuthCookieSecure", "ADLOG_AUTH_COOKIE_SECURE"));
        OwnerSetup = Setting(configuration, "OwnerSetup", "SLI_OWNER_SETUP") == "1";
        string trusted = configuration["Sli:TrustedProxies"] ?? "";
        try { proxies = string.IsNullOrWhiteSpace(trusted) ? [] : trusted.Split(',').Select(item =>
        {
            string cidr = item.Trim();
            if (!cidr.Contains('/')) cidr += IPAddress.Parse(cidr).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/32" : "/128";
            return System.Net.IPNetwork.Parse(cidr);
        }).ToArray(); }
        catch (Exception error) when (error is FormatException or ArgumentException)
        { throw new ServerConfigurationException("Sli:TrustedProxies"); }
    }

    private bool Trusted(IPAddress address) => proxies.Any(n => n.Contains(address));
    private static string Single(HttpRequest request, string header) => request.Headers[header].Count == 1 ? request.Headers[header][0]?.Trim() ?? "" : "";

    public AuthRequestIdentity Resolve(HttpContext context)
    {
        var peer = context.Connection.RemoteIpAddress;
        string address = peer?.ToString() ?? "";
        string scheme = context.Request.IsHttps ? "https" : "http";
        string host = Single(context.Request, "Host");
        if (peer is not null && Trusted(peer))
        {
            string proto = Single(context.Request, "X-Forwarded-Proto").ToLowerInvariant();
            if (proto is "http" or "https") scheme = proto;
            string forwardedHost = Single(context.Request, "X-Forwarded-Host");
            if (CanonicalOrigin(scheme, forwardedHost).Length != 0) host = forwardedHost;
            string forwarded = Single(context.Request, "X-Forwarded-For");
            if (forwarded.Length is > 0 and <= 4096)
            {
                string[] hops = forwarded.Split(',');
                var parsed = new List<IPAddress>();
                if (hops.Length <= 32)
                    foreach (string hop in hops)
                        if (IPAddress.TryParse(hop.Trim(), out var ip)) parsed.Add(ip); else { parsed.Clear(); break; }
                IPAddress client = peer;
                foreach (var ip in parsed.AsEnumerable().Reverse())
                {
                    if (!Trusted(client)) break;
                    client = ip;
                }
                address = client.ToString();
            }
            else if (!context.Request.Headers.ContainsKey("X-Forwarded-For") && IPAddress.TryParse(Single(context.Request, "X-Real-IP"), out var real))
                address = real.ToString();
        }
        return new(address, scheme, host);
    }

    public bool OriginAllowed(HttpContext context, AuthRequestIdentity identity)
    {
        var values = context.Request.Headers.Origin;
        if (values.Count == 0) return true;
        if (values.Count != 1) return false;
        string origin = values[0] ?? "";
        if (origin.Any(char.IsWhiteSpace) || !Uri.TryCreate(origin, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length != 0 || uri.AbsolutePath is not ("" or "/") || uri.Query.Length != 0 || uri.Fragment.Length != 0) return false;
        string normalized = CanonicalOrigin(uri.Scheme, uri.Authority);
        return normalized.Length != 0 && normalized == CanonicalOrigin(identity.Scheme, identity.Host);
    }

    public static string CanonicalOrigin(string scheme, string host)
    {
        if (scheme is not ("http" or "https") || !Regex.IsMatch(host, @"\A[A-Za-z0-9.\-_:\[\]]+\z")) return "";
        if (!Uri.TryCreate(scheme + "://" + host, UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 || uri.Host.Length == 0) return "";
        string hostname = uri.Host;
        if (!hostname.StartsWith('[') && !Regex.IsMatch(hostname, @"\A[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*\.?\z")) return "";
        return scheme + "://" + hostname.ToLowerInvariant() + (uri.IsDefaultPort ? "" : ":" + uri.Port);
    }
}
