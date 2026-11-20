using System.Net;
using Sli.Server.Hosting;

namespace Sli.Server.Auth;

public sealed class TransportGate
{
    private readonly System.Net.IPNetwork[] trustedProxies;

    public TransportGate(IConfiguration configuration)
    {
        string value = configuration["Sli:TrustedProxies"] ?? "";
        try
        {
            trustedProxies = string.IsNullOrWhiteSpace(value) ? [] : value.Split(',').Select(item =>
            {
                var text = item.Trim();
                if (!text.Contains('/'))
                {
                    var address = IPAddress.Parse(text);
                    text += address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/32" : "/128";
                }
                return System.Net.IPNetwork.Parse(text);
            }).ToArray();
        }
        catch (FormatException)
        {
            throw new ServerConfigurationException("Sli:TrustedProxies");
        }
    }

    public AuthenticationFailure? CheckTransport(HttpContext context)
    {
        if (trustedProxies.Length == 0 || !context.Request.Path.StartsWithSegments("/api")) return null;
        return IsSecureTransport(context) ? null : new(403, "secure_transport_required");
    }

    public bool IsSecureTransport(HttpContext context)
    {
        bool secure = context.Request.IsHttps;
        var peer = context.Connection.RemoteIpAddress;
        if (peer is not null && trustedProxies.Any(network => network.Contains(peer)))
        {
            var values = context.Request.Headers["X-Forwarded-Proto"];
            string proto = values.Count == 1 ? values[0]?.Trim().ToLowerInvariant() ?? "" : "";
            if (proto is "http" or "https") secure = proto == "https";
        }
        return secure;
    }

    public static AuthenticationFailure? CheckViewerRole(Principal principal) =>
        principal.Role is "viewer" or "operator" or "admin" ? null : new(403, "insufficient_permissions");
}
