using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Hosting;

public static class IngressHosting
{
    public static void ValidateAdmissionSettings(IConfiguration configuration)
    {
        _ = Bounded(configuration, "HttpMaxConnections", "ADLOG_HTTP_MAX_CONNECTIONS", 64, 1, 256);
        _ = Bounded(configuration, "HttpMaxConcurrentRequests", "ADLOG_HTTP_MAX_CONCURRENT_REQUESTS", 32, 4, 128);
        _ = Bounded(configuration, "HttpRatePerMinute", "ADLOG_HTTP_RATE_PER_MINUTE", 600, 60, 5000);
    }

    public static IServiceCollection AddSliIngress(this IServiceCollection services, IConfiguration configuration, AgentTlsTrust? clientTrust = null)
    {
        services.AddSingleton<AgentCertificateRejections>();
        if (clientTrust is not null)
        {
            services.AddSingleton(_ => clientTrust);
        }
        services.AddSingleton(_ => new DynamicRequestAdmission(
            Bounded(configuration, "HttpRatePerMinute", "ADLOG_HTTP_RATE_PER_MINUTE", 600, 60, 5000)));
        services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
        {
            options.Limits.MaxConcurrentConnections = Bounded(configuration, "HttpMaxConnections", "ADLOG_HTTP_MAX_CONNECTIONS", 64, 1, 256);
            options.Limits.MaxRequestHeadersTotalSize = 64 * 1024;
            options.Limits.MaxRequestHeaderCount = 100;
            options.Limits.MaxRequestLineSize = 8192;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
            options.ConfigureHttpsDefaults(https => https.HandshakeTimeout = TimeSpan.FromSeconds(30));
        });
        if (clientTrust is not null)
        {
            services.AddOptions<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>()
                .Configure<AgentTlsTrust, AgentCertificateRejections>((options, trust, rejections) => options.ConfigureHttpsDefaults(https =>
                {
                    https.HandshakeTimeout = TimeSpan.FromSeconds(30);
                    trust.Configure(https, rejections);
                }));
        }
        services.AddRateLimiter(options =>
        {
            int concurrent = Bounded(configuration, "HttpMaxConcurrentRequests", "ADLOG_HTTP_MAX_CONCURRENT_REQUESTS", 32, 4, 128);
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetConcurrencyLimiter("all",
                _ => new ConcurrencyLimiterOptions { PermitLimit = concurrent, QueueLimit = 0 }));
            options.OnRejected = async (rejected, ct) =>
            {
                HttpContext context = rejected.HttpContext;
                if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path == "/api/auth/login")
                    await AuthResponse.ErrorAsync(context, "server_busy", 429, ct);
                else
                    await DomainHttp.WriteAsync(context, new { error = "server_busy" }, 429, ct);
            };
        });
        return services;
    }

    public static IApplicationBuilder UseSliDynamicAdmission(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        string? bucket = DynamicBucket(context.Request);
        if (bucket is null) { await next(context); return; }
        string client = context.RequestServices.GetRequiredService<AuthRequestPolicy>().Resolve(context).Address;
        if (IPAddress.TryParse(client, out var ip) && ip.IsIPv4MappedToIPv6) client = ip.MapToIPv4().ToString();
        if (!context.RequestServices.GetRequiredService<DynamicRequestAdmission>().Admit(client, bucket))
        {
            context.Response.Headers.RetryAfter = "60";
            await DomainHttp.WriteAsync(context, new { error = "rate_limit_exceeded" }, 429, context.RequestAborted);
            return;
        }
        await next(context);
    });

    private static int Bounded(IConfiguration configuration, string setting, string legacy, int fallback, int min, int max)
    {
        string? raw = configuration["Sli:" + setting] ?? Environment.GetEnvironmentVariable(legacy);
        if (raw is null) return fallback;
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
            throw new ServerConfigurationException("Sli:" + setting);
        return Math.Clamp(value, min, max);
    }

    private static string? DynamicBucket(HttpRequest request)
    {
        string path = request.Path.Value ?? "";
        if (HttpMethods.IsGet(request.Method) && (path is "/" or "/login" or "/app" or "/app/" or "/app.css" or "/app.js" or "/admin.js"
                or "/api/health" or "/api/health/live" or "/api/health/ready" or "/sli-login.css" or "/sli-login.js"
            || path.StartsWith("/app/", StringComparison.Ordinal) || path.StartsWith("/assets/sli-login/", StringComparison.Ordinal))) return null;
        if (HttpMethods.IsPost(request.Method) && path == "/api/auth/login") return null;
        return path.StartsWith("/api/", StringComparison.Ordinal) ? "api" : path.StartsWith("/reports/", StringComparison.Ordinal) ? "reports" : "other";
    }

    // Run before RunAsync/StartAsync: an unsafe listener must never become reachable.
    public static void ValidateBindSecurity(IConfiguration configuration)
    {
        bool proxy = !string.IsNullOrWhiteSpace(configuration["Sli:TrustedProxies"]);
        string[] configured = configuration.GetSection("Kestrel:Endpoints").GetChildren()
            .Select(endpoint => endpoint["Url"] ?? throw new ServerConfigurationException("Kestrel:Endpoints:Url", "missing")).ToArray();
        string? urls = configuration["urls"];
        bool preferUrls = bool.TryParse(configuration["preferHostingUrls"], out bool prefer) && prefer;
        if (configured.Length == 0 || (preferUrls && !string.IsNullOrWhiteSpace(urls)))
        {
            if (!string.IsNullOrWhiteSpace(urls)) configured = urls.Split(';', StringSplitOptions.RemoveEmptyEntries);
            else
            {
                configured = (configuration["HTTP_PORTS"] ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries).Select(port => "http://*:" + port)
                    .Concat((configuration["HTTPS_PORTS"] ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries).Select(port => "https://*:" + port)).ToArray();
                if (configured.Length == 0) configured = ["http://localhost:5000"];
            }
        }
        foreach (string address in configured)
        {
            var endpoint = Microsoft.AspNetCore.Http.BindingAddress.Parse(address);
            bool loopback = endpoint.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || (IPAddress.TryParse(endpoint.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));
            if (endpoint.Scheme is not ("http" or "https") || (!loopback && endpoint.Scheme != "https" && !proxy))
                throw new ServerConfigurationException("Kestrel:Endpoints", "tls_or_trusted_proxies_required");
        }
    }
}
