using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.FileProviders;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Domains;

namespace Sli.Server.Hosting;

public static partial class StaticHosting
{
    // Set Sli:WebRoot to the existing web/app directory. No profile or working-directory fallback.
    public static IEndpointRouteBuilder MapSliStaticAssets(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/login", LoginAsync);
        endpoints.MapGet(InitialAdminPassword.ChangePage, LoginAsync);
        endpoints.MapGet("/sli-login.css", context => SendFileAsync(context, "sli-login.css", "text/css; charset=utf-8", "no-cache"));
        endpoints.MapGet("/sli-login.js", context => SendFileAsync(context, "sli-login.js", "application/javascript; charset=utf-8", "no-cache"));
        foreach (string name in new[] { "collector-server.svg", "feature-brain.svg", "feature-eye.svg", "feature-shield.svg", "sli-logo.svg" })
        {
            string asset = name;
            endpoints.MapGet("/assets/sli-login/" + asset, context => SendFileAsync(context, "assets/sli-login/" + asset, "image/svg+xml", "no-cache"));
        }
        endpoints.MapGet("/", ReactAsync);
        endpoints.MapGet("/app", ReactAsync);
        endpoints.MapGet("/app/{**path}", ReactAsync);
        foreach (string route in new[] { "access", "access-center", "access-requests", "access-user", "admin", "ad-accounts", "ad-report", "agents", "cases", "computers-report", "computers-v5-report", "computers-v6-report", "entities", "events", "extensions", "gpo-report", "gpo-v2-report", "notifications", "objects", "operations", "platform-settings", "plugins", "privileged-report", "problems", "project-readiness", "report", "report-builder", "report-management", "report-editor", "report-studio", "reports", "scenarios", "security-events-report", "security-overview", "settings", "investigations", "setup", "ui-kit", "users-report", "users-v2-report", "vpn-connections", "vpn-report", "what-where-when-report", "workstations" })
            endpoints.MapGet(route == "reports" ? "/reports" : "/" + route + "/{**path}", ReactAsync);
        return endpoints;
    }

    private static async Task LoginAsync(HttpContext context)
    {
        string? token = InitialAdminPassword.RequestToken(context);
        var services = context.RequestServices;
        var transport = services.GetRequiredService<TransportGate>();
        bool changePage = context.Request.Path == InitialAdminPassword.ChangePage;
        if (changePage)
        {
            if (token is null || !transport.IsSecureTransport(context)
                || !await services.GetRequiredService<InitialAdminPassword>().CanChangeAsync(token, context.RequestAborted))
            {
                if (token is not null)
                    context.Response.Headers.SetCookie = AuthEndpoints.Cookie("", 0, true);
                context.Response.Redirect("/login");
                return;
            }
        }
        else if (token is not null)
        {
            context.Response.Redirect(InitialAdminPassword.ChangePage + context.Request.QueryString);
            return;
        }
        await SendFileAsync(context, "login.html", "text/html; charset=utf-8", null);
    }

    private static async Task ReactAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        if (context.RequestServices.GetRequiredService<AuthRequestPolicy>().AuthRequired)
        {
            AuthenticationResult auth = await context.RequestServices.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!auth.Succeeded)
            {
                string target = context.Request.Path + context.Request.QueryString;
                context.Response.Redirect("/login" + QueryString.Create("next", target));
                return;
            }
            if (TransportGate.CheckViewerRole(auth.Principal!) is not null)
            {
                context.Response.Redirect("/");
                return;
            }
        }
        if (context.Request.Path != "/" && !context.Request.Path.StartsWithSegments("/app"))
        {
            context.Response.Redirect("/app" + context.Request.Path.ToUriComponent() + context.Request.QueryString);
            return;
        }
        string relative = Convert.ToString(context.Request.RouteValues["path"]) ?? "";
        bool asset = relative.StartsWith("assets/", StringComparison.Ordinal);
        string path = relative.Length == 0 ? "index.html" : relative;
        using var provider = GetReactProvider(context);
        if (provider is null)
        {
            await DomainHttp.WriteAsync(context, new { error = "react_ui_not_built" }, 503, ct);
            return;
        }
        string candidate = Path.GetFullPath(Path.Combine(provider.Root, path));
        string inside = Path.GetRelativePath(provider.Root, candidate);
        if (Path.IsPathRooted(inside) || inside == ".." || inside.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            await DomainHttp.WriteAsync(context, new { error = "not_found" }, 404, ct);
            return;
        }
        IFileInfo file = provider.GetFileInfo(path);
        if ((!file.Exists || file.IsDirectory) && !asset) file = provider.GetFileInfo("index.html");
        if (!file.Exists || file.IsDirectory)
        {
            await DomainHttp.WriteAsync(context, new { error = "react_ui_not_built" }, 503, ct);
            return;
        }
        string type = Path.GetExtension(file.Name) switch
        {
            ".html" => "text/html; charset=utf-8",
            ".js" => "application/javascript; charset=utf-8",
            ".css" => "text/css; charset=utf-8",
            _ => "application/octet-stream"
        };
        await WriteFileAsync(context, file, type, asset ? "public, max-age=31536000, immutable" : "no-cache");
    }

    private static PhysicalFileProvider? GetReactProvider(HttpContext context)
    {
        var config = context.RequestServices.GetRequiredService<IConfiguration>();
        string? root = config["Sli:ReactRoot"] ?? Environment.GetEnvironmentVariable("ADLOG_REACT_WEB_DIR");
        if (string.IsNullOrWhiteSpace(root))
        {
            string? webRoot = config["Sli:WebRoot"];
            root = string.IsNullOrWhiteSpace(webRoot) ? null : Path.Combine(webRoot, "react");
        }
        return !string.IsNullOrWhiteSpace(root) && Path.IsPathFullyQualified(root) && Directory.Exists(root)
            ? new PhysicalFileProvider(root) : null;
    }

    private static PhysicalFileProvider? GetProvider(HttpContext context)
    {
        string? root = context.RequestServices.GetRequiredService<IConfiguration>()["Sli:WebRoot"];
        return !string.IsNullOrWhiteSpace(root) && Path.IsPathFullyQualified(root) && Directory.Exists(root)
            ? new PhysicalFileProvider(root) : null;
    }

    private static async Task SendFileAsync(HttpContext context, string path, string contentType, string? cache)
    {
        using var provider = GetProvider(context);
        IFileInfo? file = provider?.GetFileInfo(path);
        if (file is null || !file.Exists || file.IsDirectory)
        {
            await DomainHttp.WriteAsync(context, new { error = "file_not_found" }, 404, context.RequestAborted);
            return;
        }
        await WriteFileAsync(context, file, contentType, cache);
    }

    private static async Task WriteFileAsync(HttpContext context, IFileInfo file, string contentType, string? cache)
    {
        string? nonce = null;
        if (contentType.StartsWith("text/html", StringComparison.Ordinal))
        {
            using var reader = new StreamReader(file.CreateReadStream(), new UTF8Encoding(false, true));
            string html = await reader.ReadToEndAsync(context.RequestAborted);
            nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            html = HtmlTag().Replace(html, match => "<" + match.Groups[1].Value + " nonce=\"" + nonce + "\"");
            byte[] bytes = Encoding.UTF8.GetBytes(html);
            DomainHttp.ApplyHeaders(context, cache, nonce);
            await Results.Bytes(bytes, contentType).ExecuteAsync(context);
            return;
        }
        DomainHttp.ApplyHeaders(context, cache, nonce);
        await Results.File(file.CreateReadStream(), contentType).ExecuteAsync(context);
    }

    [GeneratedRegex("<(script|style)(?![^>]*\\bnonce=)(?=[\\s>])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HtmlTag();
}
