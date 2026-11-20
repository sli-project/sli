using System.Net;
using System.ComponentModel;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// The agent's outbound HTTPS calls (<c>sli_agent/transport.py</c>): JSON in canonical form, answer accepted only as
/// HTTP 200 with a JSON object of at most 60 KiB. Rejections expose only a finite allowlist
/// or the HTTP status. Server bodies, certificate details and exception text are never kept.
/// </summary>
public interface IAgentControlTransport
{
    Task<JsonObject> PostAsync(string path, JsonNode body, CancellationToken cancellationToken);
    Task<JsonObject> GetAsync(string path, CancellationToken cancellationToken);
}

public sealed class AgentHttpClient(HttpClient http) : IPacketTransport, IAgentControlTransport, IDisposable
{
    public const string PacketsPath = "/api/v1/agent/packets";
    public const int MaxResponseBytes = Packets.MaxPacketBytes;

    public async Task<JsonNode?> PostPacketAsync(SignedPacket packet, CancellationToken cancellationToken) =>
        await PostAsync(PacketsPath, packet.ToJson(), cancellationToken).ConfigureAwait(false);

    public Task<JsonObject> PostAsync(string path, JsonNode body, CancellationToken cancellationToken) => SendAsync(HttpMethod.Post, path, body, cancellationToken);

    public Task<JsonObject> GetAsync(string path, CancellationToken cancellationToken) => SendAsync(HttpMethod.Get, path, null, cancellationToken);

    private async Task<JsonObject> SendAsync(HttpMethod method, string path, JsonNode? body, CancellationToken cancellationToken)
    {
        // HttpClient.Timeout with ResponseHeadersRead ends at the headers. Keep the same deadline
        // through the entire body, including for bootstrap, check-in, reports and packets.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(http.Timeout > TimeSpan.Zero && http.Timeout < AgentHttp.Timeout ? http.Timeout : AgentHttp.Timeout);
        var token = deadline.Token;
        try
        {
            using var request = new HttpRequestMessage(method, path);
            if (body is not null)
            {
                request.Content = new ByteArrayContent(CanonicalJson.ToBytes(body));
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            // These enrollment statuses require an administrator, not another attempt with the same one-use token.
            // Preserve the terminal one-use-token bootstrap contract.
            if (path == "/api/v1/agent/enroll" && response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Conflict)
                throw new TransportException("agent_bootstrap_rejected");
            var rejected = response.StatusCode != HttpStatusCode.OK;
            var rejection = $"agent_server_rejected_{(int)response.StatusCode}";
            await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > MaxResponseBytes) throw new TransportException(rejected ? rejection : "agent_transport_failed");
            }
            if (rejected)
            {
                try
                {
                    if (JsonNode.Parse(buffer.ToArray()) is JsonObject error && JsonRead.TryString(error["error"], out var code)
                        && code is "agent_instance_name_mismatch" or "agent_registration_name_mismatch"
                            or "agent_csr_key_mismatch" or "agent_host_already_enrolled" or "agent_certificate_rejected"
                            or "agent_mtls_required" or "agent_service_unavailable" or "invalid_agent_module_config")
                        rejection = code;
                }
                catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException) { }
                throw new TransportException(rejection);
            }
            return JsonNode.Parse(buffer.ToArray()) as JsonObject ?? throw new TransportException();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TransportException("agent_http_timeout");
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or IOException or AuthenticationException)
        {
            throw new TransportException(TransportErrors.Code(exception));
        }
    }

    public void Dispose() => http.Dispose();
}

/// <summary>Only allowlisted codes cross the transport boundary; never retain exception messages or inner exceptions.</summary>
internal static class TransportErrors
{
    internal static bool IsDiagnostic(string code) => code is "agent_http_timeout" or "agent_tls_client_key_unusable"
        or "agent_tls_server_untrusted" or "agent_tls_name_mismatch";

    internal static string Code(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TransportException transport && IsDiagnostic(transport.Code)) return transport.Code;
            if (current is TimeoutException || current is System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.TimedOut })
                return "agent_http_timeout";
            var native = current is Win32Exception windows ? windows.NativeErrorCode : current.HResult;
            var code = unchecked((uint)native) switch
            {
                // SEC_E_NO_CREDENTIALS / UNKNOWN_CREDENTIALS and unavailable Windows key containers.
                0x8009030E or 0x8009030D or 0x80090016 or 0x8009000B or 0x8009000D => "agent_tls_client_key_unusable",
                0x80090322 or 0x800B010F => "agent_tls_name_mismatch",
                0x80090325 or 0x80090328 or 0x800B0109 or 0x800B010A or 0x800B0101 or 0x800B0110 or 0x800B010C => "agent_tls_server_untrusted",
                _ => null,
            };
            if (code is not null) return code;
        }
        return "agent_transport_failed";
    }
}

/// <summary>Builds the HTTP client: TLS 1.2+, no redirects, no proxy, trust only the configured CA, optional client certificate.</summary>
public static class AgentHttp
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public static HttpClient Create(Uri serverUrl, X509Certificate2? clientCertificate, X509Certificate2Collection trustedRoots, string? caFingerprint = null)
    {
        if (serverUrl.Scheme != Uri.UriSchemeHttps || serverUrl.UserInfo.Length > 0 || serverUrl.Query.Length > 0 || serverUrl.Fragment.Length > 0
            || serverUrl.AbsolutePath != "/") throw new AgentException("agent_config_invalid");
        if (clientCertificate is not null && !clientCertificate.HasPrivateKey) throw new TransportException("agent_tls_client_key_unusable");
        // Schannel cannot use the ephemeral key attached by CopyWithPrivateKey. Import into a
        // temporary machine key container, without adding certificates to any X509Store.
        // Omitting PersistKeySet lets .NET delete the protected key container on Dispose.
        var windowsCertificate = clientCertificate is not null && OperatingSystem.IsWindows() ? LoadWindowsClientCertificate(clientCertificate) : null;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ConnectTimeout = Timeout,
            // The server closes an idle packet connection after 5 s; the Python agent drops it after 2 s.
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(2),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                TargetHost = serverUrl.IdnHost,
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                {
                    if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) throw new TransportException("agent_tls_name_mismatch");
                    var trusted = caFingerprint is null ? trustedRoots.Count == 0 ? errors == SslPolicyErrors.None
                        : ServerTrust.IsTrusted(certificate, chain, errors, trustedRoots)
                        : ServerTrust.IsPinned(certificate, chain, errors, caFingerprint);
                    if (!trusted) throw new TransportException("agent_tls_server_untrusted");
                    return true;
                },
            },
        };
        if (clientCertificate is not null) handler.SslOptions.ClientCertificates = [windowsCertificate ?? clientCertificate];
        HttpMessageHandler owned = windowsCertificate is null ? handler : new CertificateLifetimeHandler(handler, windowsCertificate);
        return new HttpClient(owned, disposeHandler: true) { BaseAddress = serverUrl, Timeout = Timeout };
    }

    private static X509Certificate2 LoadWindowsClientCertificate(X509Certificate2 certificate)
    {
        byte[]? pkcs12 = null;
        try
        {
            var password = RandomNumberGenerator.GetHexString(64);
            pkcs12 = certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
            // No UserKeySet, Exportable or PersistKeySet: LocalSystem does not need a user profile,
            // and the temporary OS-protected key is not retained after the HTTP client is disposed.
            return X509CertificateLoader.LoadPkcs12(pkcs12, password, X509KeyStorageFlags.MachineKeySet);
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            throw new TransportException("agent_tls_client_key_unusable");
        }
        finally
        {
            if (pkcs12 is not null) CryptographicOperations.ZeroMemory(pkcs12);
        }
    }

    private sealed class CertificateLifetimeHandler(HttpMessageHandler inner, X509Certificate2 certificate) : DelegatingHandler(inner)
    {
        protected override void Dispose(bool disposing)
        {
            try { base.Dispose(disposing); }
            finally { if (disposing) certificate.Dispose(); }
        }
    }
}

public static class ServerTrust
{
    public static bool IsPinned(X509Certificate? certificate, X509Chain? presented, SslPolicyErrors errors, string fingerprint)
    {
        if (presented is null || !System.Text.RegularExpressions.Regex.IsMatch(fingerprint, "^[a-fA-F0-9]{64}$")) return false;
        var pinned = new X509Certificate2Collection();
        foreach (var element in presented.ChainElements)
            if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(element.Certificate.RawData)).Equals(fingerprint, StringComparison.OrdinalIgnoreCase)
                && element.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority == true)
                pinned.Add(element.Certificate);
        return pinned.Count == 1 && IsTrusted(certificate, presented, errors, pinned);
    }

    /// <summary>Like Python's <c>ssl.create_default_context(cafile=...)</c>: only the supplied CAs are trusted and the name must match.</summary>
    public static bool IsTrusted(X509Certificate? certificate, X509Chain? presented, SslPolicyErrors errors, X509Certificate2Collection trustedRoots)
    {
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
        using var leaf = new X509Certificate2(certificate);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(trustedRoots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        if (presented is not null)
        {
            foreach (var element in presented.ChainElements) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        }
        return chain.Build(leaf);
    }
}
