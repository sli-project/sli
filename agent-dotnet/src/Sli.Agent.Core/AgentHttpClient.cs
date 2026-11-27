using System.Net;
using System.ComponentModel;
using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
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

public sealed class AgentHttpClient(HttpClient http, bool clientCertificateConfigured = false) : IPacketTransport, IAgentControlTransport, IDisposable
{
    public const string PacketsPath = "/api/v1/agent/packets";
    public const int MaxResponseBytes = Packets.MaxPacketBytes;

    public async Task<JsonNode?> PostPacketAsync(SignedPacket packet, CancellationToken cancellationToken) =>
        await PostAsync(PacketsPath, packet.ToJson(), cancellationToken).ConfigureAwait(false);

    public Task<JsonObject> PostAsync(string path, JsonNode body, CancellationToken cancellationToken) => SendAsync(HttpMethod.Post, path, body, cancellationToken);

    public Task<JsonObject> GetAsync(string path, CancellationToken cancellationToken) => SendAsync(HttpMethod.Get, path, null, cancellationToken);

    public Task<JsonObject> GetIdentityAsync(bool supportsFileAuditCatalog, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, "/api/v1/agent/identity", null, cancellationToken, supportsFileAuditCatalog);

    private async Task<JsonObject> SendAsync(HttpMethod method, string path, JsonNode? body, CancellationToken cancellationToken,
        bool supportsFileAuditCatalog = false)
    {
        // HttpClient.Timeout with ResponseHeadersRead ends at the headers. Keep the same deadline
        // through the entire body, including for bootstrap, check-in, reports and packets.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(http.Timeout > TimeSpan.Zero && http.Timeout < AgentHttp.Timeout ? http.Timeout : AgentHttp.Timeout);
        var token = deadline.Token;
        int? rejectedStatus = null;
        try
        {
            using var request = new HttpRequestMessage(method, path);
            if (supportsFileAuditCatalog) request.Headers.Add("X-SLI-File-Audit-Catalog", "1");
            if (body is not null)
            {
                request.Content = new ByteArrayContent(CanonicalJson.ToBytes(body));
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            // These enrollment statuses require an administrator, not another attempt with the same one-use token.
            // Preserve the terminal one-use-token bootstrap contract.
            if (path == "/api/v1/agent/enroll" && response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Conflict)
                throw new TransportException("agent_bootstrap_rejected", (int)response.StatusCode);
            var rejected = response.StatusCode != HttpStatusCode.OK;
            rejectedStatus = rejected ? (int)response.StatusCode : null;
            var rejection = TransportErrors.HttpCode((int)response.StatusCode);
            await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > MaxResponseBytes)
                    throw new TransportException(rejected ? rejection : "agent_transport_failed", rejectedStatus);
            }
            if (rejected)
            {
                try
                {
                    if (JsonNode.Parse(buffer.ToArray()) is JsonObject error && JsonRead.TryString(error["error"], out var code))
                    {
                        if (path == "/api/v1/agent/enroll" && response.StatusCode == HttpStatusCode.BadRequest
                            && code == "invalid_agent_registration_name")
                            throw new TransportException(rejection, rejectedStatus) { EnrollmentRejectionReason = code };
                        if (code is "agent_instance_name_mismatch" or "agent_registration_name_mismatch"
                            or "agent_csr_key_mismatch" or "agent_host_already_enrolled" or "agent_certificate_rejected"
                            or "agent_mtls_required" or "agent_service_unavailable" or "invalid_agent_module_config")
                            rejection = code;
                    }
                }
                catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException) { }
                throw new TransportException(rejection, rejectedStatus);
            }
            return JsonNode.Parse(buffer.ToArray()) as JsonObject ?? throw new TransportException();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw rejectedStatus is int status
                ? new TransportException(TransportErrors.HttpCode(status), status)
                : new TransportException("agent_http_timeout");
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or IOException or AuthenticationException)
        {
            var httpStatus = rejectedStatus ?? (exception is HttpRequestException { StatusCode: { } status } ? (int)status : null);
            throw httpStatus is int received
                ? new TransportException(TransportErrors.HttpCode(received), received)
                : new TransportException(TransportErrors.Code(exception, clientCertificateConfigured));
        }
    }

    public void Dispose() => http.Dispose();
}

/// <summary>Only allowlisted codes cross the transport boundary; never retain exception messages or inner exceptions.</summary>
internal static class TransportErrors
{
    internal static bool IsDiagnostic(string code) => code is "agent_http_timeout" or "agent_tls_client_key_unusable"
        or "agent_tls_server_untrusted" or "agent_tls_name_mismatch";

    internal static string HttpCode(int status) => "agent_server_rejected_" + status.ToString(CultureInfo.InvariantCulture);

    internal static string Detail(string code, int? status) => status is int httpStatus
        ? "Server returned HTTP " + httpStatus.ToString(CultureInfo.InvariantCulture) + "."
        : code switch
        {
            "agent_dns_failed" => "Could not resolve the server name.",
            "agent_tcp_refused" => "The server refused the TCP connection.",
            "agent_http_timeout" => "The connection or response from the server timed out.",
            "agent_tls_server_untrusted" => "The server certificate is not trusted.",
            "agent_tls_name_mismatch" => "The server certificate does not match the server name.",
            "agent_tls_server_expired" => "The server certificate chain has expired.",
            "agent_tls_client_rejected" => "The server rejected the agent certificate during TLS.",
            "agent_tls_client_key_unusable" => "The agent certificate private key is unavailable.",
            "agent_tls_handshake_failed" => "The TLS handshake with the server failed.",
            _ => "Communication with the server failed."
        };

    internal static string Code(Exception exception, bool clientCertificateConfigured)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TransportException transport && (IsDiagnostic(transport.Code) || transport.Code == "agent_tls_server_expired"))
                return transport.Code;
            if (current is TimeoutException or SocketException { SocketErrorCode: SocketError.TimedOut })
                return "agent_http_timeout";
            if (current is HttpRequestException { HttpRequestError: HttpRequestError.NameResolutionError }
                or SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData or SocketError.NoRecovery })
                return "agent_dns_failed";
            if (current is SocketException { SocketErrorCode: SocketError.ConnectionRefused }) return "agent_tcp_refused";
            if (current is AuthenticationException or Win32Exception or IOException or CryptographicException
                && IsCertificateAlert(current.Message))
                return "agent_tls_client_rejected";
            var native = current is Win32Exception windows ? windows.NativeErrorCode : current.HResult;
            var code = unchecked((uint)native) switch
            {
                // SEC_E_NO_CREDENTIALS / UNKNOWN_CREDENTIALS and unavailable Windows key containers.
                0x8009030E or 0x8009030D or 0x80090016 or 0x8009000B or 0x8009000D => "agent_tls_client_key_unusable",
                0x80090322 or 0x800B010F => "agent_tls_name_mismatch",
                // Schannel returns these statuses for peer alerts as well. AgentHttp handles
                // local server trust failures in its callback using explicit transport codes.
                0x80090325 or 0x80090328 or 0x80092010 when clientCertificateConfigured => "agent_tls_client_rejected",
                0x80090325 or 0x800B0109 or 0x800B010A or 0x800B0110 or 0x800B010C => "agent_tls_server_untrusted",
                0x80090328 or 0x800B0101 => "agent_tls_server_expired",
                0x80090327 => "agent_tls_client_rejected", // Schannel SEC_E_CERT_UNKNOWN for peer certificate alerts.
                _ => null,
            };
            if (code is not null) return code;
        }
        return exception is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError }
            ? "agent_tls_handshake_failed" : "agent_transport_failed";
    }

    private static bool IsCertificateAlert(string message)
    {
        // .NET's managed alert names and the OpenSSL alert reason are invariant.
        // Match the alert only, and never report native exception text.
        if (message.Contains("sent a TLS alert:", StringComparison.Ordinal))
            return message.Contains("'BadCertificate'", StringComparison.Ordinal)
                || message.Contains("'CertificateUnknown'", StringComparison.Ordinal)
                || message.Contains("'CertificateExpired'", StringComparison.Ordinal)
                || message.Contains("'CertificateRevoked'", StringComparison.Ordinal)
                || message.Contains("'UnsupportedCertificate'", StringComparison.Ordinal)
                || message.Contains("'UnknownCA'", StringComparison.Ordinal)
                || message.Contains("'CertificateRequired'", StringComparison.Ordinal);
        return message.Contains("alert bad certificate", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert certificate unknown", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert certificate expired", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert certificate revoked", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert unsupported certificate", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert unknown ca", StringComparison.OrdinalIgnoreCase)
            || message.Contains("alert certificate required", StringComparison.OrdinalIgnoreCase);
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
                    if (!trusted)
                    {
                        var now = DateTime.UtcNow;
                        var expired = certificate is X509Certificate2 leaf && leaf.NotAfter.ToUniversalTime() <= now
                            || chain is not null && chain.ChainElements.Cast<X509ChainElement>()
                                .Any(element => element.Certificate.NotAfter.ToUniversalTime() <= now);
                        throw new TransportException(expired ? "agent_tls_server_expired" : "agent_tls_server_untrusted");
                    }
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
