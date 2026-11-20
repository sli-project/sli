using System.Security.Cryptography;
using System.Text;

namespace Sli.Server.Auth.Lifecycle;

public interface ICredentialTokens
{
    string NewSessionToken();
    string Digest(string token);
}

public sealed class CredentialTokens : ICredentialTokens
{
    public string NewSessionToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string Digest(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
