using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;

namespace Sli.Server.Auth.Lifecycle;

public sealed record PasswordVerification(bool Valid);
public interface IPasswordCodec
{
    PasswordVerification Verify(string encoded, string password);
    string Hash(string password);
    bool NeedsRehash(string encoded);
}

// PHC parsing, Argon2 computation and constant-time comparison belong to the provider.
// Parameters are loaded only from the stored credential, never from request JSON.
public sealed class PasswordCodec : IPasswordCodec
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public PasswordVerification Verify(string encoded, string password)
    {
        byte[] bytes = Utf8.GetBytes(password);
        try
        {
            var config = new Argon2Config { Password = bytes, Threads = 2 };
            if (!config.DecodeString(encoded, out var hash)) return new(false);
            using (hash)
            {
                if (hash is null || !ValidParameters(config)) return new(false);
            }
            return new(Argon2.Verify(encoded, config));
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException)
        {
            return new(false);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public string Hash(string password)
    {
        byte[] bytes = Utf8.GetBytes(password);
        try
        {
            return Argon2.Hash(new Argon2Config
            {
                Type = Argon2Type.HybridAddressing, Version = Argon2Version.Nineteen,
                TimeCost = 3, MemoryCost = 65536, Lanes = 2, Threads = 2,
                HashLength = 32, Salt = RandomNumberGenerator.GetBytes(16), Password = bytes
            });
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public bool NeedsRehash(string encoded)
    {
        var config = new Argon2Config();
        if (!config.DecodeString(encoded, out var hash)) throw new FormatException("Invalid password hash.");
        using (hash)
            return config.Type != Argon2Type.HybridAddressing || config.Version != Argon2Version.Nineteen
                || config.TimeCost != 3 || config.MemoryCost != 65536 || config.Lanes != 2
                || config.Salt?.Length != 16 || config.HashLength != 32;
    }

    private static bool ValidParameters(Argon2Config config) =>
        config.Version is Argon2Version.Sixteen or Argon2Version.Nineteen
        && config.Type is Argon2Type.DataDependentAddressing or Argon2Type.DataIndependentAddressing or Argon2Type.HybridAddressing
        && config.TimeCost >= 1 && config.Lanes >= 1 && (long)config.MemoryCost >= 8L * config.Lanes
        && config.Salt is { Length: >= 8 } && config.HashLength >= 4;
}
