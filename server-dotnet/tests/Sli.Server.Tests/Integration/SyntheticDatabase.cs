using System.Collections;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Sli.Server.Tests.Integration;

// These values come from the external control operation, never from the proof itself.
internal sealed record OwnedDatabaseBinding(string Root, Guid RunId, string Side, string ProofSha256,
    string ExpectedContainer, string ExpectedNetwork, string ExpectedVolume, string ExpectedImage,
    string ExpectedHost, int ExpectedPort, string ExpectedSourceSha256, string ExpectedConfigSha256)
{
    public static OwnedDatabaseBinding FromEnvironment()
    {
        static string Required(string key) => Environment.GetEnvironmentVariable("SLI_T2_" + key)
            ?? throw new InvalidOperationException("Missing explicit T2 binding: " + key);
        return new(Required("ROOT"), Guid.Parse(Required("RUN_ID")), Required("SIDE"), Required("PROOF_SHA256"),
            Required("CONTAINER"), Required("NETWORK"), Required("VOLUME"), Required("IMAGE"),
            Required("HOST"), int.Parse(Required("PORT"), CultureInfo.InvariantCulture),
            Required("SOURCE_SHA256"), Required("CONFIG_SHA256"));
    }
}

internal sealed class SyntheticDatabase : IAsyncDisposable
{
    private const string Image = "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c";
    private const string SourceHash = "86ea77320b99f29f358b528b439ccace77887a19bc037ecd12cfda2e81bd8836";
    private readonly OwnedDatabaseBinding binding;
    private bool disposed;
    private SyntheticDatabase(OwnedDatabaseBinding binding) => this.binding = binding;

    public static async Task<SyntheticDatabase> BorrowAsync(OwnedDatabaseBinding binding, CancellationToken ct)
    {
        var db = new SyntheticDatabase(binding);
        await db.AssertProofAsync(binding.ProofSha256, ct);
        return db;
    }

    private static bool IsHash(string s) => s.Length == 64 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string Text(JsonElement e, string key) => e.GetProperty(key).GetString() ?? throw new InvalidOperationException();
    private static void Check(bool condition) { if (!condition) throw new InvalidOperationException("Owned database admission refused"); }

    private static string SafePath(string root, params string[] parts)
    {
        Check(Path.IsPathFullyQualified(root) && !root.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Contains(".."));
        string fullRoot = Path.GetFullPath(root);
        string path = Path.GetFullPath(Path.Combine(new[] { fullRoot }.Concat(parts).ToArray()));
        Check(path.StartsWith(Path.TrimEndingDirectorySeparator(fullRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        // Reject reparse points in every existing ancestor, including the root itself.
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            Check((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0);
        return path;
    }

    private static void RejectInheritedDatabaseSettings()
    {
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            string key = (string)item.Key;
            Check(!key.StartsWith("PG", StringComparison.OrdinalIgnoreCase)
                && !key.StartsWith("POSTGRES", StringComparison.OrdinalIgnoreCase)
                && !key.Equals("DATABASE_URL", StringComparison.OrdinalIgnoreCase));
        }
    }

    internal async Task<string> AssertProofAsync(string expectedHash, CancellationToken ct)
    {
        Check(!disposed && binding.RunId != Guid.Empty && binding.RunId.ToString("D")[14] == '4'
            && binding.Side is "python" or "dotnet" && IsHash(expectedHash) && expectedHash == binding.ProofSha256);
        RejectInheritedDatabaseSettings();
        try
        {
            string path = SafePath(binding.Root, binding.RunId.ToString("D"), binding.Side, "proof.json");
            byte[] bytes = await File.ReadAllBytesAsync(path, ct);
            Check(Hash(bytes) == expectedHash);
            using var doc = JsonDocument.Parse(bytes);
            var p = doc.RootElement;
            string[] fields = ["format", "run_id", "side", "container_id", "volume_id", "network_id", "host", "port", "database", "user", "sentinel_sha256", "image_digest", "config_manifest_sha256", "source_tree_sha256", "verified_at", "expires_at"];
            Check(p.ValueKind == JsonValueKind.Object && p.EnumerateObject().Count() == fields.Length
                && p.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() == fields.Length
                && fields.All(x => p.TryGetProperty(x, out _)));
            Check(Text(p, "format") == "sli.test.owned-pg-proof.v1" && Text(p, "run_id") == binding.RunId.ToString("D")
                && Text(p, "side") == binding.Side && Text(p, "host") == "127.0.0.1" && binding.ExpectedHost == "127.0.0.1"
                && p.GetProperty("port").GetInt32() == binding.ExpectedPort && binding.ExpectedPort is >= 1024 and <= 65535 and not 5432
                && Text(p, "database") == "sli_oracle" && Text(p, "user") == "adlog_user"
                && Text(p, "container_id") == binding.ExpectedContainer && IsHash(binding.ExpectedContainer)
                && Text(p, "network_id") == binding.ExpectedNetwork && IsHash(binding.ExpectedNetwork)
                && Text(p, "volume_id") == binding.ExpectedVolume && binding.ExpectedVolume == $"sli-test-{binding.RunId:D}-{binding.Side}"
                && Text(p, "image_digest") == Image && binding.ExpectedImage == Image
                && Text(p, "source_tree_sha256") == binding.ExpectedSourceSha256 && binding.ExpectedSourceSha256 == SourceHash
                && Text(p, "config_manifest_sha256") == binding.ExpectedConfigSha256 && IsHash(binding.ExpectedConfigSha256)
                && IsHash(Text(p, "sentinel_sha256")));
            var verified = DateTimeOffset.Parse(Text(p, "verified_at"), CultureInfo.InvariantCulture);
            var expires = DateTimeOffset.Parse(Text(p, "expires_at"), CultureInfo.InvariantCulture);
            Check(verified <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow < expires && expires - verified <= TimeSpan.FromMinutes(5));
            return Text(p, "sentinel_sha256");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is not InvalidOperationException || ex.Message != "Owned database admission refused")
        { throw new InvalidOperationException("Owned database admission refused"); }
    }

    internal async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken ct)
    {
        await AssertProofAsync(binding.ProofSha256, ct);
        NpgsqlConnectionStringBuilder builder;
        try
        {
            string path = SafePath(binding.Root, binding.RunId.ToString("D"), binding.Side, "runtime-secret.json");
            using var secret = JsonDocument.Parse(await File.ReadAllBytesAsync(path, ct));
            var s = secret.RootElement;
            string[] fields = ["format", "run_id", "side", "host", "port", "database", "user", "password"];
            Check(s.ValueKind == JsonValueKind.Object && s.EnumerateObject().Count() == fields.Length
                && s.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() == fields.Length
                && fields.All(x => s.TryGetProperty(x, out _)));
            string password = Text(s, "password");
            Check(Text(s, "format") == "sli.test.pg.runtime-credential.v1" && Text(s, "run_id") == binding.RunId.ToString("D")
                && Text(s, "side") == binding.Side && Text(s, "host") == binding.ExpectedHost
                && s.GetProperty("port").GetInt32() == binding.ExpectedPort && Text(s, "database") == "sli_oracle"
                && Text(s, "user") == "adlog_user" && password.Length >= 16);
            builder = new NpgsqlConnectionStringBuilder { Host = binding.ExpectedHost, Port = binding.ExpectedPort,
                Database = "sli_oracle", Username = "adlog_user", Password = password, SslMode = SslMode.Disable,
                Pooling = false, Enlist = false, Timeout = 3, CommandTimeout = 5, IncludeErrorDetail = false };
            Check(builder.Host == "127.0.0.1" && builder.Port == binding.ExpectedPort && builder.Database == "sli_oracle"
                && builder.Username == "adlog_user" && !builder.Pooling && builder.SslMode == SslMode.Disable);
            await AssertProofAsync(binding.ProofSha256, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch { throw new InvalidOperationException("Owned database connection refused"); }

        // Admission failures above are redacted. Native connect/query failures
        // below must retain their original type, SQLSTATE and stack trace.
        var connection = new NpgsqlConnection(builder.ConnectionString);
        try
        {
            await connection.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select run_id::text, side, sentinel from public.sli_test_ownership", connection);
            await using var reader = await command.ExecuteReaderAsync(ct);
            Check(await reader.ReadAsync(ct) && reader.GetString(0) == binding.RunId.ToString("D") && reader.GetString(1) == binding.Side);
            string actual = Hash(Encoding.UTF8.GetBytes(reader.GetString(2)));
            Check(!await reader.ReadAsync(ct));
            // Use the sentinel from the same bytes that passed proof validation,
            // keeping proof read/parse failures inside the redaction boundary.
            string expected = await AssertProofAsync(binding.ProofSha256, ct);
            Check(actual == expected);
            return connection;
        }
        catch
        {
            try { await connection.DisposeAsync(); }
            catch (Exception) { /* Cleanup must not replace the original failure. */ }
            throw;
        }
    }

    internal async Task<(int MajorVersion, int SchemaVersion, long LedgerRows)> ReadBaselineAsync(CancellationToken ct)
    {
        await using var connection = await OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("select current_setting('server_version_num')::int / 10000, max(version)::int, count(*) from public.schema_migrations", connection);
        await using var reader = await command.ExecuteReaderAsync(ct);
        Check(await reader.ReadAsync(ct));
        return (reader.GetInt32(0), reader.GetInt32(1), reader.GetInt64(2));
    }

    internal async Task MutateSeedAsync(CancellationToken ct)
    {
        await using var connection = await OpenConnectionAsync(ct);
        await AssertProofAsync(binding.ProofSha256, ct);
        await using var command = new NpgsqlCommand("update public.auth_users set is_active = true where id = 104 and username = 'oracle_inactive' and role = 'viewer' and is_active = false returning id", connection);
        object? result = await command.ExecuteScalarAsync(ct);
        Check(result is int id && id == 104);
    }

    internal async Task<bool> SeedRestoredAsync(CancellationToken ct)
    {
        await using var connection = await OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("select is_active from public.auth_users where id = 104 and username = 'oracle_inactive' and role = 'viewer'", connection);
        object? result = await command.ExecuteScalarAsync(ct);
        return result is bool active && !active;
    }

    public ValueTask DisposeAsync() { disposed = true; return ValueTask.CompletedTask; }
}
