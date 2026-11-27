using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Isopoh.Cryptography.Argon2;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class PasswordInteropTests(ITestOutputHelper output)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private sealed record Vector(string Name, string Password, string Encoded, int Type, int Version,
        int TimeCost, int MemoryCost, int Parallelism, int SaltLength, int HashLength, bool Rehash);

    [Fact]
    public async Task PythonCffiPhcBothDirections()
    {
        // Only synthetic credentials; execute the independent implementation locally.
        string python = Environment.GetEnvironmentVariable("SLI_AUTH_PYTHON") ?? "python";
        using var resource = typeof(PasswordInteropTests).Assembly.GetManifestResourceStream(
            "Sli.Server.Tests.Auth.password-phc-vectors.json")!;
        using var document = JsonDocument.Parse(resource);
        var vectors = document.RootElement.GetProperty("vectors").Deserialize<Vector[]>(JsonOptions)!;
        Assert.Equal(16, vectors.Length);
        var codec = new PasswordCodec();
        var generated = new List<object>();
        foreach (var vector in vectors)
        {
            Assert.True(codec.Verify(vector.Encoded, vector.Password).Valid, vector.Name);
            Assert.False(codec.Verify(vector.Encoded, vector.Password + "x").Valid, vector.Name);
            Assert.Equal(vector.Rehash, codec.NeedsRehash(vector.Encoded));
            if (vector.Version == 16)
            {
                string unversioned = vector.Encoded.Replace("$v=16", "");
                Assert.True(codec.Verify(unversioned, vector.Password).Valid);
                Assert.False(codec.Verify(unversioned, vector.Password + "x").Valid);
                Assert.True(codec.NeedsRehash(unversioned));
            }
            byte[] bytes = Encoding.UTF8.GetBytes(vector.Password);
            string encoded;
            try
            {
                encoded = Argon2.Hash(new Argon2Config
                {
                    Password = bytes, Salt = Enumerable.Range(0, vector.SaltLength).Select(x => (byte)x).ToArray(),
                    Type = (Argon2Type)vector.Type, Version = (Argon2Version)vector.Version,
                    TimeCost = vector.TimeCost, MemoryCost = vector.MemoryCost,
                    Lanes = vector.Parallelism, Threads = vector.Parallelism, HashLength = vector.HashLength
                });
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            Assert.Equal(vector.Encoded, encoded);
            string replacement = codec.Hash(vector.Password);
            Assert.True(codec.Verify(replacement, vector.Password).Valid);
            Assert.False(codec.NeedsRehash(replacement));
            generated.Add(new { vector.Name, vector.Password, encoded, replacement, vector.Rehash });
        }

        // Unicode is exact UTF-8, without normalization or truncation at NUL.
        Assert.False(codec.Verify(vectors.Single(x => x.Name == "composed").Encoded, "synthetic-e\u0301").Valid);
        var nul = vectors.Single(x => x.Name == "long-null");
        Assert.False(codec.Verify(nul.Encoded, nul.Password.Split('\0')[0]).Valid);
        var baselineVector = vectors.Single(x => x.Name == "baseline");
        string baseline = baselineVector.Encoded;
        string[] malformed = ["", "plaintext", baseline.Replace("argon2id", "argon2x"),
            baseline.Replace("v=19", "v=20"), baseline.Replace("m=65536", "m=invalid"),
            baseline.Replace("t=3", "t=0"), baseline.Replace("p=2", "p=0"),
            baseline.Replace("m=65536", "m=1"), baseline[..baseline.LastIndexOf('$')],
            baseline[..^1] + "!", baseline.Replace("$AAECAwQFBgcICQoLDA0ODw$", "$YQ$")];
        foreach (string encoded in malformed) Assert.False(codec.Verify(encoded, baselineVector.Password).Valid);
        string corrupted = baseline[..baseline.LastIndexOf('$')] + "$" + new string('A', 43);
        Assert.False(codec.Verify(corrupted, baselineVector.Password).Valid);

        const string script = """
            import json, platform, sys
            from importlib.metadata import version
            from argon2 import Type
            from argon2.exceptions import InvalidHashError, VerificationError
            from argon2.low_level import hash_secret
            assert version('argon2-cffi') == '25.1.0'
            request = json.load(sys.stdin)
            sys.path.insert(0, sys.argv[1])
            from deploy.linux.sli_core.auth import PASSWORD_HASHER as hasher
            def reject(encoded, password):
                try:
                    hasher.verify(encoded, password)
                except (InvalidHashError, VerificationError):
                    return
                raise AssertionError('Expected rejection of synthetic credential')
            replacements = []
            for vector, dotnet in zip(request['vectors'], request['generated'], strict=True):
                encoded = hash_secret(vector['password'].encode('utf-8'), bytes(range(vector['saltLength'])),
                    time_cost=vector['timeCost'],memory_cost=vector['memoryCost'],parallelism=vector['parallelism'],
                    hash_len=vector['hashLength'],type=Type(vector['type']),version=vector['version']).decode('ascii')
                assert encoded == vector['encoded'] == dotnet['encoded'], vector['name']
                assert hasher.verify(dotnet['encoded'], vector['password'])
                reject(dotnet['encoded'], vector['password']+'x')
                assert hasher.check_needs_rehash(dotnet['encoded']) == vector['rehash']
                assert hasher.verify(dotnet['replacement'], vector['password'])
                assert not hasher.check_needs_rehash(dotnet['replacement'])
                replacements.append(hasher.hash(vector['password']))
                if vector['version'] == 16:
                    unversioned = dotnet['encoded'].replace('$v=16', '')
                    assert hasher.verify(unversioned, vector['password'])
                    reject(unversioned, vector['password']+'x')
                    assert hasher.check_needs_rehash(unversioned)
            for encoded in request['malformed']:
                reject(encoded, request['baselinePassword'])
            reject(request['corrupted'], request['baselinePassword'])
            print(json.dumps(dict(runtime=dict(python=platform.python_version(),cffi=version('argon2-cffi'),
                bindings=version('argon2-cffi-bindings'),platform=platform.platform()),vectors=len(request['vectors']),
                rejected=len(request['malformed'])+1,replacements=replacements)),flush=True)
            """;
        var start = new ProcessStartInfo(python)
        {
            RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, UseShellExecute = false
        };
        start.ArgumentList.Add("-I"); start.ArgumentList.Add("-c"); start.ArgumentList.Add(script);
        start.ArgumentList.Add(Sli.Server.Tests.Agents.PostCollectionPostgres.Repository());
        using var process = Process.Start(start)!;
        var ct = TestContext.Current.CancellationToken;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try
        {
            await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new
            {
                vectors, generated, malformed, corrupted,
                baselinePassword = baselineVector.Password
            }, JsonOptions));
            process.StandardInput.Close();
            await process.WaitForExitAsync(ct);
            Assert.True(process.ExitCode == 0, "Independent Python interoperability failed: " + await stderr);
            using var result = JsonDocument.Parse(await stdout);
            Assert.Equal(vectors.Length, result.RootElement.GetProperty("vectors").GetInt32());
            Assert.Equal(malformed.Length + 1, result.RootElement.GetProperty("rejected").GetInt32());
            var replacements = result.RootElement.GetProperty("replacements").EnumerateArray().ToArray();
            Assert.Equal(vectors.Length, replacements.Length);
            for (int index = 0; index < vectors.Length; index++)
            {
                string replacement = replacements[index].GetString()!;
                Assert.True(codec.Verify(replacement, vectors[index].Password).Valid);
                Assert.False(codec.Verify(replacement, vectors[index].Password + "x").Valid);
                Assert.False(codec.NeedsRehash(replacement));
            }
            output.WriteLine($".NET {Environment.Version}, {RuntimeInformation.OSDescription}, " +
                $"Isopoh.Cryptography.Argon2 NuGet pin 2.0.0 (assembly {typeof(Argon2).Assembly.GetName().Version}); " +
                $"Python: {result.RootElement.GetProperty("runtime")}");
            output.WriteLine("16 golden vectors and fresh rehashes in each direction: verify/reject/rehash PASS; " +
                "3 unversioned v16 PHC variants and 12 corrupt PHC rejections PASS.");
        }
        finally
        {
            // An assertion/cancellation must not leave our own oracle process waiting for input.
            if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
        }
    }
}
