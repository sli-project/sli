using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Integration;

public sealed class NativeDatabaseErrorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TransportOutageRetainsNativeErrorWithoutSqlState()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var files = new AdmissionFiles(((IPEndPoint)listener.LocalEndpoint).Port);
        listener.Stop();
        await using var database = await SyntheticDatabase.BorrowAsync(files.Binding, Ct);
        var error = await Assert.ThrowsAsync<NpgsqlException>(() => database.OpenConnectionAsync(Ct));
        Assert.IsType<SocketException>(error.InnerException);
        Assert.Null(error.SqlState);
    }

    [Fact]
    public async Task NativeConnectFailureRetainsSqlStateAndRecovers()
    {
        await using var fixture = new OwnedFixture();
        await fixture.StartAsync();
        await using var database = await SyntheticDatabase.BorrowAsync(fixture.Files.Binding, Ct);
        await fixture.Sql("alter role adlog_user nologin");
        var error = await Assert.ThrowsAsync<PostgresException>(() => database.OpenConnectionAsync(Ct));
        Assert.Equal("28000", error.SqlState);
        Assert.Null(error.InnerException);
        await fixture.AssertNoRuntimeConnections();
        await fixture.Sql("alter role adlog_user login");
        await AssertRecovered(database);
    }

    [Fact]
    public async Task SentinelQueryFailureRetainsSqlStateAndClosesConnection()
    {
        await using var fixture = new OwnedFixture();
        await fixture.StartAsync();
        await using var database = await SyntheticDatabase.BorrowAsync(fixture.Files.Binding, Ct);
        await fixture.Sql("revoke select on public.sli_test_ownership from adlog_user");
        var error = await Assert.ThrowsAsync<PostgresException>(() => database.OpenConnectionAsync(Ct));
        Assert.Equal("42501", error.SqlState);
        await fixture.AssertNoRuntimeConnections();
        await fixture.Sql("grant select on public.sli_test_ownership to adlog_user");
        await AssertRecovered(database);
    }

    [Theory]
    [InlineData(false, "55P03")]
    [InlineData(true, "57014")]
    public async Task ActualSentinelTimeoutPathsRemainDistinctAndRecover(bool statement, string sqlState)
    {
        await using var fixture = new OwnedFixture();
        await fixture.StartAsync();
        await using var database = await SyntheticDatabase.BorrowAsync(fixture.Files.Binding, Ct);
        // Fault injection only in this disposable cluster. A blocked sentinel query
        // produces a real server timeout, rather than a fabricated driver exception.
        await fixture.Sql(statement
            ? "alter role adlog_user set statement_timeout='50ms'; alter role adlog_user set lock_timeout=0"
            : "alter role adlog_user set lock_timeout='50ms'; alter role adlog_user set statement_timeout=0");
        await using (var transaction = await fixture.Admin!.BeginTransactionAsync(Ct))
        {
            await using var command = new NpgsqlCommand("lock table public.sli_test_ownership in access exclusive mode", fixture.Admin, transaction);
            await command.ExecuteNonQueryAsync(Ct);
            var error = await Assert.ThrowsAsync<PostgresException>(() => database.OpenConnectionAsync(Ct));
            Assert.Equal(sqlState, error.SqlState);
            Assert.Contains(statement ? "statement timeout" : "lock timeout", error.MessageText);
            // Check cleanup over another admin session while the lock is still held.
            await fixture.AssertNoRuntimeConnections();
            await transaction.RollbackAsync(Ct);
        }
        await fixture.Sql("alter role adlog_user reset statement_timeout; alter role adlog_user reset lock_timeout");
        await AssertRecovered(database);
    }

    [Theory]
    [InlineData("proof")]
    [InlineData("credential")]
    [InlineData("malformed-credential")]
    public async Task SafetyMismatchIsRedactedBeforeNativeConnect(string mismatch)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var files = new AdmissionFiles(((IPEndPoint)listener.LocalEndpoint).Port);
        await using var database = await SyntheticDatabase.BorrowAsync(files.Binding, Ct);
        if (mismatch == "proof")
            File.WriteAllText(files.ProofPath, files.Password);
        else if (mismatch == "malformed-credential")
            File.WriteAllText(files.CredentialPath, files.Password);
        else
        {
            files.Credential["host"] = "192.0.2.17";
            File.WriteAllText(files.CredentialPath, files.Credential.ToJsonString());
        }
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => database.OpenConnectionAsync(Ct));
        Assert.Equal(mismatch == "proof" ? "Owned database admission refused" : "Owned database connection refused", error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(files.Password, error.ToString());
        Assert.DoesNotContain(files.Root, error.ToString());
        Assert.False(listener.Pending());
    }

    [Theory]
    [InlineData("run")]
    [InlineData("side")]
    [InlineData("sentinel")]
    [InlineData("extra-row")]
    public async Task SentinelMismatchIsRedactedAndClosesConnection(string mismatch)
    {
        await using var fixture = new OwnedFixture();
        await fixture.StartAsync();
        await using var database = await SyntheticDatabase.BorrowAsync(fixture.Files.Binding, Ct);
        await fixture.Sql(mismatch switch
        {
            "run" => "update public.sli_test_ownership set run_id='00000000-0000-4000-8000-000000000001'",
            "side" => "update public.sli_test_ownership set side='python'",
            "sentinel" => "update public.sli_test_ownership set sentinel='synthetic-wrong-sentinel'",
            _ => "insert into public.sli_test_ownership select * from public.sli_test_ownership"
        });
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => database.OpenConnectionAsync(Ct));
        Assert.Equal("Owned database admission refused", error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(fixture.Files.Password, error.ToString());
        Assert.DoesNotContain(fixture.Files.Sentinel, error.ToString());
        await fixture.AssertNoRuntimeConnections();
    }

    private static async Task AssertRecovered(SyntheticDatabase database)
    {
        await using var connection = await database.OpenConnectionAsync(Ct);
        await using var command = new NpgsqlCommand("select 1", connection);
        Assert.Equal(1, await command.ExecuteScalarAsync(Ct));
    }

    private sealed class AdmissionFiles : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-gap017-" + Guid.NewGuid().ToString("N"));
        internal string Password { get; } = "synthetic-" + Guid.NewGuid().ToString("N");
        internal string Sentinel { get; } = "synthetic-" + Guid.NewGuid().ToString("N");
        internal string ProofPath { get; }
        internal string CredentialPath { get; }
        internal JsonObject Credential { get; }
        internal OwnedDatabaseBinding Binding { get; }

        internal AdmissionFiles(int port)
        {
            var run = Guid.NewGuid();
            string directory = Path.Combine(Root, run.ToString("D"), "dotnet");
            Directory.CreateDirectory(directory);
            ProofPath = Path.Combine(directory, "proof.json");
            CredentialPath = Path.Combine(directory, "runtime-secret.json");
            const string image = "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c";
            const string source = "86ea77320b99f29f358b528b439ccace77887a19bc037ecd12cfda2e81bd8836";
            string container = new('a', 64), network = new('b', 64), config = new('c', 64);
            string volume = $"sli-test-{run:D}-dotnet";
            var now = DateTimeOffset.UtcNow;
            var proof = new JsonObject {
                ["format"] = "sli.test.owned-pg-proof.v1", ["run_id"] = run.ToString("D"), ["side"] = "dotnet",
                ["container_id"] = container, ["network_id"] = network, ["volume_id"] = volume,
                ["host"] = "127.0.0.1", ["port"] = port, ["database"] = "sli_oracle", ["user"] = "adlog_user",
                ["sentinel_sha256"] = Hash(Encoding.UTF8.GetBytes(Sentinel)), ["image_digest"] = image,
                ["source_tree_sha256"] = source, ["config_manifest_sha256"] = config,
                ["verified_at"] = now.ToString("O"), ["expires_at"] = now.AddMinutes(5).ToString("O")
            };
            File.WriteAllText(ProofPath, proof.ToJsonString());
            Credential = new JsonObject {
                ["format"] = "sli.test.pg.runtime-credential.v1", ["run_id"] = run.ToString("D"), ["side"] = "dotnet",
                ["host"] = "127.0.0.1", ["port"] = port, ["database"] = "sli_oracle", ["user"] = "adlog_user", ["password"] = Password
            };
            File.WriteAllText(CredentialPath, Credential.ToJsonString());
            Binding = new(Root, run, "dotnet", Hash(File.ReadAllBytes(ProofPath)), container, network, volume, image,
                "127.0.0.1", port, source, config);
        }

        private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        public void Dispose()
        {
            string resolved = Path.GetFullPath(Root);
            if (Path.GetDirectoryName(resolved) == Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()))
                && Path.GetFileName(resolved).StartsWith("sli-gap017-", StringComparison.Ordinal))
                Directory.Delete(resolved, true);
        }
    }

    private sealed class OwnedFixture : IAsyncDisposable
    {
        private readonly PostCollectionPostgres pg = new(canonicalSchema: true);
        internal AdmissionFiles Files { get; private set; } = null!;
        internal NpgsqlConnection? Admin { get; private set; }

        internal async Task StartAsync()
        {
            await pg.StartAsync(Ct);
            await using (var initial = new NpgsqlConnection(pg.ConnectionString))
            {
                await initial.OpenAsync(Ct);
                await PostCollectionPostgres.Sql(initial, "create database sli_oracle;", Ct);
                await PostCollectionPostgres.Sql(initial, "create role adlog_user login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication", Ct);
            }
            Files = new(new NpgsqlConnectionStringBuilder(pg.ConnectionString).Port);
            Admin = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(pg.ConnectionString) { Database = "sli_oracle" }.ConnectionString);
            await Admin.OpenAsync(Ct);
            await Sql("create table public.sli_test_ownership(run_id uuid, side text, sentinel text); grant select on public.sli_test_ownership to adlog_user");
            await using var seed = new NpgsqlCommand("insert into public.sli_test_ownership values(@run,'dotnet',@sentinel)", Admin);
            seed.Parameters.AddWithValue("run", Files.Binding.RunId);
            seed.Parameters.AddWithValue("sentinel", Files.Sentinel);
            await seed.ExecuteNonQueryAsync(Ct);
        }

        internal Task Sql(string sql) => PostCollectionPostgres.Sql(Admin!, sql, Ct);
        internal async Task AssertNoRuntimeConnections()
        {
            await using var monitor = new NpgsqlConnection(pg.ConnectionString);
            await monitor.OpenAsync(Ct);
            // Clearing snapshots and waiting for PG's disconnect processing avoids
            // assuming that a local socket close is observed synchronously by PG.
            while (true)
            {
                await using var command = new NpgsqlCommand("select count(*) from pg_stat_activity where usename='adlog_user'", monitor);
                if (await command.ExecuteScalarAsync(Ct) is 0L) return;
                await Task.Delay(10, Ct);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Admin is not null) await Admin.DisposeAsync();
            await pg.DisposeAsync();
            Files?.Dispose();
        }
    }
}
