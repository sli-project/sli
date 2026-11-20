using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_storage_v2_runtime_authorization.py.
public sealed partial class StorageV2RuntimeAuthorizationTests
{
    static CancellationToken Token => TestContext.Current.CancellationToken;
    static readonly DateTime Issued = new(2026, 8, 26, 0, 0, 0, DateTimeKind.Utc);
    static DirectRuntimeRecord Record(string root = "/fixture/archive")
    {
        var record = new DirectRuntimeRecord("v2", "storage-v2-transition-controller/v1", new string('a', 64), root,
            JsonNode.Parse("""{"backup_restore_verified":true,"nested":{"label":"проверено","ids":[10,11]}}""")!.AsObject(),
            "fixture-owner", Issued, Issued.AddDays(1), null, "");
        return record with { AuthorizationDigest = DirectRuntimeAuthorization.Digest(record) };
    }

    [Fact]
    public void Persisted_digest_matches_Python_canonical_payload()
    {
        var record = Record();
        Assert.Equal("21e9b224f84f84a422729dfafe70fa230e71786c95f16936433f6521c93b5100", record.AuthorizationDigest);
        Assert.Equal(record.ArchiveRoot, DirectRuntimeAuthorization.Validate(record, Issued.AddHours(1)).ArchiveRoot);
    }

    [Theory]
    [InlineData("archive_root")]
    [InlineData("evidence")]
    [InlineData("authorized_by")]
    [InlineData("authorized_at")]
    [InlineData("expires_at")]
    [InlineData("preflight_digest")]
    [InlineData("digest")]
    public void Persisted_payload_tampering_is_rejected(string field)
    {
        var record = Record();
        record = field switch {
            "archive_root" => record with { ArchiveRoot = "/fixture/tampered" },
            "evidence" => record with { Evidence = new() },
            "authorized_by" => record with { AuthorizedBy = "other-owner" },
            "authorized_at" => record with { AuthorizedAt = Issued.AddMinutes(1) },
            "expires_at" => record with { ExpiresAt = Issued.AddDays(2) },
            "preflight_digest" => record with { PreflightDigest = new string('b', 64) },
            _ => record with { AuthorizationDigest = new string('0', 64) }
        };
        Rejected(record);
    }

    [Fact]
    public void Revocation_and_expiry_including_exact_boundary_fail_closed()
    {
        var record = Record();
        Assert.NotNull(DirectRuntimeAuthorization.Validate(record, record.ExpiresAt.AddTicks(-1)));
        Rejected(record, record.ExpiresAt);
        Rejected(record, record.ExpiresAt.AddHours(1));
        Rejected(record with { RevokedAt = Issued.AddMinutes(1) });
    }

    [Theory]
    [InlineData("v2_primary_compat", "storage-v2-transition-controller/v1")]
    [InlineData("v1", "storage-v2-transition-controller/v1")]
    [InlineData("v2", "fixture-untrusted-authority")]
    public void Direct_import_refuses_compatibility_and_untrusted_authorities_even_with_valid_digest(string route, string authority)
    {
        var record = Record() with { Route = route, Authority = authority };
        Rejected(record with { AuthorizationDigest = DirectRuntimeAuthorization.Digest(record) });
    }

    static void Rejected(DirectRuntimeRecord record, DateTime? now = null) =>
        Assert.Equal("storage_v2_admission_required", Assert.Throws<InvalidOperationException>(() =>
            DirectRuntimeAuthorization.Validate(record, now ?? Issued.AddHours(1))).Message);

    static string Table(string file, string name)
    {
        string sql = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations", file));
        var match = Regex.Match(sql, @"create table (?:if not exists )?" + Regex.Escape(name) + @"\s*\([\s\S]*?\r?\n\);", RegexOptions.IgnoreCase);
        Assert.True(match.Success, name);
        return match.Value;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Optional_database_loader_round_trips_persisted_authority_without_requiring_archive_directory(bool missingDirectory)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema:true);
        await pg.StartAsync(Token);
        await using var db = new NpgsqlConnection(pg.ConnectionString);
        await db.OpenAsync(Token);
        await using var tx = await db.BeginTransactionAsync(Token);
        Assert.Null(await DirectRuntimeAuthorization.LoadAsync(db, tx, Issued, Token));
        async Task RequiresAdmission() => Assert.Equal("agent_storage_unavailable", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DirectAdDcPacket.ImportAsync(db, tx, null!, Guid.NewGuid(), new(), new(), [], "unused-catalog", Token))).Message);
        await RequiresAdmission();
        await using (var create = new NpgsqlCommand(Table("091_storage_v2_runtime_authorization.sql", "storage_v2_runtime_authorizations"), db, tx))
            await create.ExecuteNonQueryAsync(Token);
        Assert.Null(await DirectRuntimeAuthorization.LoadAsync(db, tx, Issued, Token));
        await RequiresAdmission();
        string root = Path.Combine(pg.Root, "absent-archive");
        if (!missingDirectory) Directory.CreateDirectory(root);
        var record = Record(root);
        await using (var insert = new NpgsqlCommand("""
            insert into storage_v2_runtime_authorizations(route,authority,preflight_digest,authorization_digest,
                archive_root,evidence,authorized_by,authorized_at,expires_at)
            values(@route,@authority,@preflight,@digest,@root,@evidence::jsonb,@owner,@issued,@expires)
            """, db, tx))
        {
            insert.Parameters.AddWithValue("route", record.Route); insert.Parameters.AddWithValue("authority", record.Authority);
            insert.Parameters.AddWithValue("preflight", record.PreflightDigest); insert.Parameters.AddWithValue("digest", record.AuthorizationDigest);
            insert.Parameters.AddWithValue("root", record.ArchiveRoot); insert.Parameters.AddWithValue("evidence", record.Evidence.ToJsonString());
            insert.Parameters.AddWithValue("owner", record.AuthorizedBy); insert.Parameters.AddWithValue("issued", record.AuthorizedAt);
            insert.Parameters.AddWithValue("expires", record.ExpiresAt); await insert.ExecuteNonQueryAsync(Token);
        }
        var first = await DirectRuntimeAuthorization.LoadAsync(db, tx, Issued.AddHours(1), Token);
        Assert.NotNull(first); Assert.Equal(root, first.ArchiveRoot);
        Assert.Equal(!missingDirectory, Directory.Exists(root));
        await using (var tamper = new NpgsqlCommand("update storage_v2_runtime_authorizations set archive_root=archive_root||'/tampered'", db, tx))
            await tamper.ExecuteNonQueryAsync(Token);
        Assert.Equal("storage_v2_admission_required", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DirectRuntimeAuthorization.LoadAsync(db, tx, Issued.AddHours(1), Token))).Message);
        // Reading/tamper detection does not mutate the persisted record.
        await using var read = new NpgsqlCommand("select authorization_digest from storage_v2_runtime_authorizations", db, tx);
        Assert.Equal(record.AuthorizationDigest, await read.ExecuteScalarAsync(Token));
        await tx.RollbackAsync(Token);
    }
}
