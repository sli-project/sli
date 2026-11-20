using Npgsql;
using Xunit;

namespace Sli.Server.Tests;

public sealed class AccountDecoyRestoreTests
{
    private const string Signature = "public.read_account_decoy_events(uuid,text,text,text,text,uuid)";
    private static string Migration(string suffix = ".sql") => Path.Combine(
        SqlPostgresFixture.Repository(), "config/postgres_migrations/334_account_decoy_restore" + suffix);

    [Fact]
    public async Task Restore334_matches326_exactly_preserves327_and_rolls_back_to333()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 326);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        string definitionSql = $"select pg_get_functiondef('{Signature}'::regprocedure)";
        string catalogSql = $"select (to_jsonb(p)-'prosrc')::text from pg_proc p where oid='{Signature}'::regprocedure";
        string expected326 = await Scalar(definitionSql);
        foreach (string file in Directory.GetFiles(Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations"), "*.sql")
            .Where(p => int.TryParse(Path.GetFileName(p).Split('_')[0], out int v) && v is > 326 and <= 333 && !p.EndsWith(".rollback.sql"))
            .OrderBy(p => p, StringComparer.Ordinal))
            await fixture.Pg.ApplyFileAsync(file, null, ct);
        Assert.Equal("333", await Scalar("select max(version)::text from schema_migrations"));
        string before333 = await Scalar(definitionSql), catalog333 = await Scalar(catalogSql);
        Assert.NotEqual(expected326, before333);
        const string othersSql = """
            select jsonb_agg(jsonb_build_array(p.oid,pg_get_functiondef(p.oid),to_jsonb(p)) order by p.oid)::text
            from pg_proc p join pg_namespace n on n.oid=p.pronamespace
            where (n.nspname='public' or n.nspname like 'sli_plugin_%') and p.prokind='f'
              and p.oid<>'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure
            """;
        const string indexesSql = """
            select jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready)
                order by i.indexrelid)::text from pg_index i
            join pg_class c on c.oid=i.indrelid join pg_namespace n on n.oid=c.relnamespace
            where (n.nspname='public' or n.nspname like 'sli_plugin_%')
            """;
        const string snapshot327Sql = "select jsonb_agg(to_jsonb(d) order by signature)::text from detector_definitions327 d";
        string snapshot327 = await Scalar(snapshot327Sql);
        string others333 = await Scalar(othersSql);
        // Exclude only the migration's private rollback table index below.
        string indexes333 = await Scalar(indexesSql);
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        Assert.Equal(expected326, await Scalar(definitionSql));
        Assert.Equal(catalog333, await Scalar(catalogSql));
        Assert.Equal(others333, await Scalar(othersSql));
        Assert.Equal(snapshot327, await Scalar(snapshot327Sql));
        Assert.Equal(indexes333, await Scalar(indexesSql + " and i.indrelid<>'public.account_decoy_definition334'::regclass"));
        Assert.Equal("334", await Scalar("select max(version)::text from schema_migrations"));
        Assert.Equal("true", await Scalar("""
            select (c.relowner='adlog_storage_owner'::regrole
                and not has_table_privilege('adlog_user',c.oid,'SELECT')
                and not has_table_privilege('adlog_semantic_worker',c.oid,'SELECT')
                and not exists(select 1 from aclexplode(c.relacl) where grantee=0))::text
            from pg_class c where c.oid='public.account_decoy_definition334'::regclass
            """));
        await fixture.Pg.ApplyFileAsync(Migration(".rollback.sql"), null, ct);
        Assert.Equal(before333, await Scalar(definitionSql));
        Assert.Equal(catalog333, await Scalar(catalogSql));
        Assert.Equal(others333, await Scalar(othersSql));
        Assert.Equal(snapshot327, await Scalar(snapshot327Sql));
        Assert.Equal(indexes333, await Scalar(indexesSql));
        Assert.Equal("333", await Scalar("select max(version)::text from schema_migrations"));
        Assert.Equal("true", await Scalar("select (to_regclass('public.account_decoy_definition334') is null)::text"));
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        Assert.Equal(expected326, await Scalar(definitionSql));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Restore334_rejects_invalid_predecessor_future_owner_and_missing_snapshot_atomically()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 333);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await db.OpenAsync(ct);
        async Task Execute(string sql) {
            await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
            await q.ExecuteNonQueryAsync(ct);
        }
        foreach (string mutation in new[] {
            "delete from schema_migrations where version=333",
            "insert into schema_migrations(version,name) values(335,'synthetic_future')",
            $"alter function {Signature} owner to adlog_user",
            "delete from detector_definitions327 where signature like 'read_account_decoy_events(%'",
            "drop table detector_definitions327",
            "set session authorization adlog_user"
        }) {
            await Execute("begin;" + mutation);
            try {
                var error = await Assert.ThrowsAsync<PostgresException>(() => Execute(File.ReadAllText(Migration())));
                Assert.Equal("55000", error.SqlState);
                Assert.StartsWith("account_decoy_restore_334_", error.MessageText, StringComparison.Ordinal);
            } finally { await Execute("rollback;reset session authorization"); }
            await using var check = new NpgsqlCommand("select count(*) from schema_migrations where version>=334", db);
            Assert.Equal(0L, await check.ExecuteScalarAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(Migration(), null, ct);
        await Execute("begin;insert into schema_migrations(version,name) values(335,'synthetic_future')");
        try {
            var error = await Assert.ThrowsAsync<PostgresException>(() => Execute(File.ReadAllText(Migration(".rollback.sql"))));
            Assert.Equal("55000", error.SqlState);
            Assert.Equal("account_decoy_restore_334_rollback_preflight", error.MessageText);
        } finally { await Execute("rollback"); }
    }
}
