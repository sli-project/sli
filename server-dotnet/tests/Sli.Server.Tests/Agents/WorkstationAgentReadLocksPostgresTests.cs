using System.Text.Json;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Diagnostics;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Port of tests/reporting/test_workstation_agent_read_locks_postgres.py.
// Real overlapping transactions on the migrated runtime role; no mocked rows.
public sealed class WorkstationAgentReadLocksPostgresTests
{
    private static readonly string[] Fields = ["identity_basic", "technical", "security", "privilege"];

    [Theory]
    [InlineData("scope_all")]
    [InlineData("scope_agent")]
    [InlineData("agent_list")]
    [InlineData("agent_status")]
    public async Task Ui_read_completes_while_agent_writer_holds_row(string reader)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var agent = await SeedAsync(fixture, ct);
        await using var writer = await OpenAsync(fixture, ct);
        await using var readerDb = await OpenAsync(fixture, ct);
        await using var writerTx = await writer.BeginTransactionAsync(ct);
        await using var readerTx = await readerDb.BeginTransactionAsync(ct);
        await DisableAsync(writer, writerTx, agent, ct);
        // The writer stays uncommitted throughout the real read. A locking
        // reader fails at lock_timeout rather than waiting for an early commit.
        await ReadAsync(readerDb, readerTx, agent, reader, "active", ct);
        await writerTx.CommitAsync(ct);
        // The same READ COMMITTED transaction now sees the lifecycle change.
        await ReadAsync(readerDb, readerTx, agent, reader, "disabled", ct);
        await AssertDisabledAsync(readerDb, readerTx, agent, ct);
        await readerTx.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData("scope_all")]
    [InlineData("scope_agent")]
    [InlineData("agent_list")]
    [InlineData("agent_status")]
    public async Task Ui_read_transaction_does_not_hold_agent_row(string reader)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var agent = await SeedAsync(fixture, ct);
        await using var readerDb = await OpenAsync(fixture, ct);
        await using var writer = await OpenAsync(fixture, ct);
        await using var readerTx = await readerDb.BeginTransactionAsync(ct);
        await using var writerTx = await writer.BeginTransactionAsync(ct);
        await ReadAsync(readerDb, readerTx, agent, reader, "active", ct);
        // No reader commit/rollback: an accidental row lock in either actual
        // reader would block this independent lifecycle write.
        await DisableAsync(writer, writerTx, agent, ct);
        await writerTx.CommitAsync(ct);
        await AssertDisabledAsync(readerDb, readerTx, agent, ct);
        await readerTx.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task<NpgsqlConnection> OpenAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        try
        {
            await db.OpenAsync(ct);
            await using var role = new NpgsqlCommand("select current_user", db);
            Assert.Equal("adlog_user", await role.ExecuteScalarAsync(ct));
            // Test-only failure detector for conflicting row locks, matching
            // the oracle. Never configure a runtime process time limit here.
            await PostCollectionPostgres.Sql(db, "set lock_timeout='500ms'", ct);
            return db;
        }
        catch { await db.DisposeAsync(); throw; }
    }

    private static async Task<Guid> SeedAsync(SqlPostgresFixture fixture, CancellationToken ct)
    {
        await using var db = await OpenAsync(fixture, ct);
        var agent = Guid.NewGuid();
        await using var seed = new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            values(@agent,@host,@fingerprint,'[{"module_id":"sli.workstations"}]'::jsonb)
            """, db);
        seed.Parameters.AddWithValue("agent", agent);
        seed.Parameters.AddWithValue("host", Guid.NewGuid());
        seed.Parameters.AddWithValue("fingerprint", new string('a', 64));
        Assert.Equal(1, await seed.ExecuteNonQueryAsync(ct));
        return agent;
    }

    private static async Task ReadAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent,
        string reader, string status, CancellationToken ct)
    {
        var capability = JsonSerializer.SerializeToElement(new
        { capability_key = "workstations.read", effect = "allow", scope_json = new { kind = "all" } });
        var facts = new AccessFacts(false, "operator", [], [], [capability], [], [], [], []);
        var scope = reader == "scope_all"
            ? JsonSerializer.SerializeToElement(new { kind = "all" })
            : JsonSerializer.SerializeToElement(new { kind = "agent", ids = new[] { agent.ToString("D") } });
        var grant = new AtomicReportGrant(scope, Fields.ToHashSet(), new HashSet<string> { "view" }, 1, 1);
        var access = new AccessDecision("operator", new CapabilityComposer().Compose(facts),
            [new ReportDecision("workstations.overview", true, [grant])]);
        if (reader.StartsWith("scope_", StringComparison.Ordinal))
        {
            // This is the scope resolver used by workstation report reads;
            // the caller's transaction remains open after resolving keys.
            var keys = await WorkstationReports.AgentKeysAsync(db, facts, access, "workstations.overview", ct);
            Assert.Contains(agent.ToString("D"), keys);
            if (reader == "scope_agent") Assert.Equal(new[] { agent.ToString("D") }, keys);
            return;
        }
        var result = await new WorkstationAgentReader().ReadAsync(db, tx, facts, access,
            reader == "agent_list" ? "" : "?agent_key=" + agent.ToString("D"), ct);
        var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal(agent.ToString("D"), item["agent_key"]!.GetValue<string>());
        Assert.Equal(status, item["status"]!.GetValue<string>());
        Assert.False(result["has_more"]!.GetValue<bool>());
        Assert.Null(result["next_cursor"]);
    }

    private static async Task DisableAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("update sli_agents set status='disabled' where id=@agent", db, tx);
        command.Parameters.AddWithValue("agent", agent);
        Assert.Equal(1, await command.ExecuteNonQueryAsync(ct));
    }

    private static async Task AssertDisabledAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select status from sli_agents where id=@agent", db, tx);
        command.Parameters.AddWithValue("agent", agent);
        Assert.Equal("disabled", await command.ExecuteScalarAsync(ct));
    }
}
