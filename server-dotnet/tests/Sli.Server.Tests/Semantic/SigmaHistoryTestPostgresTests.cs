using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SigmaHistoryTestPostgresTests
{
    private sealed record TestSource(Guid Agent, Guid Host, long Server, string Name);

    [Fact]
    public async Task Reads_scoped_original_xml_with_pinned_pagination_and_distinct_outcomes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var first = new TestSource(Guid.NewGuid(), Guid.NewGuid(), 930001, "sigma-source-a.example.test");
        var second = new TestSource(Guid.NewGuid(), Guid.NewGuid(), 930002, "sigma-source-b.example.test");
        string stamp = DateTime.UtcNow.Date.AddDays(-1).ToString("yyyy-MM-dd") + "T01:00:00.1234567Z";
        DateTime utc = DirectEventTime.Utc(stamp);
        Assert.Equal(123457, utc.Ticks % TimeSpan.TicksPerSecond / 10);

        foreach (var source in new[] { first, second })
            await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, source.Agent, source.Host, source.Server,
                1, source.Name, "Security", ct, "System", completePolicy: true);

        var firstScope = await ScopeAsync(owner, first, ct);
        var secondScope = await ScopeAsync(owner, second, ct);
        await BindAsync(owner, firstScope, first, ct);
        var start = new DateTimeOffset(utc.Date, TimeSpan.Zero);
        var end = start.AddDays(1);
        var create = Rule(4698, "security", "TaskContent");
        var update = Rule(4702, "security", "TaskContentNew");
        var install = Rule(7045, "system", "ImagePath");
        var rules = new[] { create, update, install };
        var firstSelection = new SigmaHistoryTestSelection(firstScope, start, end, [4698, 4702, 7045]);
        var secondSelection = new SigmaHistoryTestSelection(secondScope, start, end, [4698]);
        const string marker = "sigma-qa-only";
        static string TaskText(string text) => """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Description>""" + text + "</Description></Task>";

        await SeedAsync(fixture, owner, first, stamp, 10, 4698, "Security", 1, "TaskContent", TaskText(marker), ct);
        await SeedAsync(fixture, owner, first, stamp, 20, 4698, "Security", 1, "TaskContent", TaskText("ordinary fixture"), ct);
        await SeedAsync(fixture, owner, first, stamp, 30, 4698, "Security", 1, null, null, ct);
        await SeedAsync(fixture, owner, first, stamp, 40, 4698, "Security", 1, "TaskContent", TaskText(marker), ct);
        await SeedAsync(fixture, owner, first, stamp, 50, 4702, "Security", 1, "TaskContentNew", TaskText(marker), ct);
        await SeedAsync(fixture, owner, first, stamp, 60, 4702, "Security", 1, "TaskContentNew", TaskText(new string('a', 9000)), ct);
        await SeedAsync(fixture, owner, first, stamp, 70, 4702, "Security", 1, "TaskContentNew", TaskText(marker), ct);
        await SeedAsync(fixture, owner, first, stamp, 80, 7045, "System", 0, "ImagePath", marker, ct);
        await SeedAsync(fixture, owner, first, stamp, 85, 7045, "System", 0, "ImagePath", marker, ct);
        await SeedAsync(fixture, owner, first, stamp, 90, 4720, "Security", 0, null, null, ct);
        await SeedAsync(fixture, owner, second, stamp, 110, 4698, "Security", 1, "TaskContent", TaskText(marker), ct);
        await PostCollectionPostgres.Sql(owner, """
            delete from event_source_representations_v2 where event_id=900040;
            update event_source_representations_v2 set representation=jsonb_set(representation,'{xml}','"<invalid/>"') where event_id=900070;
            """, ct);

        string stored = (string)(await ScalarAsync(owner,
            "select representation::text from event_source_representations_v2 where event_id=900085", ct))!;
        var invalid = JsonNode.Parse(stored)!.AsObject();
        invalid["xml"] = "<invalid/>";
        await using (var replace = new NpgsqlCommand("""
            update event_source_representations_v2 set representation=$1,representation_sha256=$2 where event_id=900085
            """, owner))
        {
            replace.Parameters.AddWithValue(NpgsqlDbType.Jsonb, invalid.ToJsonString());
            replace.Parameters.AddWithValue(Convert.FromHexString(DirectEventIdentityStore.RepresentationDigest(invalid)));
            await replace.ExecuteNonQueryAsync(ct);
        }

        await using var database = NpgsqlDataSource.Create(fixture.Dsn("sli_semantic_login"));
        var denied = await Assert.ThrowsAsync<InvalidDataException>(() => SigmaHistoryTest.OpenAsync(database,
            "sigma-test", new string('a', 64), rules, [firstSelection, secondSelection], ct));
        Assert.Equal("permission_denied", denied.Message);

        var alternateGeneration = firstScope.DeepClone().AsObject();
        alternateGeneration["source_generation"] = "unbound";
        var stale = await Assert.ThrowsAsync<InvalidDataException>(() => SigmaHistoryTest.OpenAsync(database,
            "sigma-test", new string('a', 64), rules, [firstSelection with { Scope = alternateGeneration }], ct));
        Assert.Equal("permission_denied", stale.Message);

        await BindAsync(owner, secondScope, second, ct);
        await using var job = await SigmaHistoryTest.OpenAsync(database, "sigma-test", new string('a', 64),
            rules, [firstSelection, secondSelection], ct);
        var page = await job.RunPageAsync(new(Rows: 1, EventBytes: 2048), ct);
        Assert.Equal("partial", page.Status);
        Assert.Equal("row_budget", page.Reason);
        Assert.Equal(1, page.Checkpoint.Number("rows_read"));
        await SeedAsync(fixture, owner, first, stamp, 15, 4698, "Security", 1, "TaskContent", TaskText(marker), ct);
        for (int i = 0; i < 10 && page.Status == "partial"; i++)
            page = await job.RunPageAsync(new(Rows: 1, EventBytes: 2048), ct);

        Assert.Equal("completed", page.Status);
        Assert.Equal(10, page.Checkpoint.Number("rows_read"));
        var counts = page.Checkpoint["counts"]!.AsArray();
        Assert.Equal(6, counts.Count);
        var createCounts = counts.Where(c => c.Text("rule_id") == create.Id).OrderByDescending(c => c.Number("scanned")).ToArray();
        AssertCounts(createCounts[0], scanned: 9, evaluable: 2, matched: 1, unknown: 2, rejected: 0, skipped: 5);
        AssertCounts(createCounts[1], scanned: 1, evaluable: 1, matched: 1, unknown: 0, rejected: 0, skipped: 0);
        var updateCounts = counts.Where(c => c.Text("rule_id") == update.Id).OrderByDescending(c => c.Number("scanned")).ToArray();
        AssertCounts(updateCounts[0], scanned: 9, evaluable: 1, matched: 1, unknown: 0, rejected: 2, skipped: 6);
        var installCounts = counts.Where(c => c.Text("rule_id") == install.Id).OrderByDescending(c => c.Number("scanned")).ToArray();
        AssertCounts(installCounts[0], scanned: 9, evaluable: 1, matched: 1, unknown: 0, rejected: 1, skipped: 7);
        Assert.Equal(4, page.Checkpoint["samples"]!.AsArray().Count);
        Assert.DoesNotContain(marker, page.Checkpoint.ToJsonString(), StringComparison.Ordinal);
        Assert.Equal(1, Reason(createCounts[0], "payload_unavailable"));
        Assert.Equal(1, Reason(createCounts[0], "field_missing"));
        Assert.Equal(1, Reason(updateCounts[0], "source_payload_oversized"));
        Assert.Equal(1, Reason(updateCounts[0], "source_representation_digest_mismatch"));
        Assert.Equal(1, Reason(installCounts[0], "source_xml_invalid"));

        var onlySecurity = firstSelection with { Kinds = [4698] };
        int byteLimit = (int)(await ScalarAsync(owner, """
            select sum(octet_length(representation::text))::integer-1 from event_source_representations_v2
            where event_id in (900010,900015)
            """, ct))!;
        await using (var byteJob = await SigmaHistoryTest.OpenAsync(database, "byte-resume", new string('b', 64),
            [create], [onlySecurity], ct))
        {
            var limited = await byteJob.RunPageAsync(new(Bytes: byteLimit, EventBytes: 2048), ct);
            Assert.Equal("partial", limited.Status);
            Assert.Equal("byte_budget", limited.Reason);
            Assert.Equal(1, limited.Checkpoint.Number("rows_read"));
            var resumed = await byteJob.RunPageAsync(new(EventBytes: 2048), ct);
            Assert.Equal("completed", resumed.Status);
            AssertCounts(Assert.Single(resumed.Checkpoint["counts"]!.AsArray()),
                scanned: 5, evaluable: 3, matched: 2, unknown: 2, rejected: 0, skipped: 0);
        }

        string planPath = Path.Combine(fixture.Pg.Root, "sigma-test-plan.json");
        string rulePath = Path.Combine(fixture.Pg.Root, "sigma-test-rule.yaml");
        var plan = new JsonObject { ["job"] = "test-cli", ["partitions"] = new JsonArray(new JsonObject
        {
            ["scope"] = firstScope.DeepClone(), ["start"] = SemanticJson.Stamp(start), ["end"] = SemanticJson.Stamp(end),
            ["event_ids"] = new JsonArray(4698)
        }) };
        await File.WriteAllTextAsync(planPath, plan.ToJsonString(), ct);
        await File.WriteAllTextAsync(rulePath, RuleYaml(Guid.Parse(create.Id), 4698, "security", "TaskContent"), ct);
        var commandResult = await RunCliAsync(fixture, planPath, rulePath, ct);
        Assert.Equal("test", commandResult.Text("mode"));
        Assert.Equal("event_hot_only", commandResult.Text("coverage"));
        Assert.Equal("completed", commandResult.Text("status"));
        var commandCounts = Assert.Single(commandResult!["result"]!["counts"]!.AsArray());
        AssertCounts(commandCounts, scanned: 5, evaluable: 3, matched: 2, unknown: 2, rejected: 0, skipped: 0);
        TestContext.Current.TestOutputHelper?.WriteLine(new JsonObject
        {
            ["mode"] = commandResult.Text("mode"),
            ["coverage"] = commandResult.Text("coverage"),
            ["status"] = commandResult.Text("status"),
            ["reason"] = commandResult.Text("reason"),
            ["scanned"] = commandCounts.Number("scanned"),
            ["evaluable"] = commandCounts.Number("evaluable"),
            ["matched"] = commandCounts.Number("matched"),
            ["unknown"] = commandCounts.Number("unknown"),
            ["rejected"] = commandCounts.Number("rejected"),
            ["skipped"] = commandCounts.Number("skipped")
        }.ToJsonString());

        await using (var revoked = await SigmaHistoryTest.OpenAsync(database, "revoked", new string('c', 64),
            rules, [firstSelection], ct))
        {
            Assert.Equal("partial", (await revoked.RunPageAsync(new(Rows: 1), ct)).Status);
            await using var revision = await owner.BeginTransactionAsync(ct);
            await using var stage = new NpgsqlCommand("""
                insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
                select id,policy_revision+1,jsonb_set(jsonb_set(assigned_modules,'{0,config,channels,System}','false'),
                    '{0,config,policy_revision}',to_jsonb((policy_revision+1)::text)),collection_policy
                from sli_agents where id=$1
                """, owner, revision);
            stage.Parameters.AddWithValue(first.Agent);
            Assert.Equal(1, await stage.ExecuteNonQueryAsync(ct));
            await using var disable = new NpgsqlCommand("""
                update sli_agents a set policy_revision=a.policy_revision+1,assigned_modules=h.assigned_modules
                from sli_agent_policy_history h where a.id=$1 and h.agent_id=a.id and h.revision=a.policy_revision+1
                """, owner, revision);
            disable.Parameters.AddWithValue(first.Agent);
            Assert.Equal(1, await disable.ExecuteNonQueryAsync(ct));
            await revision.CommitAsync(ct);
            var revokedResult = await revoked.RunPageAsync(new(), ct);
            Assert.Equal("permission_denied", revokedResult.Reason);
            Assert.Empty(revokedResult.Checkpoint);
        }

        await using (var stillAllowed = await SigmaHistoryTest.OpenAsync(database, "security-only", new string('d', 64),
            [create], [onlySecurity], ct))
        {
            Assert.Equal("completed", (await stillAllowed.RunPageAsync(new(), ct)).Status);
        }

        var alternative = SigmaRule.Compile(RuleYaml(Guid.NewGuid(), 4698, "security", "TaskContent", "selection or alternate"));
        var unsupported = await Assert.ThrowsAsync<InvalidDataException>(() => SigmaHistoryTest.OpenAsync(database,
            "unsupported-rule", new string('f', 64), [alternative], [onlySecurity], ct));
        Assert.Equal("sigma_test_rule_kind_unsupported", unsupported.Message);

        await using (var changed = await SigmaHistoryTest.OpenAsync(database, "changed", new string('e', 64),
            [create], [onlySecurity], ct))
        {
            await PostCollectionPostgres.Sql(owner, """
                update event_source_representations_v2
                set representation=jsonb_set(representation,'{xml}','"<changed/>"'),representation_sha256=decode(repeat('4a',32),'hex')
                where event_id=900010
                """, ct);
            var changedResult = await changed.RunPageAsync(new(), ct);
            Assert.Equal("failed", changedResult.Status);
            Assert.Equal("sigma_test_snapshot_changed", changedResult.Reason);
            Assert.Empty(changedResult.Checkpoint);
        }
        Assert.Equal(false, await ScalarAsync(owner, """
            select has_table_privilege('adlog_semantic_worker','event_hot','SELECT')
                or has_table_privilege('adlog_semantic_worker','event_source_representations_v2','SELECT')
            """, ct));
        Assert.Equal(0L, await ScalarAsync(owner, "select count(*) from semantic_detection_matches", ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static async Task<JsonNode?> RunCliAsync(SqlPostgresFixture fixture, string planPath, string rulePath, CancellationToken ct)
    {
        string name = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        string host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ??
            Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", name));
        var start = new ProcessStartInfo(host)
        {
            WorkingDirectory = fixture.Pg.Root,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string arg in new[] { typeof(SigmaHistoryTestCommand).Assembly.Location, "sigma-history-test",
            "--plan", planPath, "--rule", rulePath, "--page-rows", "1" })
            start.ArgumentList.Add(arg);
        start.Environment["ADLOG_SIGMA_TEST_DSN"] = fixture.Dsn("sli_semantic_login");
        start.Environment.Remove("ADLOG_SIGMA_TEST_DSN_FILE");
        start.Environment.Remove("ADLOG_SIGMA_TEST_PASSWORD");
        start.Environment.Remove("ADLOG_SIGMA_TEST_PASSWORD_FILE");
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start Sigma TEST CLI");
        Task<string> stdout = child.StandardOutput.ReadToEndAsync(ct);
        Task<string> stderr = child.StandardError.ReadToEndAsync(ct);
        try { await child.WaitForExitAsync(ct); }
        catch (OperationCanceledException)
        {
            if (!child.HasExited) child.Kill();
            throw;
        }
        string response = await stdout;
        string error = await stderr;
        Assert.True(child.ExitCode == 0, $"Sigma TEST CLI exit {child.ExitCode}: {response} {error}");
        return JsonNode.Parse(response);
    }

    private static long Reason(JsonNode? row, string reason)
        => row!["reasons"]!.AsArray().Single(pair => pair![0]!.GetValue<string>() == reason)![1]!.GetValue<long>();

    private static void AssertCounts(JsonNode? row, int scanned, int evaluable, int matched, int unknown, int rejected, int skipped)
    {
        Assert.Equal(scanned, row.Number("scanned"));
        Assert.Equal(evaluable, row.Number("evaluable"));
        Assert.Equal(matched, row.Number("matched"));
        Assert.Equal(unknown, row.Number("unknown"));
        Assert.Equal(rejected, row.Number("rejected"));
        Assert.Equal(skipped, row.Number("skipped"));
    }

    private static SigmaRule Rule(int kind, string channel, string field)
        => SigmaRule.Compile(RuleYaml(Guid.NewGuid(), kind, channel, field));

    private static string RuleYaml(Guid id, int kind, string channel, string field, string condition = "selection") => $$"""
        title: Bounded native TEST fixture
        id: {{id}}
        author: Test
        logsource:
            product: windows
            service: {{channel}}
        detection:
            selection:
                EventID: {{kind}}
                {{field}}|contains: 'sigma-qa-only'
            alternate:
                {{field}}: 'QA-alternate'
            condition: {{condition}}
        """;

    private static async Task SeedAsync(SqlPostgresFixture fixture, NpgsqlConnection owner, TestSource source,
        string stamp, int record, int kind, string channel, int version, string? field, string? value, CancellationToken ct)
    {
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [kind],
            registered: (source.Agent, source.Host, source.Server, 1), nativeTimestamp: stamp, packetId: Guid.NewGuid(),
            sequence: record, firstRecordId: record, hostName: source.Name, eventChannel: channel,
            nativeFields: field is null ? null : new Dictionary<string, string> { [field] = value! }, nativeVersion: version);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
    }

    private static async Task<JsonObject> ScopeAsync(NpgsqlConnection owner, TestSource source, CancellationToken ct)
    {
        string installation = (string)(await ScalarAsync(owner,
            "select installation_id::text from semantic_default_installation", ct))!;
        return new() { ["installation_id"] = installation, ["plugin_id"] = "sli.windows.ad-dc",
            ["source_instance_id"] = source.Host.ToString(), ["source_generation"] = source.Host.ToString(),
            ["collection_scope_id"] = "" };
    }

    private static async Task BindAsync(NpgsqlConnection owner, JsonObject scope, TestSource source, CancellationToken ct)
    {
        await using var bind = new NpgsqlCommand("""
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select oid,rolname,(@scope->>'installation_id')::uuid,@scope->>'plugin_id',@scope->>'source_instance_id',
                @scope->>'source_generation','','core_event',(select id from log_sources where name='Security'),@agent
            from pg_roles where rolname='sli_semantic_login'
            """, owner);
        bind.Parameters.AddWithValue("scope", NpgsqlDbType.Jsonb, scope.ToJsonString());
        bind.Parameters.AddWithValue("agent", source.Agent);
        await bind.ExecuteNonQueryAsync(ct);
    }

    private static async Task<object?> ScalarAsync(NpgsqlConnection connection, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync(ct);
    }
}
