using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticDevelopmentCalibrationTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public void Development_fixture_is_measured_but_never_claims_production_accuracy()
    {
        var result = SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(
            Enumerable.Repeat("confirmed_security", 8).Concat(Enumerable.Repeat("false_positive", 2)));
        Assert.Equal("measured", result.Text("state"));
        Assert.Equal(20.0, result["rate_percent"]!.GetValue<double>());
        Assert.True(result.Flag("development_contract_ready"));
        Assert.False(result.Flag("counts_as_analyst_sample"));
        Assert.False(result.Flag("production_accuracy_claim"));
        Assert.False(result.Flag("writes_runtime_data"));
        Assert.Equal("development_decisive_fixture_available", result.Text("reason"));
        Assert.Equal("637e1acc67a14245dd67181f86b0d4be1aceada678f3cb44455c2d3512329658", result.Text("fixture_fingerprint_sha256"));
        Assert.Equal(10, result.Number("reviewed_scenarios"));
        Assert.Equal(10, result.Number("decisive_labels"));
        Assert.Equal(2, result.Number("false_positive_labels"));
        SemanticDevelopmentCalibration.AssertDevelopmentOnly(result);
    }

    [Theory]
    [InlineData(1, "insufficient_sample", "development_fixture_minimum_10_decisive_labels_required", false)]
    [InlineData(9, "insufficient_sample", "development_fixture_minimum_10_decisive_labels_required", false)]
    [InlineData(10, "measured", "development_decisive_fixture_available", true)]
    [InlineData(100, "measured", "development_decisive_fixture_available", true)]
    public void Decisive_sample_boundaries(int count, string state, string reason, bool ready)
    {
        var result = SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(Enumerable.Repeat(" FALSE_POSITIVE ", count));
        Assert.Equal(state, result.Text("state"));
        Assert.Equal(reason, result.Text("reason"));
        Assert.Equal(ready, result.Flag("development_contract_ready"));
        Assert.Equal(100.0, result["rate_percent"]!.GetValue<double>());
        Assert.Equal(count, result["by_verdict"].Number("false_positive"));
        SemanticDevelopmentCalibration.AssertDevelopmentOnly(result);
    }

    [Fact]
    public void Nondecisive_labels_do_not_inflate_accuracy_sample()
    {
        var result = SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(["benign_expected", "insufficient_evidence"]);
        Assert.Equal("not_measurable", result.Text("state"));
        Assert.Equal("development_fixture_decisive_analyst_labels_not_available", result.Text("reason"));
        Assert.Null(result["rate_percent"]);
        Assert.Equal(2, result.Number("reviewed_scenarios"));
        Assert.Equal(0, result.Number("decisive_labels"));
        Assert.False(result.Flag("development_contract_ready"));
        var mixed = SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(["confirmed_security", "false_positive", "benign_expected", "insufficient_evidence"], minimumSample: 2);
        Assert.Equal("measured", mixed.Text("state"));
        Assert.Equal(2, mixed.Number("minimum_decisive_sample"));
        Assert.Equal(2, mixed.Number("decisive_labels"));
        Assert.Equal(4, mixed.Number("reviewed_scenarios"));
        Assert.Equal(50.0, mixed["rate_percent"]!.GetValue<double>());
    }

    [Theory] [InlineData(0)] [InlineData(101)]
    public void Fixture_size_rejected(int count) => Assert.Equal("development calibration requires 1..100 fixture labels",
        Assert.Throws<ArgumentException>(() => SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(Enumerable.Repeat("false_positive", count))).Message);

    [Theory] [InlineData(null)] [InlineData("")] [InlineData("enabled")]
    public void Unsupported_verdicts_rejected(string? verdict) => Assert.Equal("unsupported development fixture verdicts: " + (verdict ?? ""),
        Assert.Throws<ArgumentException>(() => SemanticDevelopmentCalibration.EvaluateDevelopmentFixture([verdict])).Message);

    [Theory]
    [InlineData("evidence_class", "\"analyst_review\"", "development calibration evidence class mismatch")]
    [InlineData("counts_as_analyst_sample", "true", "development fixture cannot count as an analyst sample")]
    [InlineData("counts_as_analyst_sample", "null", "development fixture cannot count as an analyst sample")]
    [InlineData("counts_as_analyst_sample", "0", "development fixture cannot count as an analyst sample")]
    [InlineData("production_accuracy_claim", "true", "development fixture cannot claim production accuracy")]
    [InlineData("production_accuracy_claim", "null", "development fixture cannot claim production accuracy")]
    [InlineData("production_accuracy_claim", "\"false\"", "development fixture cannot claim production accuracy")]
    public void Fixture_cannot_be_relabelled_as_production(string field, string json, string error)
    {
        var result = SemanticDevelopmentCalibration.EvaluateDevelopmentFixture(["confirmed_security"]);
        result[field] = JsonNode.Parse(json);
        Assert.Equal(error, Assert.Throws<ArgumentException>(() => SemanticDevelopmentCalibration.AssertDevelopmentOnly(result)).Message);
        result.Remove(field);
        Assert.Equal(error, Assert.Throws<ArgumentException>(() => SemanticDevelopmentCalibration.AssertDevelopmentOnly(result)).Message);
    }

    [Fact]
    public async Task Development_scope_guard_leaves_no_outer_transaction_and_rejects_enabled_policy()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Token);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await owner.OpenAsync(Token);
        await PostCollectionPostgres.Sql(owner, """
            update semantic_risk_policies set lifecycle_status='shadow' where lifecycle_status='enabled';
            insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values('synthetic-development-calibration',1,'control_health','test','{}',sha256('{}'::bytea));
            """, Token);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var db = await runtime.OpenAsync(Token);
        foreach (string mode in new[] { "test", "shadow", "enabled" })
        {
            await using var update = new NpgsqlCommand("update semantic_risk_policies set lifecycle_status=@mode where policy_id='synthetic-development-calibration'", owner);
            update.Parameters.AddWithValue("mode", mode);
            await update.ExecuteNonQueryAsync(Token);
            if (mode == "enabled")
                Assert.Equal("semantic_development_scope_required", (await Assert.ThrowsAsync<InvalidOperationException>(() => DevelopmentSemanticGuard.ValidateDatabaseAsync(db, Token))).Message);
            else
                await DevelopmentSemanticGuard.ValidateDatabaseAsync(db, Token);
            // Npgsql executes the guard in autocommit; the next job owns a fresh transaction.
            await using var job = await db.BeginTransactionAsync(Token);
            await job.CommitAsync(Token);
        }
        await fixture.AssertNoSqlErrorsAsync(Token);
    }

    [Theory] [InlineData("ok")] [InlineData("missing")] [InlineData("corrupt")] [InlineData("identity")]
    public async Task Semantic_source_uses_controller_authorized_archive_without_rerouting(string outcome)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-development-calibration-" + Guid.NewGuid().ToString("N"));
        try
        {
            var manifest = new ArchivePublisherTests.MemoryManifest();
            var source = new JsonObject { ["id"] = 7L, ["server_id"] = 1, ["domain_id"] = 1, ["log_source_id"] = 1,
                ["event_id"] = 4724, ["time_created_utc"] = "2026-11-01T00:00:00+00:00", ["event_data_json"] = new JsonObject() };
            var identity = source.DeepClone().AsObject();
            identity["provider_name"] = "Microsoft-Windows-Security-Auditing";
            identity["channel"] = "Security"; identity["computer"] = "dc.example.test";
            identity["migrated_at"] = "2026-11-01T00:00:01+00:00"; identity["normalized_hash"] = new string('a', 64);
            await new ArchivePublisher(root, manifest).PublishDirectAsync("synthetic-development-calibration", [source], [], Token);
            if (outcome == "missing") manifest.Blocks.Clear();
            if (outcome == "corrupt") File.WriteAllText(Assert.Single(manifest.Blocks.Values).ObjectLocation, "corrupt");
            if (outcome == "identity") identity["server_id"] = 2;
            await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? "Host=192.0.2.1;Username=synthetic_semantic;Database=synthetic" : null, _ => throw new InvalidOperationException());
            var pipeline = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticProduction.DevelopmentMode, 1,
                development: true, authorizedArchive: new ArchiveReader(root, manifest));
            await using var session = new NoRoutingSession();
            Task<JsonObject> Read() => pipeline.LoadSource(session, 7, identity, Token);
            if (outcome == "missing") await Assert.ThrowsAsync<FileNotFoundException>(Read);
            else if (outcome is "corrupt" or "identity") await Assert.ThrowsAsync<InvalidDataException>(Read);
            else
            {
                var result = await Read();
                Assert.Equal(7, result.Number("id"));
                Assert.Equal("dc.example.test", result.Text("computer"));
                Assert.Equal(identity.Text("normalized_hash"), result.Text("source_event_sha256"));
                Assert.Equal(1, result.Number("source_host_id"));
            }
            Assert.Equal(0, session.Calls);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private sealed class NoRoutingSession : ISemanticSession
    {
        internal int Calls;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        { Calls++; throw new InvalidOperationException("authorized archive must not fall back to database or environment routing"); }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
