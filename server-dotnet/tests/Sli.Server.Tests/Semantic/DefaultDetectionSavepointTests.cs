using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class DefaultDetectionSavepointTests
{
    // tests/semantic/test_default_detection_savepoints.py: real transaction failures,
    // with synthetic detector inputs and writes, rather than a fake transaction.
    [Theory]
    [InlineData("sql", 2, 1, "decoy")]
    [InlineData("rollback", 0, 1, "")]
    [InlineData("entry", 0, 1, "")]
    [InlineData("release", 0, 1, "")]
    [InlineData("commit", 0, 1, "")]
    [InlineData("none", 5, 0, "decoy,ransom-admission,ransom-runtime")]
    [InlineData("disabled", 2, 0, "decoy,ransom-admission")]
    public async Task Default_source_counts_only_committed_work_and_recovers_connection(
        string failure, int jobs, int failed, string kinds)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table isolation_writes(kind text, unique(kind) deferrable initially deferred);
            create table isolation_sources(source jsonb);
            create function public.default_detection_sources() returns table(source jsonb)
                language sql as $$select source from isolation_sources$$;
            create function public.read_default_file_acl_resources(jsonb,integer) returns jsonb
                language sql as $$select '{"items":[]}'::jsonb$$;
            """, ct);
        var source = new JsonObject {
            ["scope"] = RemainingDetectorTests.Scope("sli.file-audit"),
            ["agent_id"] = "11111111-1111-1111-1111-111111111111",
            ["config"] = new JsonObject { ["policy_revision"] = "3", ["mass_operation_files"] = 25, ["mass_operation_seconds"] = 60 }
        };
        source["scope"]!["collection_scope_id"] = "root";
        await using (var insert = new NpgsqlCommand("insert into isolation_sources values($1)", db)) {
            SemanticSession.Parameters(insert, [source]); await insert.ExecuteNonQueryAsync(ct);
        }
        await using var runtime = PasswordProducerRuntime.Create(
            n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? pg.ConnectionString : null, _ => throw new InvalidOperationException());
        var production = new SemanticProduction(runtime, new(true, true, false, false, false, false), "facts-v1", 1);
        SourceSession? session = null;
        var (result, discovered) = await production.ProcessDefaultDetections(db, ct,
            inner => session = new SourceSession(inner, source, failure));

        Assert.Single(discovered);
        Assert.Equal(1, result.Number("sources"));
        Assert.Equal(jobs, result.Number("jobs"));
        Assert.Equal(failed, result.Number("failed"));
        Assert.Null(result["file_ransom_status"]);
        Assert.NotNull(session);
        Assert.Equal(failure != "entry", session.AdmissionReached);
        Assert.Equal(failure is not ("entry" or "disabled"), session.RuntimeReached);
        Assert.Equal(failure is "none" or "commit" or "release" ? 5 : 2, session.GeneratedJobs);
        string[] expectedStates = failure switch {
            "sql" => ["22012"], "rollback" => ["22012", "3B001"],
            "entry" => ["3B001"], "release" => ["3B001", "3B001"], _ => []
        };
        Assert.Equal(expectedStates, session.SqlStates);
        Assert.Equal(failure == "commit", session.DeferredDuplicateAccepted);
        Assert.Equal(42, await Scalar(db, "select 42", ct));
        await using (var query = new NpgsqlCommand("select kind from isolation_writes order by kind", db)) {
            await using var reader = await query.ExecuteReaderAsync(ct);
            var actual = new List<string>();
            while (await reader.ReadAsync(ct)) actual.Add(reader.GetString(0));
            Assert.Equal(kinds.Length == 0 ? [] : kinds.Split(','), actual);
        }
        // Recovery includes a fresh durable transaction on the very same connection.
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await using var insert = new NpgsqlCommand("insert into isolation_writes values('recovered')", db, tx);
            await insert.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        Assert.Equal(1L, await Scalar(db, "select count(*) from isolation_writes where kind='recovered'", ct));
    }

    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand(sql, db); return await query.ExecuteScalarAsync(ct);
    }

    private sealed class SourceSession : ISemanticSession
    {
        private readonly ISemanticSession inner;
        private readonly string failure;
        private readonly RemainingDetectorTests.NativeSession decoy, ransom;
        private RemainingDetectorTests.NativeSession active;
        private bool inRansom;
        internal bool AdmissionReached, RuntimeReached, DeferredDuplicateAccepted;
        internal List<string> SqlStates = [];
        internal int GeneratedJobs => decoy.Jobs + ransom.Jobs;

        internal SourceSession(ISemanticSession inner, JsonObject source, string failure)
        {
            this.inner = inner; this.failure = failure;
            decoy = Detector("file-decoy", "read", source);
            ransom = Detector("file-ransom", "complete", source);
            active = decoy;
        }

        private static RemainingDetectorTests.NativeSession Detector(string kind, string name, JsonObject source)
        {
            var vector = JsonNode.Parse((string)RemainingDetectorTests.Vectors()
                .Single(v => (string)v[0] == kind && (string)v[1] == name)[2])!.AsObject();
            var input = vector["rule"]!.AsObject();
            input["scope"] = source["scope"]!.DeepClone();
            if (kind == "file-ransom") {
                input["source_policy_revision"] = "3"; input["threshold"] = 25; input["window_seconds"] = 60;
                var result = vector["row"]!["result"]!;
                result["details"]!["threshold"] = 25; result["details"]!["window_seconds"] = 60;
                result["details"]!["distinct_files"] = 25;
                result["action_ids"] = new JsonArray(Enumerable.Range(0, 25).Select(i => (JsonNode?)JsonValue.Create("action-" + i)).ToArray());
            }
            var rule = DetectorRule.Read(kind, input);
            return new(vector, rule) { AclDefinition = rule.Definition() };
        }

        public async Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.StartsWith("savepoint ") || sql.StartsWith("rollback to ") || sql.StartsWith("release ")) {
                bool breakCommand = failure switch {
                    "entry" => sql.StartsWith("savepoint "),
                    "rollback" => sql.StartsWith("rollback to "),
                    "release" => sql.StartsWith("release "),
                    _ => false
                };
                // The error originates in PostgreSQL, and aborts its transaction.
                return await DatabaseQuery(breakCommand ? "rollback to savepoint synthetic_missing_savepoint" : sql, ct);
            }
            if (sql.Contains("pg_advisory_xact_lock")) return await DatabaseQuery(sql, ct, values);
            if (sql.Contains("ensure_default_qw_policy")) {
                var definition = JsonNode.Parse((string)values[1]!)!;
                inRansom = definition.Text("scenario_kind") == "qw.file-ransom";
                active = inRansom ? ransom : decoy;
                Assert.True(JsonNode.DeepEquals(active.AclDefinition, definition));
                if (inRansom) {
                    AdmissionReached = true;
                    await DatabaseQuery("insert into isolation_writes values('ransom-admission')", ct);
                    return new(new JsonObject { ["admitted"] = failure != "disabled" });
                }
            }
            // Native proof verification re-reads one observation; only the initial scan writes.
            if (sql.Contains("read_file_decoy_observations") && values.Length == 3)
                await DatabaseQuery("insert into isolation_writes values('decoy')", ct);
            if (sql.Contains("read_file_ransom_results")) {
                RuntimeReached = true;
                Assert.Equal("3", values[2]); Assert.Equal(25, values[4]); Assert.Equal(60, values[5]);
                await DatabaseQuery("insert into isolation_writes values('ransom-runtime')", ct);
                if (failure is "sql" or "rollback") await DatabaseQuery("select 1/0", ct);
                if (failure == "commit") {
                    await DatabaseQuery("insert into isolation_writes values('decoy')", ct);
                    DeferredDuplicateAccepted = true;
                }
            }
            var rows = await active.QueryAsync(sql, ct, values);
            if (sql.Contains("from semantic_risk_policy_subscriptions")) {
                var policies = new JsonArray();
                for (int i = 0; i < (inRansom ? 3 : 2); i++) {
                    var policy = rows[0]!.DeepClone(); policy["policy_id"] = "synthetic-policy-" + i; policies.Add(policy);
                }
                return policies;
            }
            if (sql.StartsWith("insert into semantic_qw_signals")) {
                var signal = (JsonObject)values[2]!;
                Assert.Equal(TimeSpan.Zero, DateTimeOffset.Parse(signal.Text("received_at_utc")!).Offset);
            }
            return rows;
        }
        private async Task<JsonArray> DatabaseQuery(string sql, CancellationToken ct, params object?[] values)
        {
            try { return await inner.QueryAsync(sql, ct, values); }
            catch (PostgresException error) { SqlStates.Add(error.SqlState); throw; }
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
