using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticContextHydrationTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string Provider = "Microsoft-Windows-Security-Auditing";
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-29T10:00:00Z");
    static CancellationToken Token => TestContext.Current.CancellationToken;
    static SemanticCorrelation Rule(string[]? roles = null) => SemanticCorrelation.Compile(new JsonObject {
        ["rule_id"] = "failed-then-success", ["rule_version"] = 1, ["rule_kind"] = "all_of",
        ["definition_json"] = new JsonObject {
            ["type"] = "all_of", ["inputs"] = new JsonArray("authentication.session.failed", "authentication.session.created"),
            ["join_roles"] = new JsonArray((roles ?? ["source_host", "affected_entity"]).Select(x => JsonValue.Create(x)).ToArray()),
            ["window_seconds"] = 300, ["output_relation_kind"] = "authentication.failed_then_succeeded",
            ["confidence"] = "medium", ["explanation"] = "A successful session followed failures for the same account."
        }
    });
    static JsonObject Source(long id = 7, int eventId = 4624) => new() {
        ["id"] = id, ["server_id"] = 3, ["domain_id"] = 1, ["log_source_id"] = 2, ["event_id"] = eventId,
        ["time_created_utc"] = SemanticJson.Stamp(Now), ["migrated_at"] = SemanticJson.Stamp(Now),
        ["normalized_hash"] = new string('a', 64), ["provider_name"] = Provider, ["channel"] = "Security",
        ["computer"] = "dc3.example.test", ["event_data_json"] = new JsonObject { ["TargetUserSid"] = Sid }
    };
    static JsonObject Trigger() => Row(SemanticNormalization.Normalize(Source(10, 4625)));
    static JsonObject Row(SemanticEvent ev) => new() {
        ["normalized_event_id"] = ev.Id().ToString(), ["source_event_id"] = ev.Source, ["semantic_type"] = ev.Type,
        ["occurred_at_utc"] = SemanticJson.Stamp(ev.At), ["roles_json"] = ev.Roles.DeepClone(),
        ["facts_json"] = ev.Facts.DeepClone(), ["quality_json"] = ev.Quality.DeepClone(), ["semantic_sha256"] = ev.Sha,
        ["semantic_contract_version"] = 1, ["normalizer_id"] = SemanticEvent.Normalizer, ["normalizer_version"] = SemanticEvent.Version
    };

    [Fact] public void Source_pack_identities_are_derived_from_projection_and_keep_noise_metadata()
    {
        var identities = SemanticNormalization.IdentitiesForTypes(["authentication.session.created", "audit.policy.changed"]);
        var session = Assert.Single(identities, x => x.Type == "authentication.session.created");
        Assert.Equal(("sli.windows.ad-dc", "Security", "4624", Provider, "context"), (session.Source, session.Stream, session.EventKey, session.Provider, session.Noise));
        Assert.False(string.IsNullOrWhiteSpace(session.CatalogVersion));
        Assert.Equal("signal", Assert.Single(identities, x => x.Type == "audit.policy.changed").Noise);
    }

    [Fact] public async Task Hydration_uses_exact_host_window_descriptor_roles_and_persists_without_jobs()
    {
        var session = new Session { Summaries = new(Source()) };
        int reads = 0;
        async Task<IReadOnlyDictionary<long, JsonObject>> Read(IReadOnlyList<JsonObject> summaries, CancellationToken ct) {
            reads++; Assert.Equal(7, Assert.Single(summaries).Number("id"));
            await Task.CompletedTask; return new Dictionary<long, JsonObject> { [7] = Source() };
        }
        Assert.Equal(1, await SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(Trigger()), "3", Now, Now, Read, Token));
        Assert.Equal(1, reads);
        var stored = Assert.Single(session.Normalized.Values);
        Assert.Equal(7, stored.Number("source_event_id")); Assert.Equal("authentication.session.created", stored.Text("semantic_type"));
        Assert.Equal("sid:" + Sid, stored["roles_json"].Text("affected_entity"));
        var query = Assert.Single(session.Commands, x => x.Sql.Contains("from public.semantic_event_source355 core"));
        Assert.Contains("lower(core.channel)=lower($8)", query.Sql);
        Assert.Contains("lower(coalesce(core.provider_name,''))=lower($9)", query.Sql);
        Assert.Contains("lower(case when nullif(btrim(core.target_user_sid)", query.Sql);
        Assert.Contains("stored_noise_catalog_version", query.Sql);
        Assert.Contains("normalized.source_event_id is null", query.Sql);
        Assert.Equal(3L, query.Values[3]); Assert.Equal(Now, query.Values[4]); Assert.Equal(Now, query.Values[5]);
        Assert.Equal(Sid, query.Values[9]);
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("semantic_processing_outbox") || x.Sql.Contains("insert into semantic_correlation_dispatch_jobs"));
    }

    [Fact] public async Task Context_exceeding_existing_matcher_contract_fails_before_archive()
    {
        var session = new Session { Summaries = new(Enumerable.Range(1, 5001).Select(x => (JsonNode)new JsonObject { ["id"] = x }).ToArray()) };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(Trigger()), "3", Now, Now, UnexpectedRead, Token));
        Assert.Equal("semantic_context_limit_exceeded", error.Message); Assert.Empty(session.Normalized);
    }

    [Fact] public async Task Dispatch_hydrates_before_matching_failed_then_success_without_context_job()
    {
        var success = Source(11); success["time_created_utc"] = SemanticJson.Stamp(Now.AddMinutes(1));
        var session = new Session { Summaries = new(success.DeepClone()) };
        session.Normalized[10] = Trigger();
        var events = await SemanticProduction.LoadDispatchEvents(session, Rule(), Trigger(), "3", (_, _) => Task.FromResult<IReadOnlyDictionary<long, JsonObject>>(new Dictionary<long, JsonObject> { [11] = success }), Token);
        var relation = Assert.Single(Rule().Match(events));
        Assert.Equal(new long[] { 10, 11 }, relation.Evidence.Select(x => x.Source));
        Assert.Equal("authentication.failed_then_succeeded", relation.Kind);
        var query = session.Commands.Last(); Assert.Contains("roles_json @> $7::jsonb", query.Sql);
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("semantic_processing_outbox") || x.Sql.Contains("insert into semantic_correlation_dispatch_jobs"));
    }

    [Fact] public async Task PostgreSQL_worker_filters_exact_short_context_without_jobs()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Token);
        await using var owner = await fixture.Pg.OpenAsync(Token);
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, Token);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, Token);
        await using (var legacy = new NpgsqlCommand("""
            select to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null
            """, owner))
            Assert.Equal(true, await legacy.ExecuteScalarAsync(Token));
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(Token);
        await using var transaction = await worker.BeginTransactionAsync(Token);
        await using var session = new SemanticSession(worker, transaction);
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticRuntimeSettings.InvestigationMode, 1);
        var at = new DateTimeOffset(rows[1].Time);
        var trigger = Trigger(); trigger["occurred_at_utc"] = SemanticJson.Stamp(at); trigger["roles_json"]!["source_host"] = "900001";
        // Neither a different host, time nor account can hydrate this context.
        Assert.Equal(0, await SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(trigger), "901000", at, at, UnexpectedRead, Token));
        Assert.Equal(0, await SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(trigger), "900001", at.AddHours(1), at.AddHours(1), UnexpectedRead, Token));
        var other = trigger.DeepClone(); other["roles_json"]!["affected_entity"] = "sid:S-1-5-21-100000001-200000002-300000003-1002";
        Assert.Equal(0, await SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(other), "900001", at, at, UnexpectedRead, Token));
        var events = await SemanticProduction.LoadDispatchEvents(session, Rule(), trigger, "900001", (identities, ct) => production.LoadContextSources(session, identities, ct), Token);
        var context = Assert.Single(events); Assert.Equal(rows[1].EventId, context.Source); Assert.Equal("sid:" + Sid, context.Roles.Text("affected_entity"));
        Assert.Equal(new long[] { 10, rows[1].EventId }, Assert.Single(Rule().Match([SemanticEvent.Read(trigger), context])).Evidence.Select(x => x.Source));
        Assert.Equal(0, await SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(trigger), "900001", at, at, UnexpectedRead, Token));
        var jobs = await session.QueryAsync("select count(*) as count from semantic_processing_outbox where source_event_id=$1", Token, rows[1].EventId);
        Assert.Equal(0, jobs[0].Number("count"));
        await transaction.CommitAsync(Token); await fixture.AssertNoSqlErrorsAsync(Token);
    }

    [Theory] [InlineData("server_id")] [InlineData("time_created_utc")]
    public async Task Archive_identity_conflicts_fail_before_persistence(string field)
    {
        var payload = Source(); payload[field] = field == "server_id" ? JsonValue.Create(4) : JsonValue.Create(SemanticJson.Stamp(Now.AddSeconds(1)));
        var session = new Session { Summaries = new(Source()) };
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(Trigger()), "3", Now, Now, (_, _) => Task.FromResult<IReadOnlyDictionary<long, JsonObject>>(new Dictionary<long, JsonObject> { [7] = payload }), Token));
        Assert.Empty(session.Normalized);
    }

    [Fact] public async Task Normalized_type_must_agree_with_requested_descriptor()
    {
        var session = new Session { Summaries = new(Source(7, 4719)) };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(Trigger()), "3", Now, Now, (_, _) => Task.FromResult<IReadOnlyDictionary<long, JsonObject>>(new Dictionary<long, JsonObject> { [7] = Source(7, 4719) }), Token));
        Assert.Equal("semantic_context_type_mismatch", error.Message); Assert.Empty(session.Normalized);
    }

    [Fact] public async Task Unsupported_join_role_never_broadens_context_lookup()
    {
        var session = new Session();
        Assert.Equal(0, await SemanticProduction.HydrateDispatchContext(session, Rule(["source_host", "actor"]), SemanticEvent.Read(Trigger()), "3", Now, Now, UnexpectedRead, Token));
        Assert.Empty(session.Commands);
    }

    [Theory] [InlineData("0")] [InlineData("other-host")]
    public async Task Non_numeric_or_non_positive_host_is_rejected(string host)
    {
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.HydrateDispatchContext(new Session(), Rule(), SemanticEvent.Read(Trigger()), host, Now, Now, UnexpectedRead, Token));
    }

    [Fact] public async Task Duplicate_context_and_inverted_window_fail_before_archive()
    {
        var session = new Session { Summaries = new(Source(), Source()) };
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.HydrateDispatchContext(session, Rule(), SemanticEvent.Read(Trigger()), "3", Now, Now, UnexpectedRead, Token));
        await Assert.ThrowsAsync<ArgumentException>(() => SemanticProduction.HydrateDispatchContext(new Session(), Rule(), SemanticEvent.Read(Trigger()), "3", Now.AddSeconds(1), Now, UnexpectedRead, Token));
    }

    [Fact] public async Task Bulk_archive_reads_shared_block_once_and_rejects_missing_identities()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-context-" + Guid.NewGuid().ToString("N"));
        try {
            var manifest = new ArchivePublisherTests.MemoryManifest();
            await new ArchivePublisher(root, manifest).PublishDirectAsync("synthetic-context", [Source(1), Source(2, 4672)], [], Token);
            var reader = new ArchiveReader(root, manifest);
            Assert.Equal(new long[] { 1, 2 }, (await reader.ReadEventsManyAsync([2, 1], Token)).Keys.Order());
            await Assert.ThrowsAsync<KeyNotFoundException>(() => reader.ReadEventsManyAsync([1, 3], Token));
            var cache = new Dictionary<ArchiveBlock, IReadOnlyList<JsonObject>>();
            var block = Assert.Single(manifest.Blocks.Values);
            Assert.Equal(1, reader.ReadEventFromBlock(block, 1, cache, Token).Number("id"));
            File.Delete(block.ObjectLocation);
            Assert.Equal(2, reader.ReadEventFromBlock(block, 2, cache, Token).Number("id"));
        } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    static Task<IReadOnlyDictionary<long, JsonObject>> UnexpectedRead(IReadOnlyList<JsonObject> _, CancellationToken ct) => throw new InvalidOperationException("archive must not be read");
    sealed class Session : ISemanticSession
    {
        internal JsonArray Summaries = [];
        internal readonly Dictionary<long, JsonObject> Normalized = [];
        internal readonly List<(string Sql, object?[] Values)> Commands = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) {
            Commands.Add((sql, values)); JsonArray rows = [];
            if (sql.Contains("from public.semantic_event_source355 core")) rows = (JsonArray)Summaries.DeepClone();
            else if (sql.Contains("insert into normalized_events")) {
                var ev = new SemanticEvent((long)values[1]!, (string)values[5]!, (DateTimeOffset)values[6]!, (JsonObject)values[8]!, (JsonObject)values[9]!, (JsonObject)values[10]!, Convert.ToHexStringLower((byte[])values[4]!));
                Normalized.TryAdd(ev.Source, Row(ev));
            }
            else if (sql.Contains("from normalized_events where source_event_id=$1")) rows = new(Normalized[(long)values[0]!].DeepClone());
            else if (sql.Contains("from normalized_events where processing_status")) rows = new(Normalized.Values.Select(x => x.DeepClone()).ToArray());
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
