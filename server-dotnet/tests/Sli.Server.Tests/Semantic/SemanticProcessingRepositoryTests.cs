using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Repository vectors from tests/semantic/test_semantic_processing_repository1.py.
// The session supplies database responses, like the reference Cursor; all SQL
// and transformations under test run through the production repository methods.
[Collection("Semantic producer environment")]
public sealed class SemanticProcessingRepositoryTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Occurred = DateTimeOffset.Parse("2026-07-19T01:00:00Z");
    private static JsonObject Identity(long id = 7) => new()
    {
        ["id"] = id, ["server_id"] = 1, ["domain_id"] = 2, ["log_source_id"] = 3, ["event_id"] = 4624,
        ["time_created_utc"] = SemanticJson.Stamp(Occurred), ["normalized_hash"] = string.Concat(Enumerable.Repeat("6e", 32)),
        ["correlation_id"] = null, ["migrated_at"] = SemanticJson.Stamp(Occurred),
        ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["channel"] = "Security", ["computer"] = "dc.example.test"
    };
    private sealed class Session : ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Commands = [];
        internal Func<string, object?[], JsonArray> Respond = (_, _) => new();
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            ct.ThrowIfCancellationRequested(); Commands.Add((sql, values));
            return Task.FromResult(Respond(sql, values));
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private static JsonArray Rows(JsonNode row) => new(row.DeepClone());
    private static JsonObject Job(int attempts = 1) => new()
    {
        ["job_id"] = "11111111-1111-4111-8111-111111111111", ["lease_token"] = "22222222-2222-4222-8222-222222222222",
        ["attempt_count"] = attempts, ["max_attempts"] = 5
    };
    private static SemanticEvent Event(long id = 7, int eventId = 4624)
    {
        var source = Identity(id); source["event_id"] = eventId;
        source["event_data_json"] = new JsonObject { ["TargetUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001", ["TargetLogonId"] = "0x7" };
        return SemanticNormalization.Normalize(source);
    }

    [Fact]
    public async Task Enqueue_is_identity_only_idempotent_and_missing_source_is_an_error()
    {
        var row = new JsonObject { ["job_id"] = Job()["job_id"].Copy(), ["payload_json"] = new JsonObject { ["selection_reason"] = "signal" }, ["source_identity_json"] = Identity() };
        var session = new Session { Respond = (sql, _) => sql.StartsWith("select job_id,") ? Rows(row) : new() };
        await SemanticProduction.EnqueueSource(session, 7, "signal", Ct);
        await SemanticProduction.EnqueueSource(session, 7, "signal", Ct);
        var insert = session.Commands[0];
        Assert.Equal(insert.Values[..3], session.Commands[2].Values[..3]);
        Assert.True(JsonNode.DeepEquals(Assert.IsType<JsonObject>(insert.Values[3]), Assert.IsType<JsonObject>(session.Commands[2].Values[3])));
        Assert.Equal(insert.Values[4], session.Commands[2].Values[4]);
        Assert.Contains("on conflict(idempotency_key) do nothing", insert.Sql);
        foreach (string field in new[] { "partition_key", "occurred_at_utc", "source_identity_json" }) Assert.Contains(field, insert.Sql);
        Assert.DoesNotContain("raw_xml", insert.Sql); Assert.DoesNotContain("event_data", insert.Sql);
        Assert.Equal(SemanticEvent.Version, insert.Values[1]);
        Assert.Equal(Guid.Parse("952f691a-b153-5ea0-83f5-c67a433c68b5"), insert.Values[0]);
        Assert.Equal(Convert.FromHexString(SemanticProducer.JobIdentity(7)), Assert.IsType<byte[]>(insert.Values[2]));
        var error = await Assert.ThrowsAsync<KeyNotFoundException>(() => SemanticProduction.EnqueueSource(new Session(), 404, "signal", Ct));
    }

    [Theory] [InlineData("payload")] [InlineData("source")]
    public async Task Enqueue_rejects_conflicting_replay(string conflict)
    {
        var row = new JsonObject { ["job_id"] = Job()["job_id"].Copy(), ["payload_json"] = new JsonObject { ["selection_reason"] = conflict == "payload" ? "different" : "signal" }, ["source_identity_json"] = Identity(conflict == "source" ? 9 : 7) };
        var session = new Session { Respond = (sql, _) => sql.StartsWith("select job_id,") ? Rows(row) : new() };
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.EnqueueSource(session, 7, "signal", Ct));
        Assert.Equal(conflict == "payload" ? "semantic_job_replay_payload_conflict" : "semantic_job_source_identity_conflict", error.Message);
    }

    [Fact]
    public void Source_identity_strips_payload_and_validates_its_retained_boundary()
    {
        var input = Identity(); input["event_data_json"] = new JsonObject { ["private"] = "synthetic" }; input["normalized_hash"] = input.Text("normalized_hash")!.ToUpperInvariant();
        var actual = SemanticProduction.SourceIdentity(input);
        Assert.True(JsonNode.DeepEquals(Identity(), actual)); Assert.Equal(12, actual.Count);
        input["normalized_hash"] = "invalid";
        Assert.Throws<InvalidDataException>(() => SemanticProduction.SourceIdentity(input));
        input = Identity(); input.Remove("channel");
        Assert.Throws<InvalidDataException>(() => SemanticProduction.SourceIdentity(input));
        input = Identity(); input["computer"] = new string('x', 4096);
        Assert.Throws<InvalidDataException>(() => SemanticProduction.SourceIdentity(input));
    }

    [Fact]
    public void Queue_identity_changes_with_identity_rules_and_normalizer_release()
    {
        Assert.EndsWith("identity-1.0", SemanticEvent.Version);
        Assert.Equal("f80b3392afbed2d337f0326672a26cffa5537994a8ae2e56e2d0d2cdbeb47ef8", SemanticProducer.JobIdentity(7));
        Assert.NotEqual(SemanticProducer.JobIdentity(7, identityVersion: "identity-v1"), SemanticProducer.JobIdentity(7, identityVersion: "identity-v2"));
        Assert.NotEqual(SemanticProducer.JobIdentity(7, version: "1.1+identity-1.0"), SemanticProducer.JobIdentity(7));
        var row = Assert.Single(SemanticProducer.JobRows([new(7, "signal")]));
        Assert.Equal("\\x" + SemanticProducer.JobIdentity(7), row.Text("hash"));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Claim_requires_current_contract_skip_locked_and_exact_recovery_scope(bool repair)
    {
        var session = new Session(); string? digest = repair ? new string('a', 64) : null;
        Assert.Empty(await SemanticProduction.Claim(session, Ct, digest, [9, 7, 9]));
        var (sql, args) = Assert.Single(session.Commands);
        Assert.Contains("semantic_contract_version=1", sql); Assert.Contains("processor_id='semantic-shadow'", sql);
        Assert.Contains("job_kind='semantic_replay' and processor_version like $3", sql);
        Assert.Contains("job_kind<>'semantic_replay' and processor_version=$2", sql);
        Assert.Equal(SemanticEvent.Version, args[1]); Assert.Equal(SemanticEvent.Version + "+r7-%", args[2]);
        Assert.Contains("for update skip locked", sql); Assert.Contains("status='leased'", sql);
        // Attempt accounting is exercised against PostgreSQL, including a
        // crashed final lease, in SemanticShortWorkerPostgresTests.
        Assert.Contains("lease_token=$1", sql);
        Assert.Contains("lease_until<now()", sql); Assert.Contains("attempt_count<max_attempts", sql);
        Assert.Contains("source_event_id=any($" + args.Length + ")", sql);
        Assert.Equal(new long[] { 7, 9 }, Assert.IsType<long[]>(args[^1]));
        if (repair) { Assert.Contains("job_kind='semantic_v2_quarantine_repair'", sql); Assert.Contains("payload_json->>'repair_plan_digest'=$4", sql); Assert.Equal(digest, args[3]); }
        else { Assert.Contains("job_kind<>'semantic_v2_quarantine_repair'", sql); Assert.DoesNotContain("repair_plan_digest", sql); }
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.Claim(session, Ct, "invalid"));
    }

    [Fact]
    public async Task Heartbeat_completion_failure_and_deferral_require_the_lease_owner()
    {
        var job = Job(5); var session = new Session { Respond = (_, _) => Rows(new JsonObject { ["job_id"] = job["job_id"].Copy() }) };
        Assert.True(await SemanticProduction.HeartbeatJob(session, job, Ct));
        await SemanticProduction.Complete(session, "semantic_processing_outbox", "status", job, Ct);
        await SemanticProduction.Fail(session, "semantic_processing_outbox", "status", job, Ct, new InvalidDataException("synthetic"), SemanticProcessingStep.PersistAction);
        Assert.Equal("quarantined", session.Commands[2].Values[0]);
        await SemanticProduction.Fail(session, "semantic_processing_outbox", "status", Job(1), Ct, new InvalidDataException("synthetic"), SemanticProcessingStep.Normalize);
        Assert.Equal("failed", session.Commands[3].Values[0]);
        await SemanticProduction.Defer(session, job, Ct);
        foreach (var command in session.Commands) { Assert.Contains("status='leased'", command.Sql); Assert.Contains("lease_token=", command.Sql); Assert.Contains(Guid.Parse(job.Text("job_id")!), command.Values); Assert.Contains(Guid.Parse(job.Text("lease_token")!), command.Values); }
        Assert.Contains("status='completed'", session.Commands[1].Sql);
        Assert.Contains("status='queued',attempt_count=greatest(attempt_count-1,0)", session.Commands[^1].Sql);
        var lost = new Session(); Assert.False(await SemanticProduction.HeartbeatJob(lost, job, Ct));
        Assert.Contains("lease was lost", (await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.Complete(lost, "semantic_processing_outbox", "status", job, Ct))).Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.Defer(lost, job, Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.Fail(lost, "semantic_processing_outbox", "status", job, Ct, new Exception(), SemanticProcessingStep.Normalize));
    }

    [Fact]
    public void Archived_payload_is_hydrated_using_retained_identity()
    {
        var identity = Identity(); var payload = Identity();
        foreach (string field in new[] { "provider_name", "channel", "computer", "normalized_hash", "migrated_at", "correlation_id" }) payload.Remove(field);
        payload["event_data_json"] = new JsonObject { ["TargetLogonId"] = "0x1" };
        var result = SemanticProduction.HydrateSource(7, identity, payload);
        Assert.Equal("0x1", result["event_data_json"].Text("TargetLogonId")); Assert.Equal(1, result.Number("source_host_id"));
        Assert.Equal(identity.Text("normalized_hash"), result.Text("source_event_sha256")); Assert.Equal(identity.Text("migrated_at"), result.Text("source_ingested_at"));
        foreach (string field in new[] { "provider_name", "channel", "computer" }) Assert.Equal(identity.Text(field), result.Text(field));
        Assert.Throws<InvalidDataException>(() => SemanticProduction.HydrateSource(9, identity, payload));
        payload["domain_id"] = 9;
        Assert.Throws<InvalidDataException>(() => SemanticProduction.HydrateSource(7, identity, payload));
    }

    [Fact]
    public async Task Source_load_reads_verified_archive_after_core_retention_without_legacy_join()
    {
        string root = Path.Combine(Path.GetTempPath(), "semantic-source-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT");
        try
        {
            var payload = Identity(); payload["event_data_json"] = new JsonObject { ["TargetLogonId"] = "0x1" };
            var raw = ArchiveCodec.Encode("event", [payload]); var compressed = ArchiveCodec.Compress(raw.Raw);
            string path = Path.Combine(root, "published", "fixture.jsonl.gz");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllBytes(path, compressed);
            var block = new JsonObject
            {
                ["archive_set_id"] = "44444444-4444-4444-8444-444444444444", ["format_version"] = 1, ["block_index"] = 0,
                ["first_event_id"] = 7, ["last_event_id"] = 7, ["row_count"] = 1,
                ["raw_bytes"] = raw.Raw.Length, ["compressed_bytes"] = compressed.Length,
                ["raw_sha256"] = ArchiveCodec.Hash(raw.Raw), ["archive_sha256"] = ArchiveCodec.Hash(compressed),
                ["object_location"] = path, ["created_at"] = SemanticJson.Stamp(Occurred)
            };
            Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", root);
            // Builds a data source without opening a connection. The archive path
            // must remain readable after both the core and short row expire.
            await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? "Host=192.0.2.1;Database=synthetic;Username=synthetic;Password=synthetic" : null, _ => throw new InvalidOperationException("unexpected_secret_read"));
            var production = new SemanticProduction(runtime, new(true, true, false, false, false, false), SemanticRuntimeSettings.FactsMode, 1);
            var session = new Session { Respond = (sql, _) => sql.Contains("from public.semantic_event_source355 where") ? new JsonArray() : sql.Contains("from storage_v2_archive_blocks") ? Rows(block) : sql.Contains("has_table_privilege") ? Rows(new JsonObject { ["available"] = true }) : sql.Contains("from public.storage_v2_runtime_authorizations") ? Rows(SemanticArchiveFixture.Authorization(root)) : throw new InvalidOperationException("unexpected_database_read") };
            var result = await production.LoadSource(session, 7, Identity(), Ct);
            Assert.Equal("0x1", result["event_data_json"].Text("TargetLogonId")); Assert.Equal(1, result.Number("source_host_id"));
            Assert.Equal(Identity().Text("normalized_hash"), result.Text("source_event_sha256"));
            Assert.All(session.Commands, query => { Assert.DoesNotContain("events_v2_core", query.Sql); Assert.DoesNotContain("join events legacy", query.Sql); });
            File.WriteAllBytes(path, new byte[compressed.Length]);
            await Assert.ThrowsAsync<InvalidDataException>(() => production.LoadSource(session, 7, Identity(), Ct));
        }
        finally
        {
            Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", previous);
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Theory] [InlineData(4624)] [InlineData(4625)]
    public async Task Normalized_persistence_is_versioned_and_keeps_complete_facts_without_core_join(int eventId)
    {
        var ev = Event(eventId: eventId); const string version = "1.3+identity-1.0";
        Assert.NotEqual(ev.Id("1.1+identity-1.0"), ev.Id(version));
        var stored = new JsonObject { ["normalized_event_id"] = ev.Id(version).ToString(), ["semantic_sha256"] = ev.Sha, ["semantic_type"] = ev.Type, ["occurred_at_utc"] = SemanticJson.Stamp(ev.At), ["roles_json"] = ev.Roles.Copy(), ["facts_json"] = ev.Facts.Copy(), ["quality_json"] = ev.Quality.Copy() };
        var session = new Session { Respond = (sql, _) => sql.StartsWith("select normalized_event_id,") ? Rows(stored) : new() };
        await SemanticProduction.PersistNormalized(session, ev, Identity(), version, Ct);
        var (sql, args) = session.Commands[0];
        Assert.Contains("values($1", sql); Assert.Contains("source_identity_json", sql); Assert.DoesNotContain("events_v2_core", sql);
        Assert.Equal(ev.Id(version), args[0]); Assert.Equal(version, args[2]); Assert.Equal(ev.Type, args[5]); Assert.Equal(ev.At, args[6]);
        Assert.True(JsonNode.DeepEquals(ev.Roles, Assert.IsType<JsonObject>(args[8]))); Assert.True(JsonNode.DeepEquals(ev.Facts, Assert.IsType<JsonObject>(args[9]))); Assert.True(JsonNode.DeepEquals(ev.Quality, Assert.IsType<JsonObject>(args[10])));
        stored["semantic_type"] = "different";
        Assert.Equal("normalized_event_replay_conflict", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistNormalized(session, ev, Identity(), version, Ct))).Message);
        await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistNormalized(session, ev, Identity(9), version, Ct));
    }

    private static SemanticAction Action(string kind = "audit.policy.changed", params SemanticEvent[] evidence) => new(kind, Occurred, string.Concat(Enumerable.Repeat("ab", 32)), new JsonObject { ["material_identity"] = new JsonObject { ["source_host"] = "dc.example.test" } }, evidence);
    private static JsonObject Existing(SemanticAction action) => new()
    {
        ["canonical_action_id"] = action.Id.ToString(), ["action_kind"] = action.Kind, ["action_status"] = "observed",
        ["semantic_contract_version"] = 1, ["assembler_id"] = "semantic-action-assembler", ["assembler_version"] = "1.0",
        ["dedup"] = action.Key, ["action_sha256"] = string.Concat(Enumerable.Repeat("11", 32)), ["attributes_json"] = action.Attributes.Copy()
    };
    private static JsonObject Link(SemanticEvent ev, int order = 0) => new()
    {
        ["source_event_id"] = ev.Source, ["normalized_event_id"] = ev.Id("1.1+identity-1.0").ToString(),
        ["evidence_role"] = order == 0 ? "primary" : "supporting", ["entity_role"] = null, ["evidence_order"] = order, ["relation_confidence"] = "1.000"
    };
    private static Session CanonicalSession(JsonObject? old, JsonArray? links = null, bool dedupLookup = false) => new()
    {
        Respond = (sql, args) =>
        {
            if (sql.StartsWith("select *,encode(canonical_deduplication_key")) return old is not null && (!dedupLookup || sql.Contains("where semantic_contract_version")) ? Rows(old) : new();
            if (sql.StartsWith("select n.source_event_id,")) return links?.DeepClone().AsArray() ?? new();
            if (sql.StartsWith("select normalized_event_id from canonical_action_evidence")) return new JsonArray(links?.Where(x => x.Number("source_event_id") == (long)args[1]!).Select(x => x!.DeepClone()).ToArray() ?? []);
            if (sql.StartsWith("update canonical_action_evidence set normalized_event_id"))
                foreach (var link in links ?? new()) if (link.Text("normalized_event_id") == args[2]!.ToString()) link!["normalized_event_id"] = args[0]!.ToString();
            return new();
        }
    };

    [Fact]
    public async Task Canonical_writer_persists_stable_action_and_normalized_evidence()
    {
        var source = Identity(8); source["event_id"] = 4719;
        source["event_data_json"] = new JsonObject { ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001", ["SubjectUserName"] = "auditor", ["SubjectDomainName"] = "example.test", ["SubjectLogonId"] = "0x123", ["CategoryId"] = "%%8272", ["SubcategoryId"] = "%%12801", ["SubcategoryGuid"] = "{00000000-0000-4000-8000-000000000004}", ["AuditPolicyChanges"] = "%%8448" };
        var ev = SemanticNormalization.Normalize(source); var action = Assert.Single(SemanticAssembly.Assemble([ev]));
        var session = CanonicalSession(null); await SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct);
        Assert.Contains("pg_advisory_xact_lock", session.Commands[0].Sql); Assert.Equal(action.Key, session.Commands[0].Values[0]);
        var insert = Assert.Single(session.Commands, x => x.Sql.Contains("insert into canonical_actions("));
        Assert.Equal(action.Id, insert.Values[0]); Assert.Contains("canonical_deduplication_key", insert.Sql);
        var evidence = Assert.Single(session.Commands, x => x.Sql.Contains("insert into canonical_action_evidence("));
        Assert.Equal(new object?[] { action.Id, ev.Id() }, evidence.Values);
        Assert.Contains("multi_source_confirmed", session.Commands[^1].Sql); Assert.Contains("count(distinct normalized.source_event_id)", session.Commands[^1].Sql);
    }

    [Fact]
    public async Task Canonical_replay_reuses_stable_uuid_across_assembler_versions()
    {
        var action = Action(); var session = CanonicalSession(Existing(action));
        Assert.Equal(Guid.Parse("1de3a90e-5b72-5b3e-acff-06cba4d1a250"), action.Id);
        await SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct);
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("insert into canonical_actions("));
        var update = Assert.Single(session.Commands, x => x.Sql.Contains("update canonical_actions set attributes_json"));
        Assert.Equal(action.Id, update.Values[^1]); Assert.Contains("assembler_version='1.1'", update.Sql);
    }

    [Theory] [InlineData("dedup")] [InlineData("assembler_id")] [InlineData("canonical_action_id")]
    public async Task Canonical_replay_rejects_conflicting_identity_before_mutation(string field)
    {
        var action = Action(); var old = Existing(action); old[field] = field == "dedup" ? new string('b', 64) : field == "canonical_action_id" ? "33333333-3333-4333-8333-333333333333" : "another-assembler";
        var session = CanonicalSession(old, dedupLookup: field == "canonical_action_id");
        Assert.Equal("canonical_action_replay_conflict", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct))).Message);
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("update canonical_actions") || x.Sql.Contains("insert into canonical_actions"));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Version_change_archives_all_links_and_replaces_only_replayed_source(bool reinterpret)
    {
        var ev = Event(42); var other = Event(43); var action = Action(reinterpret ? "authentication.succeeded" : "directory.attribute.changed", ev);
        if (reinterpret)
        {
            action.Attributes["material_identity"]!["source_event_id"] = 42;
            action.Attributes["source_evidence"] = new JsonArray(new JsonObject { ["source_event_id"] = 42, ["semantic_sha256"] = "new-hash" });
            action.Attributes["observed_facts"] = new JsonArray(new JsonObject { ["logon_type"] = "network" });
            action.Attributes["observed_roles"] = new JsonArray(new JsonObject { ["source_host"] = "dc.example.test" });
        }
        var old = Existing(action);
        if (reinterpret) old["attributes_json"]!["source_evidence"]![0]!["semantic_sha256"] = "old-hash";
        var links = new JsonArray(Link(ev), Link(other, 1)); var priorLinks = links.DeepClone(); var session = CanonicalSession(old, links);
        await SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct);
        Assert.Equal(ev.Id().ToString(), links[0].Text("normalized_event_id")); Assert.Equal(other.Id("1.1+identity-1.0").ToString(), links[1].Text("normalized_event_id"));
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("insert into canonical_action_evidence") || x.Sql.Contains("delete from canonical_action_evidence"));
        var replacement = Assert.Single(session.Commands, x => x.Sql.StartsWith("update canonical_action_evidence"));
        Assert.Equal(new object?[] { ev.Id(), action.Id, ev.Id("1.1+identity-1.0") }, replacement.Values);
        var update = Assert.Single(session.Commands, x => x.Sql.Contains("update canonical_actions set attributes_json"));
        var attributes = Assert.IsType<JsonObject>(update.Values[0]); var history = Assert.Single(attributes["prior_interpretations"]!.AsArray())!;
        Assert.Equal("1.0", history.Text("assembler_version")); Assert.Equal("semantic-action-assembler", history.Text("assembler_id")); Assert.Equal(old.Text("action_sha256"), history.Text("action_sha256"));
        Assert.True(JsonNode.DeepEquals(priorLinks, history["evidence"])); Assert.True(JsonNode.DeepEquals(old["attributes_json"], history["attributes"]));
        if (reinterpret) Assert.Equal("new-hash", attributes["source_evidence"]![0].Text("semantic_sha256"));
        Assert.Equal(new object?[] { action.Id }, session.Commands[^1].Values);
    }

    [Fact]
    public async Task Reinterpretation_without_old_evidence_fails_before_any_write()
    {
        var ev = Event(42); var action = Action("authentication.succeeded", ev);
        action.Attributes["material_identity"]!["source_event_id"] = 42;
        action.Attributes["source_evidence"] = new JsonArray(new JsonObject { ["source_event_id"] = 42, ["semantic_sha256"] = "new-hash" });
        action.Attributes["observed_facts"] = new JsonArray(new JsonObject()); action.Attributes["observed_roles"] = new JsonArray(new JsonObject());
        var old = Existing(action); old["attributes_json"]!["source_evidence"]![0]!["semantic_sha256"] = "old-hash";
        var session = CanonicalSession(old);
        Assert.Equal("canonical_action_prior_evidence_conflict", (await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistAction(session, action, SemanticEvent.Version, Ct))).Message);
        Assert.DoesNotContain(session.Commands, x => x.Sql.Contains("update canonical_actions") || x.Sql.Contains("insert into canonical_action_evidence"));
    }
}
