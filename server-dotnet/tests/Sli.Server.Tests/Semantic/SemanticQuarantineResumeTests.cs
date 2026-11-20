using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Archive;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[CollectionDefinition("Semantic quarantine archive environment", DisableParallelization = true)]
public sealed class SemanticQuarantineArchiveEnvironment;

[Collection("Semantic quarantine archive environment")]
public sealed class SemanticQuarantineResumeTests(ITestOutputHelper output)
{
    // Frozen output of tests.semantic.test_semantic_quarantine_resume.retained().
    // The expected digest and UUID come from Python, not the .NET normalizer.
    private static JsonObject Identity() => JsonNode.Parse("""
        {"id":7,"server_id":1,"domain_id":2,"log_source_id":3,"event_id":4624,
         "event_record_id":42,"channel":"Security","computer":"fixture-dc",
         "provider_name":"Microsoft-Windows-Security-Auditing",
         "time_created_utc":"2026-10-09T00:00:00+00:00","migrated_at":"2026-10-09T00:00:00+00:00",
         "normalized_hash":"9b8fcc35f824d1f2f4cc1fc9a0c605c2fbe488ae2689f164c9e06a16334c4148"}
        """)!.AsObject();
    private static JsonObject Retained() => JsonNode.Parse("""
        {"source_event_id":7,"normalized_event_id":"1b6448bd-2b2a-559e-8ea9-61dd6eff2210",
         "source_event_sha256":"9b8fcc35f824d1f2f4cc1fc9a0c605c2fbe488ae2689f164c9e06a16334c4148",
         "semantic_sha256":"41ad690a20c146825ad17fd5f9eb17bdfe339b7843a570178db96bfcf5ae6cb8",
         "semantic_type":"authentication.session.created","occurred_at_utc":"2026-10-09T00:00:00+00:00",
         "roles_json":{"affected_entity":"name:fixture-account","source_host":"1"},
         "facts_json":{"channel":"Security","domain_id":2,"event_record_id":42,"host":"fixture-dc",
           "logon_type":"3","provider":"Microsoft-Windows-Security-Auditing","source_host_id":1,
           "source_event_sha256":"9b8fcc35f824d1f2f4cc1fc9a0c605c2fbe488ae2689f164c9e06a16334c4148","windows_event_id":4624},
         "quality_json":{"catalog_independent":true,"defined_but_not_emitted":false,"event_data_encoding":"named",
           "identity_resolution_version":"1.0","identity_roles":{"affected_entity":{"aliases":[],"confidence":0.3,
             "key":"name:fixture-account","provisional":false,"reason":"нет_домена","rule":"identity-ladder/v1","state":"unresolved","step":5}},
           "missing_actor_sid":true,"missing_source_ip":true,"provisional_identity_roles":[],"raw_event_mutated":false,
           "relation_account_identity":{"sid_field":"TargetUserSid","state":"not_exact"},"semantic_mapping_status":"mapped",
           "unknown_event_mapping":false,"unresolved_actor":false,"unresolved_identity_roles":["affected_entity"],"unresolved_target":true}}
        """)!.AsObject();

    [Fact]
    public async Task Retained_facts_resume_only_current_ordinary_normalization_with_exact_proof()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        // Use the actual predecessor so the later packet attestation keeps the inbox schema from 363.
        await fixture.StartAsync(ct, throughVersion: 365);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await using var runtime = PasswordProducerRuntime.Create(n => n == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var db = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, new(true, true, false, true, false, false), SemanticProduction.DevelopmentMode, 1);
        await SemanticArchiveFixture.Seed(owner, fixture.Pg.Root, ct);
        await SeedRetained(owner, Retained(), "valid", ct);
        await SeedJob(owner, Guid.NewGuid(), "normalize_event", Identity(), new(), false, ct);
        string migration = Path.Combine(SemanticProduction.SourceBundleRoot(null, AppContext.BaseDirectory), "config/postgres_migrations/366_semantic_archive_authorization_reader.sql");
        await AssertAdmissionAccess(false);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await AssertAdmissionAccess(true);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await AssertAdmissionAccess(false);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await AssertAdmissionAccess(true);
        await SeedSubscription(owner, ct);

        async Task AssertAdmissionAccess(bool granted)
        {
            await using var command = new NpgsqlCommand("""
                select has_table_privilege('adlog_semantic_worker','storage_v2_runtime_authorizations','SELECT'),
                    has_table_privilege('adlog_semantic_worker','storage_v2_runtime_authorizations','INSERT,UPDATE,DELETE'),
                    exists(select 1 from normalized_events where source_event_id=7),
                    exists(select 1 from semantic_processing_outbox where source_event_id=7 and status='queued'),
                    exists(select 1 from storage_v2_runtime_authorizations where singleton)
                """, owner);
            await using var reader = await command.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal(granted, reader.GetBoolean(0)); Assert.False(reader.GetBoolean(1));
            Assert.True(reader.GetBoolean(2)); Assert.True(reader.GetBoolean(3)); Assert.True(reader.GetBoolean(4));
        }
        foreach (var next in MigrationDirectory.Read().Where(m => m.Version > 366))
            await fixture.Pg.ApplyFileAsync(next.Path, null, ct);
        string? oldRoot = Environment.GetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT");
        Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", fixture.Pg.Root);
        try
        {
            // No source row or agent payload exists. Each case starts from a fresh job.
            foreach (string source in new[] { "absent", "missing_file", "missing_directory" })
            foreach (string kind in new[] { "normalize_event", "semantic_repair" })
                await Run(source, kind, "valid", kind == "normalize_event", kind == "normalize_event" ? null : "source_read");
            foreach (string conflict in new[] { "source_hash", "digest", "facts", "roles", "time", "id", "identity_version" })
                await Run("absent", "normalize_event", conflict, false, "retained_normalization");
            await Run("absent", "normalize_event", "job_identity", false, "identity");
            foreach (string unavailable in new[] { "missing", "contract", "normalizer", "version", "status" })
                await Run("absent", "normalize_event", unavailable, false, "retained_normalization");
            foreach (string invalid in new[] { "corrupt_archive", "malformed_archive" })
                await Run(invalid, "normalize_event", "valid", false, "source_read");

            async Task Run(string source, string kind, string change, bool success, string? failureStep)
            {
                output.WriteLine($"source={source}; kind={kind}; retained={change}");
                await PostCollectionPostgres.Sql(owner, """
                    delete from semantic_correlation_dispatch_jobs;
                    delete from canonical_action_evidence; delete from canonical_actions;
                    delete from normalized_events; delete from semantic_processing_outbox;
                    delete from storage_v2_archive_blocks; delete from storage_v2_archive_sets;
                    """, ct);
                var identity = Identity(); var row = Retained();
                switch (change)
                {
                    case "source_hash": row["source_event_sha256"] = new string('a', 64); break;
                    case "digest": row["semantic_sha256"] = new string('a', 64); break;
                    case "facts": row["facts_json"]!["LogonType"] = "10"; break;
                    case "roles": row["roles_json"]!["source_host"] = "other-fixture"; break;
                    case "time": row["occurred_at_utc"] = "2026-10-09T00:00:01+00:00"; break;
                    case "id": row["normalized_event_id"] = "11111111-1111-4111-8111-111111111111"; break;
                    case "identity_version": row["quality_json"]!["identity_resolution_version"] = "old"; break;
                    case "job_identity": identity["id"] = 8; break;
                }
                if (change != "missing") await SeedRetained(owner, row, change, ct);
                Guid jobId = Guid.NewGuid(); var payload = new JsonObject();
                if (kind == "semantic_repair")
                {
                    Guid original = Guid.NewGuid(); await SeedJob(owner, original, "normalize_event", Identity(), new(), completed: true, ct);
                    payload = new JsonObject { ["original_job_id"] = original.ToString(), ["original_source_hash"] = identity["normalized_hash"].Copy(), ["repair_plan_digest"] = new string('b', 64), ["history_plan_digest"] = new string('c', 64) };
                }
                await SeedJob(owner, jobId, kind, identity, payload, completed: false, ct);
                if (source != "absent") await SeedArchive(owner, fixture.Pg.Root, source, ct);
                var steps = new List<SemanticProcessingStep>();
                var result = await production.ProcessOutbox(db, ct, (step, _) => steps.Add(step));
                Assert.True(result.Number("claimed") == 1, result.ToJsonString()); Assert.Equal(success ? 1 : 0, result.Number("completed"));
                Assert.Equal(success ? 0 : 1, result.Number("failed")); Assert.Equal(success ? 1 : 0, result.Number("normalized"));
                Assert.Equal(success ? 1 : 0, result.Number("actions"));
                await using var session = new SemanticSession(owner, await owner.BeginTransactionAsync(ct));
                var storedJob = (await session.QueryAsync("select status,last_error_detail,completed_at from semantic_processing_outbox where job_id=$1", ct, jobId)).Single()!;
                Assert.Equal(success ? "completed" : "failed", storedJob.Text("status"));
                if (success)
                {
                    Assert.NotNull(storedJob["completed_at"]); Assert.Null(storedJob["last_error_detail"]);
                    var stored = (await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events", ct)).Single()!;
                    Assert.Equal("1b6448bd-2b2a-559e-8ea9-61dd6eff2210", stored.Text("normalized_event_id"));
                    Assert.Equal("41ad690a20c146825ad17fd5f9eb17bdfe339b7843a570178db96bfcf5ae6cb8", stored.Text("semantic_sha256"));
                    Assert.Equal("authentication.session.created", stored.Text("semantic_type"));
                    foreach (string field in new[] { "facts_json", "roles_json", "quality_json" }) Assert.True(JsonNode.DeepEquals(Retained()[field], stored[field]), field);
                    var evidence = await session.QueryAsync("select normalized_event_id from canonical_action_evidence", ct);
                    Assert.Equal("1b6448bd-2b2a-559e-8ea9-61dd6eff2210", Assert.Single(evidence).Text("normalized_event_id"));
                    var dispatch = Assert.Single(await session.QueryAsync("select normalized_event_id,partition_key,dispatch_status from semantic_correlation_dispatch_jobs where rule_id='fixture-quarantine-resume'", ct));
                    Assert.Equal("1b6448bd-2b2a-559e-8ea9-61dd6eff2210", dispatch.Text("normalized_event_id"));
                    Assert.Equal("1", dispatch.Text("partition_key")); Assert.Equal("queued", dispatch.Text("dispatch_status"));
                    var effects = steps.Where(x => x is SemanticProcessingStep.PersistNormalized or SemanticProcessingStep.PersistAction or SemanticProcessingStep.EnqueueDispatch or SemanticProcessingStep.Complete).ToArray();
                    Assert.Equal(new[] { SemanticProcessingStep.PersistNormalized, SemanticProcessingStep.PersistAction, SemanticProcessingStep.EnqueueDispatch, SemanticProcessingStep.Complete }, effects);
                }
                else
                {
                    Assert.Null(storedJob["completed_at"]);
                    Assert.Equal(failureStep, JsonNode.Parse(storedJob.Text("last_error_detail")!).Text("step"));
                    Assert.Empty(await session.QueryAsync("select 1 from canonical_actions", ct));
                    Assert.Empty(await session.QueryAsync("select 1 from semantic_correlation_dispatch_jobs", ct));
                    Assert.DoesNotContain(SemanticProcessingStep.PersistNormalized, steps);
                    if (failureStep != "retained_normalization") Assert.DoesNotContain(SemanticProcessingStep.RetainedNormalization, steps);
                }
                await session.CommitAsync(ct);

                if (source == "absent" && kind == "normalize_event")
                {
                    // Manual quarantine replay requires the original source, even when ordinary work resumed.
                    async Task<string> ReadEffects()
                    {
                        await using var command = new NpgsqlCommand("""
                            select jsonb_build_array(
                                (select jsonb_agg(to_jsonb(n) order by n.normalized_event_id) from normalized_events n),
                                (select jsonb_agg(to_jsonb(a) order by a.canonical_action_id) from canonical_actions a),
                                (select jsonb_agg(to_jsonb(e) order by to_jsonb(e)::text) from canonical_action_evidence e),
                                (select jsonb_agg(to_jsonb(d) order by to_jsonb(d)::text) from semantic_correlation_dispatch_jobs d)
                            )::text
                            """, owner);
                        return (string)(await command.ExecuteScalarAsync(ct))!;
                    }

                    string effects = await ReadEffects();
                    await using var replaySession = new SemanticSession(db, await db.BeginTransactionAsync(ct));
                    var replayJob = (await replaySession.QueryAsync("select * from semantic_processing_outbox where job_id=$1", ct, jobId)).Single()!.AsObject();
                    if (change == "job_identity")
                        await Assert.ThrowsAsync<SemanticSourceIntegrityException>(() => production.ReplayQuarantined(replaySession, replayJob, true, ct));
                    else
                        await Assert.ThrowsAsync<SemanticSourceDeletedException>(() => production.ReplayQuarantined(replaySession, replayJob, true, ct));
                    await replaySession.CommitAsync(ct);
                    Assert.Equal(effects, await ReadEffects());
                }
            }
        }
        finally { Environment.SetEnvironmentVariable("ADLOG_STORAGE_V2_ARCHIVE_ROOT", oldRoot); }
    }

    private static async Task SeedSubscription(NpgsqlConnection db, CancellationToken ct)
    {
        var definition = JsonNode.Parse("""
            {"type":"count","inputs":["authentication.session.created"],"join_roles":["source_host"],
             "window_seconds":60,"minimum_count":2,"output_relation_kind":"fixture.resumed",
             "confidence":"low","explanation":"Synthetic retained-facts dispatch"}
            """)!;
        await using var command = new NpgsqlCommand("""
            insert into semantic_correlation_rules(rule_id,rule_version,rule_kind,definition_json,definition_sha256)
                values('fixture-quarantine-resume',1,'count',@definition,@digest);
            insert into semantic_correlation_subscriptions(rule_id,rule_version,semantic_type,subscription_order,definition_sha256)
                values('fixture-quarantine-resume',1,'authentication.session.created',0,@digest);
            update semantic_correlation_rules set lifecycle_status='shadow' where rule_id='fixture-quarantine-resume';
            """, db);
        command.Parameters.AddWithValue("definition", NpgsqlTypes.NpgsqlDbType.Jsonb, definition.ToJsonString());
        command.Parameters.AddWithValue("digest", Convert.FromHexString(SemanticJson.Hash(definition)));
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedRetained(NpgsqlConnection db, JsonObject row, string change, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,normalizer_id,normalizer_version,
                processing_status,source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,roles_json,facts_json,quality_json,source_identity_json)
            values(@id,7,@contract,@normalizer,@version,@status,@source_hash,@digest,@type,@at,@ingested,@roles,@facts,@quality,@identity)
            """, db);
        command.Parameters.AddWithValue("id", Guid.Parse(row.Text("normalized_event_id")!));
        command.Parameters.AddWithValue("contract", change == "contract" ? 2 : 1);
        command.Parameters.AddWithValue("normalizer", change == "normalizer" ? "other-normalizer" : "windows.named-eventdata");
        command.Parameters.AddWithValue("version", change == "version" ? "old" : "1.4+identity-1.0");
        command.Parameters.AddWithValue("status", change == "status" ? "ignored" : "normalized");
        command.Parameters.AddWithValue("source_hash", Convert.FromHexString(row.Text("source_event_sha256")!));
        command.Parameters.AddWithValue("digest", Convert.FromHexString(row.Text("semantic_sha256")!));
        command.Parameters.AddWithValue("type", row.Text("semantic_type")!);
        command.Parameters.AddWithValue("at", DateTimeOffset.Parse(row.Text("occurred_at_utc")!));
        command.Parameters.AddWithValue("ingested", DateTimeOffset.Parse("2026-10-09T00:00:00Z"));
        foreach (string field in new[] { "roles", "facts", "quality" }) command.Parameters.AddWithValue(field, NpgsqlTypes.NpgsqlDbType.Jsonb, row[field + "_json"]!.ToJsonString());
        command.Parameters.AddWithValue("identity", NpgsqlTypes.NpgsqlDbType.Jsonb, Identity().ToJsonString());
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedJob(NpgsqlConnection db, Guid id, string kind, JsonObject identity, JsonObject payload, bool completed, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
                idempotency_key,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json,payload_json,status,completed_at)
            values(@id,7,@kind,1,'semantic-shadow','1.4+identity-1.0',sha256(@id::text::bytea),3,2,'1:Security',
                '2026-10-09T00:00:00Z',@identity,@payload,@status,case when @completed then now() end)
            """, db);
        command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("kind", kind);
        command.Parameters.AddWithValue("identity", NpgsqlTypes.NpgsqlDbType.Jsonb, identity.ToJsonString());
        command.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, payload.ToJsonString());
        command.Parameters.AddWithValue("status", completed ? "completed" : "queued"); command.Parameters.AddWithValue("completed", completed);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task SeedArchive(NpgsqlConnection db, string root, string source, CancellationToken ct)
    {
        string directory = Path.Combine(root, source == "missing_directory" ? "expired" : "published");
        if (source != "missing_directory") Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "fixture.jsonl.gz");
        byte[] raw = ArchiveCodec.Encode("event", [new JsonObject { ["id"] = 7 }]).Raw;
        byte[] compressed = ArchiveCodec.Compress(raw);
        if (File.Exists(path)) File.Delete(path);
        if (source is "corrupt_archive" or "malformed_archive") File.WriteAllBytes(path, source == "corrupt_archive" ? new byte[compressed.Length] : compressed);
        await using var command = new NpgsqlCommand("""
            insert into storage_v2_archive_sets(archive_set_id,archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows,state)
                values(@id,'event',1,7,7,1,'published');
            insert into storage_v2_archive_blocks(archive_set_id,archive_kind,format_version,block_index,first_event_id,last_event_id,row_count,
                raw_bytes,compressed_bytes,raw_sha256,archive_sha256,object_location,state)
                values(@id,'event',1,0,7,7,1,@raw_size,@size,@raw_hash,@hash,@path,'published');
            """, db);
        command.Parameters.AddWithValue("id", Guid.NewGuid()); command.Parameters.AddWithValue("path", path);
        command.Parameters.AddWithValue("raw_size", raw.Length); command.Parameters.AddWithValue("size", compressed.Length);
        command.Parameters.AddWithValue("raw_hash", Convert.FromHexString(ArchiveCodec.Hash(raw)));
        command.Parameters.AddWithValue("hash", Convert.FromHexString(ArchiveCodec.Hash(compressed)));
        await command.ExecuteNonQueryAsync(ct);
    }
}
