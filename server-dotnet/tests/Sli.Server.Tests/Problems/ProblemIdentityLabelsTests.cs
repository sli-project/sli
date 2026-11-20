using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Problems;

// Frozen vectors: tests/reporting/test_problem_identity_labels.py. Synthetic retained data only.
public sealed class ProblemIdentityLabelsTests
{
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1101";
    const string Group = "S-1-5-21-100000001-200000002-300000003-512";
    const string Absent = "S-1-5-21-100000001-200000002-300000003-1999";
    const string At = "2026-09-03T10:00:00+00:00", Snapshot = "2026-08-01T10:00:00+00:00";
    static JsonObject Event() => new() {
        ["event_db_id"] = 91, ["event_id"] = 4728, ["hostname"] = "synthetic-dc", ["channel"] = "Security",
        ["identity_provider"] = "Microsoft-Windows-Security-Auditing", ["time_created_utc"] = At,
        ["domain_id"] = 3, ["subject_user_sid"] = Sid, ["subject_user_name"] = "synthetic-admin", ["subject_domain_name"] = "EXAMPLE",
        ["target_user_sid"] = Group, ["membership_member_sid"] = Sid, ["identity_domain_min"] = 3, ["identity_domain_max"] = 3, ["identity_event_count"] = 1
    };
    static JsonObject Row(string? actor = null) => new() {
        ["id"] = 7, ["title"] = "Member was added to a privileged group", ["actor"] = actor, ["target"] = Sid, ["evidence_count"] = 1,
        ["assigned_to"] = null, ["evidence"] = new JsonArray(Event()), ["entities"] = new JsonArray(new JsonObject {
            ["entity_role"] = "container_entity", ["entity_type"] = "group", ["display_name"] = Group })
    };
    static JsonObject Label(int index = 0, string name = "Retained synthetic name") => new() {
        ["request_index"] = index, ["label"] = name, ["observed_at_utc"] = Snapshot, ["source_run_id"] = "synthetic-run", ["entity_id"] = 14
    };
    static string? Text(JsonNode? n) => n?.ToString();
    static JsonObject View(JsonObject raw, string locale = "ru") => ProblemPresentation.Finding(raw, ProblemLifecycleTests.Access("security.queue"), locale);
    static JsonObject Home(string value, JsonObject? context = null) => ProblemPresentation.IdentityObject(value, context ?? new(), "EXAMPLE");
    static async Task<JsonArray> Attach(JsonObject raw, JsonArray? labels = null, bool fail = false,
        IReadOnlySet<(string Stream, string Provider, long Event)>? contract = null)
    {
        var requests = new JsonArray();
        await ProblemRepository.AttachIdentities(new JsonArray(raw), (r, _) => {
            requests = r.DeepClone().AsArray();
            if (fail) throw new InvalidOperationException("synthetic unavailable");
            return Task.FromResult(labels ?? new JsonArray());
        }, TestContext.Current.CancellationToken, contract);
        return requests;
    }
    [Theory]
    [InlineData(4728)] [InlineData(4732)] [InlineData(4756)]
    public async Task ObservedInitiatorPreservesSourceAndEvidence(int id)
    {
        var raw = Row(); raw["evidence"]![0]!["event_id"] = id;
        await Attach(raw); var view = View(raw);
        Assert.Equal("EXAMPLE\\synthetic-admin", Text(view["actor_text"]));
        Assert.Null(view["actor"]); Assert.Equal(Sid, Text(view["target"]));
        Assert.Equal("event", Text(view["identity_context"]!["actor"]!["source"]));
        Assert.Equal("91", Text(view["identity_context"]!["actor"]!["event_db_id"]));
        Assert.Equal("91", Text(view["evidence"]![0]!["event_db_id"]));
        Assert.False(raw["evidence"]![0]!.AsObject().ContainsKey("subject_user_name"));
        Assert.False(view["evidence"]![0]!.AsObject().ContainsKey("subject_user_name"));
    }
    [Fact] public async Task InitiatorConsumesExactSourceContract()
    {
        Assert.Equal(new long[] { 4728, 4732, 4756 }, SemanticNormalization.MembershipEventIdentities().Select(i => i.Event).Order().ToArray());
        foreach (var contract in new HashSet<(string, string, long)>[] {
            [], [("Application", "Microsoft-Windows-Security-Auditing", 4728)], [("Security", "Synthetic-Other-Provider", 4728)] }) {
            var raw = Row(); await Attach(raw, contract: contract);
            Assert.Null(View(raw)["actor_text"]);
        }
    }
    public static TheoryData<string, JsonNode?> IncompleteActors => new() {
        { "event_id", JsonValue.Create(4624) }, { "subject_user_name", JsonValue.Create("-") },
        { "channel", JsonValue.Create("Application") }, { "identity_provider", JsonValue.Create("Synthetic-Other-Provider") },
        { "identity_provider", null }, { "identity_event_count", JsonValue.Create(21) }, { "identity_domain_max", JsonValue.Create(4) }
    };
    [Theory] [MemberData(nameof(IncompleteActors))]
    public async Task MissingOrAmbiguousActorStaysUnknown(string field, JsonNode? value)
    {
        var raw = Row(); raw["evidence"]![0]![field] = value?.DeepClone(); await Attach(raw);
        Assert.Null(View(raw)["actor_text"]);
    }
    [Fact] public async Task ConflictingAndPartialSamplesCannotNameAnActor()
    {
        var raw = Row(); raw["evidence_count"] = 2; await Attach(raw);
        Assert.Null(View(raw)["actor_text"]);
        raw = Row(); raw["evidence_count"] = 2; var other = Event(); other["event_db_id"] = 92;
        other["subject_user_sid"] = Absent; other["subject_user_name"] = "another-admin"; other["identity_event_count"] = 2;
        raw["evidence"]![0]!["identity_event_count"] = 2; raw["evidence"]!.AsArray().Add(other); await Attach(raw);
        Assert.Null(View(raw)["actor_text"]);
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task ExistingActorCannotBorrowNameFromDifferentSidOrHost(bool differentSid)
    {
        string actor = differentSid ? "sid:synthetic-dc:" + Absent : "sid:other-dc:" + Sid;
        var raw = Row(actor); await Attach(raw); var view = View(raw);
        Assert.Null(view["actor_text"]); Assert.Equal(actor, Text(view["actor"]));
        Assert.Null(view["identity_context"]!["actor"]); Assert.True(JsonNode.DeepEquals(raw["identity_context"], view["identity_context"]));
    }
    [Fact] public async Task RetainedSnapshotLabelsPreserveExactWitnessScopeAndIdentifiers()
    {
        var raw = Row("sid:synthetic-dc:" + Sid);
        var requests = await Attach(raw, new JsonArray(Label(), Label(1), Label(2, "Synthetic administrators")));
        var view = View(raw); var source = view["identity_context"]!["principals"]![Group]!;
        Assert.Equal("Synthetic administrators", Text(view["entity_text"]));
        Assert.Equal(Group, Text(view["entity_identifiers"])); Assert.Equal(Group, Text(view["entities"]![0]!["display_name"]));
        Assert.Equal("ad_snapshot", Text(source["source"])); Assert.Equal(Snapshot, Text(source["observed_at_utc"]));
        Assert.Equal("3", Text(source["domain_id"])); Assert.Equal(Group, Text(source["sid"])); Assert.Equal("91", Text(source["event_db_id"]));
        Assert.All(requests, r => { Assert.Equal("3", Text(r!["domain_id"])); Assert.Equal(At, Text(r["at_utc"])); });
    }
    [Theory] [InlineData("no_match")] [InlineData("ambiguous")] [InlineData("unavailable")]
    public async Task LookupOutcomesDoNotNameUnwitnessedObjects(string state)
    {
        var raw = Row(); raw["_identity_objects"] = new JsonArray(Sid, Absent);
        var labels = state == "ambiguous" ? new JsonArray(Label(0, "One"), Label(0, "Two")) : new JsonArray();
        await Attach(raw, labels, state == "unavailable");
        Assert.Equal(state, Text(raw["identity_context"]!["principal_states"]![Sid]));
        Assert.Equal("unverified", Text(raw["identity_context"]!["principal_states"]![Absent]));
        Assert.Equal(Group, Text(View(raw)["entity_text"])); Assert.Equal(Sid, Text(raw["target"]));
        var home = Home(Sid, raw["identity_context"]!.AsObject()); Assert.Equal(state, Text(home["name_state"])); Assert.Equal("", Text(home["name"]));
    }
    [Fact] public async Task AmbiguousEntityLabelKeepsRawIdentifier()
    {
        var raw = Row(); await Attach(raw, new JsonArray(Label(1, "One"), Label(1, "Two")));
        Assert.Equal(Group, Text(View(raw)["entity_text"])); Assert.Equal(Group, Text(raw["entities"]![0]!["display_name"]));
    }
    [Theory] [InlineData("ru")] [InlineData("en")]
    public async Task ProvenanceAndUnassignedAreLocalizedEvenWhenSnapshotFails(string locale)
    {
        foreach (bool fail in new[] { false, true }) {
            var raw = Row(); await Attach(raw, fail: fail); var view = View(raw, locale);
            Assert.Equal(Text(ProblemPresentation.Message("security.problems.assignee.unassigned", locale)["text"]), Text(view["assigned_to_text"]));
            Assert.Null(view["assigned_to"]); Assert.Contains("91", Text(view["identity_sources_text"])); Assert.Contains("synthetic-admin", Text(view["identity_sources_text"]));
            Assert.Equal("EXAMPLE\\synthetic-admin", Text(view["actor_text"]));
            if (fail) {
                Assert.Equal("security.problems.identity.sources_partial", Text(view["presentation_messages"]!["identity_sources_text"]!["code"]));
                Assert.Contains("AD", Text(view["identity_sources_text"]));
            }
        }
    }
    [Fact] public async Task DerivedNamesAndProvenanceRespectFieldProjection()
    {
        var raw = Row(); await Attach(raw, new JsonArray(Label(0, "synthetic-admin"), Label(1, "synthetic-admin")));
        var view = ProblemPresentation.Finding(raw, ProblemLifecycleTests.Access("security.queue", fields: ["security"]), "ru");
        Assert.DoesNotContain("synthetic-admin", view.ToJsonString()); Assert.False(view.ContainsKey("identity_context")); Assert.False(view.ContainsKey("entity_identifiers"));
    }
    public static TheoryData<string, bool> SidForms => new() {
        { Sid, true }, { "sid:" + Sid, true }, { "SID:" + Sid.ToLowerInvariant(), true }, { "sid:synthetic-dc:" + Sid, true },
        { "sid:S-1-5-18", false }, { "sid:S-1-5-21-100000001-200000002-1101", false },
        { "sid:" + Sid + "-extra", false }, { "sid:extra:synthetic-dc:" + Sid, false }
    };
    [Theory] [MemberData(nameof(SidForms))]
    public void CanonicalAndMalformedSidsNeverRewriteIdentity(string value, bool valid)
    {
        Assert.Equal(valid ? Sid : null, ProblemRepository.Sid(value));
        var home = Home(value); Assert.Equal(value, Text(home["identifier"])); Assert.Equal("", Text(home["name"])); Assert.Equal("unverified", Text(home["name_state"]));
    }
    [Fact] public async Task ShortSidUsesExactRetainedDomainAndWitnessTime()
    {
        string value = "sid:" + Sid; var raw = Row(value); raw["target"] = null; raw["entities"] = new JsonArray();
        var requests = await Attach(raw, new JsonArray(Label()));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["request_index"] = 0, ["domain_id"] = 3, ["sid"] = Sid.ToLowerInvariant(), ["at_utc"] = At }, Assert.Single(requests)));
        Assert.Equal("EXAMPLE\\synthetic-admin", Text(raw["identity_context"]!["actor"]!["label"]));
        var home = Home(value, raw["identity_context"]!.AsObject());
        Assert.Equal("Retained synthetic name", Text(home["name"])); Assert.Equal("named", Text(home["name_state"])); Assert.Equal(value, Text(home["identifier"]));
        Assert.Equal("3", Text(home["source"]!["domain_id"])); Assert.Equal(At, Text(home["source"]!["witness_at_utc"]));
    }
    [Fact] public async Task ShortSidCannotBypassWitnessDomainCompletenessOrHostScope()
    {
        for (int i = 0; i < 6; i++) {
            var ev = Event(); string value = "sid:" + Sid;
            if (i == 0) ev["identity_domain_max"] = 4;
            if (i == 1) { ev["identity_domain_min"] = null; ev["identity_domain_max"] = null; }
            if (i == 2) ev["identity_event_count"] = 2;
            if (i == 3) { ev["subject_user_sid"] = Group; ev["membership_member_sid"] = Group; }
            if (i == 4) value = "sid:other-dc:" + Sid;
            if (i == 5) { value = "sid:S-1-5-18"; ev["subject_user_sid"] = "S-1-5-18"; ev["membership_member_sid"] = "S-1-5-18"; }
            var raw = Row(value); raw["target"] = null; raw["entities"] = new JsonArray(); raw["evidence"] = new JsonArray(ev);
            Assert.Empty(await Attach(raw)); Assert.Null(raw["identity_context"]!["actor"]);
            Assert.Equal("unverified", Text(Home(value, raw["identity_context"]!.AsObject())["name_state"]));
        }
    }
    [Theory] [InlineData("no_match")] [InlineData("ambiguous")] [InlineData("unavailable")]
    public async Task ShortSidPreservesLookupStates(string state)
    {
        string value = "sid:" + Sid; var raw = Row(value); raw["target"] = null; raw["entities"] = new JsonArray();
        var labels = state == "ambiguous" ? new JsonArray(Label(0, "One"), Label(0, "Two")) : new JsonArray();
        Assert.Single(await Attach(raw, labels, state == "unavailable"));
        var home = Home(value, raw["identity_context"]!.AsObject()); Assert.Equal(value, Text(home["identifier"])); Assert.Equal("", Text(home["name"])); Assert.Equal(state, Text(home["name_state"]));
    }
    [Theory] [InlineData("ordinary-name")] [InlineData("sid:not-a-principal")] [InlineData("sid:")]
    [InlineData("0b525814-8c42-4e9a-8899-1d3bea4ade84")]
    public void LiteralNamesKeepTheirSpelling(string value)
    {
        var home = Home(value, new() { ["snapshot_state"] = "unavailable" });
        Assert.Equal(value, Text(home["name"])); Assert.Equal(value, Text(home["identifier"])); Assert.Equal("literal", Text(home["name_state"]));
        var view = View(Row(value)); Assert.Equal(value, Text(view["actor_text"])); Assert.Equal(value, Text(view["actor"]));
    }
    [Theory] [InlineData("ru")] [InlineData("en")]
    public void UnresolvedActorHidesSidWithoutCollapsingState(string locale)
    {
        foreach (string actor in new[] { Sid, "sid:" + Sid, "sid:synthetic-dc:" + Sid, "sid:S-1-5-18", "sid:S-1-5-21-malformed" })
        foreach (string state in new[] { "no_match", "ambiguous", "unverified", "unavailable" }) {
            var context = new JsonObject { ["actor"] = null, ["principals"] = new JsonObject(), ["principal_states"] = new JsonObject { [actor] = state },
                ["snapshot_state"] = state == "unavailable" ? "unavailable" : "lookup_complete" };
            var raw = Row(actor); raw["identity_context"] = context; var before = raw.DeepClone(); var view = View(raw, locale);
            Assert.Null(view["actor_text"]); Assert.Equal(actor, Text(view["actor"]));
            Assert.True(JsonNode.DeepEquals(context, view["identity_context"])); Assert.True(JsonNode.DeepEquals(before, raw));
            if (state == "unavailable") Assert.Equal(Text(ProblemPresentation.Message("security.problems.identity.unavailable", locale)["text"]), Text(view["identity_sources_text"]));
        }
    }
    [Theory] [InlineData("event")] [InlineData("ad_snapshot")]
    public async Task ConfirmedNameWinsEvenWhenSidShaped(string source)
    {
        string actor = "sid:" + Sid; var retained = Label(name: Sid); retained["source"] = source; retained["event_id"] = 4728; retained["event_db_id"] = 91; retained["sid"] = Sid; retained["domain_id"] = 3;
        var context = new JsonObject { ["actor"] = source == "event" ? retained.DeepClone() : null,
            ["principals"] = source == "ad_snapshot" ? new JsonObject { [actor] = retained.DeepClone() } : new JsonObject(), ["principal_states"] = new JsonObject { [actor] = "named" } };
        var raw = Row(actor); raw["identity_context"] = context; var view = View(raw);
        Assert.Equal(Sid, Text(view["actor_text"])); Assert.Equal(actor, Text(view["actor"])); Assert.Contains(Sid, Text(view["identity_sources_text"])); Assert.True(JsonNode.DeepEquals(context, view["identity_context"]));
        raw = Row(); await Attach(raw, new JsonArray(Label(name: Sid)));
        Assert.Equal("named", Text(raw["identity_context"]!["principal_states"]![Sid])); Assert.Equal(Sid, Text(Home(Sid, raw["identity_context"]!.AsObject())["name"]));
    }
    [Theory] [InlineData("ru")] [InlineData("en")]
    public void SystemActorRetainsLocalizedHostLabel(string locale)
    {
        string actor = "sid:synthetic-dc:S-1-5-18"; var view = View(Row(actor), locale);
        var expected = ProblemPresentation.Message("security.problems.entity.system", locale, new() { ["name"] = "SYNTHETIC-DC" });
        Assert.Equal(Text(expected["text"]), Text(view["actor_text"])); Assert.Equal(actor, Text(view["actor"]));
    }

    [Theory] [MemberData(nameof(SidForms))]
    public void HomeProjectionPreservesUnavailableAndUnverifiedStates(string value, bool valid)
    {
        var group = new JsonObject { ["representative"] = new JsonObject { ["id"] = 7 }, ["domain_name"] = "example.test" };
        var failed = HomeDecisionSummary.IdentityObject(value, group, true, new() { [(7, value)] = null });
        Assert.Equal(valid ? "unavailable" : "unverified", Text(failed["name_state"])); Assert.Equal("", Text(failed["name"]));
        var obj = HomeDecisionSummary.IdentityObject(value, group, true, new());
        Assert.Equal("unverified", Text(obj["name_state"])); Assert.Equal(value, Text(obj["identifier"]));
    }

    [Fact] public async Task IdentitySqlExecutesAsWebRoleWithRetainedSnapshotGuards()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(ct);
        await using var admin = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(admin, "create role adlog_user login nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication", ct);
        string root = PostCollectionPostgres.Repository(), baseline = Path.Combine(root, "config/postgres_baseline");
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(baseline, "manifest.json"), ct))!;
        await pg.ApplyFileAsync(Path.Combine(baseline, "roles.sql"), null, ct);
        string rendered = Path.Combine(pg.Root, "baseline.sql");
        await File.WriteAllTextAsync(rendered, (await File.ReadAllTextAsync(Path.Combine(baseline, "baseline.sql"), ct))
            .Replace(manifest["domain_placeholder"]!.ToString(), "example.test"), ct);
        await pg.ApplyFileAsync(rendered, null, ct);
        // Same clean-install path as ReadSqlPostgresTests, with the installed schema rather than a facsimile.
        await PostCollectionPostgres.Sql(admin, "insert into auth_users(username,password_hash,role) values('fixture-owner','synthetic-unusable-hash','admin')", ct);
        foreach (var file in Directory.GetFiles(Path.Combine(root, "config/postgres_migrations"), "*.sql")
            .Where(p => Regex.IsMatch(Path.GetFileName(p), @"^\d+_.*\.sql$") && !p.EndsWith(".rollback.sql") && !p.EndsWith("_rollback.sql"))
            .Select(p => (Path: p, Version: int.Parse(Path.GetFileName(p).Split('_')[0])))
            .Where(m => m.Version > manifest["baseline_version"]!.GetValue<int>()).OrderBy(m => m.Version))
            await pg.ApplyFileAsync(file.Path, null, ct);
        async Task Sql(string statement) => await PostCollectionPostgres.Sql(admin, statement, ct);
        await using (var seed = new NpgsqlCommand("""
            insert into forests(name) values('synthetic-identity-forest');
            insert into domains(forest_id,fqdn) select id,'other.example.test' from forests where name='synthetic-identity-forest';
            insert into storage_v2_entity_type(value) values('ad_user') on conflict do nothing;
            insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
                select kind.id,'synthetic-identity','Current name must not win',domain.id,sha256('entity'::bytea)
                from storage_v2_entity_type kind cross join domains domain where kind.value='ad_user' and domain.fqdn='example.test';
            insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
                select '00000000-0000-4000-8000-000000000001','synthetic','1',id,'full',@snapshot::timestamptz,sha256('bundle'::bytea),'completed'
                from domains where fqdn='example.test';
            insert into ad_context_sections(run_id,section_name,status,record_count) values
                ('00000000-0000-4000-8000-000000000001','directory_accounts','complete',1),
                ('00000000-0000-4000-8000-000000000001','directory_group_graph','complete',1);
            insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,normalized_value,first_seen_utc,last_seen_utc,source_run_id)
                select id,domain_id,'object_sid',@sid,lower(@sid),@snapshot::timestamptz,@snapshot::timestamptz,'00000000-0000-4000-8000-000000000001'
                from entities_v2 where natural_key='synthetic-identity';
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
                select id,'directory_accounts',@snapshot::timestamptz,@snapshot::timestamptz,sha256('version'::bytea),
                    jsonb_build_object('identity',jsonb_build_object('kind','ad_user','object_sid',@sid),'attributes',jsonb_build_object('display_name','Retained synthetic name')),
                    '00000000-0000-4000-8000-000000000001' from entities_v2 where natural_key='synthetic-identity';
            insert into servers(id,domain_id,hostname,fqdn) select 91001,id,'synthetic-dc','synthetic-dc.example.test' from domains where fqdn='example.test';
            insert into findings(id,fingerprint,rule_code,title,severity,evidence_count,actor)
                values(91001,'synthetic-identity','synthetic-identity','Member was added to a privileged group','high',1,@sid);
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
                select 91001,91001,@at::timestamptz,4728,id,@sid,'dc.example.test',
                    jsonb_build_object('$server_id',91001,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
                        '$principals',jsonb_build_object('SubjectUserSid',@sid,'SubjectUserName','-')),
                    '{}','{}',sha256('source'::bytea),'primary' from domains where fqdn='example.test';
            """, admin)) {
            seed.Parameters.AddWithValue("sid", Sid); seed.Parameters.AddWithValue("at", At); seed.Parameters.AddWithValue("snapshot", Snapshot);
            await seed.ExecuteNonQueryAsync(ct);
        }
        await using var web = await pg.OpenAsync(ct, "adlog_user");
        async Task Check(string state, string? actor = null)
        {
            actor ??= "sid:" + Sid;
            await using var tx = await web.BeginTransactionAsync(ct);
            var raw = Row(actor); raw["id"] = 91001; raw["target"] = null; raw["entities"] = new JsonArray();
            await using (var count = new NpgsqlCommand("select evidence_count from findings where id=91001", web, tx))
                raw["evidence_count"] = Convert.ToInt64(await count.ExecuteScalarAsync(ct));
            var rows = new JsonArray(raw);
            await ProblemRepository.AttachDetails(tx, rows, ct);
            await ProblemRepository.AttachIdentities(tx, rows, ct);
            Assert.Equal(state, Text(raw["identity_context"]!["principal_states"]![actor]));
            Assert.Equal(actor, Text(raw["actor"]));
            Assert.Equal(state == "named" ? "Retained synthetic name" : null, Text(View(raw)["actor_text"]));
            Assert.False(raw["evidence"]![0]!.AsObject().ContainsKey("subject_user_name"));
            if (state != "named") Assert.Null(raw["identity_context"]!["principals"]![actor]);
            var labels = new List<JsonObject>();
            await using (var command = new NpgsqlCommand("select to_jsonb(identity_row) from (" + HomeDecisionSummary.IdentitySql + ") identity_row", web, tx)) {
                command.Parameters.AddWithValue("requests", new JsonArray(new JsonObject {
                    ["request_index"] = 0, ["finding"] = 91001, ["sid"] = Sid.ToLowerInvariant(),
                    ["hostname"] = actor.Split(':') is { Length: 3 } parts ? parts[1] : null }).ToJsonString());
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) labels.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
            }
            var obj = HomeDecisionSummary.IdentityObject(actor, new() { ["representative"] = new JsonObject { ["id"] = 91001 }, ["domain_name"] = "example.test" },
                true, new() { [(91001, actor)] = labels });
            Assert.Equal(state, Text(obj["name_state"])); Assert.Equal(actor, Text(obj["identifier"]));
            if (state == "named") {
                Assert.Equal("Retained synthetic name", Text(obj["name"]));
                Assert.Equal(DateTimeOffset.Parse(At), DateTimeOffset.Parse(Text(obj["source"]!["witness_at_utc"])!));
            }
            await tx.RollbackAsync(ct);
        }
        await Check("named");
        await Sql("""
            insert into servers(id,domain_id,hostname,fqdn) select 91002,id,'other-dc','other-dc.example.test' from domains where fqdn='other.example.test';
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,evidence_role)
                select finding_id,91002,time_created_utc,event_kind,(select id from domains where fqdn='other.example.test'),actor,'other-dc.example.test',
                    jsonb_set(method,'{$server_id}','91002'),outcome,fields,source_sha256,evidence_role
                from finding_event_copies337 where event_id=91001;
            update findings set evidence_count=2 where id=91001;
            """);
        await Check("unverified");
        await Sql("delete from finding_event_copies337 where event_id=91002; update findings set evidence_count=1 where id=91001");
        foreach (string status in new[] { "partial", "failed", "skipped" }) {
            await Sql("update ad_context_sections set status='" + status + "'"); await Check("no_match");
        }
        await Sql("update ad_context_sections set status='complete'");
        foreach (string status in new[] { "failed", "importing" }) {
            await Sql("update ad_context_runs set status='" + status + "'"); await Check("no_match");
        }
        await Sql("update ad_context_runs set status='completed'");
        await Sql("update ad_context_entity_versions set valid_from_utc='2026-10-01'"); await Check("no_match");
        await Sql("update ad_context_entity_versions set valid_from_utc='2026-08-01T10:00:00Z',valid_to_utc='2026-09-03T10:00:00Z'"); await Check("no_match");
        await Sql("update ad_context_entity_versions set valid_to_utc=null");
        await Sql("update ad_context_runs set observed_at_utc='2026-10-01'"); await Check("no_match");
        await Sql("update ad_context_runs set observed_at_utc='2026-08-01T10:00:00Z'");
        await Sql("update ad_context_entity_aliases set domain_id=(select id from domains where fqdn='other.example.test')"); await Check("no_match");
        await Sql("update ad_context_entity_aliases set domain_id=(select id from domains where fqdn='example.test')");
        await Check("unverified", "sid:other-dc:" + Sid);
        await Sql("update findings set evidence_count=2 where id=91001");
        await Check("unverified");
        await Sql("update findings set evidence_count=1 where id=91001");
        await Sql("""
            insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            select entity_id,'directory_group_graph',valid_from_utc,last_observed_at_utc,sha256('conflict'::bytea),
                jsonb_set(attributes_json,'{attributes,display_name}','"Conflicting retained name"'),source_run_id from ad_context_entity_versions;
            """);
        await Check("ambiguous");
        // A denied optional lookup must recover its savepoint and preserve the queue, never masquerade as no_match.
        await Sql("revoke select on ad_context_entity_versions from adlog_user");
        await using (var tx = await web.BeginTransactionAsync(ct)) {
            var raw = Row("sid:" + Sid); await ProblemRepository.AttachIdentities(tx, new JsonArray(raw), ct);
            Assert.Equal("unavailable", Text(raw["identity_context"]!["principal_states"]!["sid:" + Sid]));
            await using var alive = new NpgsqlCommand("select 1", web, tx); Assert.Equal(1, await alive.ExecuteScalarAsync(ct));
        }
    }
}
