using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_semantic_processing_foundation1.py.
public sealed class SemanticProcessingFoundation1Tests
{
    private const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    private const string Target = "sid:S-1-5-21-100000001-200000002-300000003-2002";
    private const string Merge = "00000000-0000-4000-8000-000000000037";
    private static JsonObject Source(long id, int windowsId, JsonObject? data = null, int minute = 0,
        string channel = "Security", string provider = "Microsoft-Windows-Security-Auditing") => new()
    {
        ["id"] = id, ["event_id"] = windowsId, ["channel"] = channel, ["provider_name"] = provider,
        ["computer"] = "DC1", ["source_host_id"] = 1, ["event_data_json"] = data ?? new(),
        ["time_created_utc"] = $"2026-07-18T03:{minute:00}:00Z"
    };
    private static SemanticEvent Fragment(long id, string type, JsonObject facts, int minute = 0, string? actor = null) =>
        new(id, type, new DateTimeOffset(2026, 7, 18, 3, minute, 0, TimeSpan.Zero),
            actor is null ? new() { ["source_host"] = "1" } : new() { ["source_host"] = "1", ["actor"] = actor },
            facts, new() { ["event_data_encoding"] = "named" }, id.ToString("x64"));
    private static SemanticEvent Directory(long id, int minute, string? correlation = null, JsonObject? values = null)
    {
        var facts = values ?? new(); facts["object"] = "g"; facts["attribute"] = "member";
        if (correlation is not null) facts["operation_correlation_id"] = correlation;
        return Fragment(id, "directory.attribute.changed.fragment", facts, minute, Sid);
    }
    private static long[] Ids(SemanticAction action) => action.Evidence.Select(e => e.Source).ToArray();

    [Fact]
    public void Feature_flags_fail_closed_and_require_each_upstream_stage()
    {
        var env = new Dictionary<string, string?>();
        string? Get(string key) => env.GetValueOrDefault(key);
        var disabled = new SemanticRuntimeSettings(false, false, false, false, false, false);
        Assert.Equal(disabled, SemanticRuntimeSettings.Read(Get));
        env["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "true";
        Assert.Equal(disabled, SemanticRuntimeSettings.Read(Get));
        foreach (string stage in new[] { "NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION" })
            env["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "true";
        Assert.True(SemanticRuntimeSettings.Read(Get).Findings);
        foreach (string stage in new[] { "NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE" })
        {
            env["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "false";
            Assert.False(SemanticRuntimeSettings.Read(Get).Findings);
            env["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "true";
        }
        Assert.True(SemanticRuntimeSettings.Read(Get).Risk);
    }

    [Fact]
    public void Group_and_task_creation_keep_explicit_roles_and_independent_actions()
    {
        var group = SemanticNormalization.Normalize(Source(50, 4728, new()
            { ["SubjectUserName"] = "admin", ["TargetSid"] = "S-1-5-32-544", ["MemberSid"] = Sid }));
        Assert.Equal("group.member.added", group.Type); Assert.Equal("added", group.Facts.Text("change"));
        Assert.Equal("S-1-5-32-544", group.Roles.Text("container_entity")); Assert.Equal(Sid, group.Roles.Text("target_entity"));
        var task = SemanticNormalization.Normalize(Source(51, 106, new() { ["TaskName"] = "\\SLI\\Example", ["UserContext"] = "SYSTEM" },
            channel: "Microsoft-Windows-TaskScheduler/Operational", provider: "Microsoft-Windows-TaskScheduler"));
        Assert.Equal("scheduled_task.created.fragment", task.Type); Assert.Equal("\\SLI\\Example", task.Facts.Text("task_name"));
        var actions = SemanticAssembly.Assemble([group, task]);
        Assert.Collection(actions,
            a => { Assert.Equal("group.member.added", a.Kind); Assert.Equal(new long[] { 50 }, Ids(a)); },
            a => { Assert.Equal("scheduled_task.created", a.Kind); Assert.Equal(new long[] { 51 }, Ids(a)); });
    }

    [Fact]
    public void Audit_policy_preserves_exact_fields_and_never_coalesces()
    {
        JsonObject Data() => new() { ["SubjectUserSid"] = "S-1-5-18", ["SubjectLogonId"] = "0x3e7",
            ["CategoryId"] = "%%8274", ["SubcategoryId"] = "%%12807", ["SubcategoryGuid"] = "{00000000-0000-4000-8000-000000000012}", ["AuditPolicyChanges"] = "%%8448, %%8450" };
        var first = SemanticNormalization.Normalize(Source(60, 4719, Data(), 1));
        var second = SemanticNormalization.Normalize(Source(61, 4719, Data(), 1));
        Assert.Equal("audit.policy.changed", first.Type); Assert.Equal("sid:dc1:S-1-5-18", first.Roles.Text("actor"));
        Assert.Equal("resolved", first.Quality["identity_roles"]!["actor"].Text("state"));
        Assert.Equal(Data().Text("SubcategoryGuid"), first.Facts.Text("audit_subcategory_guid"));
        Assert.Equal(Data().Text("AuditPolicyChanges"), first.Facts.Text("audit_policy_changes"));
        var actions = SemanticAssembly.Assemble([first, second]);
        Assert.All(actions, a => Assert.Equal("audit.policy.changed", a.Kind));
        Assert.Equal(new long[] { 60, 61 }, actions.Select(a => Assert.Single(a.Evidence).Source));
    }

    [Theory]
    [InlineData(203, "Microsoft-Windows-Security-Auditing")]
    [InlineData(999999, "Microsoft-Windows-Security-Auditing")]
    [InlineData(4624, "Unregistered-Provider")]
    [InlineData(1102, "Unrelated-Provider")]
    public void Undocumented_or_mismatched_donors_are_unknown(int id, string provider)
    {
        var normalized = SemanticNormalization.Normalize(Source(id, id, new() { ["NotAName"] = "positional values are rejected" }, provider: provider));
        Assert.Equal("event.unknown", normalized.Type); Assert.Equal("named", normalized.Quality.Text("event_data_encoding"));
        Assert.Contains(normalized.Quality.Text("semantic_mapping_status"), new[] { "descriptor_identity_missing_or_mismatched", "source_pack_or_provider_unresolved" });
        Assert.Empty(SemanticAssembly.Assemble([normalized]));
    }

    [Fact]
    public void Eventlog_clear_requires_provider_and_source_channel()
    {
        var legitimate = SemanticNormalization.Normalize(Source(43, 1102, provider: "Microsoft-Windows-Eventlog"));
        Assert.Equal("eventlog.cleared.fragment", legitimate.Type);
        Assert.Equal("event.unknown", SemanticNormalization.Normalize(Source(44, 1102, channel: "System", provider: "Microsoft-Windows-Eventlog")).Type);
    }

    [Fact]
    public void Service_install_keeps_each_source_separate_and_keys_stable()
    {
        SemanticEvent Service(long id, string name = "svc") => Fragment(id, "service.installed.fragment", new() { ["service_name"] = name, ["service_file"] = "C:/svc.exe" });
        var first = Service(5); var second = Service(6); var different = Service(7, "other");
        var actions = SemanticAssembly.Assemble([different, second, first]);
        Assert.Equal(3, actions.Count); Assert.All(actions, a => { Assert.Equal("service.installed", a.Kind); Assert.Equal("observed", a.Status); Assert.Single(a.Evidence); });
        foreach (var ev in new[] { first, second, different })
            Assert.Equal(Assert.Single(SemanticAssembly.Assemble([ev])).Key, actions.Single(a => Ids(a).Contains(ev.Source)).Key);
        Assert.Equal(3, actions.Select(a => a.Key).Distinct().Count());
        Assert.Equal(new long[] { 50, 51 }, SemanticAssembly.Assemble([Service(50), Service(51)]).Select(a => Assert.Single(a.Evidence).Source));
    }

    [Fact]
    public void Declared_correlations_group_only_matching_directory_fragments()
    {
        var a = Directory(9, 1, "operation-1"); var b = Directory(10, 4, "operation-1"); var later = Directory(11, 6, "operation-2");
        var clear = SemanticNormalization.Normalize(Source(12, 1102, minute: 2, provider: "Microsoft-Windows-Eventlog"));
        var otherClear = Fragment(13, "eventlog.cleared.fragment", new() { ["cleared_log"] = "Security" }, 3);
        var actions = SemanticAssembly.Assemble([a, b, later, clear, otherClear]);
        Assert.Equal(4, actions.Count);
        Assert.Equal(new long[] { 9, 10 }, Ids(actions.Single(x => x.Evidence.Any(e => e.Source == 9))));
        Assert.Equal(new long[] { 11 }, Ids(actions.Single(x => x.Evidence.Any(e => e.Source == 11))));
        Assert.Equal(new long[] { 12, 13 }, actions.Where(x => x.Kind == "eventlog.cleared").Select(x => Assert.Single(x.Evidence).Source).Order());
    }

    [Fact]
    public void Directory_assembly_retains_before_after_values_and_quality()
    {
        var action = Assert.Single(SemanticAssembly.Assemble([
            Directory(30, 1, "operation-3", new() { ["added_values"] = new JsonArray("new") }),
            Directory(31, 2, "operation-3", new() { ["removed_values"] = new JsonArray("old") })]));
        Assert.True(JsonNode.DeepEquals(new JsonArray("new"), action.Attributes["added_values"]));
        Assert.True(JsonNode.DeepEquals(new JsonArray("old"), action.Attributes["removed_values"]));
        Assert.Equal("complete", action.Attributes.Text("quality"));
    }

    [Fact]
    public void Different_correlation_ids_never_coalesce_and_preserve_python_order()
    {
        var actions = SemanticAssembly.Assemble([Directory(40, 1, "a"), Directory(41, 2, "b")]);
        Assert.Equal(new long[] { 40, 41 }, actions.Select(a => Assert.Single(a.Evidence).Source));
    }

    [Fact]
    public void Exact_correlation_crosses_bucket_and_missing_correlation_never_falls_back_to_merge()
    {
        var actions = SemanticAssembly.Assemble([Directory(44, 4, "exact-operation"), Directory(45, 6, "exact-operation"), Directory(46, 7), Directory(47, 8)]);
        Assert.Equal(3, actions.Count);
        Assert.Equal(new long[] { 44, 45 }, Ids(actions.Single(a => a.Evidence.Count == 2)));
        Assert.Equal(new long[] { 46, 47 }, actions.Where(a => a.Evidence.Count == 1).Select(a => a.Evidence[0].Source).Order());
    }

    [Fact]
    public void Account_identity_ladder_exposes_provisional_and_unresolved_quality()
    {
        var provisional = SemanticNormalization.Normalize(Source(48, 4625, new() { ["TargetUserName"] = "Alice", ["TargetDomainName"] = "EXAMPLE", ["IpAddress"] = "192.0.2.10" }));
        Assert.Equal("sam:example:alice", provisional.Roles.Text("affected_entity"));
        var expected = JsonNode.Parse("""{"key":"sam:example:alice","state":"provisional","step":4,"provisional":true,"confidence":0.6,"reason":null,"aliases":["sam:example:alice"],"rule":"identity-ladder/v1"}""");
        Assert.True(JsonNode.DeepEquals(expected, provisional.Quality["identity_roles"]!["affected_entity"]));
        Assert.True(JsonNode.DeepEquals(new JsonArray("affected_entity"), provisional.Quality["provisional_identity_roles"]));
        var unresolved = SemanticNormalization.Normalize(Source(49, 4648, new() { ["SubjectUserName"] = "Operator" }));
        Assert.Equal("name:operator", unresolved.Roles.Text("actor"));
        Assert.True(JsonNode.DeepEquals(new JsonArray("actor"), unresolved.Quality["unresolved_identity_roles"]));
    }

    [Fact]
    public void Shadow_processing_defaults_off_and_has_no_source_side_effects()
    {
        var source = Source(8, 1102, provider: "Microsoft-Windows-Eventlog"); var original = source.DeepClone();
        var disabled = SemanticNormalization.ProcessShadow(source, SemanticRuntimeSettings.Read(_ => null));
        Assert.Null(disabled.Normalized); Assert.Empty(disabled.Actions); Assert.Equal("semantic_normalization_disabled", disabled.SkippedReason);
        var enabled = SemanticNormalization.ProcessShadow(source, new(true, true, false, false, false, false));
        Assert.NotNull(enabled.Normalized); Assert.Equal("eventlog.cleared", Assert.Single(enabled.Actions).Kind); Assert.Null(enabled.SkippedReason);
        Assert.Empty(SemanticNormalization.ProcessShadow(source, new(true, false, false, false, false, false)).Actions);
        Assert.True(JsonNode.DeepEquals(original, source));
    }

    private sealed class MergeSession(string sourceKey) : ISemanticSession
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected write");
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.StartsWith("select to_regclass")) return Task.FromResult(new JsonArray(new JsonObject { ["available"] = true }));
            Assert.StartsWith("select merge_id::text,source_natural_key,target_natural_key", sql);
            Assert.Contains(sourceKey, Assert.IsType<string[]>(values[0])); Assert.Equal(Guid.Parse(Merge), values[1]);
            return Task.FromResult(new JsonArray(new JsonObject { ["merge_id"] = Merge, ["source_natural_key"] = sourceKey, ["target_natural_key"] = Target }));
        }
    }
    private static JsonObject Replay() => new() { ["job_kind"] = "semantic_replay", ["payload_json"] = new JsonObject { ["identity_merge_id"] = Merge } };

    [Fact]
    public async Task R7_override_recomputes_provisional_identity_and_preserves_original_evidence()
    {
        var provisional = SemanticNormalization.Normalize(Source(61, 4728, new() { ["SubjectUserSid"] = Sid, ["SubjectUserName"] = "admin", ["SubjectDomainName"] = "EXAMPLE",
            ["MemberName"] = "CN=User,DC=example,DC=test", ["MemberSid"] = "S-1-0-0", ["TargetUserName"] = "Domain Admins", ["TargetDomainName"] = "EXAMPLE" }));
        string sourceKey = provisional.Roles.Text("affected_entity")!; Assert.StartsWith("sam:", sourceKey);
        var originalRoles = provisional.Roles.DeepClone(); var originalQuality = provisional.Quality.DeepClone();
        await using var session = new MergeSession(sourceKey);
        var merged = await SemanticProduction.IdentityOverrides(session, provisional, Replay(), TestContext.Current.CancellationToken);
        Assert.Equal(Target, merged.Roles.Text("affected_entity"));
        var quality = merged.Quality["identity_roles"]!["affected_entity"]!;
        Assert.Equal("resolved", quality.Text("state")); Assert.False(quality.Flag("provisional"));
        Assert.Contains(sourceKey, quality["aliases"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Empty(merged.Quality["provisional_identity_roles"]!.AsArray()); Assert.NotEqual(provisional.Sha, merged.Sha);
        Assert.True(JsonNode.DeepEquals(originalRoles, provisional.Roles)); Assert.True(JsonNode.DeepEquals(originalQuality, provisional.Quality));
        Assert.True(JsonNode.DeepEquals(provisional.Facts, merged.Facts));
    }

    [Fact]
    public async Task R7_override_rejects_unproved_exact_role_rewrite()
    {
        var exact = SemanticNormalization.Normalize(Source(62, 1102, new() { ["SubjectUserSid"] = Sid }, provider: "Microsoft-Windows-Eventlog"));
        await using var session = new MergeSession(exact.Roles.Text("actor") ?? exact.Roles.Text("source_host")!);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.IdentityOverrides(session, exact, Replay(), TestContext.Current.CancellationToken));
        Assert.Equal("semantic_replay_source_not_provisional", error.Message);
    }
}
