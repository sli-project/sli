using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/events/test_event_catalog_contract.py. No database or Python runtime.
public sealed class EventCatalogContractTests
{
    private static JsonObject Catalog() => EventDescriptors.Load();
    private static JsonObject Baseline() => JsonNode.Parse(File.ReadAllText(Path.Combine(Agents.PostCollectionPostgres.Repository(), "config", "event_catalog_baseline.json")))!.AsObject();
    private static JsonObject Complete() => JsonNode.Parse("""
        {"source":"sli.exchange","stream":"message-tracking","event_key":"RECEIVE","event_id":null,
         "severity":"low","title":"Проверочная запись","why":"Существует только в тесте.","fix":"Ничего не делать.",
         "base_risk":"low","purpose_tier":"technical","noise_class":"context","category":"authentication",
         "lifecycle":{"raw_payload_days":2,"record_days":7,"warm_record_days":365,"rollup":null},
         "correlation":null,"correlation_absent_reason":"одиночное событие, парного нет",
         "required_fields":["target_user_name","target_user_sid"]}
        """)!.AsObject();
    private static JsonObject Data(params JsonObject[] entries) => new() { ["entries"] = new JsonArray(entries.Cast<JsonNode>().ToArray()) };
    private static JsonObject Windows(int id) => (JsonObject)EventCatalogQuality.Entries(Catalog()).Single(e => e["event_id"]!.GetValue<int>() == id).DeepClone();
    private static void Valid(JsonObject result) => Assert.True(result["valid"]!.GetValue<bool>(), result.ToJsonString());
    private static void Invalid(JsonObject result) => Assert.False(result["valid"]!.GetValue<bool>(), result.ToJsonString());
    private static string[] Codes(JsonObject result) => result["errors"]!.AsArray().Select(e => e!["code"]!.ToString()).ToArray();
    private static JsonObject FirstViolation(JsonObject result) => result["violations"]![0]!.AsObject();

    [Fact] public void Unmodified_catalog_passes_the_original_boundary()
    {
        var result = EventCatalogQuality.ValidateChanges(Catalog(), Baseline());
        Valid(result); Assert.Equal(30, result["новых"]!.GetValue<int>()); Assert.Equal(75, result["изменённых"]!.GetValue<int>());
    }
    [Fact] public void New_incomplete_entry_blocks_and_reports_all_v2_fields()
    {
        var catalog = Catalog(); var entry = Complete();
        foreach (string key in entry.Select(p => p.Key).Where(k => !new[] { "source", "stream", "event_key", "severity", "title", "why", "fix" }.Contains(k)).ToArray()) entry.Remove(key);
        catalog["entries"]!.AsArray().Add(entry);
        var result = EventCatalogQuality.ValidateChanges(catalog, Baseline()); Invalid(result);
        Assert.Equal(31, result["новых"]!.GetValue<int>()); var violation = FirstViolation(result);
        Assert.Equal("новая", violation["вид"]!.ToString());
        foreach (string field in new[] { "lifecycle", "correlation", "required_fields" }) Assert.Contains(field, violation["не_заполнено"]!.AsArray().Select(n => n!.ToString()));
    }
    [Fact] public void New_complete_entry_passes()
    {
        var catalog = Catalog(); catalog["entries"]!.AsArray().Add(Complete());
        var result = EventCatalogQuality.ValidateChanges(catalog, Baseline()); Valid(result); Assert.Equal(31, result["новых"]!.GetValue<int>());
    }
    [Fact] public void Missing_warm_period_blocks_new_entry()
    {
        var catalog = Catalog(); var entry = Complete(); entry["lifecycle"]!.AsObject().Remove("warm_record_days"); catalog["entries"]!.AsArray().Add(entry);
        var result = EventCatalogQuality.ValidateChanges(catalog, Baseline()); Invalid(result);
        Assert.Contains("lifecycle.warm_record_days", FirstViolation(result)["не_заполнено"]!.AsArray().Select(n => n!.ToString()));
    }
    [Fact] public void Lifecycle_rejects_invalid_regex()
    {
        var entry = Complete(); entry["lifecycle"]!["warm_record_days"] = JsonNode.Parse("""{"default":365,"rules":[{"field":"message","op":"regex","value":"[","then":30}]}""");
        var result = EventCatalogQuality.Validate(Data(entry)); Invalid(result); Assert.Equal("predicate_regex_invalid", Codes(result)[0]);
    }
    [Fact] public void String_key_and_noise_predicate_pass()
    {
        var entry = Complete(); entry["noise_class"] = JsonNode.Parse("""{"default":"noise","rules":[{"field":"message_sample","op":"contains","value":"external","then":"signal"}]}""");
        Valid(EventCatalogQuality.Validate(Data(entry)));
    }
    [Fact] public void Duplicate_string_identity_blocks_even_with_different_numeric_id()
    {
        var second = Complete(); second["event_id"] = 9999;
        var result = EventCatalogQuality.Validate(Data(Complete(), second)); Invalid(result); Assert.Contains("duplicate_identity", Codes(result));
    }
    [Fact] public void Exchange_chain_correlation_passes()
    {
        var entry = Complete(); entry["correlation"] = JsonNode.Parse("""{"role":"open","key":["correlation_id"],"cardinality":"chain","terminators":["DELIVER","SEND","FAIL"],"close_timeout_seconds":86400}""");
        entry.Remove("correlation_absent_reason"); Valid(EventCatalogQuality.Validate(Data(entry)));
    }
    [Fact] public void Pair_correlation_rejects_multiple_terminators()
    {
        var entry = Complete(); entry["correlation"] = JsonNode.Parse("""{"role":"open","key":"logon_id","cardinality":"pair","terminators":["4634","4647"],"close_timeout_seconds":86400}""");
        entry.Remove("correlation_absent_reason"); var result = EventCatalogQuality.Validate(Data(entry)); Invalid(result);
        Assert.Contains("correlation_pair_has_multiple_terminators", Codes(result));
    }
    [Fact] public void Required_fields_use_storage_column_names()
    {
        var entry = Complete(); entry["required_fields"] = new JsonArray("TargetUserName");
        var result = EventCatalogQuality.Validate(Data(entry)); Invalid(result); Assert.Contains("required_fields_invalid", Codes(result));
    }
    [Fact] public void V2_lookup_preserves_string_event_key()
    {
        var descriptors = new EventDescriptors(Data(Complete()));
        Assert.Equal("RECEIVE", descriptors.Lookup("sli.exchange", "message-tracking", "RECEIVE")!["event_key"]!.ToString());
        Assert.Null(descriptors.Lookup("other", "message-tracking", "RECEIVE"));
    }
    [Fact] public void Semantic_identity_requires_the_exact_provider()
    {
        var entry = Complete(); entry["provider_name"] = "MSExchange Message Tracking"; var descriptors = new EventDescriptors(Data(entry));
        Assert.Equal("RECEIVE", descriptors.Lookup("sli.exchange", "message-tracking", "RECEIVE", "MSExchange Message Tracking", semantic: true)!["event_key"]!.ToString());
        Assert.Null(descriptors.Lookup("sli.exchange", "message-tracking", "RECEIVE", "Other Provider", semantic: true));
        Assert.Null(descriptors.Lookup("sli.exchange", "message-tracking", "RECEIVE", semantic: true));
    }
    [Fact] public void Legacy_windows_entry_is_available_through_v2_lookup()
    {
        Assert.Equal(4624, new EventDescriptors(Catalog()).Lookup("sli.windows.ad-dc", "Security", "4624")!["event_id"]!.GetValue<int>());
        var legacy = Windows(4624); foreach (string key in new[] { "source", "stream", "event_key" }) legacy.Remove(key);
        Assert.Equal(4624, new EventDescriptors(Data(legacy)).Lookup("sli.windows.ad-dc", "Security", "4624")!["event_id"]!.GetValue<int>());
    }
    [Fact] public void Authentication_uses_descriptor_roles_instead_of_general_correlation()
    {
        Assert.Null(Windows(4624)["correlation"]); Assert.Null(Windows(4634)["correlation"]);
        Assert.Equal("open", Windows(4624)["lifecycle"]!["rollup_role"]!.ToString()); Assert.Equal("close", Windows(4634)["lifecycle"]!["rollup_role"]!.ToString());
        Assert.Contains("не генерирует", Windows(4772)["why"]!.ToString()); Assert.Equal("context", Windows(4772)["noise_class"]!.ToString());
    }
    [Fact] public void Authentication_lifecycle_v2_has_exact_reviewed_promotion_and_stable_fingerprint()
    {
        var expected = JsonNode.Parse("""
            {"version":"descriptor-lifecycle-v2","archive_requirement":"no_archive","post_promotion_disposition":"delete_source",
             "read_representation":"derived_only","high_volume":true,"semantic_role":"authentication_boundary","hot_need":"raw_investigation_window",
             "warm_value":"closed_or_incomplete_authentication_history","executable_lifecycle":"semantic_then_direct_retention_executor",
             "budget":{"events_per_day_upper":5,"source_bytes_per_event_upper":468,"derived_bytes_per_object_upper":1341,"calibration":"representative"}}
            """);
        foreach (var (id, role) in new[] { (4624, "open"), (4634, "close"), (4608, "boot_scope") })
        {
            var lifecycle = Windows(id)["lifecycle"]!; Assert.Equal("authentication_session", lifecycle["rollup"]!.ToString());
            Assert.Equal(role, lifecycle["rollup_role"]!.ToString()); Assert.True(JsonNode.DeepEquals(expected, lifecycle["promotion"]));
        }
        var descriptors = new EventDescriptors(Catalog()); var result = descriptors.Resolve("sli.windows.ad-dc", "Security", "4624");
        Assert.Equal("open", result["rollup_role"]!.ToString()); Assert.Equal("no_archive", result["promotion"]!["archive_requirement"]!.ToString());
        Assert.Equal(descriptors.Resolve("sli.windows.ad-dc", "Security", "4624")["policy_fingerprint"]!.ToString(), result["policy_fingerprint"]!.ToString());
    }
    [Fact] public void High_volume_requires_complete_promotion_and_noise_cannot_choose_retention()
    {
        var incomplete = Complete(); incomplete["lifecycle"]!["rollup"] = "authentication_session"; incomplete["lifecycle"]!["rollup_role"] = "open";
        incomplete["lifecycle"]!["promotion"] = JsonNode.Parse("""{"version":"descriptor-lifecycle-v2","archive_requirement":"no_archive","post_promotion_disposition":"delete_source","read_representation":"derived_only","high_volume":true}""");
        var result = EventCatalogQuality.Validate(Data(incomplete)); Invalid(result); Assert.Contains("lifecycle_promotion_field_missing", Codes(result));
        var noisy = Complete(); noisy["noise_class"] = "noise";
        var resolution = new EventDescriptors(Data(noisy)).Resolve("sli.exchange", "message-tracking", "RECEIVE");
        Assert.Equal("archive_required", resolution["promotion"]!["archive_requirement"]!.ToString());
        Assert.Equal("preserve_source", resolution["promotion"]!["post_promotion_disposition"]!.ToString());
    }
    private static JsonObject UnsafeDirect()
    {
        var entry = Windows(4624); entry["lifecycle"]!["promotion"]!["archive_requirement"] = "archive_required";
        entry["lifecycle"]!["promotion"]!["read_representation"] = "archived_atomic"; return entry;
    }
    [Fact] public void Direct_retention_validator_rejects_archive_required()
    {
        var result = EventCatalogQuality.Validate(Data(UnsafeDirect())); Invalid(result); Assert.Contains("lifecycle_direct_retention_requires_no_archive", Codes(result));
    }
    [Fact] public void Runtime_retention_rejects_archive_required_direct_executor() =>
        Assert.Contains("direct retention requires no_archive", Assert.Throws<ArgumentException>(() => EventDescriptors.ResolveRetention(UnsafeDirect())).Message);
    [Fact] public void V2_retention_resolver_supports_string_event_key()
    {
        var result = new EventDescriptors(Data(Complete())).Resolve("sli.exchange", "message-tracking", "RECEIVE");
        Assert.Equal(7L, result["record"]!["days"]!.GetValue<long>()); Assert.Equal(365L, result["warm_record"]!["days"]!.GetValue<long>());
        Assert.Equal("catalogue", result["record"]!["source"]!.ToString());
    }
    [Fact] public void Editing_legacy_entry_removes_its_exemption()
    {
        var catalog = Catalog(); var entry = EventCatalogQuality.Entries(catalog).Single(e => e["event_id"]!.GetValue<int>() == 4624);
        entry.Remove("noise_class"); entry["title"] = entry["title"]!.ToString() + " (правка)";
        var result = EventCatalogQuality.ValidateChanges(catalog, Baseline()); Invalid(result);
        Assert.Equal(75, result["изменённых"]!.GetValue<int>()); Assert.Equal("изменённая", FirstViolation(result)["вид"]!.ToString());
    }
    [Fact] public void Canonical_catalog_shape_is_valid() => Valid(EventCatalogQuality.Validate(Catalog()));
    [Fact] public void Baseline_and_current_catalog_have_the_expected_entry_counts()
    {
        Assert.Equal(103, Baseline()["entry_count"]!.GetValue<int>()); Assert.Equal(105, Catalog()["entries"]!.AsArray().Count);
    }
    [Fact] public void Operations_completeness_counts_actual_declarations()
    {
        var result = new OperationsCatalog().Completeness(); Assert.Equal(Catalog()["entries"]!.AsArray().Count, result["entry_count"]!.GetValue<int>());
        Assert.Equal(105, result["fully_classified"]!.GetValue<int>()); Assert.Equal(1d, result["classification_ratio"]!.GetValue<double>());
        Assert.Equal(105, result["schema_v2_ready"]!.GetValue<int>());
    }
    [Fact] public void Unchanged_incomplete_legacy_is_exempt_until_edited()
    {
        var legacy = new JsonObject { ["channel"] = "Security", ["event_id"] = 4624, ["provider_name"] = "Microsoft-Windows-Security-Auditing" };
        var data = Data(legacy); var baseline = EventCatalogQuality.BuildBaseline(data); Valid(EventCatalogQuality.ValidateChanges(data, baseline));
        legacy["title"] = "changed"; Invalid(EventCatalogQuality.ValidateChanges(data, baseline));
    }
    [Fact] public void Lifecycle_runtime_rejects_unsafe_direct_descriptors_before_deletion() =>
        Assert.Contains("direct retention requires no_archive", Assert.Throws<ArgumentException>(() => new LifecycleCatalog(Data(UnsafeDirect()))).Message);
}
