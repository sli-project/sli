using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.SnapshotPublication;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AdPostCollectionTests
{
    [Theory]
    [InlineData("sli.ad-snapshot")]
    [InlineData("sli.gpo-snapshot")]
    public void PublicationRequiresUniqueEnabledAssignmentAndCurrentSourceBinding(string module)
    {
        var policy = Vector()["config"]!.AsObject();
        JsonObject Assignment() => new() { ["module_id"] = module, ["enabled"] = true, ["config"] = policy.DeepClone() };
        SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(Assignment()), policy);
        Assert.Equal("agent_module_not_assigned", Assert.Throws<ProtocolException>(() => SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(), policy)).Code);
        Assert.Equal("agent_module_not_assigned", Assert.Throws<ProtocolException>(() => SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(Assignment(), Assignment()), policy)).Code);
        var disabled = Assignment(); disabled["enabled"] = false;
        Assert.Equal("agent_module_not_assigned", Assert.Throws<ProtocolException>(() => SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(disabled), policy)).Code);
        var changed = Assignment(); changed["config"]!["source_instance_id"] = Guid.NewGuid().ToString();
        Assert.Equal("agent_source_not_bound", Assert.Throws<ProtocolException>(() => SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(changed), policy)).Code);
        Assert.Equal("agent_snapshot_module_invalid", Assert.Throws<ProtocolException>(() => SnapshotPublicationAuthorization.ValidateAssignment("sli.workstations", new JsonArray(Assignment()), policy)).Code);
    }
    private static JsonObject Vector([CallerFilePath] string path = "") => JsonNode.Parse(File.ReadAllText(Path.Combine(Path.GetDirectoryName(path)!, "ad-publication-source-vector.json")))!.AsObject();
    private static Dictionary<string, JsonObject> Families(JsonObject vector) => vector["families"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject());

    [Theory]
    [InlineData("sli.ad-snapshot", "source_instance_id")]
    [InlineData("sli.ad-snapshot", "domain_sid")]
    [InlineData("sli.ad-snapshot", "domain_dns")]
    [InlineData("sli.ad-snapshot", "scope")]
    [InlineData("sli.ad-snapshot", "search_bases")]
    [InlineData("sli.ad-snapshot", "groups")]
    [InlineData("sli.ad-snapshot", "dc")]
    [InlineData("sli.ad-snapshot", "expensive_flags")]
    [InlineData("sli.gpo-snapshot", "source_instance_id")]
    [InlineData("sli.gpo-snapshot", "domain_sid")]
    [InlineData("sli.gpo-snapshot", "domain_dns")]
    [InlineData("sli.gpo-snapshot", "scope")]
    public void PublicationRejectsEveryChangedSourceBinding(string module, string key)
    {
        var policy = Vector()["config"]!.AsObject();
        var current = (JsonObject)policy.DeepClone(); current[key] = "changed";
        var assignment = new JsonObject { ["module_id"] = module, ["enabled"] = true, ["config"] = current };
        Assert.Equal("agent_source_not_bound", Assert.Throws<ProtocolException>(() =>
            SnapshotPublicationAuthorization.ValidateAssignment(module, new JsonArray(assignment), policy)).Code);
    }

    [Fact]
    public void NormalizedFamiliesAndExactUsersMatchPythonOracle()
    {
        var root = Vector();
        foreach (var v in new[] { root }.Concat(root["scenarios"]!.AsArray().Select(n => n!.AsObject()))) {
            var prepared = AdPublicationPreparation.Prepare(v["config"]!.AsObject(), Families(v));
            foreach (var (key, b) in prepared.Bundles) Assert.True(JsonNode.DeepEquals(v["bundles"]![key], b), key);
            var ids = v["entity_ids"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.GetValue<long>());
            var actual = AdUsersSnapshot.Build(prepared, 7, "directory.invalid", ids);
            Assert.True(JsonNode.DeepEquals(v["users"], actual), Difference(v["users"], actual, v["name"]!.GetValue<string>()));
            var expectedManifest = v["manifest"]!.AsObject();
            var manifest = AdSnapshotManifest.Build(7, "S-1-5-21-100000001-200000002-300000003", "directory.invalid", v["cycle"]!["slot_start_utc"]!.GetValue<string>(), v["config"]!.AsObject(), "2026-10-08T12:00:00Z", expectedManifest["members"]!.AsArray().Select(n => n!.AsObject()));
            Assert.True(JsonNode.DeepEquals(expectedManifest, manifest), Difference(expectedManifest, manifest, "manifest"));
        }
    }

    private static string Difference(JsonNode? expected, JsonNode? actual, string path)
    {
        if (JsonNode.DeepEquals(expected, actual)) return "";
        if (expected is JsonObject eo && actual is JsonObject ao) {
            foreach (var p in eo) { string result = Difference(p.Value, ao[p.Key], path + "." + p.Key); if (result.Length > 0) return result; }
            return path + " extra keys: " + string.Join(',', ao.Select(p => p.Key).Except(eo.Select(p => p.Key)));
        }
        if (expected is JsonArray ea && actual is JsonArray aa && ea.Count == aa.Count) for (int i = 0; i < ea.Count; i++) { string result = Difference(ea[i], aa[i], path + $"[{i}]"); if (result.Length > 0) return result; }
        return $"{path}: expected {expected?.ToJsonString()}, actual {actual?.ToJsonString()}";
    }

    [Theory]
    [InlineData("missing_family")]
    [InlineData("wrong_domain")]
    [InlineData("incomplete_base")]
    [InlineData("unapproved_quality")]
    [InlineData("wrong_population")]
    [InlineData("secret_attribute")]
    [InlineData("tampered_hash")]
    [InlineData("invalid_groups")]
    [InlineData("relation_oversize")]
    public void InvalidOrUnattestedSourceCannotBecomeAuthority(string defect)
    {
        var v = Vector(); var families = Families(v); var b = families["ad_context_base"];
        foreach (var f in families.Values) f.Remove("bundle_sha256");
        switch (defect) {
            case "missing_family": families.Remove("ad_domain_health"); break;
            case "wrong_domain": b["domain"]!["sid"] = "S-1-5-21-9-9-9"; break;
            case "incomplete_base": b["sections"]![0]!["status"] = "failed"; break;
            case "unapproved_quality":
                b["records"]!.AsArray().Add(new JsonObject { ["record_type"] = "data_quality", ["record_key"] = "quality:unknown", ["section"] = "directory_accounts", ["observed_at_utc"] = b["observed_at_utc"]!.DeepClone(), ["code"] = "unknown_quality_code", ["message"] = "synthetic" });
                b["sections"]![0]!["record_count"] = b["sections"]![0]!["record_count"]!.GetValue<int>() + 1; break;
            case "wrong_population": families["computers_v6"]["objects"]![0]!["objectGuid"] = Guid.NewGuid().ToString(); break;
            case "secret_attribute": b["records"]!.AsArray().First(r => r!["record_type"]!.GetValue<string>() == "entity")!["attributes"]!["unicode_pwd"] = "synthetic"; break;
            case "tampered_hash": b["bundle_sha256"] = new string('a', 64); break;
            case "invalid_groups": b["scope"]!["privileged_group_sids"] = "not-an-array"; break;
            case "relation_oversize": b["records"]!.AsArray().First(r => r!["record_type"]!.GetValue<string>() == "relation")!["attributes"]!["source_section"] = new string('x', 4097); break;
        }
        Assert.ThrowsAny<Exception>(() => AdPublicationPreparation.Prepare(v["config"]!.AsObject(), families));
    }

    [Fact]
    public void ManifestUsesExactScheduledSlotAndStableIdentity()
    {
        var v = Vector(); var policy = v["config"]!.AsObject(); string slot = v["cycle"]!["slot_start_utc"]!.GetValue<string>();
        var member = JsonNode.Parse("""{"family":"ad_context_base","contract_id":"sli.windows.ad-context","source_id":"00000000-0000-4000-8000-000000000002","observed_at_utc":"2026-10-08T12:00:00Z","source_state":"partial","payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reason_code":"ad_context_base_source_partial"}""")!.AsObject();
        var first = AdSnapshotManifest.Build(7, "S-1-5-21-100000001-200000002-300000003", "directory.invalid", slot, policy, "2026-10-08T12:00:00Z", [member]);
        var second = AdSnapshotManifest.Build(7, "S-1-5-21-100000001-200000002-300000003", "directory.invalid", slot, policy, "2026-10-08T12:00:00Z", [member]);
        Assert.True(JsonNode.DeepEquals(first, second)); Assert.Equal("sli.ad-snapshot-manifest/2.0", first["contract_version"]!.GetValue<string>());
        Assert.Equal("2026-10-08T18:00:00", first["scheduled_local_at"]!.GetValue<string>());
        Assert.Equal("agent_ad_schedule_unsupported", Assert.Throws<ProtocolException>(() => AdSnapshotManifest.Build(7, "S-1-5-21-100000001-200000002-300000003", "directory.invalid", "2026-10-08T12:01:00Z", policy, "2026-10-08T12:00:00Z", [member])).Code);
    }
}
