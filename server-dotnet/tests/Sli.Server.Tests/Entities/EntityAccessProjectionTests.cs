using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Entities;
using Xunit;

namespace Sli.Server.Tests.Entities;

// Vectors from tests/access/test_entity_access_projection.py. The object facade
// exposes the raw projection; the legacy entity response adds nullable model fields.
public sealed class EntityAccessProjectionTests
{
    static JsonObject Object(string json) => JsonNode.Parse(json)!.AsObject();
    static CapabilityDecisionSet Capabilities(params string[] keys) =>
        new(false, keys.ToHashSet(StringComparer.Ordinal), new HashSet<string>(), [], new Dictionary<string, JsonElement>());

    [Fact]
    public void AdContextHidesUngrantedFieldsRelationsAndCounts()
    {
        var source = Object("""
            {
              "entity_id": 7,
              "ad_context_entity_id": 70,
              "resolution": "shared_entity_id",
              "returned_count": 2,
              "bounded": true,
              "items": [
                {
                  "context_evidence_id": 101,
                  "source_run_id": "run-secret",
                  "source_section": "directory_accounts",
                  "integrity_sha256": "hash-secret",
                  "context_kind": "entity",
                  "subject_entity_id": 70,
                  "subject_display_name": "Alice",
                  "attributes": {
                    "identity": {"object_sid": "S-1-5-21-100000001-200000002-300000003-7"},
                    "attributes": {
                      "display_name": "Alice",
                      "enabled": true,
                      "admin_count": 1,
                      "employee_id": "secret-hr",
                      "unknown_secret": "never-project"
                    }
                  }
                },
                {
                  "context_evidence_id": 102,
                  "context_kind": "relation",
                  "subject_entity_id": 70,
                  "related_entity_id": 71,
                  "related_display_name": "Domain Admins",
                  "attributes": {"membership_type": "direct"}
                }
              ]
            }
            """);

        var actual = EntityDirectoryReader.Project(source,
            Capabilities("field.identity_basic", "field.security"), new() { ["id"] = 7 }, facade: true);

        var expected = Object("""
            {
              "entity_id": 7,
              "resolution": "shared_entity_id",
              "returned_count": 1,
              "bounded": true,
              "items": [{
                "context_kind": "entity",
                "subject_display_name": "Alice",
                "attributes": {"display_name": "Alice", "enabled": true}
              }]
            }
            """);
        Assert.True(JsonNode.DeepEquals(expected, actual), actual.ToJsonString());
    }

    [Fact]
    public void AdContextPreservesTypedGroupRelationWhenAuthorized()
    {
        var source = Object("""
            {
              "entity_id": 7,
              "resolution": "shared_entity_id",
              "returned_count": 1,
              "bounded": true,
              "items": [{
                "context_evidence_id": 102,
                "integrity_sha256": "not-needed-in-ui",
                "context_kind": "relation",
                "subject_entity_id": 70,
                "related_entity_id": 71,
                "related_display_name": "VPNl2tp",
                "attributes": {"membership_type": "direct"}
              }]
            }
            """);

        // The caller's include_relations=True requires both privilege grants.
        var actual = EntityDirectoryReader.Project(source,
            Capabilities("field.identity_basic", "field.privilege", "field.technical", "objects.privileges"),
            new() { ["id"] = 7 }, facade: true);

        var expected = Object("""
            {
              "entity_id": 7,
              "resolution": "shared_entity_id",
              "returned_count": 1,
              "bounded": true,
              "items": [{
                "context_evidence_id": 102,
                "context_kind": "relation",
                "subject_entity_id": 70,
                "related_entity_id": 71,
                "related_display_name": "VPNl2tp",
                "attributes": {"membership_type": "direct"},
                "relation_class": "group"
              }]
            }
            """);
        Assert.True(JsonNode.DeepEquals(expected, actual), actual.ToJsonString());
    }
}
