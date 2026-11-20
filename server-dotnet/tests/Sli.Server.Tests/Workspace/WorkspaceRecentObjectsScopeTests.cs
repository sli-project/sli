using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

// Behavioral vectors from tests/reporting/test_workspace_recent_objects_scope.py.
public sealed class WorkspaceRecentObjectsScopeTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Rows(IReadOnlyList<JsonElement> items, Exception? error = null) : IWorkspaceRows
    {
        public int Calls;
        public string? Sql;
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
        {
            Calls++;
            Sql = sql;
            Assert.Equal(Ct, ct);
            if (error is not null) throw error;
            return Task.FromResult(items);
        }
    }

    private static JsonElement Row(int id = 7, string name = "Synthetic object", string context = """
        {"domain_id":11,"server_id":22}
        """)
    {
        var row = new JsonObject {
            ["id"] = id, ["object_type"] = "account", ["display_name"] = name,
            ["natural_key"] = "TECHNICAL_SENTINEL", ["last_seen_utc"] = "2026-10-21T00:00:00Z"
        };
        foreach (var item in JsonNode.Parse(context)!.AsObject()) row[item.Key] = item.Value?.DeepClone();
        return JsonSerializer.SerializeToElement(row);
    }

    private static CapabilityPolicy Policy(string capability, string kind, int id, string effect = "deny", bool valid = true) =>
        new(capability, effect, valid, false, JsonSerializer.SerializeToElement(new { kind, ids = new[] { id } }));

    private static AccessReadEvaluation Access(string[]? capabilities = null, CapabilityPolicy[]? policies = null,
        string[]? scoped = null, bool owner = false)
    {
        var facts = new AccessFacts(owner, "operator", [], [], [], [], [], [], []);
        var caps = new CapabilityDecisionSet(owner, new HashSet<string>(["workspace.view", .. capabilities ?? []]),
            new HashSet<string>(scoped ?? []), policies ?? [], new Dictionary<string, JsonElement>());
        return new(facts, caps, new ReportEligibility().Compose(facts, caps));
    }

    private static Task<JsonObject> Read(Rows rows, AccessReadEvaluation access) =>
        new WorkspaceCompatibilityReader(rows, new ConfigurationBuilder().Build(), null!, null!, null!)
            .ReadAsync("/api/v1/workspace", new QueryCollection(), new("session", 1, "operator"), access, Ct);

    private static JsonArray Recent(JsonObject response) => response["recent_objects"]!.AsArray();

    [Fact]
    public async Task Query_selects_authoritative_resource_context_and_recent_eight_in_order()
    {
        var rows = new Rows([Row()]);
        var result = await Read(rows, Access(["objects.view"]));
        Assert.Equal(1, rows.Calls);
        Assert.Contains("entities_v2_active", rows.Sql);
        Assert.Contains("entity.domain_id", rows.Sql);
        Assert.Contains("entity.server_id", rows.Sql);
        Assert.Contains("order by entity.last_seen_utc desc nulls last,entity.id desc limit 8", rows.Sql);
        var item = Assert.Single(Recent(result))!;
        Assert.Equal("account", item["object_type"]!.ToString());
        Assert.Equal("Synthetic object", item["display_name"]!.ToString());
        Assert.Equal("2026-10-21T00:00:00Z", item["observed_at_utc"]!.ToString());
        Assert.Equal("Storage V2", item["source"]!.ToString());
    }

    [Theory]
    [InlineData("domain", 11)]
    [InlineData("server", 22)]
    public async Task Resource_deny_overrides_global_object_allow(string kind, int id)
    {
        var result = await Read(new Rows([Row()]), Access(["objects.view", "field.technical"],
            [Policy("objects.view", kind, id)]));
        Assert.Empty(Recent(result));
    }

    [Theory]
    [InlineData("domain", 11, "server", 22)]
    [InlineData("server", 22, "domain", 11)]
    public async Task Other_dimension_deny_overrides_scoped_allow(string allowKind, int allowId, string denyKind, int denyId)
    {
        var result = await Read(new Rows([Row()]), Access(policies: [Policy("objects.view", allowKind, allowId, "allow"),
            Policy("objects.view", denyKind, denyId)], scoped: ["objects.view"]));
        Assert.Empty(Recent(result));
    }

    [Theory]
    [InlineData("domain", 11)]
    [InlineData("server", 22)]
    public async Task Technical_deny_redacts_key_and_display_name_fallback(string kind, int id)
    {
        var result = await Read(new Rows([Row(name: "")]), Access(["objects.view", "field.technical"],
            [Policy("field.technical", kind, id)]));
        var item = Assert.Single(Recent(result))!;
        Assert.Null(item["natural_key"]);
        Assert.Equal("7", item["display_name"]!.ToString());
        Assert.DoesNotContain("TECHNICAL_SENTINEL", result.ToJsonString());
    }

    [Fact]
    public async Task Scoped_only_allow_filters_rows_and_uses_permitted_technical_key_as_name()
    {
        var result = await Read(new Rows([Row(name: ""), Row(8, context: """{"domain_id":12,"server_id":22}""")]),
            Access(policies: [Policy("objects.view", "domain", 11, "allow"), Policy("field.technical", "server", 22, "allow")],
                scoped: ["objects.view", "field.technical"]));
        var item = Assert.Single(Recent(result))!;
        Assert.Equal("7", item["object_id"]!.ToString());
        Assert.Equal("TECHNICAL_SENTINEL", item["natural_key"]!.ToString());
        Assert.Equal("TECHNICAL_SENTINEL", item["display_name"]!.ToString());
    }

    [Fact]
    public async Task Owner_with_known_resources_reads_objects_without_explicit_capabilities()
    {
        var rows = new Rows([Row()]);
        var result = await Read(rows, Access(owner: true));
        Assert.Equal(1, rows.Calls);
        Assert.Equal("7", Assert.Single(Recent(result))!["object_id"]!.ToString());
    }

    [Fact]
    public async Task No_object_permission_does_not_query()
    {
        var rows = new Rows([Row()]);
        var result = await Read(rows, Access());
        Assert.Equal(0, rows.Calls);
        Assert.Empty(Recent(result));
    }

    [Theory]
    [InlineData("""{"domain_id":null,"server_id":null}""")]
    [InlineData("""{"domain_id":0,"server_id":22}""")]
    [InlineData("""{"domain_id":11,"server_id":-1}""")]
    [InlineData("""{"domain_id":true,"server_id":22}""")]
    [InlineData("""{"domain_id":11,"server_id":"22"}""")]
    [InlineData("""{"domain_id":1.5,"server_id":22}""")]
    [InlineData("""{"domain_id":"invalid","server_id":null}""")]
    [InlineData("""{"server_id":22}""")]
    [InlineData("""{"domain_id":11}""")]
    [InlineData("{}")]
    public async Task Invalid_or_missing_resource_context_is_omitted_even_for_owner(string context)
    {
        foreach (bool owner in new[] { false, true })
        {
            var rows = new Rows([Row(context: context)]);
            var result = await Read(rows, Access(["objects.view"], owner: owner));
            Assert.Equal(1, rows.Calls);
            Assert.Empty(Recent(result));
        }
    }

    [Theory]
    [InlineData("domain", 11, """{"domain_id":11,"server_id":null}""")]
    [InlineData("server", 22, """{"domain_id":null,"server_id":22}""")]
    public async Task Explicitly_null_partial_context_uses_available_resource_for_allow_and_deny(string kind, int id, string context)
    {
        var result = await Read(new Rows([Row(context: context)]), Access(
            policies: [Policy("objects.view", kind, id, "allow")], scoped: ["objects.view"]));
        Assert.Equal("7", Assert.Single(Recent(result))!["object_id"]!.ToString());
        result = await Read(new Rows([Row(context: context)]), Access(["objects.view"], [Policy("objects.view", kind, id)]));
        Assert.Empty(Recent(result));
    }

    [Theory]
    [InlineData("objects.view")]
    [InlineData("field.technical")]
    public async Task Invalid_deny_fails_closed(string capability)
    {
        var result = await Read(new Rows([Row(name: "")]), Access(["objects.view", "field.technical"],
            [Policy(capability, "domain", 11, valid: false)]));
        if (capability == "objects.view") Assert.Empty(Recent(result));
        else
        {
            var item = Assert.Single(Recent(result))!;
            Assert.Null(item["natural_key"]);
            Assert.Equal("7", item["display_name"]!.ToString());
        }
        Assert.DoesNotContain("TECHNICAL_SENTINEL", result.ToJsonString());
    }

    [Fact]
    public async Task First_eight_denied_rows_are_not_refilled()
    {
        var rows = new Rows(Enumerable.Range(1, 8).Select(id => Row(id)).ToArray());
        var result = await Read(rows, Access(["objects.view"], [Policy("objects.view", "domain", 11)]));
        Assert.Empty(Recent(result));
        Assert.Equal(1, rows.Calls);
        Assert.Contains("limit 8", rows.Sql);
        Assert.Equal("available", result["recent_objects_state"]!.ToString());
    }

    [Fact]
    public async Task Query_cancellation_preserves_workspace_contract()
    {
        var rows = new Rows([], new PostgresException("synthetic timeout", "ERROR", "ERROR", "57014"));
        var result = await Read(rows, Access(["objects.view"]));
        Assert.Equal(1, rows.Calls);
        Assert.Empty(Recent(result));
        Assert.Equal("temporarily_unavailable", result["recent_objects_state"]!.ToString());
        Assert.Equal(8, result["limits"]!["recent_objects"]!.GetValue<int>());
        Assert.Equal("v4", result["api_version"]!.ToString());
        Assert.DoesNotContain("synthetic timeout", result.ToJsonString());
    }

    [Fact]
    public async Task Serialized_workspace_excludes_denied_identity_and_redacted_key()
    {
        var result = await Read(new Rows([Row(99999, "DENIED_IDENTITY_SENTINEL"),
            Row(8, "", """{"domain_id":11,"server_id":23}""")]), Access(["objects.view", "field.technical"],
                [Policy("objects.view", "server", 22), Policy("field.technical", "domain", 11)]));
        var item = Assert.Single(Recent(result))!;
        Assert.Equal("8", item["object_id"]!.ToString());
        Assert.Equal("8", item["display_name"]!.ToString());
        Assert.Null(item["natural_key"]);
        foreach (string sentinel in new[] { "99999", "DENIED_IDENTITY_SENTINEL", "TECHNICAL_SENTINEL" })
            Assert.DoesNotContain(sentinel, result.ToJsonString());
    }
}
