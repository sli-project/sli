using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticChainPackTests
{
    [Fact]
    public void Chain_pack_loads_only_draft_dispatch_rules_in_pack_order()
    {
        var rules = SemanticProduction.ReadDispatchRulePack().Select(SemanticCorrelation.Compile).ToArray();
        Assert.Equal(new[] {
            "auth.session.privileged-context",
            "auth.session.lifecycle",
            "investigation.account.lockout.preceded-by-failures",
            "investigation.account.unlock.after-lock",
            "investigation.account.unlock.after-lock",
            "investigation.group.membership.removed-after-add",
            "investigation.group.membership.removed-after-add",
            "investigation.account.created-then-group-add",
            "investigation.account.created-then-group-add",
            "investigation.password.reset-then-logon",
            "investigation.password.reset-then-logon"
        }, rules.Select(x => x.Id));
        Assert.Equal(new[] {
            "sequence", "sequence", "count_then", "sequence", "sequence", "sequence",
            "sequence", "sequence", "sequence", "sequence", "sequence"
        }, rules.Select(x => x.Kind));
    }

    [Theory]
    [InlineData("investigation.account.unlock.after-lock")]
    [InlineData("investigation.group.membership.removed-after-add")]
    [InlineData("investigation.account.created-then-group-add")]
    [InlineData("investigation.password.reset-then-logon")]
    public void Investigation_sequences_preserve_legacy_version_and_anchor_ambiguity_policy(string id)
    {
        var versions = SemanticProduction.ReadDispatchRulePack().Where(x => x.Text("rule_id") == id).ToArray();
        Assert.Equal(new long[] { 1, 2 }, versions.Select(x => x.Number("rule_version")));
        Assert.Null(versions[0]["definition_json"]!["continuation_policy"]);
        Assert.Equal("anchor_all_admissible", versions[1]["definition_json"].Text("continuation_policy"));
        Assert.Equal("first_admissible", SemanticCorrelation.Compile(versions[0]).Continuation);
        Assert.Equal("anchor_all_admissible", SemanticCorrelation.Compile(versions[1]).Continuation);
    }

    private static JsonObject Pack()
    {
        var row = SemanticProduction.ReadDispatchRulePack()[0];
        return new JsonObject {
            ["owner"] = "semantic_worker", ["default_lifecycle"] = "draft",
            ["rules"] = new JsonArray(new JsonObject {
                ["rule_id"] = row.Text("rule_id"), ["rule_version"] = row.Number("rule_version"),
                ["rule_kind"] = row.Text("rule_kind"), ["lifecycle_status"] = "draft",
                ["definition"] = row["definition_json"]!.DeepClone()
            })
        };
    }

    [Fact]
    public void Loading_skips_worker_assemblers_and_non_objects_without_mutating_the_pack()
    {
        var pack = Pack(); var items = pack["rules"]!.AsArray();
        items.Insert(0, null); items.Add(42);
        items.Add(new JsonObject { ["rule_kind"] = "worker_assembler", ["lifecycle_status"] = "enabled" });
        string before = pack.ToJsonString();
        Assert.Equal("auth.session.privileged-context", Assert.Single(SemanticProduction.ReadDispatchRulePack(pack)).Text("rule_id"));
        Assert.Equal(before, pack.ToJsonString());
    }

    [Theory]
    [InlineData("owner", "semantic_chain_pack_owner_invalid")]
    [InlineData("default_lifecycle", "semantic_chain_pack_default_lifecycle_invalid")]
    [InlineData("rules", "semantic_chain_pack_rules_required")]
    [InlineData("lifecycle_status", "semantic_chain_pack_dispatcher_must_remain_draft")]
    [InlineData("duplicate", "semantic_chain_pack_duplicate_rule_version")]
    [InlineData("worker_only", "semantic_chain_pack_no_dispatcher_rules")]
    [InlineData("rule_id", "semantic_chain_pack_rule_identity_invalid")]
    [InlineData("rule_version", "semantic_chain_pack_rule_identity_invalid")]
    [InlineData("definition", "correlation_definition_type_must_match_rule_kind")]
    public void Invalid_packs_fail_closed(string field, string code)
    {
        var pack = Pack(); var items = pack["rules"]!.AsArray();
        switch (field)
        {
            case "owner": pack[field] = "other_worker"; break;
            case "default_lifecycle": pack[field] = "enabled"; break;
            case "rules": pack[field] = new JsonArray(); break;
            case "lifecycle_status": items[0]![field] = "enabled"; break;
            case "duplicate": items.Add(items[0]!.DeepClone()); break;
            case "worker_only": items[0]!["rule_kind"] = "worker_assembler"; break;
            case "rule_id": items[0]![field] = ""; break;
            case "rule_version": items[0]![field] = 0; break;
            case "definition": items[0]![field]!["type"] = "count"; break;
        }
        Assert.Equal(code, Assert.Throws<InvalidDataException>(() => SemanticProduction.ReadDispatchRulePack(pack)).Message);
    }
}
