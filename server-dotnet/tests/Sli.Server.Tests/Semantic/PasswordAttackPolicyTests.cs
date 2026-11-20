using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/semantic/test_password_attack_policy.py; no runtime or database.
public class PasswordAttackPolicyTests
{
    private static readonly PasswordScope Scope=new("00000000-0000-4000-8000-000000000099","sli.windows.ad-dc","synthetic-source","synthetic-generation","");
    private const string FamilyDigest="abc1680006ad707d3eba3a8a414ed9756d48498f73d75e808a65ecbab4ad2638";

    [Theory]
    [InlineData("brute","qw.password-brute-force","Repeated password attempts against one account","dfc162797f60e5cc05dd8e5519ebdf277b53bdf86f1bb2f12984c9613fc12199","cbf983b6336a79a198f1948c7d7054f03490461e8809b2a74760c2b9cbad71c7")]
    [InlineData("spray","qw.password-spray","Passwords tried across several accounts","016fe0e62d846fa094aca257fabd5b60b5ebd8fe7b94fc4abeb9a54fc275d1b6","aae3b541e4ff25066735b9a91d2d8e1b52f4679450cc2b575d5773b4c0e3b83c")]
    public void Factory_pins_canonical_v2_policy_and_compiled_definition(string kind,string id,string title,string pin,string definitionHash)
    {
        var rule=new PasswordRule(Scope,kind);
        var expected=new JsonObject{
            ["type"]="scenario_policy",["source_selector"]=new JsonObject{["rule_id"]=id,["execution"]=rule.Execution},
            ["scenario_kind"]=id,["result_class"]="security_incident",["merge_window_seconds"]=600,["title"]=title,
            ["explanation"]="Review the linked sign-in attempts and secure the affected accounts.",
            ["risk"]=new JsonObject{["class"]="high",["raw_score"]="60",["display_points"]=60,["rationale"]="Observed password attack evidence requires review."}};
        var definition=PasswordSignal.PolicyDefinition(rule);
        var policy=PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition);
        Assert.Equal(pin,rule.Pin);
        Assert.Equal("default:"+id+":"+pin[..32],policy.Id);
        Assert.Equal(1,policy.Version);
        Assert.True(JsonNode.DeepEquals(expected,definition));
        Assert.Equal(CanonicalJson.Serialize(expected,ensureAscii:false),CanonicalJson.Serialize(policy.Definition,ensureAscii:false));
        Assert.Equal(definitionHash,policy.Sha256);
        Assert.Equal(id,policy.Rule.Id);
        Assert.Equal(2,policy.Definition["source_selector"]!["execution"]!["rule_version"]!.GetValue<int>());
        Assert.Equal(pin,policy.Rule.Pin);
    }

    [Fact]
    public void Unicode_scope_keeps_ASCII_family_digest_and_UTF8_policy_hash_distinct()
    {
        var scope=Scope with{SourceInstanceId="источник-α",SourceGeneration="поколение-β"};
        var rule=new PasswordRule(scope);
        var definition=PasswordSignal.PolicyDefinition(rule);
        var policy=PasswordRiskPolicy.Compile(PasswordSignal.PolicyId(rule),1,definition);
        Assert.Equal("default:qw.password-brute-force:a2c2bc7d8990ad26c890ddcba5beb0a2",policy.Id);
        Assert.NotEqual(CanonicalJson.Serialize(definition),CanonicalJson.Serialize(definition,ensureAscii:false));
        Assert.Equal("3eb7cb87de5f68f29b960460f5bd232b679b45db139ef6768182bdde01d907af",policy.Sha256);
        Assert.NotEqual(PasswordJson.Hash(definition),policy.Sha256);
        Assert.Equal("sli.password.policy-family.1:7864c3749c3a9caa9607df29785a2c49e22c37e4988c76e489bc3c582b279d49:qw.password-brute-force",PasswordSignal.FamilyKey(scope,rule.Id));
    }

    [Theory]
    [InlineData("brute","a58c0f5a241c6106b9d05401533d05980105bfec371652ccf5ca94af832fd4ea")]
    [InlineData("spray","41899843da2509fd7c252bf08fa1306ede15743d572d3c8bb1b4862de5cd7fb5")]
    public void Family_unifies_legacy_and_v2_execution_but_not_pins(string kind,string legacyPin)
    {
        var rule=new PasswordRule(Scope,kind);
        // Frozen v1 execution contract, not a second implementation of the old detector.
        var legacy=new JsonObject{["version"]="sli.qw.execution.v1",["kind"]="threshold",["rule_id"]=rule.Id,["rule_version"]=1,
            ["rule_sha256"]=PasswordJson.Hash(new JsonObject{["version"]=1,["rule"]=rule.Id,["window_seconds"]=300,["threshold"]=10,["spray_accounts"]=5}),["scope"]=Scope.Document};
        Assert.Equal(legacyPin,PasswordJson.Hash(legacy));
        Assert.NotEqual(legacyPin,rule.Pin);
        string expected="sli.password.policy-family.1:"+FamilyDigest+":"+rule.Id;
        Assert.Equal(expected,PasswordSignal.FamilyKey(legacy["scope"],legacy["rule_id"]!.GetValue<string>()));
        Assert.Equal(expected,PasswordSignal.FamilyKey(rule.Execution["scope"],rule.Id));
        Assert.Equal(expected,PasswordSignal.FamilyKey(Scope,rule.Id));
        var reversed=new JsonObject(Scope.Document.Reverse().Select(p=>new KeyValuePair<string,JsonNode?>(p.Key,p.Value?.DeepClone())));
        Assert.Equal(expected,PasswordSignal.FamilyKey(reversed,rule.Id));
    }

    [Theory]
    [InlineData("installation_id","00000000-0000-4000-8000-000000000100")]
    [InlineData("plugin_id","sli.vpn-nps")]
    [InlineData("source_instance_id","another-source")]
    [InlineData("source_generation","another-generation")]
    [InlineData("collection_scope_id","another-collection")]
    public void Family_separates_every_full_scope_dimension(string field,string value)
    {
        var document=Scope.Document;document[field]=value;
        Assert.NotEqual(PasswordSignal.FamilyKey(Scope,PasswordRule.RuleId),PasswordSignal.FamilyKey(document,PasswordRule.RuleId));
        Assert.Equal(PasswordSignal.FamilyKey(document,PasswordRule.RuleId),PasswordSignal.FamilyKey(PasswordScope.Read(document),PasswordRule.RuleId));
    }

    [Fact]
    public void Family_separates_rules_without_mutating_scope()
    {
        var document=Scope.Document;var before=document.DeepClone();
        Assert.NotEqual(PasswordSignal.FamilyKey(document,PasswordRule.RuleId),PasswordSignal.FamilyKey(document,"qw.password-spray"));
        Assert.True(JsonNode.DeepEquals(document,before));
    }

    public static IEnumerable<object?[]> InvalidScopeValues()
    {
        yield return ["installation_id",null];yield return ["installation_id",JsonValue.Create("not-a-uuid")];
        yield return ["plugin_id",JsonValue.Create(true)];yield return ["plugin_id",JsonValue.Create(new string('x',129))];
        yield return ["source_instance_id",JsonValue.Create(1)];yield return ["source_instance_id",JsonValue.Create("")];
        yield return ["source_instance_id",JsonValue.Create(" source")];yield return ["source_instance_id",JsonValue.Create(new string('x',257))];
        yield return ["source_generation",JsonValue.Create("")];yield return ["source_generation",JsonValue.Create(new string('x',513))];
        yield return ["collection_scope_id",null];yield return ["collection_scope_id",JsonValue.Create(new string('x',257))];
    }
    [Theory] [MemberData(nameof(InvalidScopeValues))]
    public void Family_denies_invalid_scope_values_without_coercion(string field,JsonNode? value)
    {
        var document=Scope.Document;document[field]=value?.DeepClone();
        Assert.Equal("password_policy_family_invalid",Assert.Throws<PasswordFailure>(()=>PasswordSignal.FamilyKey(document,PasswordRule.RuleId)).Message);
    }

    public static IEnumerable<object?[]> InvalidScopeShapes()
    {
        yield return [null];yield return ["scope"];yield return [new JsonArray()];yield return [new JsonObject()];
        var extra=Scope.Document;extra["login"]="ignored";yield return [extra];
        var missing=Scope.Document;missing.Remove("collection_scope_id");yield return [missing];
    }
    [Theory] [MemberData(nameof(InvalidScopeShapes))]
    public void Family_denies_noncanonical_scope_shape(object? scope)=>
        Assert.Equal("password_policy_family_invalid",Assert.Throws<PasswordFailure>(()=>PasswordSignal.FamilyKey(scope,PasswordRule.RuleId)).Message);

    public static IEnumerable<object?[]> InvalidRuleIds()
    {
        yield return [null];yield return [1];yield return [new JsonObject()];yield return ["brute"];yield return ["qw.disabled-account-logon"];
    }
    [Theory] [MemberData(nameof(InvalidRuleIds))]
    public void Family_denies_other_rule_families_and_types(object? ruleId)=>
        Assert.Equal("password_policy_family_invalid",Assert.Throws<PasswordFailure>(()=>PasswordSignal.FamilyKey(Scope,ruleId)).Message);

    [Fact]
    public void Factory_denies_null_and_returns_fresh_definition_without_mutating_rule()
    {
        Assert.Equal("password_policy_rule_invalid",Assert.Throws<PasswordFailure>(()=>PasswordSignal.PolicyDefinition(null)).Message);
        Assert.Equal("password_policy_rule_invalid",Assert.Throws<PasswordFailure>(()=>PasswordSignal.PolicyId(null)).Message);
        var rule=new PasswordRule(Scope);var execution=rule.Execution;
        var first=PasswordSignal.PolicyDefinition(rule);first["risk"]!["class"]="critical";
        first["source_selector"]!["execution"]!["scope"]!["source_instance_id"]="changed";
        var second=PasswordSignal.PolicyDefinition(rule);
        Assert.True(JsonNode.DeepEquals(execution,rule.Execution));
        Assert.Equal("high",second["risk"]!["class"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(execution,second["source_selector"]!["execution"]));
    }
}
