using System.Text.Json.Nodes;
using Sli.Server.Auth;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Stateful SQL boundary, like the Python reference cursor; no PostgreSQL race claim.
public sealed class PasswordPolicyLockTests
{
    private const string BruteFamily = "sli.password.policy-family.1:fbac7851f70aa5e31cb6b17836db001d0e950b834f908c608e4f8ae94694605b:qw.password-brute-force";
    private const string SprayFamily = "sli.password.policy-family.1:fbac7851f70aa5e31cb6b17836db001d0e950b834f908c608e4f8ae94694605b:qw.password-spray";
    private static readonly PasswordScope Scope = new("00000000-0000-4000-8000-000000000099", "sli.windows.ad-dc", "fixture", "generation", "");

    private static JsonObject Policy(string kind = "brute", string generation = "generation")
    {
        var rule = new PasswordRule(Scope with { SourceGeneration = generation }, kind);
        var definition = PasswordSignal.PolicyDefinition(rule);
        return new() { ["policy_id"] = PasswordSignal.PolicyId(rule), ["policy_version"] = 1,
            ["source_kind"] = "qw_signal", ["definition_json"] = definition,
            ["definition_sha256"] = SemanticJson.Hash(definition), ["lifecycle_status"] = "shadow" };
    }

    private static Task Admit(Database db, JsonObject policy) => new SemanticGovernance(db).ChangeAsync(new JsonObject
    {
        ["action"] = "policy_admission", ["policy_id"] = policy["policy_id"]!.DeepClone(),
        ["policy_version"] = policy["policy_version"]!.DeepClone(), ["enabled"] = false, ["reason"] = "fixture decision"
    }, new Principal("session", 1, "admin", "owner"), "192.0.2.1", TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("admission")]
    [InlineData("transition")]
    [InlineData("subscription")]
    [InlineData("register")]
    public async Task EveryWriterLocksFamilyBeforePolicyOrWrite(string entry)
    {
        var policy = Policy(); var db = new Database(policy);
        await Invoke(entry, db, policy);
        AssertFamilyFirst(db, BruteFamily);
        if (entry != "admission") return;
        var audit = Assert.Single(db.Calls, c => c.Sql.Contains("insert into access_audit_v4"));
        Assert.Equal("semantic_policy_admission", audit.Values[2]);
        Assert.Equal(policy["policy_id"]!.GetValue<string>() + ":1", audit.Values[3]);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"enabled":false,"actor":"owner","reason":"fixture decision"}"""), Assert.IsType<JsonObject>(audit.Values[5])));
        Assert.Equal(1, db.Commits);
    }

    public static TheoryData<string, string> IdentityChanges => new(
        from entry in new[] { "admission", "transition", "subscription" }
        from change in new[] { "family", "body", "stored_hash", "source_kind", "version" }
        select (entry, change));

    [Theory]
    [MemberData(nameof(IdentityChanges))]
    public async Task ChangedIdentityAbortsWithoutUpgradeWriteOrAudit(string entry, string change)
    {
        var policy = Policy(); var db = new Database(policy) { OnFamily = d => Mutate(d, change) };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke(entry, db, policy));
        Assert.Equal("password_policy_identity_changed", error.Message);
        Assert.Equal(BruteFamily, Assert.Single(Families(db)).Values[0]);
        Assert.DoesNotContain(db.Calls, c => IsWrite(c.Sql)); Assert.Equal(0, db.Commits);
    }

    [Fact]
    public async Task InvalidStoredPasswordHashDeniesBeforeFamilyPolicyLockOrWrite()
    {
        var policy = Policy(); var db = new Database(policy); db.Stored["definition_sha256"] = "77726f6e67";
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Admit(db, policy));
        Assert.Equal("password_policy_definition_invalid", error.Message);
        Assert.Empty(Families(db)); Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("for update") || IsWrite(c.Sql));
        Assert.Equal(0, db.Commits);
    }

    [Fact]
    public async Task FreshLifecycleIsUsedWithoutTreatingItAsIdentityChange()
    {
        var policy = Policy(); var db = new Database(policy) { OnFamily = d => d.Stored["lifecycle_status"] = "disabled" };
        await Admit(db, policy);
        AssertFamilyFirst(db, BruteFamily); Assert.Equal(1, db.Commits);
    }

    [Fact]
    public async Task ValidCustomV2MetadataKeepsReferenceAdmissionBehavior()
    {
        var policy = Policy(); policy["policy_id"] = "custom-v2";
        policy["definition_json"]!["title"] = "Owner policy title";
        policy["definition_sha256"] = SemanticJson.Hash(policy["definition_json"]);
        var db = new Database(policy); await Admit(db, policy);
        AssertFamilyFirst(db, BruteFamily); Assert.Equal(1, db.Commits);
    }

    [Fact]
    public async Task RegistrationCollisionNeverLocksStoredOtherFamily()
    {
        var incoming = Policy(); var other = Policy("spray", "other"); other["policy_id"] = incoming["policy_id"]!.DeepClone();
        var db = new Database(other);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke("register", db, incoming));
        Assert.Equal("semantic risk policy version replay conflict", error.Message);
        Assert.Equal(BruteFamily, Assert.Single(Families(db)).Values[0]);
        Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("for update"));
        Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("insert into semantic_risk_policy_subscriptions"));
    }

    [Fact]
    public async Task BatchEnumeratesOnceAndLocksSortedUniqueFamiliesIncludingLegacyV1()
    {
        var brute = Policy(); var spray = Policy("spray"); var legacy = Legacy();
        int iterations = 0;
        IEnumerable<JsonObject> Policies()
        {
            Assert.Equal(0, iterations);
            foreach (var policy in new[] { spray, brute, legacy, brute }) { iterations++; yield return policy; }
        }
        var db = new Database(brute);
        var keys = await PasswordPolicyLock.LockFamiliesAsync(db, Policies(), TestContext.Current.CancellationToken);
        Assert.Equal(new[] { BruteFamily, SprayFamily }, keys); Assert.Equal(4, iterations);
        Assert.Equal(new[] { BruteFamily, SprayFamily }, Families(db).Select(c => Assert.IsType<string>(Assert.Single(c.Values))));
        Assert.All(db.Calls, c => Assert.Equal("select pg_advisory_xact_lock(hashtextextended($1,0))", c.Sql));
    }

    [Fact]
    public async Task BatchValidatesEveryPolicyBeforeTakingAnyLock()
    {
        var invalid = Policy(); invalid["definition_json"]!["source_selector"]!["execution"]!["scope"]!["source_generation"] = 123;
        invalid["definition_sha256"] = SemanticJson.Hash(invalid["definition_json"]);
        var db = new Database(Policy());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => PasswordPolicyLock.LockFamiliesAsync(db, [Policy("spray"), invalid], TestContext.Current.CancellationToken));
        Assert.Equal("password_policy_definition_invalid", error.Message); Assert.Empty(db.Calls);
    }

    [Fact]
    public async Task SubscriptionHashMismatchFailsBeforeLockingAnyOtherFamily()
    {
        var incoming = Policy(); var other = Policy(generation: "other"); other["policy_id"] = incoming["policy_id"]!.DeepClone();
        var db = new Database(other);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke("subscription", db, incoming));
        Assert.Equal("risk policy subscription definition hash mismatch", error.Message);
        Assert.Empty(Families(db)); Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("for update") || IsWrite(c.Sql));
    }

    [Theory]
    [InlineData("admission")]
    [InlineData("transition")]
    [InlineData("subscription")]
    [InlineData("register")]
    public async Task NonpasswordQwPolicyKeepsWriterBehaviorWithoutFamilyLock(string entry)
    {
        var policy = Legacy("qw.disabled-account-logon"); var db = new Database(policy);
        await Invoke(entry, db, policy);
        Assert.Empty(Families(db)); Assert.Contains(db.Calls, c => c.Sql.Contains("for update"));
        if (entry == "transition") Assert.Equal("disabled", db.Stored["lifecycle_status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("shadow", true)]
    [InlineData("draft", false)]
    public async Task SubscriptionReplacementIsMutableOnlyInDraft(string lifecycle, bool denied)
    {
        var policy = Policy(); policy["lifecycle_status"] = lifecycle; var db = new Database(policy) { Subscription = null };
        if (denied)
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Invoke("subscription", db, policy));
            Assert.Equal("risk policy subscription is mutable only in draft", error.Message);
            Assert.DoesNotContain(db.Calls, c => IsWrite(c.Sql));
        }
        else
        {
            await Invoke("subscription", db, policy);
            var write = Assert.Single(db.Calls, c => c.Sql.StartsWith("insert into semantic_risk_policy_subscriptions"));
            Assert.Equal(new object?[] { policy["policy_id"]!.GetValue<string>(), 1, "qw_signal", "qw.password-brute-force", Convert.FromHexString("cd5b09183f320c5d94538bfff9b4931a568ada98475378ba796470cd90dc2318") }, write.Values);
        }
        AssertFamilyFirst(db, BruteFamily);
    }

    [Fact]
    public async Task RegistrationCreatesDraftAndSubscriptionAndReplayIsIdempotent()
    {
        var policy = Policy(); var db = new Database(policy) { Missing = true, Subscription = null };
        await Invoke("register", db, policy);
        Assert.Equal("draft", db.Stored["lifecycle_status"]!.GetValue<string>());
        Assert.Equal("qw.password-brute-force", db.Subscription!["selector_value"]!.GetValue<string>());
        AssertFamilyFirst(db, BruteFamily);
        db.Calls.Clear(); await Invoke("register", db, policy);
        Assert.DoesNotContain(db.Calls, c => c.Sql.StartsWith("delete ") || c.Sql.StartsWith("insert into semantic_risk_policy_subscriptions"));
    }

    private static Task Invoke(string entry, Database db, JsonObject policy) => entry switch
    {
        "admission" => Admit(db, policy),
        "transition" => SemanticPolicyRepository.TransitionAsync(db, policy["policy_id"]!.GetValue<string>(), 1, "disabled", TestContext.Current.CancellationToken),
        "subscription" => SemanticPolicyRepository.ReplaceSubscriptionAsync(db, SemanticPolicy.Compile(policy), TestContext.Current.CancellationToken),
        _ => SemanticPolicyRepository.RegisterAsync(db, policy, TestContext.Current.CancellationToken)
    };

    private static JsonObject Legacy(string ruleId = "qw.password-brute-force")
    {
        var policy = Policy(); policy["policy_id"] = "custom-v1";
        var definition = policy["definition_json"]!.AsObject(); definition["merge_window_seconds"] = 300;
        definition["scenario_kind"] = ruleId;
        if (ruleId == "qw.disabled-account-logon") definition["title"] = "Sign-in attempted with a disabled account";
        var selector = definition["source_selector"]!.AsObject(); selector["rule_id"] = ruleId;
        selector["execution"] = new JsonObject { ["version"] = "sli.qw.execution.v1", ["kind"] = "threshold", ["rule_id"] = ruleId,
            ["rule_version"] = 1, ["rule_sha256"] = ruleId == "qw.password-brute-force" ? "b52404638ab78ed2b92d825378c9d9f362f62f6d9cf0f7baa7141531f190298d" : "609763e4f90dcf589c7eb006ae59bcb75ceef55178b36b136713ac04bf8104cd", ["scope"] = Scope.Document };
        policy["definition_sha256"] = SemanticJson.Hash(definition); return policy;
    }

    private static void Mutate(Database db, string change)
    {
        switch (change)
        {
            case "family": db.Stored = Policy(generation: "changed"); break;
            case "body": db.Stored["definition_json"]!["title"] = "Changed owner definition"; db.Stored["definition_sha256"] = SemanticJson.Hash(db.Stored["definition_json"]); break;
            case "stored_hash": db.Stored["definition_sha256"] = new string('a', 64); break;
            case "source_kind": db.Stored["source_kind"] = "canonical_action"; break;
            case "version": db.Stored["policy_version"] = 2; break;
        }
    }

    private static bool IsWrite(string sql) => sql.StartsWith("insert ") || sql.StartsWith("update ") || sql.StartsWith("delete ") || sql.StartsWith("with changed as(") || sql.StartsWith("with audit as(");
    private static IEnumerable<(string Sql, object?[] Values)> Families(Database db) => db.Calls.Where(c => c.Sql.Contains("pg_advisory_xact_lock"));
    private static void AssertFamilyFirst(Database db, string expected)
    {
        var locks = Families(db).ToArray(); Assert.NotEmpty(locks);
        Assert.All(locks, c => { Assert.Equal("select pg_advisory_xact_lock(hashtextextended($1,0))", c.Sql); Assert.Equal(expected, Assert.Single(c.Values)); });
        int firstLock = db.Calls.FindIndex(c => c.Sql.Contains("pg_advisory_xact_lock"));
        int barrier = db.Calls.FindIndex(c => c.Sql.Contains("for update") || IsWrite(c.Sql));
        Assert.True(firstLock < barrier);
    }

    private sealed class Database : ISemanticDatabase, ISemanticSession
    {
        internal JsonObject Stored; internal JsonObject? Subscription; internal Action<Database>? OnFamily;
        internal readonly List<(string Sql, object?[] Values)> Calls = [];
        internal int Commits; internal bool Missing;
        internal Database(JsonObject policy)
        {
            Stored = policy.DeepClone().AsObject();
            Subscription = new() { ["source_kind"] = policy["source_kind"]!.DeepClone(),
                ["selector_value"] = policy["definition_json"]!["source_selector"]!["rule_id"]!.DeepClone(),
                ["definition_sha256"] = policy["definition_sha256"]!.DeepClone() };
        }
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.True(write); return Task.FromResult<ISemanticSession>(this); }
        public Task CommitAsync(CancellationToken ct) { Commits++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            sql = string.Join(' ', sql.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)); Calls.Add((sql, values));
            if (sql.Contains("pg_advisory_xact_lock")) { var callback = OnFamily; OnFamily = null; callback?.Invoke(this); }
            else if (sql.StartsWith("select ") && sql.Contains("from semantic_risk_policies")) return Task.FromResult(Missing ? new JsonArray() : new JsonArray(Stored.DeepClone()));
            else if (sql.StartsWith("select ") && sql.Contains("from semantic_risk_policy_subscriptions")) return Task.FromResult(Subscription is null ? new JsonArray() : new JsonArray(Subscription.DeepClone()));
            else if (sql.StartsWith("update semantic_risk_policies")) { Stored["lifecycle_status"] = (string)values[0]!; return Task.FromResult(new JsonArray(new JsonObject { ["lifecycle_status"] = (string)values[0]! })); }
            else if (sql.StartsWith("insert into semantic_risk_policies") && Missing)
            {
                Stored = new() { ["policy_id"] = (string)values[0]!, ["policy_version"] = (int)values[1]!, ["source_kind"] = (string)values[2]!,
                    ["definition_json"] = ((JsonObject)values[3]!).DeepClone(), ["definition_sha256"] = Convert.ToHexStringLower((byte[])values[4]!), ["lifecycle_status"] = "draft" };
                Missing = false;
            }
            else if (sql.StartsWith("delete from semantic_risk_policy_subscriptions")) Subscription = null;
            else if (sql.StartsWith("insert into semantic_risk_policy_subscriptions")) Subscription = new() { ["source_kind"] = (string)values[2]!, ["selector_value"] = (string)values[3]!, ["definition_sha256"] = Convert.ToHexStringLower((byte[])values[4]!) };
            return Task.FromResult(new JsonArray());
        }
    }
}
