using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

// Callers own the transaction. A changed identity requires rollback and whole-writer retry.
internal static class PasswordPolicyLock
{
    private static bool PasswordRuleId(string? value) => value is "qw.password-brute-force" or "qw.password-spray";
    private static string? Family(JsonObject policy)
    {
        if (policy.Text("source_kind") != "qw_signal" || policy["definition_json"] is not JsonObject definition ||
            definition["source_selector"] is not JsonObject selector) return null;
        var execution = selector["execution"] as JsonObject;
        string? Text(JsonObject? node, string key) => node?[key] is JsonValue v && v.TryGetValue<string>(out var text) ? text : null;
        string? outer = Text(selector, "rule_id"), inner = Text(execution, "rule_id");
        if (!PasswordRuleId(outer) && !PasswordRuleId(inner)) return null;
        try
        {
            if (SemanticJson.Hash(definition) != policy.Text("definition_sha256")) throw new InvalidDataException();
            _ = SemanticPolicy.Compile(policy);
            if (!PasswordRuleId(outer) || outer != inner || execution is null || execution.Count != 6 ||
                execution["version"]?.GetValue<string>() != "sli.qw.execution.v1" ||
                execution["kind"]?.GetValue<string>() is not ("threshold" or "ransom" or "decoy" or "watch") ||
                execution["rule_version"] is not JsonValue version || !version.TryGetValue<int>(out int revision) || revision < 1 ||
                execution["rule_sha256"] is not JsonValue hash || !hash.TryGetValue<string>(out var sha) || !PasswordJson.Hex(sha) ||
                execution["scope"] is not JsonObject scope || scope.Count != 5) throw new InvalidDataException();
            foreach (var (key, minimum, maximum) in new[] { ("installation_id", 36, 36), ("plugin_id", 1, 128), ("source_instance_id", 1, 256), ("source_generation", 1, 512), ("collection_scope_id", 0, 256) })
            {
                if (scope[key] is not JsonValue value || !value.TryGetValue<string>(out var text) ||
                    PasswordJson.Trim(text) != text || text.EnumerateRunes().Count() < minimum || text.EnumerateRunes().Count() > maximum) throw new InvalidDataException();
            }
            string installation = scope.Text("installation_id")!;
            if (!Guid.TryParseExact(installation, "D", out var id) || id.ToString("D") != installation) throw new InvalidDataException();
            if (revision >= 2)
            {
                var rule = new PasswordRule(PasswordScope.Read(scope), outer == "qw.password-spray" ? "spray" : "brute", revision);
                if (!JsonNode.DeepEquals(execution, rule.Execution)) throw new InvalidDataException();
            }
            return "sli.password.policy-family.1:" + PasswordJson.Hash(scope) + ":" + outer;
        }
        catch (Exception error) when (error is InvalidDataException or InvalidOperationException or ArgumentException or FormatException or NullReferenceException or KeyNotFoundException or PasswordFailure or SemanticInputException)
        {
            throw new InvalidOperationException("password_policy_definition_invalid");
        }
    }

    internal static async Task<string[]> LockFamiliesAsync(ISemanticSession session, IEnumerable<JsonObject> policies, CancellationToken ct)
    {
        // Materialize once and validate the COMPLETE set before acquiring its first lock.
        var materialized = policies.ToArray();
        var keys = materialized.Select(Family).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        foreach (string key in keys) await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, key);
        return keys;
    }

    private static JsonObject Identity(JsonObject? row)
    {
        var identity = new JsonObject();
        foreach (string key in new[] { "policy_id", "policy_version", "source_kind", "definition_json", "definition_sha256" }) identity[key] = row?[key].Copy();
        return identity;
    }

    internal static async Task<JsonObject?> LockRowAsync(ISemanticSession session, string policy, int version, CancellationToken ct, SemanticPolicy? expected = null)
    {
        const string sql = "select policy_id,policy_version,source_kind,definition_json,encode(definition_sha256,'hex') as definition_sha256,lifecycle_status from semantic_risk_policies where policy_id=$1 and policy_version=$2";
        var snapshot = (await session.QueryAsync(sql, ct, policy, version)).FirstOrDefault()?.AsObject();
        if (snapshot is null) return null;
        var identity = Identity(snapshot);
        if (expected is not null && (snapshot.Text("source_kind") != expected.Source || snapshot.Text("definition_sha256") != expected.Sha))
            throw new InvalidOperationException("risk policy subscription definition hash mismatch");
        string? family = Family(snapshot);
        if (family is not null) await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, family);
        var current = (await session.QueryAsync(sql + " for update", ct, policy, version)).FirstOrDefault()?.AsObject();
        if (!JsonNode.DeepEquals(identity, Identity(current)) || current is null || Family(current) != family)
            throw new InvalidOperationException("password_policy_identity_changed");
        return current;
    }
}
