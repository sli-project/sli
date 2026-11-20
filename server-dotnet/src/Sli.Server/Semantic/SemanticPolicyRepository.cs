using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

// Ordinary policy writers share the same family-before-row order as governance.
// The caller owns commit/rollback, including registration plus its subscription.
internal static class SemanticPolicyRepository
{
    internal static async Task RegisterAsync(ISemanticSession session, JsonObject policy, CancellationToken ct)
    {
        var compiled = SemanticPolicy.Compile(policy);
        await PasswordPolicyLock.LockFamiliesAsync(session, [policy], ct);
        await session.QueryAsync("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values($1,$2,$3,'draft',$4,$5) on conflict(policy_id,policy_version) do nothing", ct,
            compiled.Id, compiled.Version, compiled.Source, compiled.Definition, Convert.FromHexString(compiled.Sha));
        var stored = (await session.QueryAsync("select source_kind,definition_json,encode(definition_sha256,'hex') as definition_sha256 from semantic_risk_policies where policy_id=$1 and policy_version=$2", ct, compiled.Id, compiled.Version)).FirstOrDefault();
        if (stored is null || stored.Text("source_kind") != compiled.Source || stored.Text("definition_sha256") != compiled.Sha || !JsonNode.DeepEquals(stored["definition_json"], compiled.Definition))
            throw new InvalidOperationException("semantic risk policy version replay conflict");
        await ReplaceSubscriptionAsync(session, compiled, ct);
    }

    internal static async Task ReplaceSubscriptionAsync(ISemanticSession session, SemanticPolicy policy, CancellationToken ct)
    {
        var parent = await PasswordPolicyLock.LockRowAsync(session, policy.Id, policy.Version, ct, policy);
        if (parent?.Text("definition_sha256") != policy.Sha) throw new InvalidOperationException("risk policy subscription definition hash mismatch");
        var stored = (await session.QueryAsync("select source_kind,selector_value,encode(definition_sha256,'hex') as definition_sha256 from semantic_risk_policy_subscriptions where policy_id=$1 and policy_version=$2", ct, policy.Id, policy.Version)).FirstOrDefault();
        if (stored is not null && stored.Text("source_kind") == policy.Source && stored.Text("selector_value") == policy.Selector && stored.Text("definition_sha256") == policy.Sha) return;
        if (parent.Text("lifecycle_status") != "draft") throw new InvalidOperationException("risk policy subscription is mutable only in draft");
        await session.QueryAsync("delete from semantic_risk_policy_subscriptions where policy_id=$1 and policy_version=$2", ct, policy.Id, policy.Version);
        await session.QueryAsync("insert into semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256) values($1,$2,$3,$4,$5)", ct,
            policy.Id, policy.Version, policy.Source, policy.Selector, Convert.FromHexString(policy.Sha));
    }

    internal static async Task<string> TransitionAsync(ISemanticSession session, string policy, int version, string target, CancellationToken ct)
    {
        string[] statuses = ["draft", "validated", "test", "shadow", "enabled", "disabled", "deprecated"];
        if (!statuses.Contains(target)) throw new ArgumentException("unsupported risk policy lifecycle status");
        var row = await PasswordPolicyLock.LockRowAsync(session, policy, version, ct) ?? throw new KeyNotFoundException("semantic risk policy version not found");
        string current = row.Text("lifecycle_status")!;
        if (current == target) return current;
        string[] allowed = current switch
        {
            "draft" => ["validated", "disabled"], "validated" => ["draft", "test", "disabled"], "test" => ["draft", "shadow", "disabled"],
            "shadow" => ["enabled", "disabled", "deprecated"], "enabled" => ["disabled", "deprecated"], "disabled" => ["draft", "deprecated"], _ => []
        };
        if (!allowed.Contains(target)) throw new ArgumentException($"invalid risk policy transition: {current} -> {target}");
        var changed = await session.QueryAsync("update semantic_risk_policies set lifecycle_status=$1,updated_at=now() where policy_id=$2 and policy_version=$3 and lifecycle_status=$4 returning lifecycle_status", ct, target, policy, version, current);
        if (changed.Count == 0) throw new InvalidOperationException("semantic risk policy lifecycle changed concurrently");
        return target;
    }
}
