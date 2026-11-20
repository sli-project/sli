using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Semantic;

public sealed class SemanticGovernance(ISemanticDatabase database)
{
    public async Task<JsonObject> ListAsync(CancellationToken ct)
    {
        await using var session = await database.OpenAsync(false, ct);
        return new JsonObject
        {
            ["policies"] = await session.QueryAsync("select policy_id,policy_version,lifecycle_status,definition_json->>'title' as title,created_at::text as version_created_at,semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='enabled' as enabled,exists(select 1 from semantic_policy_admission a where a.policy_id=p.policy_id and a.policy_version=p.policy_version) as managed from semantic_risk_policies p order by policy_id,policy_version limit 200", ct),
            ["suppressions"] = await session.QueryAsync("select id,semantic_type,domain_id,scope_kind,scope_value,reason,expires_at::text,created_by,case when state='active' and expires_at<=clock_timestamp() then 'expired' else state end as state from semantic_suppressions where kind='suppression' order by id desc limit 200", ct),
            ["audit"] = await session.QueryAsync("select action,target,actor,occurred_at::text from semantic_control_audit order by id desc limit 100", ct), ["limit"] = 200
        };
    }
    internal static string Required(JsonObject body, string name, int minimum, int maximum, string code)
    {
        string value = body[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s.Trim() : "";
        if (value.EnumerateRunes().Count() < minimum || value.EnumerateRunes().Count() > maximum) throw new SemanticInputException(code);
        return value;
    }
    private static string InputRequired(JsonObject body, string name, int minimum, int maximum, string code) =>
        Required(new JsonObject { [name] = AuthJsonBody.CredentialString(JsonSerializer.SerializeToElement(body), name) }, name, minimum, maximum, code);
    internal static JsonObject ValidateSuppression(JsonObject body, DateTimeOffset now)
    {
        string type = InputRequired(body, "semantic_type", 2, 160, "invalid_suppression"), reason = InputRequired(body, "reason", 1, 2000, "invalid_suppression"), scope = InputRequired(body, "scope_value", 1, 184, "invalid_suppression");
        if (!Regex.IsMatch(type, @"\A[a-z][a-z0-9_.-]{1,159}\z")) throw new SemanticInputException("invalid_suppression");
        long domain;
        var raw = body["domain_id"];
        if (raw is JsonValue d && d.TryGetValue<long>(out var number)) domain = number;
        else if (raw is JsonValue text && text.TryGetValue<string>(out var value) && long.TryParse(value, out number)) domain = number;
        else throw new SemanticInputException("invalid_suppression");
        if (domain < 1) throw new SemanticInputException("invalid_suppression");
        string expires = InputRequired(body, "expires_at", 1, 100, "invalid_suppression");
        if (!Regex.IsMatch(expires, @"(?:Z|[+-]\d{2}:?\d{2})$")) throw new SemanticInputException("invalid_suppression");
        var until = SemanticQuery.Time(expires, "UTC", "invalid_suppression");
        string? kind = InputString(body, "scope_kind");
        if (until <= now || until > now.AddDays(90) || !(kind == "subject_sid" && Regex.IsMatch(scope, @"\AS-1-(?:[0-9]+-)+[0-9]+\z") ||
            kind == "bucket" && new[] { "machine_account", "system_account", "known_gpo_refresh", "interactive_admin", "unknown" }.Contains(scope))) throw new SemanticInputException("invalid_suppression");
        return new JsonObject { ["semantic_type"] = type, ["domain_id"] = domain, ["scope_kind"] = kind, ["scope_value"] = scope, ["reason"] = reason, ["expires_at"] = SemanticJson.Stamp(until) };
    }
    public async Task<JsonObject> ChangeAsync(JsonObject body, Principal principal, string address, CancellationToken ct)
    {
        string action = InputString(body, "action") ?? "";
        if (action is not ("create_suppression" or "revoke_suppression" or "policy_admission")) throw new SemanticInputException("invalid_semantic_control_action");
        var rule = action == "create_suppression" ? ValidateSuppression(body, DateTimeOffset.UtcNow) : null;
        string actor = principal.Username?.Trim() ?? ""; if (actor.EnumerateRunes().Count() is < 1 or > 256) throw new SemanticInputException("actor_required");
        string reason = action == "create_suppression" ? rule!.Text("reason")! : InputRequired(body, "reason", 1, 2000, "reason_required");
        long id = 0; int version = 0; bool enabled = false; string policy = "";
        if (action == "revoke_suppression" && (body["id"] is not JsonValue n || !n.TryGetValue<long>(out id) || id < 1)) throw new SemanticInputException("invalid_suppression");
        if (action == "policy_admission")
        {
            if (body["policy_version"] is not JsonValue versionNode || !versionNode.TryGetValue<int>(out version) || version < 1 || body["enabled"] is not JsonValue b || !b.TryGetValue<bool>(out enabled)) throw new SemanticInputException("invalid_policy_admission");
            policy = InputString(body, "policy_id") ?? "";
        }
        await using var session = await database.OpenAsync(true, ct);
        await session.QueryAsync("select expire_semantic_suppressions_v160()", ct);
        string auditAction, target; JsonObject details;
        if (action == "create_suppression")
        {
            var rows = await session.QueryAsync("with changed as(insert into semantic_suppressions(semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by) values($1,$2,$3,$4,$5,$6,$7) returning id) select * from changed", ct,
                rule!.Text("semantic_type"), rule.Number("domain_id"), rule.Text("scope_kind"), rule.Text("scope_value"), reason, SemanticQuery.Time(rule.Text("expires_at")!, "UTC", "invalid_suppression"), actor);
            auditAction = "semantic_suppression_create"; target = rows[0].Number("id").ToString(CultureInfo.InvariantCulture); details = new() { ["reason"] = reason };
        }
        else if (action == "revoke_suppression")
        {
            var rows = await session.QueryAsync("with changed as(update semantic_suppressions set state='revoked',changed_by=$1 where id=$2 and kind='suppression' and state='active' and expires_at>clock_timestamp() returning id) select * from changed", ct, actor, id);
            if (rows.Count == 0) throw new SemanticInputException("suppression_not_active");
            auditAction = "semantic_suppression_revoke"; target = id.ToString(CultureInfo.InvariantCulture); details = new() { ["actor"] = actor, ["reason"] = reason };
        }
        else
        {
            var stored = await PasswordPolicyLock.LockRowAsync(session, policy, version, ct);
            if (stored is null) throw new SemanticInputException("policy_not_found");
            if (enabled && stored.Text("lifecycle_status") is not ("shadow" or "enabled")) throw new SemanticInputException("policy_not_ready");
            await session.QueryAsync("with changed as(insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) values($1,$2,$3,$4) on conflict(policy_id,policy_version) do update set enabled=excluded.enabled,updated_by=excluded.updated_by,updated_at=now() returning policy_id) select * from changed", ct, policy, version, enabled, actor);
            auditAction = "semantic_policy_admission"; target = policy + ":" + version; details = new() { ["enabled"] = enabled, ["actor"] = actor, ["reason"] = reason };
        }
        await session.QueryAsync("with audit as(insert into access_audit_v4(actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,details_json,remote_address) values($1,$2,$3,null,null,'semantic_control',$4,$5,'ok',$6,$7) returning id) select * from audit", ct,
            principal.Type.Length == 0 ? "local" : principal.Type, principal.Id == 0 ? null : principal.Id, auditAction, target, reason, details, address);
        await session.CommitAsync(ct); return new JsonObject { ["status"] = "ok" };
    }
    private static string? InputString(JsonObject body, string key) => body[key] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
    internal static (string Scenario, Guid Request, string Verdict, string Confidence, string Rationale, string Actor, string Role) ReviewInput(string scenario, JsonObject body, Principal principal)
    {
        string id = SemanticQuery.Uuid(scenario, "invalid_scenario_id");
        Guid request = body.Text("review_request_id") is { Length: > 0 } token ? Guid.Parse(SemanticQuery.Uuid(token, "invalid_review_request_id")) : Guid.NewGuid();
        string verdict = (body.Text("verdict") ?? "").Trim().ToLowerInvariant(), confidence = (body.Text("review_confidence") ?? "").Trim().ToLowerInvariant();
        if (!new[] { "confirmed_security", "false_positive", "benign_expected", "insufficient_evidence" }.Contains(verdict)) throw new SemanticInputException("invalid_review_verdict");
        if (confidence is not ("high" or "medium" or "low")) throw new SemanticInputException("invalid_review_confidence");
        string rationale = Required(body, "rationale", 5, 2000, "review_rationale_length"), actor = (principal.Username ?? principal.Label ?? (principal.Type.Length == 0 ? "local-operator" : principal.Type)).Trim();
        if (actor.EnumerateRunes().Count() is < 1 or > 160) throw new SemanticInputException("reviewed_by_required");
        if (principal.Role is not ("viewer" or "operator" or "admin")) throw new SemanticInputException("invalid_reviewer_role");
        return (id, request, verdict, confidence, rationale, actor, principal.Role);
    }
    public async Task<JsonObject> ReviewAsync(string scenario, JsonObject body, Principal principal, CancellationToken ct)
    {
        var input = ReviewInput(scenario, body, principal);
        await using var session = await database.OpenAsync(true, ct);
        await session.QueryAsync("select pg_advisory_xact_lock(hashtextextended($1,0))", ct, input.Scenario);
        const string columns = "review_id,review_request_id,scenario_id,supersedes_review_id,verdict,review_confidence,rationale,encode(scenario_snapshot_sha256,'hex') as scenario_snapshot_sha256,reviewed_by,reviewer_role,reviewed_at";
        var replay = (await session.QueryAsync("select " + columns + " from semantic_scenario_reviews where review_request_id=$1", ct, input.Request)).FirstOrDefault();
        if (replay is not null)
        {
            if (replay.Text("scenario_id") != input.Scenario || replay.Text("verdict") != input.Verdict || replay.Text("review_confidence") != input.Confidence || replay.Text("rationale") != input.Rationale || replay.Text("reviewed_by") != input.Actor || replay.Text("reviewer_role") != input.Role) throw new SemanticInputException("review_request_id_conflict");
            return new JsonObject { ["api_version"] = "v1", ["item"] = replay.Copy(), ["replayed"] = true };
        }
        // Same row lock as the reference review writer, through its bounded
        // capability: adlog_user must never gain direct scenario UPDATE rights.
        await session.QueryAsync("select public.lock_semantic_review_scenario_v308($1)", ct, Guid.Parse(input.Scenario));
        var snapshot = (await session.QueryAsync("select scenario_id,scenario_kind,result_class,scenario_status,partition_key,strict_keys_json,first_seen_utc,last_seen_utc,risk_class,display_score,hard_critical,confidence,confidence_score,coverage_status,step_count,evidence_count,contribution_count,updated_at from semantic_security_scenarios where scenario_id=$1", ct, Guid.Parse(input.Scenario))).FirstOrDefault()?.AsObject();
        if (snapshot is null) throw new SemanticInputException("semantic_scenario_not_found", 404);
        var previous = (await session.QueryAsync("select review_id from semantic_scenario_reviews where scenario_id=$1 order by reviewed_at desc,review_id desc limit 1", ct, Guid.Parse(input.Scenario))).FirstOrDefault();
        // psycopg datetime default=str uses a space separator in the snapshot hash.
        foreach (string key in new[] { "first_seen_utc", "last_seen_utc", "updated_at" })
            if (snapshot.Text(key) is { } stamp) snapshot[key] = DateTimeOffset.Parse(stamp, CultureInfo.InvariantCulture).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss" + (DateTimeOffset.Parse(stamp).Ticks % TimeSpan.TicksPerSecond == 0 ? "" : ".ffffff") + "zzz", CultureInfo.InvariantCulture);
        byte[] hash = Convert.FromHexString(SemanticJson.Hash(snapshot));
        var item = (await session.QueryAsync("with review as(insert into semantic_scenario_reviews(review_id,review_request_id,scenario_id,supersedes_review_id,verdict,review_confidence,rationale,scenario_snapshot_sha256,reviewed_by,reviewer_role) values($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10) returning *) select " + columns + " from review", ct,
            Guid.NewGuid(), input.Request, Guid.Parse(input.Scenario), previous.Text("review_id") is { } old ? Guid.Parse(old) : null, input.Verdict, input.Confidence, input.Rationale, hash, input.Actor, input.Role))[0];
        await session.CommitAsync(ct); return new JsonObject { ["api_version"] = "v1", ["item"] = item.Copy(), ["replayed"] = false };
    }
}
