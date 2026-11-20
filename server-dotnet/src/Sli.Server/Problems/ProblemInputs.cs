using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Agents.Ingress;
using Sli.Server.Investigations;

namespace Sli.Server.Problems;

internal static class ProblemJson
{
    internal const long SafeInteger = 9007199254740992;
    public static string Text(JsonNode? value) => value is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
    public static long Long(JsonNode? value) => Integer(value, out var n) ? n : 0;
    private static bool Integer(JsonNode? value, out long number)
    {
        number = 0;
        return value is JsonValue v && v.GetValueKind() == JsonValueKind.Number &&
            long.TryParse(v.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number);
    }
    public static bool Bool(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    public static JsonObject Object(JsonNode? value) => value as JsonObject ?? new();
    public static JsonArray Array(JsonNode? value) => value as JsonArray ?? new();
    public static JsonObject Pick(JsonObject value, params string[] fields) => new(fields.Where(value.ContainsKey).Select(k => KeyValuePair.Create(k, value[k]?.DeepClone())));
    public static string Actor(Sli.Server.Auth.Principal p, bool risk = false) => !string.IsNullOrEmpty(p.Username) ? p.Username : !string.IsNullOrEmpty(p.Label) ? p.Label : risk ? p.Type : "";
    public static string Python(JsonNode? value)
    {
        if (value is null) return "";
        using var doc = JsonDocument.Parse(value.ToJsonString());
        return Auth.Lifecycle.AuthJsonBody.Truthy(doc.RootElement) ? InvestigationPythonString.String(doc.RootElement) : "";
    }
    public static string Clean(JsonNode? value, int length) => string.Concat(Python(value).Trim().EnumerateRunes().Take(length).Select(r => r.ToString()));
    public static string StrictText(JsonNode? value, int length, string code)
    {
        if (value is not JsonValue v || !v.TryGetValue<string>(out var s) || s.EnumerateRunes().Count() is < 1 || s.EnumerateRunes().Count() > length ||
            s.Trim() != s || s.Any(c => c < 32)) throw new ProblemException(code);
        return s;
    }
    public static long Id(JsonNode? value, string code, long maximum = long.MaxValue, bool zero = false)
    {
        // JSON booleans and integral floats are not Python ints.
        if (!Integer(value, out var n) || n < (zero ? 0 : 1) || n > maximum) throw new ProblemException(code);
        return n;
    }
    public static string Uuid(string? value, string code)
    {
        string raw = value ?? "";
        // Python UUID accepts hex, hyphens, braces and the urn prefix.
        raw = raw.Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "");
        if (raw.Length != 32 || !Guid.TryParseExact(raw, "N", out var id)) throw new ProblemException(code);
        return id.ToString();
    }
    public static bool Stamp(JsonNode? value, out DateTimeOffset stamp)
    {
        string s = Text(value);
        bool aware = Regex.IsMatch(s, @"[T ][0-9:.]+(?:Z|[+-][0-9]{2}(?::?[0-9]{2})?)\z", RegexOptions.CultureInvariant);
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out stamp) && aware;
    }
    public static string Iso(DateTimeOffset stamp) => stamp.ToUniversalTime().ToString(stamp.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
    public static void RawTimes(JsonObject row, params string[] keys)
    {
        foreach (string key in keys)
            if (Stamp(row[key], out var stamp)) row[key] = stamp.ToString(stamp.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd HH:mm:sszzz" : "yyyy-MM-dd HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
    }
    public static bool Fresh(JsonNode? stamp, DateTimeOffset now) => Stamp(stamp, out var time) && now >= time && now - time <= TimeSpan.FromDays(1);
}

public sealed record WatchInput(long EntityId, string Owner, string Reason, bool Active, long Revision, DateTimeOffset Expires, DateTimeOffset DecisionAt)
{
    public static WatchInput Parse(JsonObject body, DateTimeOffset now)
    {
        const string code = "watch_invalid";
        if (!body.Select(p => p.Key).ToHashSet().SetEquals(["entity_id", "owner", "reason", "expires_at", "active", "revision"]) ||
            body["active"] is not JsonValue a || !a.TryGetValue<bool>(out bool active)) throw new ProblemException(code);
        string expiry = ProblemJson.StrictText(body["expires_at"], 40, code);
        if (!ProblemJson.Stamp(JsonValue.Create(expiry), out var stamp) || active && stamp <= now) throw new ProblemException(code);
        return new(ProblemJson.Id(body["entity_id"], code, ProblemJson.SafeInteger - 1), ProblemJson.StrictText(body["owner"], 128, code),
            ProblemJson.StrictText(body["reason"], 500, code), active, ProblemJson.Id(body["revision"], code, ProblemJson.SafeInteger - 2, true), stamp, now);
    }
    public DateTimeOffset CheckPrevious(JsonObject? previous, string? id, JsonObject identity, DateTimeOffset now)
    {
        if (previous is not null && id is not null) id = ProblemJson.Uuid(id, "watch_invalid");
        if (previous is null ? id is not null || Revision != 0 || !Active :
            id is null || ProblemJson.Text(previous["id"]) != id || ProblemJson.Long(previous["revision"]) != Revision || !JsonNode.DeepEquals(previous["identity"], identity))
            throw new ProblemException("watch_revision_conflict", 409);
        return previous is not null && ProblemJson.Bool(previous["active"]) && ProblemJson.Stamp(previous["expires_at"], out var expires) && expires > now && Active &&
            ProblemJson.Stamp(previous["active_from"], out var start) ? start : now;
    }
}

public sealed record DecoyInput(string Kind, JsonObject Identity, string Owner, string Reason, bool Active, long Revision)
{
    public static DecoyInput Parse(JsonObject body)
    {
        const string code = "decoy_invalid";
        string kind = ProblemJson.Text(body["kind"]);
        if (!body.Select(p => p.Key).ToHashSet().SetEquals(["kind", "identity", "owner", "reason", "active", "revision"]) || kind is not ("account" or "file") ||
            body["identity"] is not JsonObject original || body["active"] is not JsonValue a || !a.TryGetValue<bool>(out bool active)) throw new ProblemException(code);
        var identity = original.DeepClone().AsObject();
        if (kind == "account")
        {
            if (!identity.Select(p => p.Key).ToHashSet().SetEquals(["domain_id", "entity_id", "sid", "guid"])) throw new ProblemException(code);
            ProblemJson.Id(identity["domain_id"], code, ProblemJson.SafeInteger - 1); ProblemJson.Id(identity["entity_id"], code, ProblemJson.SafeInteger - 1);
            if (!Regex.IsMatch(ProblemJson.StrictText(identity["sid"], 184, code), @"\AS-1-(?:[0-9]+-)*[0-9]+\z")) throw new ProblemException(code);
            identity["guid"] = ProblemJson.Uuid(ProblemJson.StrictText(identity["guid"], 36, code), code);
        }
        else
        {
            if (!identity.Select(p => p.Key).ToHashSet().SetEquals(["agent_id", "source_instance_id", "collection_scope_id", "path"])) throw new ProblemException(code);
            identity["agent_id"] = ProblemJson.Uuid(ProblemJson.StrictText(identity["agent_id"], 36, code), code);
            ProblemJson.StrictText(identity["source_instance_id"], 256, code); ProblemJson.StrictText(identity["collection_scope_id"], 256, code);
            try { identity["path"] = AgentFileAuditPolicy.NormalizePath(ProblemJson.Text(identity["path"])).ToLowerInvariant(); }
            catch (Exception e) when (e is Sli.Agent.Core.AgentException or ArgumentException) { throw new ProblemException(code); }
        }
        return new(kind, identity, ProblemJson.StrictText(body["owner"], 128, code), ProblemJson.StrictText(body["reason"], 500, code), active,
            ProblemJson.Id(body["revision"], code, ProblemJson.SafeInteger - 2, true));
    }
    public void CheckPrevious(JsonObject? previous, bool updating)
    {
        if (previous is null ? updating || Revision != 0 : ProblemJson.Long(previous["revision"]) != Revision)
            throw new ProblemException("decoy_revision_conflict", 409);
    }
}

public sealed record RegistryQuery(string? Id, string? Cursor, long? Revision, long? EntityId, bool Touches)
{
    public static RegistryQuery Parse(IQueryCollection query, bool watch)
    {
        string code = watch ? "watch_invalid" : "decoy_invalid";
        string? First(string key) => query.TryGetValue(key, out var value) ? value.FirstOrDefault() ?? "" : null;
        string? id = First("id"), cursor = First("cursor"), revision = First("revision"), entity = watch ? First("entity_id") : null;
        bool touches = !watch && query.ContainsKey("touches");
        if (touches) id = First("touches");
        if (id is not null && (watch || id.Length > 0 || touches)) id = ProblemJson.Uuid(id, code);
        else id = null;
        long? Positive(string? value)
        {
            if (value is null) return null;
            if (!Regex.IsMatch(value, @"\A[0-9]+\z") || !long.TryParse(value, out long number) || number <= 0 || number >= ProblemJson.SafeInteger) throw new ProblemException(code);
            return number;
        }
        long? rev = !watch ? Positive(revision) : null;
        if (touches)
        {
            if (rev is null || cursor is not null && !Regex.IsMatch(cursor, @"\A[0-9a-f]{64}\z")) throw new ProblemException(code);
        }
        else if (rev is not null && (id is null || cursor is not null)) throw new ProblemException(code);
        else if (id is not null) _ = Positive(cursor);
        else if (!string.IsNullOrEmpty(cursor)) cursor = ProblemJson.Uuid(cursor, code);
        else cursor = null;
        long? eid = null;
        if (entity is not null)
        {
            if (!Regex.IsMatch(entity, @"\A[0-9]+\z") || !long.TryParse(entity, out var number)) throw new ProblemException(code);
            eid = number; // exact identity resolver checks the positive safe integer bound
        }
        return new(id, cursor, rev, eid, touches);
    }
}

public sealed record FindingStatusInput(string Status, string? Note, bool AssigneeSupplied, string? Assignee, bool ReasonSupplied, string? Reason)
{
    public static readonly string[] Statuses = ["new", "active", "review", "confirmed", "false_positive", "closed", "repeated"];
    public static readonly IReadOnlyDictionary<string, string[]> Transitions = new Dictionary<string, string[]> {
        ["new"] = ["active", "review", "confirmed", "false_positive", "closed"], ["active"] = ["review", "confirmed", "false_positive", "closed", "repeated"],
        ["review"] = ["active", "confirmed", "false_positive", "closed"], ["confirmed"] = ["active", "closed"], ["false_positive"] = ["active", "closed"],
        ["closed"] = ["active"], ["repeated"] = ["active", "review", "confirmed", "false_positive", "closed"] };
    public static FindingStatusInput Parse(JsonObject body, string actor)
    {
        if (actor.Trim().EnumerateRunes().Count() is < 1 or > 200) throw new ProblemException("actor_required", message: "Finding decisions require an actor");
        string status = ProblemJson.Python(body["status"]).Trim().ToLowerInvariant();
        if (!Statuses.Contains(status)) throw new ProblemException("invalid_status", message: "Unsupported finding status: " + (status.Length == 0 ? "<empty>" : status));
        string? Clean(JsonNode? value, int length) => ProblemJson.Clean(value, length) is { Length: > 0 } text ? text : null;
        string? note = Clean(body["note"], 2000);
        return new(status, note, body.ContainsKey("assigned_to"), Clean(body["assigned_to"], 300), body["status_reason"] is not null || note is not null,
            Clean(body["status_reason"] ?? JsonValue.Create(note), 2000));
    }
    public (bool Changed, string? Assignee, string? Reason, bool Audit) Apply(JsonObject current)
    {
        string old = ProblemJson.Text(current["status"]); if (old.Length == 0) old = "new";
        bool changed = old != Status;
        if (changed && (!Transitions.TryGetValue(old, out var targets) || !targets.Contains(Status)))
            throw new ProblemException("invalid_transition", 409, $"Finding status transition '{old}' -> '{Status}' is not allowed");
        if (changed && Status != "closed" && Note is null && Reason is null) throw new ProblemException("reason_required", message: "Finding transitions require a reason");
        string? assignee = AssigneeSupplied ? Assignee : current["assigned_to"]?.GetValue<string>();
        string? reason = ReasonSupplied ? Reason : current["status_reason"]?.GetValue<string>();
        bool reasonChanged = reason != current["status_reason"]?.GetValue<string>();
        if ((AssigneeSupplied || reasonChanged || Note is not null) && Note is null && Reason is null) throw new ProblemException("reason_required", message: "Finding decisions require a reason");
        return (changed, assignee, reason, changed || Note is not null || AssigneeSupplied || reasonChanged);
    }
}

public sealed record RiskInput(string Action, long? Id, string Actor, string? Reason, long? Responsible, DateTimeOffset? Expires)
{
    public static RiskInput Parse(JsonObject body, string actor, DateTimeOffset now)
    {
        string action = ProblemJson.Text(body["action"]);
        if (action is not ("create" or "revoke")) throw new ProblemException("invalid_action");
        long? id = action == "revoke" ? ProblemJson.Id(body["id"], "invalid_acceptance_id") : null;
        actor = actor.Trim(); if (actor.EnumerateRunes().Count() is < 1 or > 256) throw new ProblemException("actor_required");
        if (action == "revoke") return new(action, id, actor, null, null, null);
        if (body["reason"] is not JsonValue v || !v.TryGetValue<string>(out var reason) || reason.Trim().EnumerateRunes().Count() is < 1 or > 2000) throw new ProblemException("reason_required");
        long responsible = ProblemJson.Id(body["responsible_user_id"], "invalid_responsible");
        if (!ProblemJson.Stamp(body["expires_at"], out var expires) || expires <= now || expires > now.AddDays(90)) throw new ProblemException("invalid_expiry");
        return new(action, null, actor, reason.Trim(), responsible, expires);
    }
}

public sealed record FindingQuery(string? Status, string? Severity, string? Search, string? From, string? To, string? Risk, long? EntityId, long[]? Domains, int Limit, bool Suppressed)
{
    public long? FindingId { get; init; }
    public long? BeforeId { get; init; }
    public string? RuleCode { get; init; }
    public string? CreatedFrom { get; init; }
    public string? CreatedTo { get; init; }
    public string? Population { get; init; }
    public bool PageQueue { get; init; }
    public bool Compact { get; init; }
    public bool GroupQueue { get; init; }
    public string? Cohort { get; init; }
    public string Timezone { get; init; } = "UTC";
    public static FindingQuery Parse(IQueryCollection q, ProblemAccess access)
    {
        string? First(string key) => q.TryGetValue(key, out var v) ? v.FirstOrDefault() : null;
        var scope = access.Scope("security.queue");
        if ((q.ContainsKey("q") || q.ContainsKey("entity_id") || q.ContainsKey("cohort")) && !access.Fields("identity_basic")) throw new ProblemException("report_field_categories_not_allowed", 403);
        long[]? domains = scope.Domains();
        if (First("domain") is { } d)
        {
            if (!long.TryParse(d, out var domain)) throw new ProblemException("report_request_invalid");
            if (domains is not null && !domains.Contains(domain)) throw new ProblemException("report_scope_not_executable", 403);
            if (domain <= 0) throw new ProblemException("report_request_invalid");
            domains = [domain];
        }
        if (!int.TryParse(First("limit") ?? "200", out int limit)) throw new ProblemException("report_request_invalid");
        long? entity = null;
        if (First("entity_id") is { } e) { if (!long.TryParse(e, out long id) || id <= 0) throw new ProblemException("invalid_entity_id"); entity = id; }
        foreach (string bound in new[] { "time_from", "time_to" })
            if (First(bound) is { Length: > 0 } value && !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _)) throw new ProblemException("report_request_invalid");
        return new(First("status"), First("severity"), First("q"), First("time_from"), First("time_to"), First("risk"), entity, domains,
            Math.Clamp(limit == 0 ? 50 : limit, 1, 200), q["show_suppressed"].Count == 1 && First("show_suppressed") == "true");
    }
}
