using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Auth;

namespace Sli.Server.Problems;

public sealed class ProblemException(string code, int status = 400, string? message = null) : Exception(message ?? code)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
}

// Resolve categories within each grant, before unioning scopes. Never multiply
// fields from one grant by resources from another grant.
public sealed class ProblemScope(bool all, IReadOnlyList<JsonElement> clauses)
{
    public bool All { get; } = all;
    public IReadOnlyList<JsonElement> Clauses { get; } = clauses;
    internal static readonly string[] Dimensions = ["plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids"];
    public bool Allows(AccessResource resource) => All || Clauses.Any(c => Dimensions.All(d =>
    {
        var values = c.Get(d).Items().ToArray();
        if (values.Length == 0) return true;
        if (d == "entity_ids") return resource.EntityId.HasValue && values.Any(v => v.GetInt64() == resource.EntityId);
        string? target = d switch { "plugin_ids" => resource.PluginId, "source_instance_ids" => resource.SourceInstanceId,
            "device_ids" => resource.DeviceId, _ => resource.CollectionScopeId };
        return values.Any(v => v.GetString() == target);
    }));
    public bool Covers(ProblemScope other) => All || !other.All && other.Clauses.All(target => Clauses.Any(own =>
        Dimensions.All(d => !own.Get(d).Items().Any() || target.Get(d).Items().Any() &&
            target.Get(d).Items().All(v => own.Get(d).Items().Any(x => x.GetRawText() == v.GetRawText())))));
    public long[]? Domains()
    {
        if (All) return null;
        var ids = new HashSet<long>();
        foreach (var clause in Clauses)
        {
            if (Dimensions.Take(4).Any(d => clause.Get(d).Items().Any())) throw new ProblemException("report_scope_not_executable", 403);
            foreach (var v in clause.Get("collection_scope_ids").Items())
            {
                string s = v.GetString()!;
                if (!Regex.IsMatch(s, @"\Aad-domain:[1-9][0-9]*\z") || !long.TryParse(s.AsSpan(10), out long id))
                    throw new ProblemException("report_scope_not_executable", 403);
                ids.Add(id);
            }
        }
        if (ids.Count == 0) throw new ProblemException("report_scope_not_executable", 403);
        return ids.Order().ToArray();
    }
    internal string Predicate(Dictionary<string, object?> parameters, bool watch)
    {
        if (All) return "true";
        var clauses = new List<string>();
        foreach (var clause in Clauses)
        {
            var terms = new List<string>();
            foreach (string dimension in Dimensions)
            {
                var values = clause.Get(dimension).Items().ToArray();
                if (values.Length == 0) continue;
                if (watch && dimension is "source_instance_ids" or "device_ids") throw new ProblemException("report_scope_not_executable", 403);
                string column = dimension switch { "plugin_ids" => "plugin_id", "source_instance_ids" => "source_instance_id",
                    "device_ids" => "device_id", "entity_ids" => "entity_id", _ => "collection_scope_id" };
                string name = "scope" + parameters.Count;
                parameters[name] = dimension == "entity_ids" ? values.Select(v => v.GetInt64()).ToArray() : values.Select(v => v.GetString()!).ToArray();
                terms.Add(column + "=any(@" + name + ")");
            }
            clauses.Add("(" + string.Join(" and ", terms) + ")");
        }
        return clauses.Count == 0 ? "false" : "(" + string.Join(" or ", clauses) + ")";
    }
}

public sealed class ProblemAccess(AccessDecision decision, string fieldAction = "view")
{
    public AccessDecision Decision { get; } = decision;
    public static string[] Required(string report) => report switch {
        "watch.registry" => ["identity_basic", "security"], "decoys.registry" => ["identity_basic", "security", "technical"], _ => ["security"] };
    public ProblemScope Scope(string report, string action = "view", params string[] extra)
    {
        var entry = Decision.Reports.FirstOrDefault(r => r.ReportKey == report && r.Allowed);
        if (entry is null || !entry.Grants.Any(g => g.AllowedActions.Contains(action))) throw new ProblemException("report_access_denied", 403);
        var fields = Required(report).Concat(extra).ToHashSet();
        var eligible = entry.Grants.Where(g => g.AllowedActions.Contains(action) && fields.IsSubsetOf(g.FieldCategories)).ToArray();
        if (eligible.Length == 0) throw new ProblemException("report_field_categories_not_allowed", 403);
        var scopes = eligible.Select(g => ReportScopeResolver.ParseScope(g.Scope)).Where(s => !s.Invalid).ToArray();
        if (scopes.Any(s => s.All)) return new(true, []);
        var allClauses = scopes.SelectMany(s => s.Clauses).ToArray();
        var pure = allClauses.Where(c => !ProblemScope.Dimensions.Take(4).Any(d => c.Get(d).Items().Any()))
            .SelectMany(c => c.Get("collection_scope_ids").Items()).Select(v => v.GetString()!).Distinct().Order().ToArray();
        var clauses = allClauses.Where(c => ProblemScope.Dimensions.Take(4).Any(d => c.Get(d).Items().Any())).ToList();
        if (pure.Length > 0) clauses.Add(JsonSerializer.SerializeToElement(new { collection_scope_ids = pure }));
        if (clauses.Count == 0 || clauses.Count > 100 || pure.Length > 100) throw new ProblemException("report_scope_not_executable", 403);
        return new(false, clauses);
    }
    public bool Fields(params string[] extra)
    {
        try { return Scope("security.queue", fieldAction, extra).Covers(Scope("security.queue", fieldAction)); }
        catch (ProblemException) { return false; }
    }
    public void Capability(string key)
    {
        var result = Decision.Capabilities.Decide(key);
        if (!result.Allowed) throw new ProblemException(result.Reason, 403);
    }
    public void Registry(string registry, JsonObject? identity = null, bool manage = false, Principal? principal = null, string? kind = null)
    {
        bool watch = registry == "watch.registry";
        var scope = Scope(registry, manage ? watch ? "manage_watch" : "manage_decoy" : "view");
        var target = identity is null ? null : Resource(identity, watch ? "account" : kind!);
        if (target is not null && (!scope.Allows(target) || watch && !Decision.Capabilities.DecideForResourceGroups("objects.view", [[target]]).Allowed))
            throw new ProblemException(watch ? "watch_access_denied" : "decoy_access_denied", 403);
        if (manage && (principal is null || principal.Id <= 0 || principal.Type is not ("session" or "api_key") ||
                (watch ? principal.Role is not ("operator" or "admin") : principal.Role != "admin") ||
                !Decision.Capabilities.DecideForResourceGroups(watch ? "watch.manage" : "decoys.manage", target is null ? [] : [[target]]).Allowed))
            throw new ProblemException(watch ? "watch_access_denied" : "decoy_access_denied", 403);
    }
    public bool CanManage(string registry, JsonObject? identity, Principal principal, string? kind = null)
    {
        try { Registry(registry, identity, true, principal, kind); return true; } catch (ProblemException) { return false; }
    }
    public static AccessResource Resource(JsonObject identity, string kind) => kind == "account"
        ? new("domain", ProblemJson.Long(identity["domain_id"])) { DomainId = ProblemJson.Long(identity["domain_id"]), PluginId = "sli.ad",
            EntityId = ProblemJson.Long(identity["entity_id"]), CollectionScopeId = "ad-domain:" + ProblemJson.Long(identity["domain_id"]) }
        : new("file") { PluginId = "sli.file-audit", DeviceId = ProblemJson.Text(identity["agent_id"]),
            SourceInstanceId = ProblemJson.Text(identity["source_instance_id"]), CollectionScopeId = ProblemJson.Text(identity["collection_scope_id"]) };
}
