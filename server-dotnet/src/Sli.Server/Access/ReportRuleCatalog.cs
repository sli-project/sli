using System.Collections.Frozen;
using System.Text.Json;

namespace Sli.Server.Access;

public sealed record ReportRule(string RegistryKey, string ReportKey, string Scope,
    IReadOnlySet<string> RequiredFields, IReadOnlySet<string> RequiredCapabilities,
    string? RequiredRole, bool GlobalScopeOnly)
{
    public string OwnerId { get; init; } = "sli.core";
    public bool GuardedContribution { get; init; }
    public bool AcceptsGenericScope { get; init; }
    // A declaration registration alone never authorizes the bundled callable.
    public bool DeclarationOnly { get; internal init; }
}
public interface IReportRuleCatalog { IReadOnlyList<ReportRule> Rules { get; } }

public interface IReportCatalogProvider
{
    ReportCatalogSnapshot Capture();
    ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured);
}

// Only this provider constructs snapshots. Every collection and field set is immutable.
public sealed class ReportCatalogSnapshot
{
    internal Guid CatalogId { get; }
    internal IReadOnlyDictionary<string, long> Revisions { get; }
    public IReadOnlyList<ReportRule> Rules { get; }
    public IReadOnlyDictionary<string, PluginGeneration> Generations { get; }
    public IReadOnlyDictionary<string, string> UnavailableOwners { get; }
    internal ReportCatalogSnapshot(IEnumerable<ReportRule> rules, IDictionary<string, PluginGeneration> generations,
        IDictionary<string, string> unavailable) : this(rules, generations, unavailable, Guid.Empty, new Dictionary<string, long>()) { }
    internal ReportCatalogSnapshot(IEnumerable<ReportRule> rules, IDictionary<string, PluginGeneration> generations,
        IDictionary<string, string> unavailable, Guid catalogId, IDictionary<string, long> revisions)
    {
        Rules = Array.AsReadOnly(rules.Select(r => r with {
            RequiredFields = r.RequiredFields.ToFrozenSet(StringComparer.Ordinal),
            RequiredCapabilities = r.RequiredCapabilities.ToFrozenSet(StringComparer.Ordinal)
        }).ToArray());
        Generations = generations.ToFrozenDictionary(StringComparer.Ordinal);
        UnavailableOwners = unavailable.ToFrozenDictionary(StringComparer.Ordinal);
        CatalogId = catalogId;
        Revisions = revisions.ToFrozenDictionary(StringComparer.Ordinal);
    }
    public bool SupportsGenericScope(string reportKey) => Rules.Any(r => r.ReportKey == reportKey && r.AcceptsGenericScope);
}

// Only static report declarations are embedded. No subject/facts/expected decisions enter runtime.
public sealed class ReportRuleCatalog : IReportRuleCatalog, IReportCatalogProvider
{
    private readonly IReadOnlyList<ReportRule> bundled;
    private readonly PluginGenerationReader generations;
    private readonly Guid catalogId = Guid.NewGuid();
    private readonly object sync = new();
    private readonly Dictionary<(string Owner, string? Generation), IReadOnlyList<ReportRule>?> contributions = [];
    private readonly Dictionary<string, long> revisions = new(StringComparer.Ordinal);
    private readonly HashSet<string> disabled = new(StringComparer.Ordinal);
    private static readonly string[] GuardedOwners = ["sli.ad", "sli.gpo", "sli.remote-access", "sli.file-audit"];
    public IReadOnlyList<ReportRule> Rules => Capture().Rules;
    public ReportRuleCatalog() : this(new PluginGenerationReader()) { }
    public ReportRuleCatalog(PluginGenerationReader generations)
    {
        this.generations = generations;
        using var stream = typeof(ReportRuleCatalog).Assembly.GetManifestResourceStream("Sli.Server.Access.frozen-report-rules.json")
            ?? throw new InvalidOperationException("Frozen report registry is missing.");
        using var document = JsonDocument.Parse(stream);
        if (document.RootElement.Text("source_commit") != "ddce909d0ddebe43a670e63c85df369e0bd16f17")
            throw new InvalidOperationException("Frozen report registry source mismatch.");
        var rules = new List<ReportRule>();
        foreach (var entry in document.RootElement.Get("registered_reports").Items())
        {
            var access = entry.Get("access");
            if (access.Text("kind") is not ("AccessRule" or "AccessRequirement"))
                throw new InvalidOperationException("Unrepresentable frozen report access declaration.");
            var role = access.Text("required_role");
            string key = entry.Text("key");
            string owner = Owner(key);
            rules.Add(new(key, access.Text("report_key"), access.Text("scope"),
                access.Get("required_fields").Strings().ToFrozenSet(StringComparer.Ordinal), access.Get("required_capabilities").Strings().ToFrozenSet(StringComparer.Ordinal),
                role.Length == 0 ? null : role,
                access.Get("global_scope_only").ValueKind == JsonValueKind.True)
            {
                OwnerId = owner,
                GuardedContribution = GuardedOwners.Contains(owner, StringComparer.Ordinal),
                AcceptsGenericScope = access.Text("kind") == "AccessRequirement"
                    || access.Text("scope") == "delegated" && access.Get("accepts_generic_scope").ValueKind == JsonValueKind.True
            });
        }
        if (rules.Count != 27 || rules.Count(r => r.Scope == "domain") != 6 || rules.Select(r => r.RegistryKey).Distinct().Count() != rules.Count)
            throw new InvalidOperationException("Frozen built-in report composition mismatch.");
        bundled = rules.AsReadOnly();
    }

    // Trusted compiled modules only, like CoreJobPluginCatalog.Add. Package metadata
    // is never code/access authority. A loader must validate a generation before
    // publishing its complete contribution here; an absent declaration is not an allow.
    // This access catalog does not admit an updated callable to the report dispatcher.
    public void Register(string owner, string? generation, IEnumerable<ReportRule>? declarations)
    {
        ValidateOwner(owner);
        if (generation is not null && !System.Text.RegularExpressions.Regex.IsMatch(generation, "\\A[a-f0-9]{64}\\z"))
            throw new ArgumentException("plugin_update_invalid_generation");
        lock (sync)
        {
            // Invalidate first: a malformed replacement must not preserve old authority.
            contributions[(owner, generation)] = null;
            revisions[owner] = checked(revisions.GetValueOrDefault(owner) + 1);
            if (declarations is null) return;
            var rules = declarations.ToArray();
            if (rules.Any(r => r is null || r.OwnerId != owner
                || !bundled.Any(b => b.OwnerId == owner && b.RegistryKey == r.RegistryKey)
                || string.IsNullOrWhiteSpace(r.ReportKey) || r.Scope is not ("domain" or "generic" or "delegated")
                || r.RequiredFields is null || r.RequiredCapabilities is null
                || r.RequiredFields.Any(string.IsNullOrWhiteSpace) || r.RequiredCapabilities.Any(string.IsNullOrWhiteSpace))
                || rules.Select(r => r.RegistryKey).Distinct(StringComparer.Ordinal).Count() != rules.Length)
                throw new InvalidOperationException("plugin_report_declaration_unrepresentable");
            contributions[(owner, generation)] = Array.AsReadOnly(rules.Select(r => r with {
                GuardedContribution = true,
                DeclarationOnly = true,
                RequiredFields = r.RequiredFields.ToFrozenSet(StringComparer.Ordinal),
                RequiredCapabilities = r.RequiredCapabilities.ToFrozenSet(StringComparer.Ordinal)
            }).ToArray());
        }
    }

    public void SetEnabled(string owner, bool enabled)
    {
        ValidateOwner(owner);
        lock (sync)
        {
            bool changed = enabled ? disabled.Remove(owner) : disabled.Add(owner);
            if (changed) revisions[owner] = checked(revisions.GetValueOrDefault(owner) + 1);
        }
    }

    private static void ValidateOwner(string owner)
    {
        if (!GuardedOwners.Contains(owner, StringComparer.Ordinal))
            throw new ArgumentException("plugin_report_owner_not_allowlisted");
    }

    public ReportCatalogSnapshot Capture()
    {
        var states = new Dictionary<string, PluginGeneration>(StringComparer.Ordinal);
        var unavailable = new Dictionary<string, string>(StringComparer.Ordinal);
        var capturedRevisions = new Dictionary<string, long>(StringComparer.Ordinal);
        var rules = bundled.Where(r => !r.GuardedContribution).ToList();
        foreach (var owner in GuardedOwners)
        {
            try
            {
                var before = generations.Read(owner);
                states[owner] = before;
                if (before.Fenced) { unavailable[owner] = "plugin_update_draining"; continue; }
                IReadOnlyList<ReportRule>? contribution;
                lock (sync)
                {
                    capturedRevisions[owner] = revisions.GetValueOrDefault(owner);
                    if (disabled.Contains(owner)) { unavailable[owner] = "plugin_disabled"; continue; }
                    if (!contributions.TryGetValue((owner, before.Generation), out contribution))
                    {
                        if (before.Generation is not null) { unavailable[owner] = "plugin_generation_unsupported"; continue; }
                        contribution = bundled.Where(r => r.OwnerId == owner).ToArray();
                    }
                    if (contribution is null) { unavailable[owner] = "plugin_report_declaration_unrepresentable"; continue; }
                }
                // Compiled declarations execute no plugin hook. Native callable admission
                // (the source's Linux flock) belongs to the future native contribution loader.
                if (generations.Read(owner) != before) unavailable[owner] = "plugin_version_changed";
                lock (sync)
                    if (revisions.GetValueOrDefault(owner) != capturedRevisions[owner]) unavailable[owner] = "plugin_version_changed";
                if (!unavailable.ContainsKey(owner)) rules.AddRange(contribution);
            }
            catch (Exception error) when (ReadFailure(error)) { unavailable[owner] = Error(error); }
        }
        // Keep former catalog slots on replacement (registry.py sli.ad/sli.gpo).
        var positions = bundled.Select((r, i) => (r.RegistryKey, i)).ToDictionary(p => p.RegistryKey, p => p.i);
        return new(rules.OrderBy(r => positions[r.RegistryKey]),
            states, unavailable, catalogId, capturedRevisions);
    }

    public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured)
    {
        if (captured.CatalogId != catalogId) throw new ArgumentException("plugin_catalog_snapshot_mismatch");
        var unavailable = captured.UnavailableOwners.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        foreach (var (owner, previous) in captured.Generations)
        {
            if (unavailable.ContainsKey(owner)) continue; // Never upgrade a captured denial after the facts read.
            try
            {
                var current = generations.Read(owner);
                if (current.Fenced) unavailable[owner] = "plugin_update_draining";
                else if (current != previous) unavailable[owner] = "plugin_version_changed";
                lock (sync)
                {
                    if (!unavailable.ContainsKey(owner) && disabled.Contains(owner)) unavailable[owner] = "plugin_disabled";
                    else if (!unavailable.ContainsKey(owner) && revisions.GetValueOrDefault(owner) != captured.Revisions.GetValueOrDefault(owner))
                        unavailable[owner] = "plugin_version_changed";
                }
            }
            catch (Exception error) when (ReadFailure(error)) { unavailable[owner] = Error(error); }
        }
        return new(captured.Rules.Where(r => !r.GuardedContribution || !unavailable.ContainsKey(r.OwnerId)),
            captured.Generations.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal), unavailable,
            catalogId, captured.Revisions.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal));
    }

    private static bool ReadFailure(Exception error) => error is IOException or UnauthorizedAccessException
        or JsonException or InvalidOperationException;
    private static string Error(Exception error) => error is InvalidOperationException
        && error.Message is "plugin_update_draining" or "plugin_version_changed" or "plugin_update_invalid_generation"
            ? error.Message : "plugin_catalog_unavailable";

    // Reviewed ownership, not access authority. Source frozen at ddce909:
    // each package's config/plugin_packages/v3 manifest + registration.py reports hook;
    // reporting/v2/registry.py100–105 deliberately adds workstation reports outside that hook guard.
    private static string Owner(string key) => key switch
    {
        "ad.infrastructure" or "ad.computer-logons" or "ad.computers.v6" or "ad.new-logon-pairs" or "ad.users.v2" => "sli.ad",
        "ad.gpo.v2" => "sli.gpo",
        "vpn.accounts" or "vpn.connections" => "sli.remote-access",
        "file-audit.overview" or "file-audit.actions" or "file-audit.mass-operations" or "file-audit.permission-changes"
            or "file-audit.access-denials" or "file-audit.out-of-hours" or "file-audit.permissions" or "file-audit.audit-state" => "sli.file-audit",
        "workstations.logons" or "workstations.processes" or "workstations.usb" or "workstations.protection" or "workstations.overview" => "sli.workstations",
        "events.journal" or "notifications.channels" or "notifications.deliveries" or "security.rule-quality"
            or "security.events.chains" or "security.problems" => "sli.core",
        _ => throw new InvalidOperationException("Unreviewed bundled report owner.")
    };
}
