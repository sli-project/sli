using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.InstallationSetup;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

// Vectors from tests/reporting/test_navigation_registry.py; no database or plugin execution.
public sealed class NavigationRegistryTests
{
    private static readonly string[] DefaultGrants = ["ad.state", "ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.gpo.v2", "vpn.audit", "security.queue"];
    private static readonly string[] DefaultCapabilities = ["problem.view", "entity.view"];
    private static readonly IReportCatalogProvider Provider = new ReportRuleCatalog(new PluginGenerationReader(null));
    private static IReadOnlyList<ReportRule> Rules => Provider.Capture().Rules;
    private static JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
    private static JsonObject O(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    private static AccessReadEvaluation Access(string[]? grants = null, string[]? capabilities = null, bool allowed = true)
    {
        var caps = new CapabilityDecisionSet(false, (capabilities ?? DefaultCapabilities).ToHashSet(StringComparer.Ordinal), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var reports = (grants ?? DefaultGrants).Select(key => new ReportDecision(key, allowed, [])).ToArray();
        return new(new(false, "viewer", [], [], [], [], [], [], []), caps, new("viewer", caps, reports));
    }
    private static JsonElement[] States(string? disabled = null) => NavigationRegistry.PluginSections.Keys
        .Select(id => J(new { plugin_id = id, enabled = id != disabled })).ToArray();
    private static JsonObject Catalog(AccessReadEvaluation? access = null, string? disabled = null) => O(WorkspaceReportCatalog.Compose(access ?? Access(), Rules, States(disabled)));
    private static JsonObject Nav(AccessReadEvaluation? access = null, string? disabled = null) => Catalog(access, disabled)["navigation"]!.AsObject();
    private static JsonNode[] Entries(JsonNode nav) => nav["sections"]!.AsArray().SelectMany(s => s!["groups"]!.AsArray())
        .SelectMany(g => g!["entries"]!.AsArray()).Select(e => e!).ToArray();
    private static string S(JsonNode? n) => n!.GetValue<string>();
    private static string[] Ids(JsonNode nav) => Entries(nav).Select(e => S(e["id"])).ToArray();
    private static JsonNode Entry(JsonNode nav, string id) => Entries(nav).Single(e => S(e["id"]) == id);
    private static (JsonObject Config, JsonObject[] Manifests, JsonObject Schema) Declarations() =>
        (NavigationRegistry.Configuration(), NavigationRegistry.Manifests(), InstallationPackages.Contract("plugin_architecture_v3.json"));
    private static IReadOnlyDictionary<string, JsonObject> Validate(JsonObject config, JsonObject[] manifests, JsonObject schema) => NavigationRegistry.Validate(config, manifests, schema);
    private static void Invalid(string code, Action<JsonObject, JsonObject[]> mutate)
    {
        var (config, manifests, schema) = Declarations();
        mutate(config, manifests);
        Assert.Equal("navigation_" + code, Assert.Throws<InvalidDataException>(() => Validate(config, manifests, schema)).Message);
    }

    [Fact]
    public void Every_report_has_one_owner_and_preserves_access_keys_fields_and_routes()
    {
        var (config, manifests, schema) = Declarations();
        var owners = Validate(config, manifests, schema);
        var declared = config["core_reports"]!.AsObject().Select(p => p.Key)
            .Concat(manifests.SelectMany(m => m["reports"]!.AsArray()).Select(r => S(r!["report_key"]))).ToArray();
        Assert.Equal(declared.Length, declared.Distinct().Count());
        Assert.Contains(Rules, r => r.RegistryKey == "security.rule-quality");
        foreach (var rule in Rules)
        {
            var owner = owners[rule.RegistryKey];
            Assert.Equal(rule.OwnerId, S(owner["owner_id"]));
            var definition = WorkspaceJson.Declarations.GetProperty("reports").EnumerateArray().Single(d => d.GetProperty("key").GetString() == rule.RegistryKey);
            if (rule.OwnerId == "sli.core") { Assert.Equal(definition.GetProperty("section").GetString(), S(owner["section_id"])); continue; }
            Assert.Equal(rule.ReportKey, S(owner["access_key"]));
            Assert.True(rule.RequiredFields.SetEquals(owner["required_fields"]!.AsArray().Select(S)));
            Assert.Contains("/report/" + rule.RegistryKey, owner["routes"]!.AsArray().Select(S));
            Assert.Equal(rule.RegistryKey, S(owner["definition_id"]));
        }
        Assert.Equal("sli.gpo", S(owners["ad.gpo.v2"]["owner_id"]));
        Assert.Equal("group-policies", S(owners["ad.gpo.v2"]["section_id"]));
        Assert.Equal("active-directory", S(owners["ad.users.v2"]["section_id"]));
        Assert.Equal("sli.remote-access", S(owners["vpn.connections"]["owner_id"]));
        Assert.Equal("sli.remote-access", S(owners["vpn.audit"]["owner_id"]));
    }

    private static string Root()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "config", "navigation_v3.json"))) dir = dir.Parent;
        Assert.NotNull(dir); return dir.FullName;
    }

    [Fact]
    public void Ad_agent_declarations_remain_in_runtime_manifest_and_cannot_be_executed_by_navigation()
    {
        var runtime = JsonNode.Parse(File.ReadAllText(Path.Combine(Root(), "config", "plugin_packages", "sli.ad.agent-v3.json")))!;
        var modules = runtime["agent_modules"]!.AsArray();
        Assert.Equal(new[] { "sli.windows.ad-dc", "sli.windows.ad-dc-history" }, modules.Select(m => S(m!["module_id"])).Order(StringComparer.Ordinal));
        Assert.All(modules, m => { Assert.Equal("windows-dc-eventlog-read", S(m!["rights_check_id"])); Assert.Equal("sli.ad-dc-policy.v1", S(m["policy_schema_ref"])); });
        var (config, manifests, schema) = Declarations();
        var ad = manifests.Single(m => S(m["plugin_id"]) == "sli.ad"); Assert.Empty(ad["agent_modules"]!.AsArray());
        Assert.Equal("sli.ad", S(Validate(config, manifests, schema)["ad.users.v2"]["owner_id"]));
        ad["agent_modules"] = modules.DeepClone();
        Assert.Equal("navigation_manifest_not_in_place", Assert.Throws<InvalidDataException>(() => Validate(config, manifests, schema)).Message);
    }

    [Fact]
    public void Policy_denials_dataset_belongs_to_remote_access()
    {
        var (config, manifests, schema) = Declarations();
        var remote = manifests.Single(m => S(m["plugin_id"]) == "sli.remote-access");
        Assert.Contains(remote["datasets"]!.AsArray(), d => S(d!["dataset_id"]) == "vpn.policy-denials");
        var entry = Entry(config, "vpn-connections");
        Assert.Equal(new[] { "vpn.policy-denials" }, entry["datasets"]!.AsArray().Select(S)); Assert.Equal("sli.remote-access", S(entry["plugin_id"]));
        Validate(config, manifests, schema);
        entry["datasets"] = new JsonArray("foreign.dataset");
        Assert.Equal("navigation_dataset_owner_invalid", Assert.Throws<InvalidDataException>(() => Validate(config, manifests, schema)).Message);
    }

    [Fact]
    public void All_legacy_registry_keys_from_migrations_remain_owned()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(Path.Combine(Root(), "config", "postgres_migrations"), "*.sql").Where(p => !p.Contains("rollback", StringComparison.Ordinal)))
        {
            string sql = File.ReadAllText(file);
            foreach (Match match in Regex.Matches(sql, @"insert into report_registry_v4\s*\([^;]+?\)\s*select\s*'([a-z0-9.-]+)'", RegexOptions.IgnoreCase)) keys.Add(match.Groups[1].Value);
            var definitions = Regex.Match(sql, @"with definitions\(report_key,[^;]+?as \(values(.*?)\)\s*insert into report_registry_v4", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (definitions.Success) foreach (Match match in Regex.Matches(definitions.Groups[1].Value, @"\('([a-z0-9.-]+)'")) keys.Add(match.Groups[1].Value);
        }
        Assert.NotEmpty(keys); Assert.True(keys.IsSubsetOf(NavigationRegistry.Owners().Keys));
    }

    [Theory]
    [InlineData("sli.ad", "ad-report,users-report,computers-report,new-logon-pairs-report")]
    [InlineData("sli.gpo", "gpo-report")]
    [InlineData("sli.remote-access", "vpn-connections")]
    public void Disabling_plugin_hides_only_contributions_and_preserves_history(string plugin, string hidden)
    {
        var enabled = Catalog(); var disabled = Catalog(disabled: plugin);
        Assert.True(JsonNode.DeepEquals(enabled["items"], disabled["items"]));
        var ids = Ids(disabled["navigation"]!);
        Assert.All(hidden.Split(','), id => Assert.DoesNotContain(id, ids));
        Assert.Contains("workspace", ids); Assert.Contains("problems", ids); Assert.DoesNotContain("objects", ids);
        if (plugin == "sli.ad") Assert.Contains("gpo-report", ids);
        if (plugin == "sli.gpo")
        {
            Assert.Contains("users-report", ids);
            Assert.DoesNotContain(disabled["navigation"]!["sections"]!.AsArray(), s => S(s!["id"]) == "group-policies");
        }
        Assert.Contains(Rules, r => r.RegistryKey == "ad.gpo.v2");
    }

    [Fact]
    public void Preview_entries_require_opt_in_and_keep_existing_grants()
    {
        var access = Access(["vpn.audit", "file-audit.overview", "workstations.overview"], ["operations.view", "access.manage"]);
        var defaultNavigation = Ids(WorkspaceReportCatalog.Navigation(access, Rules, States()));
        var preview = Ids(WorkspaceReportCatalog.Navigation(access, Rules, States(), preview: true));
        foreach (string id in new[] { "file-audit", "workstations-overview" })
        {
            Assert.Contains(id, defaultNavigation);
            Assert.Contains(id, preview);
        }
        foreach (string id in new[] { "vpn-connections", "admin-plugin-file-audit",
            "admin-plugin-remote-access", "admin-plugin-workstations", "admin-plugin-sigma" })
        {
            Assert.DoesNotContain(id, defaultNavigation);
            Assert.Contains(id, preview);
        }
        Assert.DoesNotContain("admin-plugin-file-audit", Ids(WorkspaceReportCatalog.Navigation(Access([], []), Rules, States(), preview: true)));
    }

    [Fact]
    public void Navigation_never_widens_empty_or_denied_grants()
    {
        Assert.Equal(new[] { "workspace" }, Ids(Nav(Access([], []))));
        Assert.Equal(new[] { "workspace" }, Ids(Nav(Access(["ad.users.v2"], [], false))));
    }

    [Theory]
    [InlineData("ad.computers.v6", "computers-report", "computers")]
    [InlineData("ad.computer-logons", "computers-report", "logons")]
    [InlineData("ad.computers.v6,ad.computer-logons", "computers-report", "computers,logons")]
    [InlineData("vpn.audit", "vpn-connections", "connections")]
    [InlineData("vpn.connections", "vpn-connections", "connections")]
    public void Merged_entries_keep_independent_view_grants(string grants, string entryId, string views)
    {
        var nav = WorkspaceReportCatalog.Navigation(Access(grants.Split(','), []), Rules, States(), preview: true);
        Assert.Equal(views.Split(','), Entry(nav, entryId)["views"]!.AsArray().Select(v => S(v!["id"])));
        Assert.All(new[] { "objects", "logons-report", "vpn-access" }, id => Assert.DoesNotContain(id, Ids(nav)));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"path":"/search","capabilities":["objects.view","entity.view"]}"""), nav["global_search"]));
    }

    [Theory]
    [InlineData("unknown-view", "redirect_invalid")]
    [InlineData("duplicate", "duplicate_redirect")]
    [InlineData("chain", "redirect_invalid")]
    public void Broken_compatibility_redirects_are_rejected(string mutation, string code) => Invalid(code, (c, _) =>
    {
        if (mutation == "unknown-view") c["redirects"]![2]!["view"] = "unknown";
        if (mutation == "duplicate") c["redirects"]!.AsArray().Add(c["redirects"]![0]!.DeepClone());
        if (mutation == "chain") c["redirects"]![0]!["to"] = "/entities";
    });

    [Theory]
    [InlineData("ad.computers.v6")]
    [InlineData("ad.computer-logons,ad.computers.v6")]
    public void View_cannot_borrow_another_reports_access_key(string grants) => Invalid("entry_reference_invalid", (c, _) =>
    {
        var entry = Entry(c, "computers-report");
        entry["views"]![1]!["reports"] = new JsonArray(grants.Split(',').Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        entry["reports"] = new JsonArray(entry["views"]!.AsArray().SelectMany(v => v!["reports"]!.AsArray()).Select(S).Distinct().Order(StringComparer.Ordinal).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
    });

    [Fact]
    public void Config_disables_plugins_independently_without_mutating_shared_declarations()
    {
        var (config, manifests, schema) = Declarations(); config["enabled_plugins"] = new JsonArray("sli.gpo"); Validate(config, manifests, schema);
        Assert.Equal(new[] { "workspace", "problems", "gpo-report" }, Ids(WorkspaceReportCatalog.Navigation(Access(), Rules, States(), config)));
        Assert.Contains("users-report", Ids(Nav()));
    }

    private sealed class FakeRows(Func<IReadOnlyList<JsonElement>> read) : IWorkspaceRows
    {
        public int Calls;
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
        {
            Calls++; Assert.Equal("select plugin_id,enabled from read_plugin_states_v1()", sql); Assert.Empty(parameters);
            return Task.FromResult(read());
        }
    }

    [Fact]
    public async Task Catalog_reads_activation_with_a_fake_and_keeps_report_history()
    {
        var rows = new FakeRows(() => States("sli.remote-access"));
        var body = O(await new WorkspaceReportCatalog(rows, Provider).ReadAsync(Access(), TestContext.Current.CancellationToken));
        Assert.DoesNotContain("vpn-connections", Ids(body["navigation"]!));
        Assert.Contains(body["items"]!.AsArray(), i => S(i!["key"]) == "vpn.accounts"); Assert.Equal(1, rows.Calls);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("missing")]
    [InlineData("runtime-error")]
    [InlineData("postgres-error")]
    public async Task Activation_observation_is_read_only_and_fails_closed(string state)
    {
        var rows = new FakeRows(() => state switch
        {
            "disabled" => States("sli.remote-access"), "missing" => [],
            "runtime-error" => throw new InvalidOperationException("state_unavailable"), _ => throw new NpgsqlException("state_unavailable")
        });
        var body = O(await new WorkspaceReportCatalog(rows, Provider).ReadAsync(Access(), TestContext.Current.CancellationToken));
        Assert.DoesNotContain("vpn-connections", Ids(body["navigation"]!));
        Assert.DoesNotContain(body["navigation"]!["enabled_plugins"]!.AsArray(), p => S(p) == "sli.remote-access");
        Assert.Contains(body["items"]!.AsArray(), i => S(i!["key"]) == "vpn.accounts"); Assert.Equal(1, rows.Calls);
    }

    [Theory]
    [InlineData("schema", "manifest_value_invalid")]
    [InlineData("permanent", "manifest_value_invalid")]
    [InlineData("permanent-type", "manifest_type_invalid")]
    [InlineData("workers", "manifest_unknown_field")]
    [InlineData("api", "core_api_incompatible")]
    [InlineData("report", "duplicate_report_owner")]
    [InlineData("dataset", "report_reference_invalid")]
    [InlineData("section", "report_reference_invalid")]
    [InlineData("reader", "history_reader_invalid")]
    [InlineData("title", "entry_reference_invalid")]
    [InlineData("navigation", "duplicate_section")]
    public void Invalid_manifest_contributions_are_rejected(string mutation, string code) => Invalid(code, (_, manifests) =>
    {
        var m = manifests[0];
        switch (mutation)
        {
            case "schema": m["schema_version"] = 2; break;
            case "permanent": m["own_permanent_workers"] = true; break;
            case "permanent-type": m["own_permanent_workers"] = 0; break;
            case "workers": m["workers"] = new JsonArray(); break;
            case "api": m["core_api"]!["minimum"] = "4.0.0"; break;
            case "report": m["reports"]!.AsArray().Add(m["reports"]![0]!.DeepClone()); break;
            case "dataset": m["reports"]![0]!["dataset_id"] = "unknown.dataset"; break;
            case "section": m["reports"]![0]!["section_id"] = "admin"; break;
            case "reader": m["reports"]![0]!["history_reader_id"] = "unknown.reader"; break;
            case "title": m["reports"]![0]!["title_key"] = "unknown.title"; break;
            case "navigation": m["navigation"]!.AsArray().Add(m["navigation"]![0]!.DeepClone()); break;
        }
    });

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Plugin_navigation_cannot_lose_its_owner(bool replace) => Invalid("entry_reference_invalid", (c, _) =>
    {
        var entry = Entry(c, "ad-report").AsObject(); if (replace) entry["plugin_id"] = "sli.gpo"; else entry.Remove("plugin_id");
    });

    [Fact]
    public void Core_report_section_must_exist() => Invalid("core_section_invalid", (c, _) =>
    {
        var sections = c["sections"]!.AsArray(); sections.Remove(sections.Single(s => S(s!["id"]) == "investigation"));
    });

    [Fact]
    public void Admin_groups_follow_accepted_information_architecture_and_independent_capabilities()
    {
        var nav = Nav(Access(["operations.readiness"], ["access.manage", "operations.view", "reports.design"]));
        var admin = nav["sections"]!.AsArray().Single(s => S(s!["id"]) == "admin")!;
        var expected = new Dictionary<string, string[]>
        {
            ["status"] = ["/admin/status"], ["base"] = ["/agents", "/access", "/notifications", "/operations", "/admin/language-time", "/admin/update"],
            ["plugins"] = ["/admin/plugins/sli.ad", "/admin/plugins/sli.gpo", "/plugins"],
            ["advanced"] = ["/report-studio", "/admin/activity"]
        };
        Assert.Equal(expected.Keys, admin["groups"]!.AsArray().Select(g => S(g!["id"])));
        foreach (var group in admin["groups"]!.AsArray()) Assert.Equal(expected[S(group!["id"])], group["entries"]!.AsArray().Select(e => S(e!["path"])));
        Assert.Equal(new[] { "workspace" }, Ids(Nav(Access([], []))));
        Assert.Equal(new[] { "workspace", "admin-status", "operations", "admin-plugin-ad", "admin-plugin-gpo", "plugins" },
            Ids(Nav(Access([], ["operations.view"]))));
    }

    [Theory]
    [InlineData("notifications.deliveries", "notifications")]
    [InlineData("operations.readiness", "admin-status")]
    [InlineData("decoys.registry", "admin-status")]
    [InlineData("watch.registry", "admin-status")]
    public void Admin_report_grants_are_independent_and_denials_do_not_add_navigation(string report, string destination)
    {
        Assert.Equal(new[] { "workspace", destination }, Ids(Nav(Access([report], []))));
        Assert.Equal(new[] { "workspace" }, Ids(Nav(Access([report], [], false))));
    }
}
