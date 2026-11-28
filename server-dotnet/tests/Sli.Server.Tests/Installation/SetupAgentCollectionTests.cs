using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

// Behavioral vectors from tests/core/test_setup_agent_collection.py.
public sealed class SetupAgentCollectionTests
{
    [Theory]
    [InlineData("active", "domain_controller", false, false, true)]
    [InlineData("disabled", "domain_controller", false, false, true)]
    [InlineData("disabled", "domain_controller", false, true, false)]
    [InlineData("active", "workstation", false, false, false)]
    [InlineData("active", null, true, false, true)]
    [InlineData("active", "file_server", true, false, false)]
    [InlineData("replaced", "domain_controller", true, false, false)]
    public void First_run_uses_registered_dc_agents_even_before_they_send_data(
        string status, string? role, bool legacyAssignment, bool removalRequested, bool expected)
    {
        var agents = Agents();
        var agent = agents[0]!;
        agent["status"] = status;
        agent["machine_role"] = role;
        agent["removal_requested"] = removalRequested;
        agent["last_seen"] = null;
        if (!legacyAssignment) agent["assigned_modules"] = new JsonArray();

        var health = SetupCollectionHealth.View(agents, new JsonArray(), DateTimeOffset.Parse(Stamp), diagnosticsAvailable: false);
        Assert.Equal(expected, health["has_domain_controller_agent"]!.GetValue<bool>());
        Assert.Equal(0, health["connected_domain_controllers"]!.GetValue<int>());
    }

    [Theory]
    [InlineData(20, 20, "current", null)]
    [InlineData(20, 900, "current", null)]
    [InlineData(20, 901, "error", "import_overdue")]
    [InlineData(901, null, "error", "packet_stale")]
    public void Stream_health_distinguishes_normal_import_wait_from_overdue_import_and_stale_packets(
        int packetAge, int? pendingAge, string expectedState, string? expectedReason)
    {
        var now = DateTimeOffset.Parse(Stamp);
        var agents = Agents();
        agents[0]!["last_seen"] = Stamp;
        agents[0]!["created_at"] = now.AddHours(-1).ToString("O");
        var streams = new JsonArray(new JsonObject {
            ["agent_id"] = "agent-1", ["module_id"] = Dc, ["revision"] = "1", ["channel"] = "Security",
            ["last_packet_at"] = now.AddSeconds(-packetAge).ToString("O"),
            ["last_import_at"] = now.AddSeconds(-60).ToString("O"),
            ["pending_since"] = pendingAge is int age ? now.AddSeconds(-age).ToString("O") : null
        });
        var setup = SetupCollectionHealth.View(agents, streams, now);
        var workspace = JsonSerializer.SerializeToNode(AgentCollectionOverview.Compose(
            JsonSerializer.SerializeToElement(agents).EnumerateArray().ToArray(),
            JsonSerializer.SerializeToElement(streams).EnumerateArray().ToArray(), now))!.AsObject();
        foreach (var view in new[] { setup, Sli.Server.Operations.OperationsService.AgentView(agents, streams, now), workspace })
        {
            var source = Assert.Single(view["items"]!.AsArray())!;
            var channel = Assert.Single(source["modules"]![0]!["channels"]!.AsArray())!;
            Assert.Equal("online", T(source["connection"]));
            Assert.Equal(expectedState, T(source["state"]));
            Assert.Equal(expectedState, T(channel["state"]));
            Assert.Equal(expectedReason, channel["failure_reason"]?.GetValue<string>());
            if (pendingAge is int wait) Assert.Equal((long)wait, channel["import_lag_seconds"]!.GetValue<long>());
        }
        Assert.Equal(expectedState == "current",
            Instance(Project(setup, SetupCollectionHealth.Bindings(agents), Controllers()))["data_received"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData("short_event_attestation_failed")]
    [InlineData("short_event_summary_conflict")]
    public void Packet_refusal_is_visible_immediately_even_after_a_new_successful_import(string reason)
    {
        var now=DateTimeOffset.UtcNow;
        var agents=Agents(); var streams=Streams();
        streams[0]!["import_failure_reason"]=reason;
        streams[0]!["import_failure_at"]=now.ToString("O");
        foreach(var view in new[] { SetupCollectionHealth.View(agents,streams,now),
            Sli.Server.Operations.OperationsService.AgentView(agents,streams,now) }) {
            var source=Assert.Single(view["items"]!.AsArray())!;
            var check=Assert.Single(source["modules"]![0]!["channels"]!.AsArray())!;
            Assert.Equal("error",T(check["state"])); Assert.Equal("import_rejected",T(check["failure_reason"]));
            Assert.Equal(reason,T(check["import_failure_reason"]));
            Assert.Equal(now.ToUnixTimeMilliseconds(),DateTimeOffset.Parse(T(check["import_failure_at"])).ToUnixTimeMilliseconds());
            Assert.Null(check["issue_since_utc"]);
        }
    }

    [Fact]
    public void Setup_source_keeps_reported_audit_and_event_log_observations()
    {
        var agents = Agents();
        agents[0]!["windows_audit"] = O("""{"policy_revision":1,"families":{"domain_controller":{"state":"managed_by_gpo"}}}""");
        agents[0]!["eventlog_diagnostics"] = O("""{"items":[{"channel":"Security","policy_revision":1,"error":{"winerror":5}}]}""");
        var source = Assert.Single(SetupCollectionHealth.View(agents, Streams(), DateTimeOffset.Parse(Stamp))["items"]!.AsArray())!;
        Assert.Equal("managed_by_gpo", T(source["windows_audit"]!["families"]!["domain_controller"]!["state"]));
        var observed = Assert.Single(source["eventlog_diagnostics"]!["items"]!.AsArray())!;
        Assert.Equal("Security", T(observed["channel"]));
        Assert.Equal(5, observed["error"]!["winerror"]!.GetValue<int>());
    }

    [Fact]
    public void Canonical_dc_has_one_source_and_retains_replaced_agent_for_removal()
    {
        var agents=new JsonArray();
        foreach(var (id,name,status,version) in new[] { ("old","DC","replaced","1.0.0"),("new","dc.example.test","active","1.1.0"),("extra","DC","active","1.0.0") })
            agents.Add(new JsonObject { ["id"]=id,["host_id"]=id,["registration_host_name"]=name,["canonical_host_name"]="dc.example.test",["server_id"]=7,
                ["status"]=status,["agent_version"]=version,["identity_conflict"]=id=="extra",["assigned_modules"]=new JsonArray(),["collection_policy"]=new JsonObject(),["policy_revision"]=1,["applied_policy_revision"]=1,["applied_collection_state"]="active" });
        var view=SetupCollectionHealth.View(agents,new JsonArray(),DateTimeOffset.Parse(Stamp));
        var source=Assert.Single(view["items"]!.AsArray());
        Assert.Equal("dc.example.test",T(source!["name"])); Assert.Equal("new",T(source["id"])); Assert.Equal(2,(int)source["duplicate_agents"]!);
        Assert.True((bool)source["identity_conflict"]!);
        Assert.Equal(1,(int)view["active_agents"]!);
        var old=Assert.Single(view["replaced_agents"]!.AsArray());
        Assert.Equal("1.0.0",T(old!["agent_version"])); Assert.Equal("1.1.0",T(old["replacement_version"]));
    }

    [Theory]
    [InlineData("online", false, true)]
    [InlineData("offline", false, false)]
    [InlineData("online", true, false)]
    public void Silent_replacement_exposes_previous_delivery(string connection,bool hasPacket,bool expected)
    {
        var now=DateTimeOffset.Parse(Stamp);
        var agents=Agents(); var current=agents[0]!;
        current["server_id"]=7; current["agent_version"]="1.1.0";
        current["created_at"]=now.AddHours(-2).ToString("O");
        current["policy_applied_at"]=now.AddHours(-1).ToString("O");
        current["last_seen"]=(connection=="online"?now:now.AddHours(-1)).ToString("O");
        var old=current.DeepClone(); old["id"]="old"; old["status"]="replaced";
        old["last_packet_at"]=now.AddMinutes(-20).ToString("O"); old["can_restore"]=true;
        agents.Add(old);
        var streams=hasPacket ? new JsonArray(new JsonObject { ["agent_id"]="agent-1",["module_id"]=Dc,["revision"]="1",["channel"]="Security",
            ["last_packet_at"]=now.ToString("O"),["last_import_at"]=now.ToString("O") }) : new JsonArray();
        var view=SetupCollectionHealth.View(agents,streams,now);
        var source=Assert.Single(view["items"]!.AsArray())!;
        if(!expected) { Assert.Null(source["delivery_fallback"]); return; }
        Assert.Equal("old",T(source["delivery_fallback"]!["agent_id"]));
        Assert.Equal(now.AddMinutes(-20),DateTimeOffset.Parse(T(source["delivery_fallback"]!["last_packet_at"])));
        Assert.True(DateTimeOffset.Parse(T(source["delivery_fallback"]!["since"]))<now);
    }

    const string Dc = "sli.windows.ad-dc", Context = "sli.windows.ad-context";
    const string Stamp = "2026-10-01T00:00:00+00:00";
    static string T(JsonNode? n) => InstallationPackages.Text(n);
    static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    static JsonArray Bindings(string? name = "dc.example.test", bool enabled = true) => new(new JsonObject {
        ["agent_id"] = "agent-1", ["module_id"] = Dc, ["source_name"] = name, ["domain_dns"] = null, ["enabled"] = enabled });
    static JsonObject Health(string state = "current") => new() {
        ["state"] = state == "current" ? "current" : state == "error" ? "error" : "partial",
        ["active_agents"] = 1, ["current_agents"] = state == "current" ? 1 : 0,
        ["items"] = new JsonArray(new JsonObject { ["id"] = "agent-1", ["state"] = state,
            ["modules"] = new JsonArray(new JsonObject { ["module_id"] = Dc,
                ["channels"] = new JsonArray(new JsonObject { ["channel"] = "Security", ["state"] = state,
                    ["last_import_at"] = Stamp, ["last_packet_at"] = Stamp }) }) }) };
    static JsonObject Controllers(string name = "dc.example.test", bool enabled = true) => new() {
        ["items"] = new JsonArray(new JsonObject { ["hostname"] = name, ["enabled"] = enabled }), ["source"] = "db" };
    static JsonObject Project(JsonObject health, JsonArray bindings, JsonObject? controllers = null, string pack = Dc, JsonArray? domains = null)
        => InstallationService.SourceSummary(new JsonObject { ["pack_id"] = pack, ["display_name"] = "AD", ["version"] = "1",
            ["source_kind"] = pack == Context ? "context" : "event" },
            InstallationService.AgentSourceConfiguration(pack, controllers, domains, health, bindings), null);
    static JsonObject Instance(JsonObject source) => Assert.Single(source["instances"]!.AsArray())!.AsObject();
    static JsonObject Source(JsonNode body, string pack = Dc) => body["sources"]!.AsArray().OfType<JsonObject>().Single(s => T(s["pack_id"]) == pack);
    static JsonObject Step(JsonNode body, string id) => body["steps"]!.AsArray().OfType<JsonObject>().Single(s => T(s["id"]) == id);

    [Fact]
    public void ExactCaseInsensitiveAssignmentOverridesDisabledLegacyTarget()
    {
        var item = Instance(Project(Health(), Bindings(), Controllers("DC.EXAMPLE.TEST", false)));
        Assert.True(item["configured"]!.GetValue<bool>()); Assert.True(item["enabled"]!.GetValue<bool>());
        Assert.True(item["data_received"]!.GetValue<bool>()); Assert.Equal("current", T(item["collection_state"]));
    }

    [Theory]
    [InlineData("other.example.test", "dc.example.test")]
    [InlineData(null, "dc.example.test")]
    [InlineData("dc.other.example.test", "dc")]
    public void UnrelatedOrAbsentClaimDoesNotEnableLegacyTarget(string? claim, string target)
    {
        var source = Project(Health(), Bindings(claim), Controllers(target));
        var item = source["instances"]!.AsArray().Single(i => T(i?["source_instance_id"]) == target)!;
        Assert.Null(item["configured"]); Assert.Null(item["enabled"]); Assert.Null(item["data_received"]);
        Assert.Equal("unknown", T(item["collection_state"])); Assert.Equal("check_configuration", T(item["next_action"]));
    }

    [Theory]
    [InlineData("current", true, "current", true, null)]
    [InlineData("error", true, "error", false, "check_data")]
    [InlineData("waiting", true, "waiting", false, "check_data")]
    [InlineData("unknown", true, "unknown", null, "check_data")]
    [InlineData("paused", false, "disabled", false, "enable")]
    [InlineData("disabled", false, "disabled", false, "enable")]
    [InlineData("lagging", true, "lagging", false, "check_data")]
    public void OldImportDoesNotMakeInactiveOrUnconfirmedAssignmentFresh(string state, bool enabled, string expectedState, bool? received, string? action)
    {
        var source = Project(Health(state), Bindings(enabled: enabled)); var item = Instance(source);
        Assert.Equal(expectedState, T(item["collection_state"])); Assert.Equal(received, item["data_received"]?.GetValue<bool>());
        Assert.Equal(received, source["data_received"]?.GetValue<bool>()); Assert.Equal(action, item["next_action"]?.GetValue<string>());
        Assert.Equal(received == true ? "fresh" : received is null ? "unavailable" : "stale", T(item["data_state"]));
    }

    [Fact]
    public void FailedDiagnosticsPreserveAssignmentButCannotProveDelivery()
    {
        var health = Health(); health["diagnostics"] = O("""{"state":"unavailable","reason":"timeout"}""");
        var source = Project(health, Bindings()); Assert.True(source["configured"]!.GetValue<bool>());
        Assert.Null(source["data_received"]); Assert.Equal("unknown", T(Instance(source)["collection_state"]));
    }

    [Fact]
    public void OneCurrentAgentCannotMaskMissingSecondAssignment()
    {
        var bindings = Bindings(); var missing = bindings[0]!.DeepClone(); missing["agent_id"] = "missing-agent"; bindings.Add(missing);
        var source = Project(Health(), bindings); Assert.Null(source["data_received"]);
        Assert.Equal("unknown", T(Instance(source)["collection_state"]));
    }

    [Fact]
    public void DisabledAssignmentWithoutModuleAndPausedAssignmentKeepTheirStates()
    {
        var health = Health(); health["items"]![0]!["modules"] = new JsonArray();
        var item = Instance(Project(health, Bindings(enabled: false)));
        Assert.True(item["configured"]!.GetValue<bool>()); Assert.False(item["enabled"]!.GetValue<bool>());
        Assert.False(item["data_received"]!.GetValue<bool>()); Assert.Equal("disabled", T(item["collection_state"]));
        var bindings = Bindings(enabled: false); bindings[0]!["paused"] = true;
        Assert.Equal("paused", T(Instance(Project(Health("paused"), bindings))["collection_state"]));
    }

    [Theory]
    [InlineData("agent-1")]
    [InlineData("HOST-1")]
    [InlineData(null)]
    public void RegistryIdentifiersCannotBecomeSourceHostClaims(string? source)
    {
        var agents = Agents(); agents[0]!["assigned_modules"]![0]!["config"]!["source_name"] = source;
        Assert.Null(Assert.Single(SetupCollectionHealth.Bindings(agents))!["source_name"]);
    }

    static JsonArray Agents(string state = "current", string? name = "dc.example.test")
    {
        string now = DateTimeOffset.UtcNow.ToString("o");
        var agents = new JsonArray(O("""
            {"id":"agent-1","host_id":"host-1","status":"active","policy_revision":1,"applied_policy_revision":1,
             "applied_collection_state":"active","collection_policy":{"state":"active"},"assigned_modules":[
               {"module_id":"sli.windows.ad-dc","enabled":true,"config":{"source_name":"dc.example.test",
                "channels":{"Security":true,"System":false,"Directory Service":false}}}]}
            """));
        var agent = agents[0]!; agent["created_at"] = now; agent["last_seen"] = now;
        agent["assigned_modules"]![0]!["config"]!["source_name"] = name;
        if (state == "disabled") agent["assigned_modules"]![0]!["enabled"] = false;
        if (state == "paused") agent["assigned_modules"]![0]!["config"]!["paused"] = true;
        if (state == "waiting") agent["applied_policy_revision"] = 0;
        return agents;
    }
    static JsonArray Streams(string state = "current") => new(new JsonObject {
        ["agent_id"] = "agent-1", ["module_id"] = Dc, ["revision"] = "1", ["channel"] = "Security",
        ["last_packet_at"] = DateTimeOffset.UtcNow.ToString("o"),
        ["last_import_at"] = state == "unknown" ? null : DateTimeOffset.UtcNow.ToString("o"),
        ["read_error"] = state == "error", ["pending_since"] = state == "lagging" ? DateTimeOffset.UtcNow.ToString("o") : null });

    [Theory]
    [InlineData(true, "error", false)]
    [InlineData(false, "current", true)]
    public async Task FreshSecurityCannotMaskAnExpectedChannelThatNeverReported(bool directoryEnabled, string expectedState, bool received)
    {
        var agents = Agents();
        var now = DateTimeOffset.UtcNow;
        agents[0]!["policy_applied_at"] = now.AddHours(-1).ToString("o");
        agents[0]!["assigned_modules"]![0]!["config"]!["channels"]!["Directory Service"] = directoryEnabled;
        await using var f = new InstallationFixture();
        Configure(f, agents, Streams(), Controllers());
        await f.StartAsync();
        var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status);
        var item = Instance(Source(body));
        Assert.Equal(expectedState, T(item["collection_state"]));
        Assert.Equal(received, item["data_received"]!.GetValue<bool>());
        var health = Assert.Single(body["agent_collection"]!["items"]!.AsArray())!;
        Assert.Equal("online", T(health["connection"]));
        var channels = health["modules"]![0]!["channels"]!.AsArray();
        Assert.Equal("current", T(channels.Single(c => T(c?["channel"]) == "Security")!["state"]));
        var directory = channels.SingleOrDefault(c => T(c?["channel"]) == "Directory Service");
        if (directoryEnabled)
        {
            Assert.NotNull(directory);
            Assert.Equal("error", T(directory["state"]));
            Assert.Equal("packet_missing", T(directory["failure_reason"]));
            Assert.Null(directory["last_packet_at"]);
            Assert.True(DateTimeOffset.Parse(T(directory["issue_since_utc"])) < now);
        }
        else Assert.Null(directory);
    }
    static void Configure(InstallationFixture f, JsonArray agents, JsonArray streams, JsonObject? controllers, bool diagnosticsFailure = false, bool history = false, bool includeDomains = true)
    {
        f.Database.Override = (sql, _) => sql.Contains("from sli_agents a", StringComparison.Ordinal) ? agents.DeepClone().AsArray()
            : sql.Contains("with requested as materialized", StringComparison.Ordinal) ? diagnosticsFailure ? throw new TimeoutException("synthetic diagnostic failure") : streams.DeepClone().AsArray()
            : sql.Contains("from domain_controller_targets t", StringComparison.Ordinal) ? controllers?["items"]!.DeepClone().AsArray() ?? new()
            : sql.Contains("from domains d join forests", StringComparison.Ordinal) && !includeDomains ? new()
            : sql.Contains("from ad_snapshot_manifests m", StringComparison.Ordinal) && history
                ? new(new JsonObject { ["source_instance_id"] = "example.test", ["last_data_utc"] = Stamp })
            : sql.Contains("collector_channel_runs", StringComparison.Ordinal) ? throw new InvalidOperationException("legacy history read") : null;
    }
    static void AssertSingleHealthRead(InstallationFixture f)
    {
        Assert.Single(f.Database.Calls, c => c.Sql.Contains("from sli_agents a", StringComparison.Ordinal));
        Assert.DoesNotContain(f.Database.Calls, c => c.Sql.Contains("collector_channel_runs", StringComparison.Ordinal)
            || c.Sql.Contains("runtime_collection", StringComparison.Ordinal) || c.Sql.Contains("insert ", StringComparison.OrdinalIgnoreCase)
            || c.Sql.Contains("update ", StringComparison.OrdinalIgnoreCase));
    }

    public static TheoryData<bool, string> ControllerStates => new() {
        { false, "current" }, { true, "current" }, { false, "waiting" }, { true, "waiting" },
        { false, "error" }, { true, "error" }, { false, "unknown" }, { true, "unknown" },
        { false, "disabled" }, { true, "disabled" }, { false, "paused" }, { true, "paused" } };
    [Theory, MemberData(nameof(ControllerStates))]
    public async Task ControllerStepUsesContactRegardlessOfCollectionStateOrLegacyFlag(bool legacyEnabled, string state)
    {
        await using var f = new InstallationFixture(); Configure(f, Agents(state), Streams(state), Controllers(enabled: legacyEnabled));
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); var source = Source(body); var item = Instance(source);
        Assert.Equal(state, T(item["collection_state"]));
        Assert.Equal("done", T(Step(body, "domain-controllers")["state"]));
        Assert.Equal(1, body["agent_collection"]!["connected_domain_controllers"]!.GetValue<int>());
        Assert.Equal(legacyEnabled, body["domain_controllers"]![0]!["enabled"]!.GetValue<bool>());
        Assert.False(body["domains"]![0]!["is_archived"]!.GetValue<bool>());
        Assert.Equal("agents", T(source["collection_basis"])); Assert.Null(body["collection"]!["block_reason"]);
        AssertSingleHealthRead(f); Assert.DoesNotContain("_setup_bindings", body.ToJsonString()); Assert.DoesNotContain("_agent_source_bindings", body.ToJsonString());
        if (state == "current")
        {
            Assert.Equal("done", T(Step(body, "first-collection")["state"]));
            Assert.Equal("Сбор работает.", T(Step(body, "first-collection")["summary"]));
        }
        if (state == "error")
        {
            Assert.Equal("todo", T(Step(body, "first-collection")["state"]));
            Assert.Equal("check_data", T(item["next_action"]));
        }
    }

    [Theory]
    [InlineData("sli.windows.ad-dc", "active", 600, 1)]
    [InlineData("sli.windows.ad-dc", "active", 601, 0)]
    [InlineData("sli.windows.ad-dc", "active", null, 0)]
    [InlineData("sli.windows.ad-dc", "disabled", 0, 0)]
    [InlineData("sli.windows.ad-dc-history", "active", 0, 1)]
    [InlineData("sli.file-audit", "active", 0, 0)]
    public void ConnectedControllersUseDcRoleAndExpectedContactWindow(string module, string status, int? age, int expected)
    {
        var now = DateTimeOffset.Parse(Stamp);
        var agents = Agents();
        var agent = agents[0]!;
        agent["status"] = status;
        agent["collection_policy"]!["interval_seconds"] = 200;
        agent["last_seen"] = age is int seconds ? now.AddSeconds(-seconds).ToString("O") : null;
        agent["assigned_modules"]![0]!["module_id"] = module;
        var duplicate = agent.DeepClone();
        duplicate["id"] = "agent-2";
        agents.Add(duplicate);

        var health = SetupCollectionHealth.View(agents, new(), now, diagnosticsAvailable: false);

        Assert.Equal(expected, health["connected_domain_controllers"]!.GetValue<int>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnapshotHistoryCannotProveAssignmentOrCurrentCollection(bool historical)
    {
        await using var f = new InstallationFixture(); Configure(f, Agents(), Streams(), null, history: historical);
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); var item = Instance(Source(body, Context));
        Assert.Null(item["configured"]); Assert.Null(item["enabled"]); Assert.Null(item["data_received"]);
        Assert.Equal(historical ? Stamp : null, item["last_data_utc"]?.GetValue<string>());
        Assert.Equal("unavailable", T(item["data_state"]));
    }

    [Fact]
    public async Task AgentOnlyControllerIsReadyWithoutLegacyTarget()
    {
        await using var f = new InstallationFixture(); Configure(f, Agents(), Streams(), null);
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); Assert.Empty(body["domain_controllers"]!.AsArray());
        Assert.Equal("done", T(Step(body, "domain-controllers")["state"]));
        Assert.Equal("dc.example.test", T(Instance(Source(body))["source_instance_id"]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnboundOrEmptyAgentSourceKeepsAgentDestinationAndUnknownReadiness(bool empty)
    {
        await using var f = new InstallationFixture(); Configure(f, empty ? new() : Agents("unknown", name: null), Streams("unknown"), null);
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); var source = Source(body); Assert.Equal("agents", T(source["collection_basis"]));
        Assert.Equal(empty ? false : (bool?)null, source["configured"]?.GetValue<bool>());
        Assert.NotEqual("done", T(Step(body, "first-collection")["state"]));
        Assert.DoesNotContain("_setup_bindings", body.ToJsonString());
    }

    [Fact]
    public async Task ConnectedDcWithoutSourceBindingCompletesControllerStep()
    {
        await using var f = new InstallationFixture(); Configure(f, Agents(name: null), Streams(), Controllers());
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); Assert.Equal("done", T(Step(body, "domain-controllers")["state"]));
        Assert.Null(Instance(Source(body))["configured"]);
    }

    [Fact]
    public async Task FailedDiagnosticsKeepPrivateAssignmentAndDegradePublicSetup()
    {
        await using var f = new InstallationFixture(); Configure(f, Agents(), Streams(), Controllers(), diagnosticsFailure: true);
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); var source = Source(body); Assert.True(source["configured"]!.GetValue<bool>());
        Assert.Null(source["data_received"]); Assert.Equal("unknown", T(Instance(source)["collection_state"]));
        Assert.Equal("timeout", T(body["agent_collection"]!["diagnostics"]!["reason"]));
        Assert.Equal("unavailable", T(Step(body, "first-collection")["state"]));
        Assert.DoesNotContain("synthetic diagnostic failure", body.ToJsonString()); AssertSingleHealthRead(f);
    }

    [Fact]
    public async Task NextStepRetainsTheFailingSourceAction()
    {
        await using var f = new InstallationFixture(); Configure(f, Agents("error"), Streams("error"), null, includeDomains: false);
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); Assert.Equal(Dc, T(body["next_step"]!["pack_id"]));
        Assert.Equal("dc.example.test", T(body["next_step"]!["source_instance_id"])); Assert.Equal("check_data", T(body["next_step"]!["action"]));
        Assert.Equal("todo", T(Step(body, "first-collection")["state"]));
    }

    [Fact]
    public async Task PublicHealthAndSetupBindingsExposeOnlyAllowedPolicyFields()
    {
        var agents = Agents(); var config = agents[0]!["assigned_modules"]![0]!["config"]!;
        config["credential"] = "synthetic-never-expose"; config["connect_address"] = "not-for-setup.example.test";
        var streams = Streams(); var now = DateTimeOffset.UtcNow;
        var publicHealth = JsonSerializer.SerializeToNode(AgentCollectionOverview.Compose(
            agents.Select(a => JsonSerializer.SerializeToElement(a)).ToArray(), streams.Select(s => JsonSerializer.SerializeToElement(s)).ToArray(), now))!;
        Assert.False(publicHealth.AsObject().ContainsKey("_setup_bindings"));
        var bindings = SetupCollectionHealth.Bindings(agents); Assert.Equal("dc.example.test", T(Assert.Single(bindings)!["source_name"]));
        await using var f = new InstallationFixture(); Configure(f, agents, streams, null);
        var privateHealth = await SetupCollectionHealth.ReadAsync(f.Database, TestContext.Current.CancellationToken);
        Assert.True(privateHealth.Remove("_setup_bindings"));
        Assert.Equal(T(publicHealth["state"]),T(privateHealth["state"]));
        Assert.Equal(T(publicHealth["active_agents"]),T(privateHealth["active_agents"]));
        Assert.Equal(T(publicHealth["current_agents"]),T(privateHealth["current_agents"]));
        string exposed = publicHealth.ToJsonString() + privateHealth.ToJsonString() + bindings.ToJsonString();
        Assert.DoesNotContain("synthetic-never-expose", exposed); Assert.DoesNotContain("not-for-setup", exposed);
    }

    [Fact]
    public async Task RegistryTimeoutMakesCollectionUnavailableWithoutLeakingError()
    {
        await using var f = new InstallationFixture();
        f.Database.Override = (sql, _) => sql.Contains("from sli_agents a", StringComparison.Ordinal) ? throw new TimeoutException("synthetic registry failure") : null;
        await f.StartAsync(); var (status, body) = await f.SendAsync("GET", "/api/v1/setup/status");
        Assert.Equal(200, status); Assert.Equal("unavailable", T(body["agent_collection"]!["state"]));
        Assert.Equal("unavailable", T(Step(body, "first-collection")["state"]));
        Assert.DoesNotContain("synthetic registry failure", body.ToJsonString()); AssertSingleHealthRead(f);
    }
}
