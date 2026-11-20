using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>
/// Not a unit test: it writes real .NET packets, an enrollment request and the module configuration to a file, and
/// <c>tests/unit/test_agent_dotnet_vectors.py</c> feeds them to the server's own code (<c>receive_packet</c>, <c>parse_csr</c>).
/// That is the proof that the server accepts what this agent produces. It runs only when SLI_DOTNET_INTEROP_DIR is set.
/// </summary>
public sealed class InteropExportTests : IDisposable
{
    private readonly string _directory = Helpers.TempDirectory();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [InteropFact]
    public void WritesPacketsForTheServerCodeToAccept()
    {
        var catalog = EventCatalog.Load();
        var store = new HostIdentityStore(Path.Combine(_directory, "state"), new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
        var prepared = store.Prepare();
        using var key = store.LoadKey();
        var signer = new EcdsaPacketSigner(key);

        var scenarios = Vectors.Load("ad-dc-scenarios.json").AsArray();
        var packets = new JsonArray();
        var configs = new JsonArray();
        var auditReports = new JsonArray();
        DateTimeOffset last = default;
        foreach (var scenarioNode in scenarios.Where(s => s!["name"]!.GetValue<string>() is "three-channel-rotation" or "security-backlog-and-catch-up"))
        {
            var scenario = scenarioNode!.AsObject();
            // Every scenario is its own stream, as if it were another enrolled agent on the same host kind.
            var agentId = Guid.NewGuid().ToString("D");
            using var queue = Helpers.Queue(Path.Combine(_directory, "queue-" + scenario["name"]));
            var source = new ScriptedSource();
            var module = new AdDcModule(prepared.HostId, AdDcConfig.Parse(scenario["config"]!.AsObject(), catalog), source, catalog);
            string? catchUp = null;
            var items = new JsonArray();
            foreach (var step in scenario["steps"]!.AsArray())
            {
                source.Script = step!["reader"]!.AsObject();
                var now = Iso8601.ParseUtc(step["now"]!.GetValue<string>());
                var result = module.Collect(queue.Captured(AdDcModule.ModuleId), now, step["channel_override"] is null ? null : catchUp);
                catchUp = result.CatchUpChannel;
                var packet = queue.Capture(signer, agentId, result.Sample!, now);
                items.Add(packet.ToJson());
                last = now > last ? now : last;
            }
            configs.Add(new JsonObject { ["agent_id"] = agentId, ["config"] = scenario["config"]!.DeepClone(), ["packets"] = items });
            packets.Add(scenario["name"]!.GetValue<string>());
        }

        foreach (var scenario in Vectors.Load("workstations-scenarios.json").AsArray())
        {
            var agentId = Guid.NewGuid().ToString("D");
            using var queue = Helpers.Queue(Path.Combine(_directory, "ws-" + agentId));
            var source = new ScriptedSource();
            var config = scenario!["config"]!.AsObject();
            var module = new WorkstationsModule(prepared.HostId, WorkstationPolicy.Parse(config), source);
            var items = new JsonArray();
            foreach (var step in scenario["steps"]!.AsArray())
            {
                source.Script = step!["reader"]!.AsObject();
                var now = Iso8601.ParseUtc(step["now"]!.GetValue<string>());
                var result = module.Collect(queue.Captured(WorkstationsModule.ModuleId), now);
                items.Add(queue.Capture(signer, agentId, result.Sample!, now).ToJson());
                last = now > last ? now : last;
            }
            configs.Add(new JsonObject { ["agent_id"] = agentId, ["module_id"] = WorkstationsModule.ModuleId, ["config"] = config.DeepClone(), ["packets"] = items });
            var assignment = PolicyCycleTests.Assignment();
            assignment["assigned_modules"]![0]!["config"] = config.DeepClone();
            var policy = AgentPolicy.Parse(assignment, Helpers.AgentId, catalog);
            var report = new WindowsAuditManager(Path.Combine(_directory, "audit-" + agentId), new PhysicalDurableFiles(), new ExportAuditApi()).Reconcile(policy, last);
            auditReports.Add(new JsonObject { ["config"] = config.DeepClone(), ["report"] = report });
        }
        var export = new JsonObject
        {
            ["public_key_spki_b64"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            ["host_id"] = prepared.HostId,
            ["key_fingerprint"] = prepared.KeyFingerprint,
            ["csr_pem"] = store.CreateCsrPem(),
            ["now"] = Iso8601.Format(last),
            ["streams"] = configs,
            ["audit_reports"] = auditReports,
            ["scenarios"] = packets,
        };
        var target = Environment.GetEnvironmentVariable(InteropFactAttribute.Variable)!;
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "dotnet-packets.json"), export.ToJsonString());
        Assert.True(File.Exists(Path.Combine(target, "dotnet-packets.json")));
    }

    private sealed class ExportAuditApi : IWindowsAuditApi
    {
        public Dictionary<string, int> Query(IReadOnlyCollection<string> guids) => guids.ToDictionary(guid => guid, _ => 0);
        public void Set(IReadOnlyDictionary<string, int> changes) => throw new InvalidOperationException();
        public string Ownership() => "ok";
        public bool IsSystem => false;
        public int? CommandLine { get; set; }
        public string CommandLineOwnership() => "ok";
    }
}
