using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests;
using Sli.Server.Agents.Registry;

const string Domain = "directory.invalid";
const string Dc = "dc-quiet.directory.invalid";
const string DomainSid = "S-1-5-21-100000001-200000002-300000003";
const int EventId = 4624;

try
{
    var mode = args[0];
    var input = mode == "preflight" ? null : JsonNode.Parse(Console.In.ReadToEnd())!.AsObject();
    var host = input?["host"]?.GetValue<string>() ?? Guid.NewGuid().ToString("D");
    var agent = input?["agent"]?.GetValue<string>() ?? Guid.NewGuid().ToString("D");
    var now = input is null ? DateTimeOffset.UtcNow : Iso8601.ParseUtc(input["now"]!.GetValue<string>());
    var catalog = EventCatalog.Load();
    var settings = input is null ? DefaultAssignment(host) : input["config"]!.AsObject();

    if (input is not null && !JsonNode.DeepEquals(settings, JsonNode.Parse(File.ReadAllText(args[2]))))
        throw new InvalidOperationException("registered_ad_dc_assignment_differs_from_preflight");

    // Reuse the existing .NET scenario, scripted Event Log source and release collector.
    var scenarios = JsonNode.Parse(File.ReadAllText(args[1]))!.AsArray();
    var reader = scenarios.Single(node => node!["name"]!.GetValue<string>() == "security-initial-window-all")!
        ["steps"]![0]!["reader"]!.DeepClone().AsObject();
    var row = reader["rows"]!.AsArray().Single()!.AsObject();
    var original = row["xml"]!.GetValue<string>();
    Require(original.Contains("<EventID>4624</EventID>", StringComparison.Ordinal), "unexpected_scenario_event");
    row["xml"] = original.Replace("2026-10-07T00:00:00.1234567Z", Iso8601.Format(now.AddSeconds(-2)), StringComparison.Ordinal)
        .Replace("dc1.example.test", Dc, StringComparison.Ordinal)
        .Replace("fixture-account", "object-1", StringComparison.Ordinal)
        .Replace("</EventData>", $"<Data Name='TargetUserSid'>{DomainSid}-100001</Data>"
            + "<Data Name='LogonType'>3</Data><Data Name='IpAddress'>192.0.2.42</Data></EventData>",
            StringComparison.Ordinal);
    var source = new ScriptedSource { Script = reader };
    var configuration = AdDcConfig.Parse(settings, catalog);
    Require(configuration.AllowEventIds?.Contains(EventId) == true, "registered_ad_dc_assignment_excludes_4624");
    var sample = new AdDcModule(host, configuration, source, catalog).Collect(null, now, "Security").Sample
        ?? throw new InvalidOperationException("missing_security_sample");
    Require(source.Calls.Count == 1 && source.Calls[0].Channel == "Security", "unexpected_event_log_read");
    Require(sample.Payload["records"] is JsonArray { Count: 1 }, "expected_one_security_record");

    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    if (input is not null)
        key.ImportFromPem(File.ReadAllText(args[3]));
    var packet = Packets.Make(new EcdsaPacketSigner(key), agent, 1, sample, now);
    var wire = packet.ToCanonical();
    var serialized = JsonNode.Parse(wire)!;
    var records = serialized["payload"]!["records"]!.AsArray();
    Require(records.Single()!["payload"]!["event_id"]!.GetValue<int>() == EventId
        && PacketVerifier.Verify(serialized, key).RecordCount == 1, "unexpected_signed_record");

    if (mode == "preflight")
    {
        File.WriteAllText(args[2], CanonicalJson.Serialize(settings));
        Console.WriteLine("P1_EVIDENCE quiet_dotnet_preflight=" + new JsonObject
        {
            ["allow_event_ids"] = configuration.AllowEventIds!.Count,
            ["assignment_sha256"] = Packets.Digest(settings),
            ["serialized_records"] = records.Count,
            ["event_id"] = EventId,
        }.ToJsonString());
    }
    else
        Console.WriteLine(wire);
    return 0;
}
catch (Exception exception)
{
    string reason = exception switch
    {
        AgentException error => error.Code,
        ProtocolException error => error.Code,
        InvalidOperationException error => error.Message,
        _ => exception.GetType().Name,
    };
    // A failed proof still identifies its stage without emitting a key or packet body.
    if (!System.Text.RegularExpressions.Regex.IsMatch(reason, @"\A[A-Za-z0-9_.-]{1,100}\z"))
        reason = exception.GetType().Name;
    Console.Error.WriteLine("P1_EVIDENCE quiet_dotnet_error=" + reason);
    return 1;
}

static JsonObject DefaultAssignment(string host)
{
    // Use the exact method called by enrollment, including the unmodified beta allow-list.
    var method = typeof(AgentEnrollmentService).GetMethod("DefaultModules", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("missing_enrollment_assignment_builder");
    var domain = new JsonObject { ["domain_sid"] = DomainSid, ["fqdn"] = Domain };
    var modules = (JsonArray)method.Invoke(null, new object?[] { null, "domain_controller", Guid.Parse(host), Dc, domain, "UTC" })!;
    return modules.Select(node => node!.AsObject()).Single(node => node["module_id"]!.GetValue<string>() == AdDcModule.ModuleId)
        ["config"]!.AsObject();
}

static void Require(bool valid, string message)
{
    if (!valid)
        throw new InvalidOperationException(message);
}
