using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Ad;
using Xunit;
using PublicationBundle = Sli.Server.Agents.SnapshotPublication.AdContextBundle;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reports/test_computers_v6_collection_contract.py.
public sealed class ComputersV6CollectionContractTests
{
    static readonly Dictionary<string, string> BaseSources = new()
    {
        ["enabled"] = "Enabled", ["last_logon_utc"] = "LastLogonDate",
        ["dns_host_name"] = "DNSHostName", ["operating_system"] = "OperatingSystem",
        ["operating_system_version"] = "OperatingSystemVersion"
    };
    static readonly Dictionary<string, string> ReferenceSources = new(BaseSources)
    {
        ["operating_system_service_pack"] = "OperatingSystemServicePack",
        ["canonical_name"] = "CanonicalName", ["description"] = "Description",
        ["location"] = "Location", ["managed_by"] = "ManagedBy",
        ["password_last_set_utc"] = "PasswordLastSet", ["created_utc"] = "whenCreated",
        ["when_changed_utc"] = "whenChanged", ["service_principal_names"] = "servicePrincipalName",
        ["trusted_for_delegation"] = "TrustedForDelegation",
        ["trusted_to_auth_for_delegation"] = "TrustedToAuthForDelegation",
        ["user_account_control"] = "userAccountControl"
    };

    static JsonObject States(Dictionary<string, string> sources)
    {
        var states = new JsonObject();
        foreach (var (key, source) in sources)
            states[key] = new JsonObject
            {
                ["state"] = key == "dns_host_name" ? "absent_in_source" : "present",
                ["source_attribute"] = source
            };
        return states;
    }

    static JsonObject Bundle(string version = "0.9.0")
    {
        var bundle = JsonNode.Parse("""
            {
              "schema_version":"ad-context-bundle/v1", "source_pack_id":"sli.windows.ad-context",
              "source_pack_version":"0.9.0", "run_id":"00000000-0000-4000-8000-000000000053",
              "mode":"full", "domain":{"sid":"S-1-5-21-100000001-200000002-300000003","dns_name":"example.test"},
              "scope":{"search_base":"DC=example,DC=test","privileged_group_sids":[],"vpn_group_sids":[]},
              "observed_at_utc":"2026-07-20T12:00:00Z",
              "sections":[{"name":"directory_accounts","status":"complete","record_count":1,"duration_ms":10,"error_code":null}],
              "records":[{
                "record_type":"entity", "record_key":"ad:s-1-5-21-100000001-200000002-300000003:00000000-0000-4000-8000-000000000065",
                "section":"directory_accounts", "observed_at_utc":"2026-07-20T12:00:00Z",
                "identity":{"kind":"ad_computer","domain_sid":"S-1-5-21-100000001-200000002-300000003",
                  "object_guid":"00000000-0000-4000-8000-000000000065","object_sid":"S-1-5-21-100000001-200000002-300000003-2101"},
                "attributes":{
                  "display_name":"APP-SRV-01", "sam_account_name":"APP-SRV-01$",
                  "distinguished_name":"CN=APP-SRV-01,OU=Servers,DC=example,DC=test",
                  "canonical_name":"example.test/Servers/APP-SRV-01", "enabled":true,"object_class":"computer",
                  "last_logon_utc":"2026-07-20T12:00:00Z", "created_utc":"2025-01-01T00:00:00Z",
                  "password_last_set_utc":"2026-07-01T00:00:00Z", "when_changed_utc":"2026-07-20T11:00:00Z",
                  "description":"Application server", "location":"Datacenter A",
                  "managed_by":"CN=IT Operations,OU=Groups,DC=example,DC=test",
                  "service_principal_names":["HOST/app-srv-01.example.test"],
                  "trusted_for_delegation":false,"trusted_to_auth_for_delegation":false,
                  "user_account_control":4096,"operating_system_service_pack":"Service Pack 1"
                }
              }]
            }
            """)!.AsObject();
        bundle["source_pack_version"] = version;
        Attributes(bundle)["attribute_states"] = States(BaseSources);
        Attributes(bundle)["computer_reference_attribute_states"] = States(ReferenceSources);
        return bundle;
    }

    static JsonObject Attributes(JsonObject bundle) => bundle["records"]![0]!["attributes"]!.AsObject();
    static JsonObject Normalize(JsonObject bundle, bool publication) =>
        publication ? PublicationBundle.Normalize(bundle) : AdContextBundle.Normalize(bundle);

    [Theory]
    [InlineData(false, "0.9.0")][InlineData(true, "0.9.0")]
    [InlineData(false, "0.10.0")][InlineData(true, "0.10.0")]
    public void Reference_fields_and_exact_provenance_survive_both_normalizers(bool publication, string version)
    {
        var bundle = Bundle(version);
        var expected = Attributes(bundle).DeepClone();
        var actual = Attributes(Normalize(bundle, publication));
        Assert.True(JsonNode.DeepEquals(expected, actual));
        Assert.Equal("example.test/Servers/APP-SRV-01", actual["canonical_name"]!.GetValue<string>());
        Assert.Equal("Datacenter A", actual["location"]!.GetValue<string>());
        Assert.Equal("HOST/app-srv-01.example.test", Assert.Single(actual["service_principal_names"]!.AsArray())!.GetValue<string>());
        Assert.Equal("Service Pack 1", actual["operating_system_service_pack"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(States(ReferenceSources), actual["computer_reference_attribute_states"]));
    }

    public static IEnumerable<object[]> MissingFields => ReferenceSources.Keys.SelectMany(key =>
        new[] { new object[] { false, key }, new object[] { true, key } });

    [Theory][MemberData(nameof(MissingFields))]
    public void Provenance_requires_every_supported_field_including_managed_by(bool publication, string field)
    {
        var bundle = Bundle();
        Attributes(bundle)["computer_reference_attribute_states"]!.AsObject().Remove(field);
        Assert.Equal("agent_ad_family_invalid", Assert.Throws<ProtocolException>(() => Normalize(bundle, publication)).Message);
    }

    [Theory]
    [InlineData(false, "0.9.0")][InlineData(true, "0.9.0")]
    [InlineData(false, "0.10.0")][InlineData(true, "0.10.0")]
    public void New_packs_require_reference_provenance(bool publication, string version)
    {
        var bundle = Bundle(version);
        Attributes(bundle).Remove("computer_reference_attribute_states");
        Assert.Equal("agent_ad_family_invalid", Assert.Throws<ProtocolException>(() => Normalize(bundle, publication)).Message);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void Legacy_pack_accepts_no_reference_provenance_and_preserves_base_states(bool publication)
    {
        var bundle = Bundle("0.8.0");
        Attributes(bundle).Remove("computer_reference_attribute_states");
        var actual = Attributes(Normalize(bundle, publication));
        Assert.False(actual.ContainsKey("computer_reference_attribute_states"));
        Assert.True(JsonNode.DeepEquals(States(BaseSources), actual["attribute_states"]));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public void Reference_provenance_does_not_expand_base_quality_states_or_change_report_quality(bool publication)
    {
        var attrs = Attributes(Normalize(Bundle(), publication));
        Assert.Equal(BaseSources.Keys.Order(), attrs["attribute_states"]!.AsObject().Select(p => p.Key).Order());
        Assert.True(JsonNode.DeepEquals(States(BaseSources), attrs["attribute_states"]));

        // The current report consumes a native computers_v6 object. Reference metadata
        // must remain independent of its source quality, just as it is for v5 in Python.
        using var stream = typeof(ComputersV6CollectionContractTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.snapshot-reference.json")!;
        var raw = JsonNode.Parse(stream)!["families"]!["computers_v6"]!["objects"]![0]!.AsObject();
        raw["dnsHostName"] = null;
        raw["attribute_states"] = attrs["attribute_states"]!.DeepClone();
        var source = new JsonObject { ["domain_id"] = 1, ["fqdn"] = "example.test" };
        var without = AdInventoryRows.Computer(raw, source, "2026-07-20T12:00:00Z", new());
        Assert.NotEmpty(without["quality_issues"]!.AsArray());
        raw["computer_reference_attribute_states"] = attrs["computer_reference_attribute_states"]!.DeepClone();
        var with = AdInventoryRows.Computer(raw, source, "2026-07-20T12:00:00Z", new());
        Assert.True(JsonNode.DeepEquals(without["quality_issues"], with["quality_issues"]));
        Assert.Equal(without["quality_text"]?.ToString(), with["quality_text"]?.ToString());
    }

    static string Read(string relative, [CallerFilePath] string path = "")
    {
        for (var directory = new FileInfo(path).Directory; directory is not null; directory = directory.Parent)
        {
            string file = Path.Combine(directory.FullName, relative);
            if (File.Exists(file)) return File.ReadAllText(file);
        }
        throw new FileNotFoundException(relative);
    }

    [Fact]
    public void Shared_collector_requests_all_reference_properties_and_service_pack_in_base_query()
    {
        string source = Read("scripts/ad_context/Export-AdAuditContextBundle.ps1").Replace("\r\n", "\n");
        Assert.StartsWith("#requires -Version 5.1", source);
        string properties = source.Split("$computerProperties = @(", 2)[1].Split(")\n        $computers", 2)[0];
        foreach (string property in ReferenceSources.Where(p => !BaseSources.ContainsKey(p.Key) && p.Key != "created_utc").Select(p => p.Value))
            Assert.Contains('"' + property + '"', properties);
        string baseProperties = source.Split("$baseComputerProperties = @(", 2)[1].Split(") | Sort-Object -Unique", 2)[0];
        Assert.Contains("\"OperatingSystemServicePack\"", baseProperties);
    }

    [Fact]
    public void Shared_collector_and_source_pack_publish_enriched_version()
    {
        var pack = JsonNode.Parse(Read("config/source_packs/ad_context.json"))!;
        Assert.Equal("0.10.0", pack["version"]!.GetValue<string>());
        Assert.Contains("source_pack_version = \"0.10.0\"", Read("scripts/ad_context/Export-AdAuditContextBundle.ps1"));
    }
}
