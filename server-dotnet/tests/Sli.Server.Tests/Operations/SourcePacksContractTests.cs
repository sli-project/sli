using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Behavioral vectors from tests/events/test_source_packs_contract.py.
public sealed class SourcePacksContractTests
{
    static readonly string[] EventAdapters = ["windows-eventlog-pywin32", "windows-eventlog-powershell"];
    static string[] Strings(JsonNode node) => node.AsArray().Select(x => x!.ToString()).ToArray();
    static KnownBundleNormalizer Normalizer() => new(EventCardSemanticsTests.Repository(), null, null);
    static JsonObject Row(string channel, string provider = "", int id = 140) => new()
    { ["channel"] = channel, ["provider_name"] = provider, ["event_id"] = id };

    [Fact]
    public void ManifestFingerprintIgnoresCheckoutLineEndings()
    {
        const string lf = "{\n  \"schema_version\": 1\n}\n";
        Assert.Equal(OperationsCatalog.ManifestSha256(Encoding.UTF8.GetBytes(lf)),
            OperationsCatalog.ManifestSha256(Encoding.UTF8.GetBytes(lf.Replace("\n", "\r\n"))));
    }

    [Fact]
    public void BundledPacksKeepEventAndContextContracts()
    {
        var catalog = new OperationsCatalog();
        var dc = catalog.GetPack("sli.windows.ad-dc")!;
        Assert.Equal("event", dc["source_kind"]!.ToString());
        Assert.Equal("windows-ad-dc-v1", dc["normalizer"]!.ToString());
        Assert.Equal(EventAdapters, Strings(dc["adapters"]!));
        Assert.Empty(dc["sections"]!.AsArray());
        Assert.Matches("^[0-9a-f]{64}$", dc["manifest_sha256"]!.ToString());
        Assert.Contains(catalog.Packs(), p => JsonNode.DeepEquals(p, dc));
        var context = catalog.GetPack("sli.windows.ad-context")!;
        Assert.Equal("context", context["source_kind"]!.ToString());
        Assert.Equal("0.10.0", context["version"]!.ToString());
        Assert.Empty(context["channels"]!.AsArray());
        Assert.Null(context["normalizer"]);
        Assert.Equal(new[] { "privileged_membership", "directory_accounts", "directory_group_graph", "directory_exact_logon", "vpn_membership", "gpo_governance", "domain_posture", "domain_health" }, Strings(context["sections"]!));
        Assert.True(JsonNode.DeepEquals(context, catalog.ValidateAdapterForPack("ad-context-powershell", "sli.windows.ad-context")));
        Assert.Null(catalog.GetPack("untrusted-module"));
    }

    [Fact]
    public void AdapterRegistryOnlyResolvesBundledDescriptors()
    {
        Assert.Equal(EventAdapters.Append("ad-context-powershell"), OperationsCatalog.Adapters().Select(a => a!["adapter_id"]!.ToString()));
        Assert.Equal("normalized-event-jsonl-v1", OperationsCatalog.GetAdapter(EventAdapters[0])!["output_contract"]!.ToString());
        Assert.Null(OperationsCatalog.GetAdapter("untrusted-module"));
    }

    [Fact]
    public async Task AllSixDcChannelsResolveAndAcceptBothDeclaredAdapters()
    {
        string[] channels = ["Security", "System", "Directory Service", "DNS Server", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational"];
        var catalog = new OperationsCatalog();
        Assert.Equal(channels, Strings(catalog.GetPack("sli.windows.ad-dc")!["channels"]!));
        var normalizer = Normalizer();
        foreach (string channel in channels)
        {
            var card = await normalizer.CardAsync(Row(channel), TestContext.Current.CancellationToken);
            Assert.Equal("sli.windows.ad-dc", card["source_pack"]!["pack_id"]!.ToString());
            Assert.Equal("windows-ad-dc-v1", card["source_pack"]!["normalizer"]!.ToString());
            foreach (string adapter in EventAdapters)
                Assert.Equal("sli.windows.ad-dc", catalog.ValidateAdapterForChannels(adapter, [channel])[0]!["pack_id"]!.ToString());
        }
    }

    [Theory]
    [InlineData("Security", "Microsoft-Windows-Security-Auditing", 4625, "sli.windows.ad-dc")]
    [InlineData("System", "Unrelated-Provider", 140, null)]
    [InlineData("Unrelated/Channel", "", 140, null)]
    [InlineData("Security", "Microsoft-Windows-Security-Auditing", 4663, "sli.windows.file-audit")]
    public async Task EventOwnershipRequiresExactProviderWhenPresent(string channel, string provider, int id, string? expected)
    {
        var card = await Normalizer().CardAsync(Row(channel, provider, id), TestContext.Current.CancellationToken);
        Assert.Equal(expected, card["source_pack"]?["pack_id"]?.ToString());
    }

    [Fact]
    public void CollectionMetadataIsDeduplicatedSortedAndExcludesPacketOnlyPack()
    {
        var catalog = new OperationsCatalog();
        var metadata = catalog.MetadataForChannels(["Security", "System", "Unrelated/Channel", "Security"]);
        Assert.Equal(new[] { "sli.windows.ad-dc", "sli.windows.vpn-radius", "sli.windows.workstations" }, metadata.Select(p => p!["pack_id"]!.ToString()));
        var expectedDc = JsonNode.Parse("""
            {"pack_id":"sli.windows.ad-dc","version":"1.4.0","display_name":"Windows Active Directory Domain Controller","source_kind":"event","channels":["Security","System","Directory Service","DNS Server","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TaskScheduler/Operational"],"sections":[],"adapters":["windows-eventlog-pywin32","windows-eventlog-powershell"],"entity_contract":"catalog-field-roles-v1","analysis_contract":"catalog-semantics-v1","normalizer":"windows-ad-dc-v1"}
            """)!;
        var expectedRadius = JsonNode.Parse("""
            {"pack_id":"sli.windows.vpn-radius","version":"0.1.0","display_name":"Windows NPS and VPN/RADIUS","source_kind":"event","channels":["Security"],"sections":[],"adapters":["windows-eventlog-pywin32","windows-eventlog-powershell"],"entity_contract":"identity-ladder-v1","analysis_contract":"radius-authentication-observation-v1","normalizer":"windows-nps-radius-v1"}
            """)!;
        foreach (var pair in new[] { (expectedDc, metadata[0]!), (expectedRadius, metadata[1]!) })
        {
            var actual = pair.Item2.DeepClone().AsObject();
            Assert.Matches("^[0-9a-f]{64}$", actual["manifest_sha256"]!.ToString());
            actual.Remove("manifest_sha256");
            Assert.True(JsonNode.DeepEquals(pair.Item1, actual), actual.ToJsonString());
        }
        foreach (string adapter in EventAdapters)
        {
            Assert.True(JsonNode.DeepEquals(metadata, catalog.ValidateAdapterForChannels(adapter, ["Security", "System"])));
            Assert.Contains("not declared by source pack sli.windows.file-audit", Assert.Throws<ArgumentException>(() => catalog.ValidateAdapterForPack(adapter, "sli.windows.file-audit")).Message);
        }
        Assert.Empty(catalog.GetPack("sli.windows.file-audit")!["adapters"]!.AsArray());
        Assert.Contains("sli.windows.ad-dc", Assert.Throws<ArgumentException>(() => catalog.ValidateAdapterForChannels("not-a-dc-adapter", ["Security"])).Message);
        Assert.Empty(catalog.ValidateAdapterForChannels("not-a-dc-adapter", ["Unrelated/Channel"]));
        Assert.Contains("unknown source pack", Assert.Throws<ArgumentException>(() => catalog.ValidateAdapterForPack(EventAdapters[0], "unknown")).Message);
    }

    [Fact]
    public void CatalogSelectionRetainsLegacyFallback()
    {
        var normalizer = Normalizer();
        Assert.Equal(new[] { "event_catalog.json" }, normalizer.Catalogs(Row("Unrelated/Channel"), TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "event_catalog.json" }, normalizer.Catalogs(Row("Security"), TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "event_catalog.json" }, normalizer.Catalogs(Row("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("powershell", false, "-CollectMessage:$false", "-Channels")]
    [InlineData("powershell", true, "-CollectMessage:$true", "-Channels")]
    [InlineData("python", false, "false", "--channels")]
    public void WindowsCollectorKeepsBackendBooleanAndSingleCsvChannels(string backend, bool collectMessage, string booleanArgument, string channelsArgument)
    {
        var request = new WindowsEventLogRequest(backend, "python", "collect.py", "collect.ps1", "192.0.2.1", "DC1", 1, 50000, 300, "raw", ["Security", "System"], "current", collectMessage);
        var command = SourceAdapterCommands.WindowsEventLog(request);
        Assert.Contains(booleanArgument, command);
        Assert.Equal("Security,System", command[command.IndexOf(channelsArgument) + 1]);
        Assert.Equal(1, command.Count(c => c == channelsArgument));
        if (backend == "powershell")
            Assert.Equal(new[] { "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "collect.ps1", "-ComputerName", "192.0.2.1", "-SourceName", "DC1", "-Hours", "1", "-MaxEventsPerChannel", "50000", "-ChannelTimeoutSeconds", "300", "-OutputRoot", "raw", booleanArgument, "-RequestedCollectionMode", "current", "-Channels", "Security,System" }, command);
        else
            Assert.Equal(new[] { "python", "collect.py", "--computer-name", "192.0.2.1", "--source-name", "DC1", "--hours", "1", "--max-events-per-channel", "50000", "--channel-timeout-seconds", "300", "--output-root", "raw", "--channels", "Security,System", "--collection-mode", "current", "--collect-message", booleanArgument }, command);
        Assert.Equal(backend == "python" ? EventAdapters[0] : EventAdapters[1], SourceAdapterCommands.AdapterIdForBackend(backend));
        Assert.Throws<ArgumentException>(() => SourceAdapterCommands.AdapterIdForBackend("untrusted-module"));
    }

    static AdContextRequest Context(string section) => new(
        OperatingSystem.IsWindows() ? @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" : "/usr/bin/pwsh",
        "bundle.json", "00000000-0000-4000-8000-000000000046", "dc1.example.test", "DC=example,DC=test", "example.test", [section]);

    [Fact]
    public void AdContextBuildsOnlyRepositoryScriptWithAllowlistedExecutable()
    {
        var request = Context("privileged_membership") with { PrivilegedGroups = ["S-1-5-21-100000001-200000002-300000003-512"] };
        var command = SourceAdapterCommands.AdContext(request, EventCardSemanticsTests.Repository());
        string script = command[command.IndexOf("-File") + 1];
        Assert.Equal("Export-AdContextBundle.ps1", Path.GetFileName(script));
        Assert.True(File.Exists(script));
        Assert.Equal("dc1.example.test", command[command.IndexOf("-DirectoryServer") + 1]);
        Assert.Equal(request.PrivilegedGroups[0], command[command.IndexOf("-PrivilegedGroups") + 1]);
        Assert.Equal("2000", command[command.IndexOf("-MaxRecords") + 1]);
        Assert.Contains("allowlisted", Assert.Throws<ArgumentException>(() => SourceAdapterCommands.AdContext(request with { PowershellExecutable = "evil.exe" }, EventCardSemanticsTests.Repository())).Message);
    }

    [Fact]
    public void DirectoryContextKeepsTechnicalInventoryInSameCommand()
    {
        var command = SourceAdapterCommands.AdContext(Context("directory_accounts") with { TechnicalServers = ["DC1", "DC2"], TechnicalInventoryTimeoutSeconds = 20 }, EventCardSemanticsTests.Repository());
        Assert.Equal("Export-AdAuditContextBundle.ps1", Path.GetFileName(command[command.IndexOf("-File") + 1]));
        Assert.Equal("DC1,DC2", command[command.IndexOf("-TechnicalServers") + 1]);
        Assert.Equal("20", command[command.IndexOf("-TechnicalInventoryTimeoutSeconds") + 1]);
    }

    [Theory]
    [InlineData("relative_executable", "allowlisted")]
    [InlineData("unknown_section", "unsupported collection section")]
    [InlineData("multiple_sections", "exactly one bounded section")]
    [InlineData("missing_group", "exact privileged group SIDs")]
    [InlineData("invalid_group", "exact privileged group SIDs")]
    [InlineData("wrong_section_group", "privileged groups require")]
    [InlineData("invalid_server", "technical server inventory")]
    [InlineData("wrong_section_server", "requires the directory_accounts section")]
    [InlineData("directory_limits", "independent directory limits")]
    public void AdContextRetainsReferenceInputValidation(string change, string error)
    {
        var request = Context("directory_accounts");
        request = change switch
        {
            "relative_executable" => request with { PowershellExecutable = "pwsh" },
            "unknown_section" => request with { Sections = ["untrusted-module"] },
            "multiple_sections" => request with { Sections = ["directory_accounts", "domain_health"] },
            "missing_group" => request with { Sections = ["privileged_membership"] },
            "invalid_group" => request with { Sections = ["privileged_membership"], PrivilegedGroups = ["group; command"] },
            "wrong_section_group" => request with { PrivilegedGroups = ["S-1-5-21-100000001-200000002-300000003-512"] },
            "invalid_server" => request with { TechnicalServers = ["DC1; command"] },
            "wrong_section_server" => request with { Sections = ["domain_health"], TechnicalServers = ["DC1"] },
            "directory_limits" => request with { MaxDirectoryUsers = 1500, MaxDirectoryComputers = 1500 },
            _ => throw new ArgumentException(change)
        };
        Assert.Contains(error, Assert.Throws<ArgumentException>(() => SourceAdapterCommands.AdContext(request, EventCardSemanticsTests.Repository())).Message);
    }
}
