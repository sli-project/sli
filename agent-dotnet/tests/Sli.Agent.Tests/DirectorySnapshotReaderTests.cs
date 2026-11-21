using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Windows;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class DirectorySnapshotReaderTests
{
    private const string Domain = "example.test";
    private const string LocalDc = "dc.example.test";
    private const string GpoGuid = "440C6E5E-25AA-4BC0-A94C-5442EEF94A1B";
    private const string RootDse = """
        function New-Entry {
            if ($server -ne 'dc.example.test') { throw 'Unexpected LDAP endpoint' }
            $entry = [pscustomobject]@{ Properties = @{
                defaultNamingContext = @('DC=example,DC=test')
                configurationNamingContext = @('CN=Configuration,DC=example,DC=test')
                schemaNamingContext = @('CN=Schema,CN=Configuration,DC=example,DC=test')
                rootDomainNamingContext = @('DC=example,DC=test')
                dnsHostName = @('dc.example.test')
            } }
            $entry | Add-Member ScriptMethod RefreshCache { }
            $entry | Add-Member ScriptMethod Dispose { }
            $entry
        }
        """;

    [Fact]
    public async Task EmbeddedAdCollectorReadsPolicyAndProducesInventoryThroughTheLocalDcEndpoint()
    {
        if (!OperatingSystem.IsWindows()) return;
        var policy = Policy();
        var request = DirectorySnapshotReader.Request(policy);
        request["local_dc"] = LocalDc;
        ReplaceFunction(request, "New-Entry", RootDse);
        ReplaceFunction(request, "Search-Rows", """
            function Search-Rows([string]$Dc, [string]$Base, [string]$Filter) {
                switch -Wildcard ($Filter) {
                    '(objectClass=domainDNS)' { @{ objectsid=$policy.domain_sid; objectguid='440c6e5e-25aa-4bc0-a94c-5442eef94a10'; objectclass=@('domainDNS') } }
                    '*objectCategory=person*' { @{ objectguid='440c6e5e-25aa-4bc0-a94c-5442eef94a11'; objectclass=@('user'); name='Fixture User' } }
                    '*objectCategory=computer*ManagedServiceAccount*' { @{ objectguid='440c6e5e-25aa-4bc0-a94c-5442eef94a12'; objectclass=@('computer'); name='Fixture Computer' } }
                    '(objectCategory=group)' { @{ objectguid='440c6e5e-25aa-4bc0-a94c-5442eef94a13'; objectclass=@('group'); name='Fixture Group' } }
                }
            }
            """);
        var result = await DirectorySnapshotReader.RunCollectorAsync(policy.ModuleId, request, CancellationToken.None);
        Assert.Equal(LocalDc, result["query_dc"]!.GetValue<string>());
        var families = AdSnapshotModule.Normalize(result, policy, Helpers.Now);
        var kinds = families["ad_context_base"].Data["records"]!.AsArray().Select(row => row?["identity"]?["kind"]?.GetValue<string>()).ToArray();
        Assert.Contains("ad_user", kinds);
        Assert.Contains("ad_computer", kinds);
        Assert.Contains("ad_group", kinds);
    }

    [Theory]
    [InlineData("example.test", "observed", 131075)]
    [InlineData("different.example.test", "parse_error", null)]
    public async Task EmbeddedGpoCollectorInventoriesPolicyWithoutGpmcAndConfinesLocalGpt(string uncHost, string state, int? version)
    {
        if (!OperatingSystem.IsWindows()) return;
        var sysvol = Helpers.TempDirectory();
        try
        {
            var gptDir = Path.Combine(sysvol, Domain, "Policies", "{" + GpoGuid + "}");
            Directory.CreateDirectory(gptDir);
            File.WriteAllText(Path.Combine(gptDir, "GPT.INI"), "[General]\nVersion=131075\n");
            var policy = Policy("gpo-full");
            var request = DirectorySnapshotReader.Request(policy);
            request["local_dc"] = LocalDc;
            request["local_sysvol"] = sysvol;
            ReplaceFunction(request, "Import-GroupPolicyCommands", "function Import-GroupPolicyCommands { return $false }");
            ReplaceFunction(request, "New-Entry", RootDse);
            ReplaceFunction(request, "Search", $$"""
                function Search([string]$Base, [string]$Filter) {
                    if ($script:overflow) { return }
                    if ($Filter -eq '(objectClass=domainDNS)') {
                        @{ objectsid=$policy.domain_sid; distinguishedname='DC=example,DC=test'; name='example' }
                    } elseif ($Filter -eq '(objectClass=groupPolicyContainer)') {
                        @{
                            name='{ {{GpoGuid}} }'.Replace(' ', '')
                            objectguid='{{GpoGuid}}'
                            distinguishedname='CN={ {{GpoGuid}} },CN=Policies,CN=System,DC=example,DC=test'.Replace(' ', '')
                            gpcfilesyspath='\\{{uncHost}}\SYSVOL\example.test\Policies\{ {{GpoGuid}} }'.Replace(' ', '')
                            displayname='Fixture GPO'
                        }
                    }
                }
                """);
            var result = await DirectorySnapshotReader.RunCollectorAsync(policy.ModuleId, request, CancellationToken.None);
            var families = GpoSnapshotModule.Normalize(result, policy);
            Assert.Single(families["ad_gpo_governance"].Data["records"]!.AsArray());
            var snapshot = families["gpo_v2"].Data;
            Assert.Equal("partial", snapshot["collection_status"]!.GetValue<string>());
            var row = Assert.Single(snapshot["gpos"]!.AsArray())!;
            Assert.Equal("not_collected", row["source_states"]!["report"]!["status"]!.GetValue<string>());
            Assert.Equal(state, row["gpt"]!["status"]!.GetValue<string>());
            Assert.Equal(version, row["gpt"]!["ini_version"]?.GetValue<int>());
        }
        finally { Directory.Delete(sysvol, recursive: true); }
    }

    [Fact]
    public async Task CollectorMapsNativeFailuresWithoutIncludingExceptionText()
    {
        if (!OperatingSystem.IsWindows()) return;
        var policy = Policy();
        var request = DirectorySnapshotReader.Request(policy);
        ReplaceFunction(request, "New-Entry", """
            function New-Entry {
                throw [ComponentModel.Win32Exception]::new(5, 'fixture private LDAP details')
            }
            """);
        var error = await Assert.ThrowsAsync<SnapshotCaptureException>(() =>
            DirectorySnapshotReader.RunCollectorAsync(policy.ModuleId, request, CancellationToken.None));
        Assert.Equal("agent_ad_ldap_root_dse_failed", error.Code);
        Assert.Contains("LDAP RootDSE", error.Detail);
        Assert.Contains("Win32Exception, HResult 0x80004005, native error 5", error.Detail);
        Assert.DoesNotContain("fixture private", error.Detail);
    }

    private static SnapshotPolicy Policy(string name = "ad-full")
    {
        var policy = SnapshotModuleTests.Policy(name);
        var config = policy.Config;
        config["domain_dns"] = Domain;
        config["dc"] = new JsonArray();
        config["search_bases"] = new JsonArray();
        config["expensive_flags"] = new JsonObject();
        return SnapshotPolicy.Parse(policy.ModuleId, config);
    }

    private static void ReplaceFunction(JsonObject request, string name, string replacement)
    {
        var collector = request["collector"]!.GetValue<string>();
        var function = Regex.Match(collector, $"(?ms)^function {Regex.Escape(name)}\\b.*?^}}[ \\t]*\\r?$");
        Assert.True(function.Success);
        request["collector"] = collector.Remove(function.Index, function.Length).Insert(function.Index, replacement);
    }
}
