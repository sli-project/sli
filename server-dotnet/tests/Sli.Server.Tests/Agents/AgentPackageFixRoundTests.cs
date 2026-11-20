using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentPackageFixRoundTests
{
    [Fact]
    public void SignedStringVersionBoundsPreserveSourceFailurePhase()=>Compare("124");
    [Fact]
    public void SignedWindowsDeviceNamesMatchEverySourceStemAndNeighbors()=>Compare("125");
    private static void Compare(string scope)
    {
        var fixture=Fixture();Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",fixture["source_commit"]!.GetValue<string>());
        foreach(var item in fixture["cases"]!.AsArray().Where(i=>i!["scope"]!.GetValue<string>()==scope)) {
            byte[] raw=Convert.FromBase64String(item!["archive"]!.GetValue<string>()),trust=Encoding.UTF8.GetBytes(item["trust"]!.GetValue<string>());int status=item["status"]!.GetValue<int>();
            if(status==200)Assert.Equal(item["output"]!["sha256"]!.GetValue<string>(),AgentPackageVerifier.Verify(raw,trust).Sha256);
            else if(status==400)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentPackageVerifier.Verify(raw,trust)).Message);
            else Assert.Equal("AgentPackageVersionLimitException",Assert.ThrowsAny<Exception>(()=>AgentPackageVerifier.Verify(raw,trust)).GetType().Name);
        }
    }
    [Fact]
    public async Task SignedSourceRejectionsOccurBeforeTheProducerTouchesItsDatabase()
    {
        string path=Path.Combine(Path.GetTempPath(),"sli-agent-package-r1-"+Guid.NewGuid().ToString("N")+".json");var fixture=Fixture();var ct=TestContext.Current.CancellationToken;
        try {
            foreach(var item in fixture["cases"]!.AsArray().Where(i=>i!["status"]!.GetValue<int>()!=200)) {
                await File.WriteAllTextAsync(path,item!["trust"]!.GetValue<string>(),ct);
                var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AgentUpdateTrustFile"]=path }).Build();
                var producer=new AgentUpdateAdministration(new NoAudit(),config);byte[] raw=Convert.FromBase64String(item["archive"]!.GetValue<string>());
                // No connection/transaction can execute: exact verifier rejection
                // must precede constructing/executing the immutable package INSERT.
                if(item["status"]!.GetValue<int>()==400)Assert.Equal("agent_package_verification_failed",(await Assert.ThrowsAsync<AgentControlException>(()=>producer.UploadAsync(null!,null!,raw,"synthetic:r1",ct))).Message);
                else Assert.Equal("AgentPackageVersionLimitException",(await Assert.ThrowsAnyAsync<Exception>(()=>producer.UploadAsync(null!,null!,raw,"synthetic:r1",ct))).GetType().Name);
            }
        } finally {File.Delete(path);}
    }
    private sealed class NoAudit:IAgentControlAudit
    {public Task AppendAsync(Npgsql.NpgsqlConnection db,Npgsql.NpgsqlTransaction tx,string action,string actor,string target,object details,CancellationToken ct)=>throw new InvalidOperationException("Unexpected audit before signed package rejection");}
    private static JsonNode Fixture([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-package-fix-r1.json");if(File.Exists(f))return JsonNode.Parse(File.ReadAllBytes(f))!;}throw new IOException();}
}
