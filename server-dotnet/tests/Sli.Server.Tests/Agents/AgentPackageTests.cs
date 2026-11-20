using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentPackageTests
{
    [Fact]
    public void FullSignedSourceAgentUploadContractIncludingCrcMatches()
    {
        var fixture=Fixture();Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",fixture["source_commit"]!.GetValue<string>());
        Assert.Equal(4,fixture["cases"]!.AsArray().Count(c=>c!["error"] is null));
        foreach(var item in fixture["cases"]!.AsArray()) {
            byte[] archive=Convert.FromBase64String(item!["archive"]!.GetValue<string>()),trust=Encoding.UTF8.GetBytes(item["trust"]!.GetValue<string>());
            if(item["error"] is not null)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentPackageVerifier.Verify(archive,trust)).Message);
            else {var result=AgentPackageVerifier.Verify(archive,trust);Assert.Equal(item["output"]!["sha256"]!.GetValue<string>(),result.Sha256);Assert.Equal(item["output"]!["version"]!.GetValue<string>(),result.Manifest["version"]!.GetValue<string>());}
        }
    }
    internal static JsonNode Fixture([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-package.json");if(File.Exists(f))return JsonNode.Parse(File.ReadAllBytes(f))!;}throw new IOException();}
}
