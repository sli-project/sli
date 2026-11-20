using System.Text.Json.Nodes;

namespace Sli.Agent.Tests.Support;

/// <summary>Reference data produced by the Python implementation (<c>agent-dotnet/tools/make_vectors.py</c>).</summary>
public static class Vectors
{
    public static JsonNode Load(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "vectors", name);
        return JsonNode.Parse(File.ReadAllText(path))!;
    }
}
