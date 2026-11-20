using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class PythonIsoDateTimeTests
{
    [Fact]
    public void MatchesPython314SourceVectors()
    {
        var file=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(SourcePath())!,"..","vectors","python-iso-source.json"));
        var fixtures=JsonNode.Parse(File.ReadAllBytes(file))!.AsArray(); Assert.Equal(69,fixtures.Count);
        foreach(var item in fixtures)
        {
            var row=item!.AsObject(); string text=row["text"]!.GetValue<string>(); bool expected=row["valid"]!.GetValue<bool>();
            bool parsed=PythonIsoDateTime.TryParse(text,out var result);
            Assert.True(parsed==expected,$"parse {text}");
            Assert.True(PythonIsoDateTime.TryParseUtc(text,out _)==row["utc_source"]!.GetValue<bool>(),$"UTC source {text}");
            if(!parsed) continue;
            Assert.True(result.IsAware==row["aware"]!.GetValue<bool>(),$"awareness {text}");
            Assert.Equal(row["wall"]!.GetValue<string>(),result.WallTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff",CultureInfo.InvariantCulture));
            Assert.Equal(row["offset_us"]?.GetValue<long>(),result.Offset?.Ticks/10);
            string? utc=row["utc"]?.GetValue<string>(); bool converted=result.TryToUtc(out var actual);
            Assert.True(converted==(utc is not null),$"UTC convert {text}");
            if(converted) Assert.Equal(utc,actual.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff",CultureInfo.InvariantCulture));
        }
    }
    private static string SourcePath([CallerFilePath] string path="")=>path;
}
