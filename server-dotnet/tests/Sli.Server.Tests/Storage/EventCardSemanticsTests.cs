using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EventCardSemanticsTests
{
    internal static string Repository()
    {
        var directory=new DirectoryInfo(AppContext.BaseDirectory);
        while(directory is not null && !Directory.Exists(Path.Combine(directory.FullName,"config","source_packs"))) directory=directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException();
    }
    [Fact] public async Task Cards_match_python_for_all_bundled_sources_context_and_watch()
    {
        using var stream=typeof(EventCardSemanticsTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Storage.event-card-vectors.json")!;
        var vectors=JsonNode.Parse(stream)!.AsArray();
        var normalizer=new KnownBundleNormalizer(Repository(),null,null);
        foreach(var vector in vectors)
        {
            var actual=await normalizer.CardAsync(vector!["item"]!.AsObject(),TestContext.Current.CancellationToken);
            Assert.True(JsonNode.DeepEquals(vector["expected"],actual),vector["item"]!.ToJsonString()+"\n"+actual.ToJsonString());
        }
        var projected=await normalizer.ProjectAsync(new JsonObject { ["event_id"]=4625,["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing" },TestContext.Current.CancellationToken);
        Assert.Equal("Security:Microsoft-Windows-Security-Auditing:4625.title",projected["semantics"]!["title_code"]!.GetValue<string>());
    }
    [Fact] public async Task Bundle_files_are_snapshotted_once_per_request()
    {
        using var fixture=new BundleFixture();
        var normalizer=new KnownBundleNormalizer(fixture.Root,null,null);
        var row=new JsonObject { ["event_id"]=4625,["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing" };
        var first=await normalizer.CardAsync(row,TestContext.Current.CancellationToken);
        // The next row uses the verified snapshot, even if files change mid-request.
        File.WriteAllText(Path.Combine(fixture.Root,"config","event_catalog.json"),"{}");
        var second=await normalizer.CardAsync(row,TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(first,second));
        var nextRequest=new KnownBundleNormalizer(fixture.Root,null,null);
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>nextRequest.CardAsync(row,TestContext.Current.CancellationToken));
        Assert.Equal("source_normalizer_bundle_unsupported",error.Message);
    }
    sealed class BundleFixture : IDisposable
    {
        internal string Root {get;}=Path.Combine(Path.GetTempPath(),"sli-bundle-"+Guid.NewGuid().ToString("N"));
        internal BundleFixture()
        {
            var paths=new List<string>{"config/event_catalog.json","config/file_audit_event_catalog.json","config/radius_event_catalog.json","config/workstations_event_catalog.json","config/plugin_architecture_v3.json","config/plugin_settings_schema_v1.json","config/i18n/server.ru.json","config/i18n/server.en.json"};
            paths.AddRange(new[]{"ad_context","dc","file_audit","radius","workstations"}.Select(n=>"config/source_packs/"+n+".json"));
            foreach(string plugin in new[]{"sli.ad","sli.file-audit","sli.remote-access"})
            {
                paths.Add("config/plugin_packages/v3/"+plugin+".json");
                paths.Add("config/plugin_settings_schema/"+plugin+".settings.json");
            }
            foreach(string path in paths)
            {
                string target=Path.Combine(Root,path); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(Path.Combine(Repository(),path),target);
            }
            foreach(string plugin in new[]{"sli.ad","sli.file-audit"})
            {
                var settings=JsonNode.Parse(File.ReadAllText(Path.Combine(Root,"config/plugin_settings_schema/"+plugin+".settings.json")))!;
                Directory.CreateDirectory(Path.Combine(Root,settings["migration_directory"]!.GetValue<string>()));
            }
        }
        public void Dispose()=>Directory.Delete(Root,true);
    }
}
