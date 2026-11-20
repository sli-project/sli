using System.Reflection;
using System.Text.Json.Nodes;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditManifestTests
{
    private static bool Validate(string root,string plugin)
    {
        var method=typeof(FileAuditResult).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditManifestValidator")!.GetMethod("Installed",BindingFlags.NonPublic|BindingFlags.Static)!;
        try { return (bool)method.Invoke(null,[root,plugin])!; } catch(TargetInvocationException e) when(e.InnerException is InvalidDataException) { return false; }
    }
    [Fact]
    public void BundledManifestsRequireFullShapeUniqueKeysAndSettings()
    {
        var repo=new DirectoryInfo(AppContext.BaseDirectory);while(repo is not null && !File.Exists(Path.Combine(repo.FullName,"config","plugin_architecture_v3.json"))) repo=repo.Parent;Assert.NotNull(repo);
        string root=Path.Combine(Path.GetTempPath(),"sli-manifest-"+Guid.NewGuid().ToString("N"));
        try
        {
            foreach(var name in new[]{"plugin_architecture_v3.json","plugin_settings_schema_v1.json","plugin_packages/v3/sli.file-audit.json","plugin_packages/v3/sli.ad.json","plugin_settings_schema/sli.file-audit.settings.json","plugin_settings_schema/sli.ad.settings.json","i18n/server.ru.json","i18n/server.en.json"})
            { var target=Path.Combine(root,"config",name);Directory.CreateDirectory(Path.GetDirectoryName(target)!);File.Copy(Path.Combine(repo!.FullName,"config",name),target); }
            Directory.CreateDirectory(Path.Combine(root,"config","postgres_migrations"));
            Assert.True(Validate(root,"sli.file-audit"));Assert.True(Validate(root,"sli.ad"));
            string adSettings=Path.Combine(root,"config","plugin_settings_schema","sli.ad.settings.json");string adOriginal=File.ReadAllText(adSettings);File.WriteAllText(adSettings,JsonNode.Parse(adOriginal)!.ToJsonString());Assert.True(Validate(root,"sli.ad"));var altered=JsonNode.Parse(adOriginal)!.AsObject();altered["settings"]!["properties"]!["reports.domain_fqdn"]!["pattern"]="\\p{L}+";File.WriteAllText(adSettings,altered.ToJsonString());Assert.False(Validate(root,"sli.ad"));File.WriteAllText(adSettings,adOriginal);
            string manifest=Path.Combine(root,"config","plugin_packages","v3","sli.file-audit.json"),original=File.ReadAllText(manifest);
            File.WriteAllText(manifest,JsonNode.Parse(original)!.ToJsonString());Assert.True(Validate(root,"sli.file-audit"));
            File.WriteAllText(manifest,"""{"schema_version":3,"plugin_id":"sli.file-audit","plugin_version":"1.0.0","trust":"bundled_reviewed_only"}""");Assert.False(Validate(root,"sli.file-audit"));
            File.WriteAllText(manifest,original.Replace("\"schema_version\": 3,","\"schema_version\": 3, \"schema_version\": 3,"));Assert.False(Validate(root,"sli.file-audit"));
            var unsupported=JsonNode.Parse(original)!.AsObject();unsupported["plugin_version"]="1.0.1";File.WriteAllText(manifest,unsupported.ToJsonString());Assert.False(Validate(root,"sli.file-audit"));
            var bad=JsonNode.Parse(original)!.AsObject();bad["core_api"]!["minimum"]="4.0.0";File.WriteAllText(manifest,bad.ToJsonString());Assert.False(Validate(root,"sli.file-audit"));
            File.WriteAllText(manifest,original);string metadata=Path.Combine(root,"config","plugin_settings_schema","sli.file-audit.settings.json");var settings=JsonNode.Parse(File.ReadAllText(metadata))!.AsObject();settings.Remove("permissions");File.WriteAllText(metadata,settings.ToJsonString());Assert.False(Validate(root,"sli.file-audit"));
            string ad=Path.Combine(root,"config","plugin_packages","v3","sli.ad.json");File.WriteAllText(ad,"""{"plugin_id":"sli.ad"}""");Assert.False(Validate(root,"sli.ad"));
        }
        finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }
}


