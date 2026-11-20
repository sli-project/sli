using System.Text.Json.Nodes;
using static Sli.Server.Agents.Updates.AgentPackageJson;
namespace Sli.Server.Agents.Updates;
internal sealed record AgentPackageFile(string Path,long Size,string Sha256);
internal static class AgentPackageManifest
{
    private static readonly HashSet<string> Shared=new(StringComparer.Ordinal) {
        "server/__init__.py","server/sli/__init__.py","server/sli/release_package.py","server/sli/storage/__init__.py","server/sli/storage/xml_safety.py",
        "config/event_catalog.json","scripts/ad_context/GpoReportContract.psm1","config/source_packs/dc.json","config/source_packs/workstations.json","config/source_packs/radius.json" };
    private static readonly HashSet<string> Required=Shared.Concat(new[]{"__init__","runtime","config","enrollment","envelope","modules","protection","spool","transport","updates","workstations","policies","probe","ad_dc","snapshot_stream","ad_snapshot","ad_snapshot_security","ad_snapshot_computers","gpo_snapshot","gpo_privacy"}.Select(n=>"sli_agent/"+n+".py"))
        .Concat(new[]{"sli_agent/ad_snapshot.ps1","sli_agent/gpo_snapshot.ps1","sli_collect/__init__.py","sli_collect/eventlog.py","sli_collect/packets.py","sli_collect/bookmarked_eventlog.py"}).ToHashSet(StringComparer.Ordinal);
    internal static IReadOnlyList<AgentPackageFile> Validate(JsonObject manifest)
    {
        Fields(manifest,"schema_version","package_type","package_id","version","platform","source_commit","build_id","minimum_updater","compatibility","migrations","deletions","restart_profile","files","component","from_version","to_version","image","required_free_disk","compose_delta","config_delta");
        Need(Integer(manifest["schema_version"])==2 && Text(manifest["package_type"])=="plugin-update" && Text(manifest["package_id"])=="sli.agent" && Text(manifest["component"])=="agent" && Text(manifest["restart_profile"])=="none");
        // Source checks version grammar here; decimal conversion occurs only
        // at its later tuple comparisons, after build/API validation.
        Need(IsVersion(manifest["version"]));_=Token(manifest["build_id"]);Need(Match(manifest["source_commit"],"[0-9a-f]{40}") && Integer(manifest["minimum_updater"])==1);
        var compatibility=Object(manifest["compatibility"]);
        var fields=new List<string>{"core_api","ui_api","from_version","min_version","max_version","os","architecture","agent_api"};
        foreach(string optional in new[]{"migration_ledger_max","plugins"})if(compatibility.ContainsKey(optional))fields.Add(optional);
        Fields(compatibility,fields.ToArray());Need(Integer(compatibility["core_api"])==1 && Integer(compatibility["ui_api"])==1);
        var api=Object(compatibility["agent_api"]);Fields(api,"min","max");Need(Integer(api["min"])>=1 && Integer(api["min"])<=Integer(api["max"]));
        if(compatibility.ContainsKey("migration_ledger_max"))Need(Integer(compatibility["migration_ledger_max"])>=0);
        if(compatibility.ContainsKey("plugins"))foreach(var entry in Object(compatibility["plugins"])) {
            _=Token(JsonValue.Create(entry.Key));var policy=Object(entry.Value);Fields(policy,"min_version","max_version","enabled");_=Boolean(policy["enabled"]);Need(CompareVersion(policy["min_version"],policy["max_version"])<=0);
        }
        Need(CompareVersion(compatibility["from_version"],manifest["version"])<0 && Text(manifest["from_version"])==Text(compatibility["from_version"]) && Text(manifest["to_version"])==Text(manifest["version"]));
        Need(CompareVersion(compatibility["min_version"],compatibility["max_version"])<=0);
        string os=Text(compatibility["os"]),arch=Text(compatibility["architecture"]);Need(os is "windows" or "linux" && arch is "amd64" or "arm64" && Text(manifest["platform"])==os+"-"+arch);
        Need(Integer(manifest["required_free_disk"])>0 && Object(manifest["migrations"]).Count==0 && Array(manifest["deletions"]).Count==0 && manifest["image"] is null && manifest["compose_delta"] is null && manifest["config_delta"] is null);
        var inventory=Array(manifest["files"]);Need(inventory.Count is >=1 and <=19998);long total=0;var files=new List<AgentPackageFile>();
        var prefixes=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var value in inventory) {
            var item=Object(value);Fields(item,"path","size","sha256");string path=Path(Text(item["path"]));string[] parts=path.Split('/');
            for(int i=1;i<=parts.Length;i++) {
                string prefix=string.Join('/',parts.Take(i));Need(!prefixes.TryGetValue(prefix,out var previous)||previous==prefix);prefixes[prefix]=prefix;
                if(i<parts.Length)Need(!names.Contains(prefix));
            }
            Need(!names.Contains(path) && !prefixes.Keys.Any(p=>p.StartsWith(path+"/",StringComparison.OrdinalIgnoreCase)));names.Add(path);
            var size=Integer(item["size"]);Need(size>=0 && size<=128*1024*1024 && Match(item["sha256"],"[0-9a-f]{64}"));total+=(long)size;
            Need(total<=1024L*1024*1024);files.Add(new(path,(long)size,Text(item["sha256"])));
        }
        var exact=files.Select(f=>f.Path).ToHashSet(StringComparer.Ordinal);
        Need(Required.IsSubsetOf(exact));
        foreach(string path in exact)Need(!new[]{"sli_agent/launcher.py","sli_agent/service.py","sli_agent/msi.py"}.Contains(path.ToLowerInvariant()) && (Shared.Contains(path)||path.Split('/')[0] is "sli_agent" or "sli_collect"));
        return files;
    }
}
