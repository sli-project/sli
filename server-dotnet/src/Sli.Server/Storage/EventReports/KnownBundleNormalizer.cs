using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Storage.EventReports;

// Supports only the exact reviewed bundled generation. Other manifests or active
// generations fail explicitly; this is not a dynamic plugin or Python loader.
internal sealed class KnownBundleNormalizer(string root,string? runtimeRoot,string? lockRoot)
{
    Dictionary<string,JsonObject>? documents;
    static readonly Dictionary<string,string> Files=new(StringComparer.Ordinal)
    {
        ["config/source_packs/ad_context.json"]="6045c72945ec321de2e3cb7e20db6809b5b804e8ec2043b8c514d26118eb067c",
        ["config/source_packs/dc.json"]="5c30a5170637b2cdeca7dc883df3d11ca58a2267c4769b80d4af9e2f2b08cea7",
        ["config/source_packs/file_audit.json"]="6d2697a8b6a17896d485dbf66d3ce51facbe1f1e0219d0cedea37e18ad690019",
        ["config/source_packs/radius.json"]="a1ea9bb4690ca9344ee8c3b4f022b60b5fbecdf5b445c6b43e4def061f11f301",
        ["config/source_packs/workstations.json"]="a09e4e087061ea112d4d37b8e4b910e345978a387802812a05354d46adb2849d",
        ["config/event_catalog.json"]="d0cd5abece99249751c5b5d0ead5fbd3bb21239fcc96f84747b7d03de8b212d7",
        ["config/file_audit_event_catalog.json"]="9b7964bad0975948ca9ff8d75843e687248807d986b09b63678f43665bce8bb3",
        ["config/radius_event_catalog.json"]="6ff6ceb44bfe84c70f6ae4d9356cc94ca9de9c82f1acc16de166a730d9bacb6c",
        ["config/workstations_event_catalog.json"]="9d5d8f354f9dbc463bbd85b59e521fa90dde630a7dd8a082ac6518a6e1d00524"
    };
    static InvalidOperationException Unsupported() => new("source_normalizer_bundle_unsupported");
    internal Task<IReadOnlyList<int>> ResolveAsync(JsonObject row,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var ad=AgentAssignmentPluginAdmission.Enter("sli.ad",runtimeRoot,lockRoot);
        using var file=AgentAssignmentPluginAdmission.Enter("sli.file-audit",runtimeRoot,lockRoot);
        using var remote=AgentAssignmentPluginAdmission.Enter("sli.remote-access",runtimeRoot,lockRoot);
        EnsureDocuments(ct);
        var matches=Matches(row,ct);
        IReadOnlyList<int> family=matches.FirstOrDefault()=="dc" ? [100,102,106,129,140,200,201,324] : [];
        ct.ThrowIfCancellationRequested(); return Task.FromResult(family);
    }
    void EnsureDocuments(CancellationToken ct)
    {
        if(documents is not null) return;
        var loaded=new Dictionary<string,JsonObject>(StringComparer.Ordinal);
        string packs=Path.Combine(root,"config","source_packs");
        if(!Directory.Exists(packs)) throw Unsupported();
        var names=Directory.GetFiles(packs,"*.json").Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        if(!names.SetEquals(new[]{"ad_context.json","dc.json","file_audit.json","radius.json","workstations.json"})) throw Unsupported();
        foreach(var (path,expected) in Files)
        {
            ct.ThrowIfCancellationRequested(); if(!File.Exists(Path.Combine(root,path))) throw Unsupported();
            string text=File.ReadAllText(Path.Combine(root,path),new UTF8Encoding(false,true)).Replace("\r\n","\n");
            if(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))!=expected) throw Unsupported();
            loaded.Add(path,JsonNode.Parse(text)!.AsObject());
        }
        if(!FileAuditManifestValidator.Installed(root,"sli.ad") || !FileAuditManifestValidator.Installed(root,"sli.file-audit") ||
            Fingerprint("config/plugin_packages/v3/sli.remote-access.json")!="c5dae5b2aca19e0351e8a2f12e834586ef553234b60a5960a732a8604374a426" ||
            Fingerprint("config/plugin_settings_schema/sli.remote-access.settings.json")!="df07b6b2693f8728886c53652a9830d4e715b7fa1a8a6332028e83864e4181ed") throw Unsupported();
        documents=loaded;
    }
    List<string> Matches(JsonObject row,CancellationToken ct)
    {
        string channel=Fold(row["channel"]),provider=Fold(row["provider_name"]),eventKey=Fold(row["event_id"]);
        var matches=new List<string>();
        foreach(string name in new[]{"dc","file_audit","radius","workstations"})
        {
            ct.ThrowIfCancellationRequested();
            var pack=documents!["config/source_packs/"+name+".json"];
            if(!pack["channels"]!.AsArray().Any(x=>Fold(x)==channel)) continue;
            bool matched=provider.Length==0;
            if(!matched)
            {
                string catalog=pack["event_catalog"]!.GetValue<string>();
                var entries=documents["config/"+catalog]["entries"]!.AsArray();
                matched=entries.Any(e=>Fold(e?["stream"] ?? e?["channel"])==channel && Fold(e?["provider_name"])==provider && (eventKey.Length==0 || Fold(e?["event_key"] ?? e?["event_id"])==eventKey));
            }
            if(matched) matches.Add(name);
        }
        if(provider.Length>0 && eventKey.Length>0 && matches.Count>1) throw new InvalidDataException("multiple_source_packs_own_event");
        return matches;
    }
    internal async Task<JsonObject> ProjectAsync(JsonObject row,CancellationToken ct)
    {
        var family=await ResolveAsync(row,ct);
        var result=EventDetailProjection.Normalize(row,family);
        result["semantics"]=BuildCard(result,ct);
        return result;
    }
    internal async Task<JsonObject> CardAsync(JsonObject row,CancellationToken ct)
    {
        await ResolveAsync(row,ct);
        return BuildCard(row,ct);
    }
    internal string[] Catalogs(JsonObject row,CancellationToken ct)
    {
        EnsureDocuments(ct);
        string? name=Matches(row,ct).FirstOrDefault();
        return name is null ? ["event_catalog.json"] : new[] { documents!["config/source_packs/"+name+".json"]["event_catalog"]!.ToString(), "event_catalog.json" }.Distinct().ToArray();
    }
    JsonObject BuildCard(JsonObject row,CancellationToken ct)
    {
        string? name=Matches(row,ct).FirstOrDefault();
        JsonObject? declaration=name is null ? null : documents!["config/source_packs/"+name+".json"];
        JsonObject? pack=null;
        if(declaration is not null)
        {
            pack=new JsonObject();
            foreach(string key in new[]{"pack_id","version","channels","adapters","entity_contract","analysis_contract","capabilities"})
                if(declaration[key] is {} value) pack[key]=value.DeepClone();
            pack["display_name"]=declaration["display_name"]?.DeepClone() ?? declaration["pack_id"]!.DeepClone();
            pack["source_kind"]=declaration["source_kind"]?.DeepClone() ?? JsonValue.Create("event");
            pack["sections"]=declaration["sections"]?.DeepClone() ?? new JsonArray();
            pack["normalizer"]=declaration["normalizer"]?.DeepClone();
            pack["manifest_sha256"]=Files["config/source_packs/"+name+".json"];
            if(declaration["collector"] is JsonObject collector) pack["collector"]=new JsonObject { ["kind"]=collector["kind"]?.DeepClone(),["entry"]=collector["entry"]?.DeepClone() };
        }
        string[] catalogs=Catalogs(row,ct);
        JsonObject? entry=null;
        foreach(string catalog in catalogs)
        {
            var entries=documents!["config/"+catalog]["entries"]!.AsArray();
            string channel=Fold(row["channel"]), provider=Fold(row["provider_name"]), id=Fold(row["event_id"]);
            foreach(var key in new[]{(channel,provider),(channel,""),("",provider),("","")})
            {
                entry=entries.OfType<JsonObject>().LastOrDefault(e=>Fold(e["event_id"])==id && Fold(e["channel"])==key.Item1 && Fold(e["provider_name"])==key.Item2);
                if(entry is not null) break;
            }
            if(entry is not null) break;
        }
        return EventCardSemantics.Build(row,entry,pack);
    }
    string Fingerprint(string name)
    {
        string path=Path.Combine(root,name); if(!File.Exists(path)) throw Unsupported();
        using var stream=File.OpenRead(path); if(stream.Length>16*1024*1024) throw Unsupported();
        return Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(JsonNode.Parse(stream))));
    }
    static string Fold(JsonNode? value) => UnicodeCaseFold.TrimAndFold(value?.ToString() ?? "");
}
