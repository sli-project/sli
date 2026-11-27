using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.FileAudit;

// Narrow port of plugin_validation.py for the installed bundled manifests and settings.
internal static class FileAuditManifestValidator
{
    // Canonical SHA-256 of frozen ddce909d reviewed bundled declarations, version 1.0.0.
    private static readonly Dictionary<string,(string Manifest,string Settings)> Supported=new(StringComparer.Ordinal)
    {
        ["sli.file-audit"]=("c888a38b684efee504907542f2ef8e74d48d5360ba01f67a3720495ba1d8ce20","c8a3c015bdc3ac4865d6cd64b083892d3b9428aed523fca7d5b529521ffb7af2"),
        ["sli.ad"]=("ae3ce3896bcca905ce6b6e2e3ce90920a12f7c1c69eaca8276d0d54674f0fab9","63a4b540af2db85a005631d8449cb13a7936aa71e47a7ef0488de9648f86c24d")
    };
    private static string Fingerprint(JsonNode node)=>Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(CanonicalJson.ToBytes(node)));
    private static readonly HashSet<string> Forbidden=new(StringComparer.OrdinalIgnoreCase) { "argv","command","dsn","entrypoint","html","import_path","javascript","password","secret","sql" };
    private static InvalidDataException Bad()=>new("plugin_manifest_invalid");
    private static string S(JsonNode? n)=>n!.GetValue<string>();
    private static bool B(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
    private static JsonNode Read(string path)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
        if(stream.Length>16*1024*1024) throw Bad();
        using var doc=JsonDocument.Parse(stream); Unique(doc.RootElement);return JsonNode.Parse(doc.RootElement.GetRawText()) ?? throw Bad();
    }
    private static void Unique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object) { var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var p in value.EnumerateObject()) { if(!seen.Add(p.Name)) throw Bad();Unique(p.Value); } }
        else if(value.ValueKind==JsonValueKind.Array) foreach(var item in value.EnumerateArray()) Unique(item);
    }
    private static void Reject(JsonNode? value)
    {
        if(value is JsonObject obj) foreach(var (k,v) in obj) { if(Forbidden.Contains(k)) throw Bad();Reject(v); }
        else if(value is JsonArray array) foreach(var item in array) Reject(item);
    }
    private static bool Integer(JsonNode? n,out System.Numerics.BigInteger v)=>JsonRead.TryInteger(n,out v);
    private static string Kind(JsonNode? n)
    {
        if(n is null) return "null";if(n is JsonObject) return "object";if(n is JsonArray) return "array";
        var e=JsonSerializer.SerializeToElement(n);return e.ValueKind switch { JsonValueKind.String=>"string",JsonValueKind.True or JsonValueKind.False=>"boolean",JsonValueKind.Number when Integer(n,out _)=>"integer",_=>"other" };
    }
    private static long Bound(JsonNode? node,long fallback)=>node is null?fallback:node.GetValue<long>();
    private static void Shape(JsonNode? value,JsonObject node,JsonObject schema)
    {
        if(node["$ref"] is JsonNode reference) { Shape(value,schema["$defs"]![S(reference).Split('/')[^1]]!.AsObject(),schema);return; }
        if(node["oneOf"] is JsonArray options)
        { int count=0;foreach(var option in options) try { Shape(value,option!.AsObject(),schema);count++; } catch(InvalidDataException) { } if(count!=1) throw Bad(); }
        if(node["type"] is JsonNode types) { var choices=types is JsonArray a?a.Select(S):new[]{S(types)};if(!choices.Contains(Kind(value))) throw Bad(); }
        if(node.ContainsKey("const") && !JsonNode.DeepEquals(value,node["const"]) || node["enum"] is JsonArray values && !values.Any(x=>JsonNode.DeepEquals(x,value))) throw Bad();
        if(value is JsonObject obj)
        {
            var props=node["properties"] as JsonObject ?? new JsonObject();
            if(node["required"] is JsonArray required && required.Any(x=>!obj.ContainsKey(S(x)))) throw Bad();
            if(node["additionalProperties"] is JsonValue flag && flag.TryGetValue<bool>(out var enabled) && !enabled && obj.Any(x=>!props.ContainsKey(x.Key))) throw Bad();
            foreach(var (key,item) in obj)
            {
                if(node["propertyNames"] is JsonObject names) Shape(JsonValue.Create(key),names,schema);
                if(props[key] is JsonObject property) Shape(item,property,schema);
                else if(node["additionalProperties"] is JsonObject additional) Shape(item,additional,schema);
            }
        }
        if(value is JsonArray list)
        {
            if(list.Count<Bound(node["minItems"],0) || list.Count>Bound(node["maxItems"],list.Count)) throw Bad();
            if(B(node["uniqueItems"]) && list.Select(CanonicalJson.Serialize).Distinct(StringComparer.Ordinal).Count()!=list.Count) throw Bad();
            foreach(var item in list) Shape(item,node["items"] as JsonObject ?? new JsonObject(),schema);
        }
        if(Kind(value)=="string")
        {
            string s=S(value);int length=s.EnumerateRunes().Count();
            if(length<Bound(node["minLength"],0) || length>Bound(node["maxLength"],length) || node["pattern"] is JsonNode pattern && !Regex.IsMatch(s,S(pattern),RegexOptions.CultureInvariant)) throw Bad();
        }
        if(Integer(value,out var n))
        { if(Integer(node["minimum"],out var low) && n<low || Integer(node["maximum"],out var high) && n>high) throw Bad(); }
    }
    private static void Setting(JsonObject node)
    {
        foreach(var pair in new[]{("minimum","maximum"),("minLength","maxLength"),("minItems","maxItems")})
            if(Integer(node[pair.Item1],out var lower) && Integer(node[pair.Item2],out var upper) && lower>upper) throw Bad();
        if(node["pattern"] is JsonNode pattern) _=new Regex(S(pattern),RegexOptions.CultureInvariant);
        var types=node["type"] is JsonArray a?a.Select(S).ToArray():new[]{S(node["type"])};
        if(types.Contains("array") && !node.ContainsKey("items") || types.Contains("object") && new[]{"properties","required","additionalProperties"}.Any(x=>!node.ContainsKey(x))) throw Bad();
        var props=node["properties"] as JsonObject ?? new JsonObject();
        if(node["required"] is JsonArray required && required.Any(x=>!props.ContainsKey(S(x)))) throw Bad();
        foreach(var p in props) Setting(p.Value!.AsObject());if(node["items"] is JsonObject items) Setting(items);
        if(node["oneOf"] is JsonArray options) foreach(var option in options) Setting(option!.AsObject());
        if(node.ContainsKey("default")) Shape(node["default"],node,node);
    }
    private static void Message(string key,JsonObject ru,JsonObject en)
    {
        foreach(var catalog in new[]{ru,en}) { if(catalog[key] is not JsonNode item || Kind(item)!="string") throw Bad();string text=S(item);if(string.IsNullOrWhiteSpace(text) || text.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Length>12) throw Bad(); }
    }
    private static int CompareVersion(string a,string b)
    {
        var left=a.Split('.').Select(System.Numerics.BigInteger.Parse).ToArray();var right=b.Split('.').Select(System.Numerics.BigInteger.Parse).ToArray();
        for(int i=0;i<3;i++) { int c=left[i].CompareTo(right[i]);if(c!=0)return c; }return 0;
    }
    private static string Resolve(string path)
    {
        string full=Path.GetFullPath(path),current=Path.GetPathRoot(full)!;
        foreach(string part in full[current.Length..].Split(Path.DirectorySeparatorChar,StringSplitOptions.RemoveEmptyEntries))
        { var next=new DirectoryInfo(Path.Combine(current,part));current=next.LinkTarget is null?next.FullName:next.ResolveLinkTarget(true)!.FullName; }
        return current;
    }
    internal static bool Installed(string root,string plugin)
    {
        if(!Supported.TryGetValue(plugin,out var supported)) return false;
        string path=Path.Combine(root,"config","plugin_packages","v3",plugin+".json");if(!File.Exists(path)) return false;
        try
        {
            var manifest=Read(path).AsObject();if(S(manifest["plugin_id"])!=plugin) throw Bad();Reject(manifest);
            var architecture=Read(Path.Combine(root,"config","plugin_architecture_v3.json")).AsObject();Shape(manifest,architecture,architecture);
            var ranges=new[]{manifest["core_api"]!.AsObject()}.Concat(manifest["dependencies"]!.AsArray().Select(d=>d!["versions"]!.AsObject()));
            foreach(var range in ranges) if(CompareVersion(S(range["minimum"]),S(range["maximum_exclusive"]))>=0) throw Bad();
            var metadata=Read(Path.Combine(root,"config","plugin_settings_schema",plugin+".settings.json")).AsObject();if(S(metadata["plugin_id"])!=plugin) throw Bad();Reject(metadata);
            var settingsSchema=Read(Path.Combine(root,"config","plugin_settings_schema_v1.json")).AsObject();Shape(metadata,settingsSchema,settingsSchema);
            if(Fingerprint(manifest)!=supported.Manifest || Fingerprint(metadata)!=supported.Settings) return false;
            var ru=Read(Path.Combine(root,"config","i18n","server.ru.json")).AsObject();var en=Read(Path.Combine(root,"config","i18n","server.en.json")).AsObject();Message(S(metadata["name"]),ru,en);
            var settings=metadata["settings"]!.AsObject();var properties=settings["properties"]!.AsObject();var core=settings["x-core-settings"]!.AsArray().Select(S).ToHashSet(StringComparer.Ordinal);
            if(properties.Any(p=>core.Contains(p.Key)) || settings["required"]!.AsArray().Any(x=>!properties.ContainsKey(S(x)))) throw Bad();
            foreach(var property in properties) { var setting=property.Value!.AsObject();Message(S(setting["x-label"]),ru,en);Message(S(setting["x-help"]),ru,en);Setting(setting); }
            var ids=new HashSet<string>(StringComparer.Ordinal);
            foreach(var item in metadata["rules"]!.AsArray()) { var rule=item!.AsObject();if(!ids.Add(S(rule["rule_id"])) || rule["settings"]!.AsArray().Any(x=>!properties.ContainsKey(S(x))) || rule["core_settings"]!.AsArray().Any(x=>!core.Contains(S(x)))) throw Bad();Message(S(rule["name"]),ru,en); }
            string migration=S(metadata["migration_directory"]),directory=Resolve(Path.Combine(root,migration)),resolvedRoot=Resolve(root),relative=Path.GetRelativePath(resolvedRoot,directory);
            if(Path.IsPathRooted(relative) || relative==".." || relative.StartsWith(".."+Path.DirectorySeparatorChar,StringComparison.Ordinal) || !Directory.Exists(directory)) throw Bad();
            if(manifest["data"]!["migrations"]!.AsArray().Any(x=>!S(x!["path"]).StartsWith(migration+"/",StringComparison.Ordinal))) throw Bad();
            return true;
        }
        catch(Exception e) when(e is JsonException or InvalidOperationException or ArgumentException or FormatException or OverflowException or KeyNotFoundException or NullReferenceException or IOException or UnauthorizedAccessException) { throw new InvalidDataException("plugin_manifest_invalid",e); }
    }
}

