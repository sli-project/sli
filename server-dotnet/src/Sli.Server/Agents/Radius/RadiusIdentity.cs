using System.Text.RegularExpressions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

// Exact lookup first, then bounded unambiguous slash-DN candidates.
internal static class RadiusIdentity
{
    private static string Escape(string value)
    {
        var text=value.Replace("\\","\\\\").Replace(",","\\,").Replace("+","\\+").Replace("\"","\\\"").Replace("<","\\<").Replace(">","\\>").Replace(";","\\;").Replace("=","\\=");
        if(text.StartsWith(' ') || text.StartsWith('#')) text="\\"+text;
        if(text.EndsWith(' ')) text=text[..^1]+"\\ ";return text;
    }
    public static async Task<string?> ResolveAsync(NpgsqlConnection db,NpgsqlTransaction tx,string raw,string organization,CancellationToken ct)
    {
        async Task<string?> Exact(string org,string candidate) { await using var cmd=new NpgsqlCommand("select sli_radius_resolve_principal_key(@org,@candidate)",db,tx);cmd.Parameters.AddWithValue("org",org);cmd.Parameters.AddWithValue("candidate",candidate);var value=await cmd.ExecuteScalarAsync(ct);return value is string text?text:null; }
        return await ResolveAsync(raw,organization,Exact);
    }
    internal static Task<string?> ResolveAsync(string raw,string organization,Func<string,Task<string?>> exactLookup)
        => ResolveAsync(raw,organization,(_,candidate)=>exactLookup(candidate));

    public static (string Domain,string[] Candidates)? DeriveSlashDnCandidates(string raw)
    {
        var parts=raw.Split('/').Select(PythonText.Strip).ToArray();if(parts.Length<2 || parts.Any(string.IsNullOrEmpty)) return null;
        string domain=UnicodeCaseFold.Fold(parts[0]);if(!Regex.IsMatch(domain,@"\A[a-z0-9-]+(?:\.[a-z0-9-]+)+\z")) return null;
        var path=parts[1..];if(path.Length>8) throw new ArgumentException("radius_identity_path_depth_exceeded");
        var domainDn=string.Join(',',domain.Split('.').Select(x=>"dc="+Escape(x)));var candidates=new List<string>();
        for(int mask=0;mask<(1<<(path.Length-1));mask++) {
            var segments=new List<string> { "cn="+Escape(path[^1]) };
            for(int i=path.Length-2;i>=0;i--) segments.Add(((mask & (1<<(path.Length-2-i)))==0?"cn=":"ou=")+Escape(path[i]));
            segments.Add(domainDn);candidates.Add(UnicodeCaseFold.Fold(string.Join(',',segments)));
        }
        return (domain,candidates.ToArray());
    }

    internal static async Task<string?> ResolveAsync(string raw,string organization,Func<string,string,Task<string?>> exactLookup)
    {
        raw=PythonText.Strip(raw);organization=UnicodeCaseFold.Fold(PythonText.Strip(organization));if(raw.Length==0 || organization.Length==0) return null;
        var direct=await exactLookup(organization,raw);if(direct is not null) return direct;
        var derived=DeriveSlashDnCandidates(raw);if(derived is null || derived.Value.Domain!=organization) return null;
        var found=new HashSet<string>(StringComparer.Ordinal);
        foreach(var candidate in derived.Value.Candidates) {
            var match=await exactLookup(organization,candidate);if(match is not null) found.Add(match);
        }
        return found.Count==1?found.Single():null;
    }
}
