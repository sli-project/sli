using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Server.Agents.FileAudit;

// Portable subset of file_audit/acl.py. Unknown descriptors are never grants.
public static class FileAuditAcl
{
    public sealed record Ace(string Kind, string Sid, uint Mask, bool Inherited, bool InheritOnly);
    public sealed record Parsed(IReadOnlyList<Ace> Aces, bool Complete);
    private static readonly Dictionary<string,string> Aliases = new() { ["WD"]="S-1-1-0", ["AU"]="S-1-5-11", ["SY"]="S-1-5-18", ["BA"]="S-1-5-32-544", ["BU"]="S-1-5-32-545", ["AN"]="S-1-5-7", ["CO"]="S-1-3-0", ["CG"]="S-1-3-1" };
    private static readonly Dictionary<string,uint> Rights = new() { ["FA"]=0x1f01ff, ["FR"]=0x120089, ["FW"]=0x120116, ["FX"]=0x1200a0, ["SD"]=0x10000, ["RC"]=0x20000, ["WD"]=0x40000, ["WO"]=0x80000, ["GA"]=0x1f01ff, ["GR"]=0x120089, ["GW"]=0x120116, ["GX"]=0x1200a0 };
    private static readonly HashSet<string> Flags = ["OI", "CI", "NP", "IO", "ID"];
    private static Parsed Invalid() => new([], false);
    public static Parsed Parse(string? sddl)
    {
        if (sddl is null || sddl.EnumerateRunes().Count() > 65536 || !sddl.StartsWith("D:", StringComparison.Ordinal)) return Invalid();
        int open = sddl.IndexOf('('); string header = open < 0 ? sddl[2..] : sddl[2..open];
        if (!Regex.IsMatch(header, "\\A(?:P|AI|AR)*\\z")) return Invalid();
        var aces = new List<Ace>(); int pos = 2 + header.Length;
        foreach (Match match in Regex.Matches(sddl, @"\(([^()]*)\)"))
        {
            if (match.Index != pos) return Invalid();
            var fields = match.Groups[1].Value.Split(';');
            if (fields.Length != 6 || fields[0] is not ("A" or "D") || fields[3] != "" || fields[4] != "") return Invalid();
            var flags = fields[1]; var pairs = new List<string>();
            for (int i = 0; i < flags.Length; i += 2) pairs.Add(flags.Substring(i, Math.Min(2, flags.Length-i)));
            if (pairs.Any(f => !Flags.Contains(f))) return Invalid();
            string sid = Aliases.GetValueOrDefault(fields[5], fields[5]);
            if (!Regex.IsMatch(sid, "\\AS-1-(?:[0-9]+-)*[0-9]+\\z")) return Invalid();
            uint mask = 0; string rights = fields[2];
            if (rights.StartsWith("0x", StringComparison.Ordinal))
            {
                var hex=rights.TrimEnd(); if(!Regex.IsMatch(hex,@"\A0x_?[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*\z") || !uint.TryParse(hex[2..].Replace("_", ""), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out mask)) return Invalid();
            }
            else for (int i = 0; i < rights.Length; i += 2)
            {
                var key = rights.Substring(i, Math.Min(2, rights.Length-i));
                if (!Rights.TryGetValue(key, out uint part)) return Invalid();
                mask |= part;
            }
            foreach (var (flag, key) in new (uint,string)[] { (0x10000000,"GA"), (0x80000000,"GR"), (0x40000000,"GW"), (0x20000000,"GX") })
                if ((mask & flag) != 0) mask = (mask & ~flag) | Rights[key];
            aces.Add(new(fields[0], sid, mask, pairs.Contains("ID"), pairs.Contains("IO"))); pos = match.Index + match.Length;
        }
        return new(aces, pos == sddl.Length);
    }
    public static uint AccessMask(IEnumerable<Ace> aces, IReadOnlySet<string> token)
    {
        uint allowed = 0, denied = 0;
        foreach (var ace in aces)
        {
            if (ace.InheritOnly || !token.Contains(ace.Sid)) continue;
            if (ace.Kind == "D") denied |= ace.Mask & ~allowed;
            else allowed |= ace.Mask & ~denied;
        }
        return allowed;
    }
}

