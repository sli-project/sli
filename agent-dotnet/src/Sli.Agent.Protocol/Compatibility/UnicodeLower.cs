using System.Text;

namespace Sli.Agent.Protocol.Compatibility;

/// <summary>CPython 3.14 str.lower for Windows ntpath.normcase; unlike casefold it does not expand ß.</summary>
public static class UnicodeLower
{
    private static readonly Dictionary<int,string> Mappings=LoadMappings();
    private static readonly (int Start,int End)[] Cased=LoadRanges(UnicodeLowerData.Cased);
    private static readonly (int Start,int End)[] Ignorable=LoadRanges(UnicodeLowerData.Ignorable);
    public static string Lower(string input)
    {
        var chars=input.EnumerateRunes().Select(r=>r.Value).ToArray(); var output=new StringBuilder(input.Length);
        for(int i=0;i<chars.Length;i++)
        {
            int code=chars[i];
            if (code==0x3a3 && FinalSigma(chars,i)) output.Append('\u03c2');
            else if (Mappings.TryGetValue(code,out var mapped)) output.Append(mapped);
            else output.Append(new Rune(code).ToString());
        }
        return output.ToString();
    }
    private static bool FinalSigma(int[] chars,int index)
    {
        bool before=false;
        for(int i=index-1;i>=0;i--) { if (Contains(Ignorable,chars[i])) continue; before=Contains(Cased,chars[i]); break; }
        if (!before) return false;
        for(int i=index+1;i<chars.Length;i++) { if (Contains(Ignorable,chars[i])) continue; return !Contains(Cased,chars[i]); }
        return true;
    }
    private static bool Contains((int Start,int End)[] ranges,int value)
    {
        int lo=0,hi=ranges.Length-1;
        while(lo<=hi) { int mid=(lo+hi)/2; var r=ranges[mid]; if (value<r.Start) hi=mid-1; else if (value>r.End) lo=mid+1; else return true; }
        return false;
    }
    private static (int,int)[] LoadRanges(string text) => text.Trim().Split(',').Select(part=>
    {
        var pair=part.Split('-'); return (Convert.ToInt32(pair[0],16),Convert.ToInt32(pair[1],16));
    }).ToArray();
    private static Dictionary<int,string> LoadMappings()
    {
        var result=new Dictionary<int,string>();
        foreach(var line in UnicodeLowerData.Mappings.Split('\n',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries))
        {
            var pair=line.Split(';'); var value=new StringBuilder();
            foreach(var code in pair[1].Split(',')) value.Append(new Rune(Convert.ToInt32(code,16)).ToString());
            result.Add(Convert.ToInt32(pair[0],16),value.ToString());
        }
        return result;
    }
}
