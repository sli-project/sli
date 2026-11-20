namespace Sli.Server.Compatibility;

internal static class PythonText
{
    internal static string Strip(string text)
    {
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        int a=0,b=text.Length; while (a<b && Space(text[a])) a++; while (b>a && Space(text[b-1])) b--; return text[a..b];
    }
}
