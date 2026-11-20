using System.Security.Cryptography;

namespace Sli.Server.Storage.Direct;

internal static class Direct4624Catalog
{
    // This is the reviewed frozen source catalog, not a new catalog format.
    private const string SourceLfSha256 = "d0cd5abece99249751c5b5d0ead5fbd3bb21239fcc96f84747b7d03de8b212d7";
    private const string SourceCrlfSha256 = "2ab85a006f91bb0c0940923682c253b3fedba68c43cef70b289aa33bc7ad5d35";
    internal static void RequireRadiusCatalog(string eventCatalogPath)
    {
        using var stream=File.OpenRead(Path.Combine(Path.GetDirectoryName(eventCatalogPath)!,"radius_event_catalog.json"));
        var hash=Convert.ToHexStringLower(SHA256.HashData(stream));
        if(hash is not ("6ff6ceb44bfe84c70f6ae4d9356cc94ca9de9c82f1acc16de166a730d9bacb6c" or "5041f5a7e319e4ed498ca1946a3faaccbb3a09a31d19c0f0e44e15f1ad4d588d"))
            throw new InvalidOperationException("storage_v2_catalog_generation_pending");
    }
    internal static void RequireSourceCatalog(string path)
    {
        using var stream = File.OpenRead(path);
        string hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (hash is not (SourceLfSha256 or SourceCrlfSha256))
            throw new InvalidOperationException("storage_v2_catalog_generation_pending");
    }
}
