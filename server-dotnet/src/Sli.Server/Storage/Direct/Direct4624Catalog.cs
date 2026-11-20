using System.Security.Cryptography;

namespace Sli.Server.Storage.Direct;

internal static class Direct4624Catalog
{
    // This is the reviewed frozen source catalog, not a new catalog format.
    private const string SourceLfSha256 = "4df026e1f2d99729ac668bb778ec44c4c71c6a6112766a175954a3f3bcea860f";
    private const string SourceCrlfSha256 = "7bbb8a67b9655e40e4f233f960168c7f693d0a2b7e4182177f4af40682d907b2";
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
