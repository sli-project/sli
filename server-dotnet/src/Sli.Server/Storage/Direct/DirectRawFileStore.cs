namespace Sli.Server.Storage.Direct;

internal static class DirectRawFileStore
{
    internal static bool Matches(long storedServer,long storedSource,string storedHash,long server,long source,string hash) =>
        storedServer==server && storedSource==source && string.Equals(storedHash,hash,StringComparison.OrdinalIgnoreCase);
}
