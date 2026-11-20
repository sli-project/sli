using System.Security.Cryptography;
using System.Text;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectChunkHash(string Kind, string Identity, byte[] Hash);
internal static class DirectChunkDigest
{
    internal static byte[] Calculate(IEnumerable<DirectChunkHash> rows)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var row in rows.OrderBy(x => x.Kind, StringComparer.Ordinal).ThenBy(x => x.Identity, StringComparer.Ordinal))
        {
            if (row.Hash.Length != 32 || row.Kind.Any(c => c > 127) || row.Identity.Any(c => c > 127))
                throw new InvalidDataException("storage_v2_chunk_hash_invalid");
            digest.AppendData(Encoding.ASCII.GetBytes(row.Kind + "\0" + row.Identity + "\0"));
            digest.AppendData(row.Hash); digest.AppendData([10]);
        }
        return digest.GetHashAndReset();
    }
}
