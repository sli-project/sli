using System.Buffers.Binary;
using System.Security.Cryptography;
using Npgsql;

namespace Sli.Server.Storage.Direct;

internal static partial class DirectLinkBlock
{
    private static int Compare((long EventId,short RoleId) left,(long EventId,short RoleId) right) =>
        left.EventId!=right.EventId ? left.EventId.CompareTo(right.EventId) : left.RoleId.CompareTo(right.RoleId);

    internal static byte[] Hash(int entityId, IReadOnlyList<(long EventId,short RoleId)> rows)
    {
        if (entityId <= 0 || rows.Count is < 1 or > 512) throw new InvalidDataException("storage_v2_link_block_invalid");
        for (int i = 0; i < rows.Count; i++)
            if (rows[i].EventId <= 0 || rows[i].RoleId < 0 ||
                i > 0 && (rows[i].EventId < rows[i-1].EventId || rows[i].EventId == rows[i-1].EventId && rows[i].RoleId <= rows[i-1].RoleId))
                throw new InvalidDataException("storage_v2_link_block_invalid");
        bool wide = rows[^1].EventId > int.MaxValue;
        byte[] bytes = new byte[rows.Count * (wide ? 14 : 10)];
        int pos = 0;
        foreach (var row in rows)
        {
            if (wide) { BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(pos), row.EventId); pos += 8; }
            else { BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(pos), checked((int)row.EventId)); pos += 4; }
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(pos), entityId); pos += 4;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(pos), checked((ushort)row.RoleId)); pos += 2;
        }
        return SHA256.HashData(bytes);
    }
}
