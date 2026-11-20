using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Sli.Server.Storage.Backfill;

// Checkpoint/outbox types remain with the separately scoped ClaimSql protocol.
internal sealed class StorageV2LeaseLostException() : InvalidOperationException("storage_v2_lease_proven_lost");
internal sealed record StorageV2Checkpoint(string Worker,long? HighWatermark=null,long LastVerified=0,int ChunkSize=25000,
    string State="ready",Guid? Token=null,DateTime? LeaseUntil=null);
internal sealed record StorageV2Outbox(long Id,Guid BatchId,long First,long Last,int Count,long[] EventIds,byte[] IdentityHash,
    string State="pending",int Attempts=0,DateTime AvailableAt=default,Guid? Token=null,DateTime? LeaseUntil=null)
{
    internal static void Validate(long first,long last,int count,IReadOnlyList<long> ids)
    {
        if(ids.Count==0 || !ids.SequenceEqual(ids.Distinct().Order()) || ids[0]<=0)throw new ArgumentException("outbox event_ids must be sorted and unique");
        if(count!=ids.Count)throw new ArgumentException("outbox event_count does not match event_ids");
        if(first!=ids[0]||last!=ids[^1])throw new ArgumentException("outbox range does not match event_ids");
    }
    internal static byte[] Hash(IEnumerable<long> ids)=>SHA256.HashData(Encoding.ASCII.GetBytes(string.Join(',',ids.Select(x=>x.ToString(CultureInfo.InvariantCulture)))));
}
