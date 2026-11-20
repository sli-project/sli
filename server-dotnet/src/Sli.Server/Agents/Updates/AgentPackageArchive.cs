using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using static Sli.Server.Agents.Updates.AgentPackageJson;
namespace Sli.Server.Agents.Updates;

// Source's bounded metadata admission before ZipArchive allocates entry objects.
// Compression/entry reads remain the standard BCL implementation.
internal static class AgentPackageArchive
{
    private sealed record Header(string Name,int Offset,int Flags,int Method,uint Attributes);
    internal static void Inspect(byte[] raw)
    {
        Need(raw.Length is >0 and <=268435456);var bytes=raw.AsSpan();int start=Math.Max(0,raw.Length-65557);
        int found=bytes[start..].LastIndexOf("PK\x05\x06"u8);int end=found<0?-1:start+found;Need(end>=0 && end+22<=raw.Length);
        var e=bytes[end..];int entries=U16(e,10);long cdSize=U32(e,12),offset=U32(e,16);
        Need(U16(e,4)==0 && U16(e,6)==0 && entries==U16(e,8) && entries is >=1 and <=20000 && offset+cdSize==end && end+22+U16(e,20)==raw.Length && bytes.StartsWith("PK\x03\x04"u8));
        int cdStart=(int)offset;var headers=new List<Header>();
        while(offset<end) {
            Need(offset+46<=end);var h=bytes[(int)offset..];Need(h.StartsWith("PK\x01\x02"u8));int nl=U16(h,28),el=U16(h,30),cl=U16(h,32);uint local=U32(h,42);
            Need(headers.Count<entries && U16(h,34)==0 && local!=uint.MaxValue && offset+46L+nl+el+cl<=end && local+30L<=cdStart);
            var nameBytes=h.Slice(46,nl);Need(nameBytes.IndexOfAnyInRange((byte)128,(byte)255)<0);string name=Path(Encoding.ASCII.GetString(nameBytes));
            Extra(h.Slice(46+nl,el));
            var localHeader=bytes[(int)local..];Need(localHeader.StartsWith("PK\x03\x04"u8));int localName=U16(localHeader,26),localExtra=U16(localHeader,28);
            Need(local+30L+localName+localExtra<=cdStart && localName==nl && localHeader.Slice(30,localName).SequenceEqual(nameBytes) && (U16(localHeader,6)&(0x20|0x40))==0);
            headers.Add(new(name,(int)local,U16(h,8),U16(h,10),U32(h,38)));offset+=46+nl+el+cl;
        }
        Need(offset==end && headers.Count==entries);
        using var zip=new ZipArchive(new MemoryStream(raw,false),ZipArchiveMode.Read);Need(zip.Entries.Count==entries);long total=0;
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int[] offsets=headers.Select(h=>h.Offset).Append(cdStart).Order().ToArray();
        for(int i=0;i<entries;i++) {
            var h=headers[i];var entry=zip.Entries[i];Need(entry.FullName==h.Name && names.Add(h.Name) && !h.Name.EndsWith('/'));
            uint mode=(h.Attributes>>16)&0xF000;Need(mode is 0 or 0x8000 && (h.Attributes&0x400)==0 && (h.Flags&1)==0 && h.Method is 0 or 8);
            Need(entry.Length<=128*1024*1024 && entry.CompressedLength>=0 && entry.Length<=Math.Max(1,entry.CompressedLength)*200);
            total+=entry.Length;Need(total<=1024L*1024*1024+8*1024*1024+4096);
            int next=System.Array.FindIndex(offsets,p=>p>h.Offset);Need(next>=0);
            var local=bytes[h.Offset..];long data=h.Offset+30L+U16(local,26)+U16(local,28);Need(data+entry.CompressedLength<=offsets[next]);
        }
    }
    private static int U16(ReadOnlySpan<byte> b,int offset)=>BinaryPrimitives.ReadUInt16LittleEndian(b[offset..]);
    private static uint U32(ReadOnlySpan<byte> b,int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(b[offset..]);
    private static void Extra(ReadOnlySpan<byte> b){while(b.Length>=4){int size=U16(b,2);Need(size+4<=b.Length);b=b[(size+4)..];}}
    internal static byte[] Read(ZipArchiveEntry entry,long limit,out string sha256)
    {
        Need(entry.Length<=limit);using var stream=entry.Open();using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var crc=new Crc32();
        using var memory=limit<=8*1024*1024?new MemoryStream():null;byte[] buffer=new byte[65536];long count=0;int read;
        while((read=stream.Read(buffer))!=0){count+=read;Need(count<=limit && count<=entry.Length);hash.AppendData(buffer,0,read);crc.Append(buffer.AsSpan(0,read));memory?.Write(buffer,0,read);}
        Need(count==entry.Length && crc.GetCurrentHashAsUInt32()==entry.Crc32);sha256=Convert.ToHexStringLower(hash.GetHashAndReset());return memory?.ToArray()??[];
    }
}
