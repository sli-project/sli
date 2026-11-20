using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Core;

namespace Sli.Server.Agents.Radius;

internal sealed record RadiusEvidence(Guid Id,string Hash,string Reference,long Size,DateTimeOffset VerifiedAt);
// Content is published before DB commit; orphan objects may remain after rollback.
internal static class RadiusEvidenceStore
{
    private static readonly Guid Namespace=Guid.Parse("00000000-0000-4000-8000-000000000066");
    public static Guid Uuid5(Guid ns,string name)
    {
        var hash=SHA1.HashData([..ns.ToByteArray(bigEndian:true),..Encoding.UTF8.GetBytes(name)]);
        hash[6]=(byte)((hash[6]&15)|0x50);hash[8]=(byte)((hash[8]&63)|0x80);return new Guid(hash.AsSpan(0,16),bigEndian:true);
    }
    public static Guid Identity(string source,string stream,string binding,Guid epoch,string generation,long start,int ordinal)
    {
        foreach(var value in new[]{source,stream,binding,generation}) if(!Regex.IsMatch(value,@"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z")) throw new ArgumentException("evidence_identity_invalid");
        if(start<0 || ordinal<0) throw new ArgumentException("evidence_identity_invalid");
        var material=new JsonObject { ["source_instance_id"]=source,["stream_id"]=stream,["transport_binding"]=binding,["cursor_epoch"]=epoch.ToString("D"),["file_generation"]=generation,["cursor_start_byte_offset"]=start,["batch_record_ordinal"]=ordinal };
        return Uuid5(Namespace,CanonicalJson.Serialize(material));
    }
    [DllImport("libc",EntryPoint="open",SetLastError=true)] private static extern int Open(string path,int flags);
    [DllImport("libc",EntryPoint="fsync",SetLastError=true)] private static extern int Fsync(int fd);
    [DllImport("libc",EntryPoint="close",SetLastError=true)] private static extern int Close(int fd);
    internal static void SyncDirectory(string path)
    {
        if(OperatingSystem.IsWindows()) return;
        int fd=Open(path,0);if(fd<0) throw new IOException("evidence_directory_sync_failed");
        try { if(Fsync(fd)!=0) throw new IOException("evidence_directory_sync_failed"); } finally { _=Close(fd); }
    }
    public static RadiusEvidence Publish(string root,string source,string stream,string binding,Guid epoch,string generation,long start,int ordinal,string record)
        => PublishCore(root,source,stream,binding,epoch,generation,start,ordinal,record,null,65536);

    public static RadiusEvidence PublishCanonicalRecord(string root,string source,string stream,string binding,Guid epoch,string generation,long start,int ordinal,string record,string expectedSha256,int maximumObjectBytes=65536)
        => PublishCore(root,source,stream,binding,epoch,generation,start,ordinal,record,expectedSha256,maximumObjectBytes);

    public static IReadOnlyList<RadiusEvidence> PublishBatch(string root,RadiusCursor current,Guid epoch,string generation,RadiusPlan plan,IEnumerable<string> canonicalRecords)
    {
        var records=canonicalRecords.ToArray();
        if(records.Length!=plan.EvidenceHashes.Count) throw new ArgumentException("evidence_record_count_mismatch");
        if(records.Length==0) throw new ArgumentException("evidence_batch_empty");
        return records.Select((record,ordinal)=>PublishCanonicalRecord(root,current.SourceId,current.StreamId,current.TransportBinding,
            epoch,generation,current.ByteOffset,ordinal,record,plan.EvidenceHashes[ordinal])).ToArray();
    }

    // Resolve only the core-owned identity; publication metadata never supplies a file path.
    public static string ReadVerified(string root,RadiusEvidence publication,int maximumObjectBytes=65536)
    {
        if(maximumObjectBytes<1) throw new ArgumentException("evidence_maximum_size_invalid");
        string hex=publication.Id.ToString("N");
        if(publication.Reference!="evidence:acquisition.radius."+hex) throw new ArgumentException("evidence_reference_invalid");
        if(publication.Size>maximumObjectBytes) throw new ArgumentException("evidence_object_too_large");
        if(!Path.IsPathFullyQualified(root)) throw new ArgumentException("evidence_root_invalid");
        byte[] bytes;
        try {
            using var file=File.OpenRead(Path.Combine(root,"published","acquisition-radius",hex[..2],hex+".record"));
            if(publication.Size<1 || file.Length!=publication.Size) throw new IOException();
            bytes=new byte[checked((int)publication.Size)];file.ReadExactly(bytes);
            if(file.ReadByte()!=-1 || Convert.ToHexStringLower(SHA256.HashData(bytes))!=publication.Hash) throw new IOException();
        }
        catch(IOException) { throw new IOException("evidence_readback_failed"); }
        catch(UnauthorizedAccessException) { throw new IOException("evidence_readback_failed"); }
        try { return new UTF8Encoding(false,true).GetString(bytes); }
        catch(DecoderFallbackException) { throw new ArgumentException("evidence_utf8_invalid"); }
    }

    private static RadiusEvidence PublishCore(string root,string source,string stream,string binding,Guid epoch,string generation,long start,int ordinal,string record,string? expectedSha256,int maximumObjectBytes)
    {
        if(maximumObjectBytes<1) throw new ArgumentException("evidence_maximum_size_invalid");
        if(!Path.IsPathFullyQualified(root) || string.IsNullOrEmpty(record) || record.IndexOfAny(['\0','\r','\n'])>=0) throw new ArgumentException("evidence_invalid");
        byte[] bytes=new UTF8Encoding(false,true).GetBytes(record);if(bytes.Length>maximumObjectBytes) throw new ArgumentException("evidence_object_too_large");
        string hash=Convert.ToHexStringLower(SHA256.HashData(bytes));
        if(expectedSha256 is not null) {
            if(!Regex.IsMatch(expectedSha256,@"\A[0-9a-fA-F]{64}\z")) throw new ArgumentException("canonical_record_sha256_invalid");
            if(!string.Equals(hash,expectedSha256,StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("canonical_record_sha256_mismatch");
        }
        Guid id=Identity(source,stream,binding,epoch,generation,start,ordinal);string hex=id.ToString("N");
        string relative=Path.Combine("acquisition-radius",hex[..2],hex+".record");
        string partial=Path.Combine(root,"staging",relative+".partial"),final=Path.Combine(root,"published",relative),quarantine=Path.Combine(root,"quarantine",relative+".hash-mismatch");
        Directory.CreateDirectory(Path.GetDirectoryName(partial)!);Directory.CreateDirectory(Path.GetDirectoryName(final)!);Directory.CreateDirectory(Path.GetDirectoryName(quarantine)!);
        void Verify(string path) { using var stream=File.OpenRead(path);if(stream.Length!=bytes.Length || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream),Convert.FromHexString(hash))) throw new IOException("evidence_identity_conflict"); }
        if(File.Exists(final)) Verify(final);
        else {
            if(File.Exists(partial)) { try { Verify(partial); } catch(IOException) { if(File.Exists(quarantine)) throw; File.Move(partial,quarantine);SyncDirectory(Path.GetDirectoryName(quarantine)!);throw; } }
            else { using var file=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.None);file.Write(bytes);file.Flush(true); }
            SyncDirectory(Path.GetDirectoryName(partial)!);
            Verify(partial);
            try { File.Move(partial,final); }
            catch(IOException) when(File.Exists(final)) { Verify(final);File.Delete(partial);SyncDirectory(Path.GetDirectoryName(partial)!); }
            SyncDirectory(Path.GetDirectoryName(final)!);Verify(final);
        }
        return new RadiusEvidence(id,hash,"evidence:acquisition.radius."+hex,bytes.Length,DateTimeOffset.UtcNow);
    }
}
