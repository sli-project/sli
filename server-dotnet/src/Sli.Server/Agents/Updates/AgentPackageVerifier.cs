using System.Text.Json.Nodes;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using static Sli.Server.Agents.Updates.AgentPackageJson;
namespace Sli.Server.Agents.Updates;
internal sealed record VerifiedAgentPackage(string Sha256,JsonObject Manifest);
internal static class AgentPackageVerifier
{
    internal static VerifiedAgentPackage Verify(byte[] archive,byte[] trust)
    {
        try {
            Need(trust.Length<=65536);AgentPackageArchive.Inspect(archive);
            using var zip=new ZipArchive(new MemoryStream(archive,false),ZipArchiveMode.Read);
            byte[] raw=AgentPackageArchive.Read(zip.GetEntry("SLI_RELEASE.json")??throw new InvalidDataException(),8*1024*1024,out _);
            var manifest=Parse(raw);Need(CanonicalJson.ToBytes(manifest).AsSpan().SequenceEqual(raw));
            var signature=Parse(AgentPackageArchive.Read(zip.GetEntry("SLI_SIGNATURE.json")??throw new InvalidDataException(),4096,out _));
            Fields(signature,"algorithm","key_id","signature");Need(Text(signature["algorithm"])=="ed25519");string keyId=Token(signature["key_id"]);
            var policy=Parse(trust);Fields(policy,"schema_version","keys");Need(Integer(policy["schema_version"])==1);var keys=Array(policy["keys"]);Need(keys.Count is >=1 and <=64);
            var ids=new HashSet<string>(StringComparer.Ordinal);JsonObject? selected=null;
            foreach(var value in keys) {
                var key=Object(value);Fields(key,"key_id","public_key","package_ids","revoked");string id=Token(key["key_id"]);Need(ids.Add(id));_=Boolean(key["revoked"]);
                var packages=Array(key["package_ids"]);Need(packages.Count>0);foreach(var package in packages)_=Token(package);_=Base64(key["public_key"],32);if(id==keyId)selected=key;
            }
            Need(selected is not null && !Boolean(selected["revoked"]) && Array(selected["package_ids"]).Any(v=>Text(v)==Text(manifest["package_id"])));
            var signer=new Ed25519Signer();signer.Init(false,new Ed25519PublicKeyParameters(Base64(selected!["public_key"],32),0));
            signer.BlockUpdate("SLI-RELEASE-V1\0"u8);signer.BlockUpdate(raw);Need(signer.VerifySignature(Base64(signature["signature"],64)));
            var files=AgentPackageManifest.Validate(manifest);
            var expected=files.Select(f=>"payload/"+f.Path).Append("SLI_RELEASE.json").Append("SLI_SIGNATURE.json").ToHashSet(StringComparer.Ordinal);
            Need(expected.SetEquals(zip.Entries.Select(e=>e.FullName)));
            foreach(var item in files) {
                var entry=zip.GetEntry("payload/"+item.Path)!;Need(entry.Length==item.Size);_=AgentPackageArchive.Read(entry,item.Size,out string digest);Need(digest==item.Sha256);
            }
            return new(Convert.ToHexStringLower(SHA256.HashData(archive)),manifest);
        }
        catch(Exception error) when(error is InvalidDataException or JsonException or DecoderFallbackException or FormatException or ArgumentException or NotSupportedException or OverflowException or ProtocolException)
        {throw new AgentControlException("agent_package_verification_failed");}
    }
    private static byte[] Base64(JsonNode? value,int length)
    {string text=Text(value);byte[] bytes=Convert.FromBase64String(text);Need(bytes.Length==length && Convert.ToBase64String(bytes)==text);return bytes;}
}
