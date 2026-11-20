using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

public sealed class RadiusCursorBootstrapError(string code) : ArgumentException(code)
{
    public string Code { get; } = code;
}

public sealed record RadiusCursorAnchor(string FileGeneration, long ByteOffset, string LastRecordSha256, long BoundaryLagBytes);

// Source: server/source_packs/radius/accounting_bootstrap.py. The caller supplies an already-read suffix.
public static class RadiusCursorBootstrap
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static RadiusCursorAnchor DeriveCursorAnchor(string sourceInstanceId, string fileName, long fileCreationTimeNs,
        byte[] tailBytes, long tailStartOffset, long observedFileSize)
    {
        string source = PythonText.Strip(sourceInstanceId ?? "");
        if (!Regex.IsMatch(source, @"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z"))
            throw new RadiusCursorBootstrapError("bootstrap_source_instance_invalid");
        if (string.IsNullOrEmpty(fileName) || fileName == "." || fileName.Contains('/') || fileName.Contains('\\') || Path.GetFileName(fileName) != fileName)
            throw new RadiusCursorBootstrapError("bootstrap_file_basename_invalid");
        if (fileCreationTimeNs <= 0) throw new RadiusCursorBootstrapError("bootstrap_creation_time_invalid");
        if (tailStartOffset < 0 || observedFileSize < tailStartOffset || tailBytes.LongLength != observedFileSize - tailStartOffset)
            throw new RadiusCursorBootstrapError("bootstrap_tail_range_invalid");

        int boundary = Array.LastIndexOf(tailBytes, (byte)'\n');
        if (boundary < 0) throw new RadiusCursorBootstrapError("bootstrap_complete_record_required");

        // bytes.splitlines() in the reference recognizes CR, LF and CRLF, without decoding partial segments.
        int segmentStart = 0, segmentCount = 0, recordStart = -1, recordLength = 0;
        for (int i = 0; i <= boundary; i++)
        {
            if (tailBytes[i] is not (0x0a or 0x0d)) continue;
            int length = i - segmentStart;
            if ((tailStartOffset == 0 || segmentCount > 0) && !IsBlank(tailBytes.AsSpan(segmentStart, length)))
            {
                recordStart = segmentStart;
                recordLength = length;
            }
            segmentCount++;
            if (tailBytes[i] == 0x0d && i < boundary && tailBytes[i + 1] == 0x0a) i++;
            segmentStart = i + 1;
        }
        if (tailStartOffset > 0 && segmentCount < 2) throw new RadiusCursorBootstrapError("bootstrap_bounded_tail_too_small");
        if (recordStart < 0) throw new RadiusCursorBootstrapError("bootstrap_complete_record_required");

        string line;
        try
        {
            line = Utf8.GetString(tailBytes, recordStart, recordLength);
            if (line.StartsWith('\uFEFF')) line = line[1..]; // utf-8-sig removes one leading BOM.
        }
        catch (DecoderFallbackException) { throw new RadiusCursorBootstrapError("bootstrap_record_encoding_invalid"); }
        try { RadiusAccountingRecord.Validate(line); }
        catch (AgentException) { throw new RadiusCursorBootstrapError("bootstrap_last_record_invalid"); }

        string generationMaterial = UnicodeCaseFold.Fold(source) + "\0" + UnicodeCaseFold.Fold(fileName) + "\0" + fileCreationTimeNs.ToString(CultureInfo.InvariantCulture);
        long offset = tailStartOffset + boundary + 1L;
        return new("gen-" + Hash(generationMaterial)[..32], offset, Hash(line), observedFileSize - offset);
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Utf8.GetBytes(value)));

    private static bool IsBlank(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
            if (value is not (0x09 or 0x0a or 0x0b or 0x0c or 0x0d or 0x20)) return false;
        return true;
    }
}
