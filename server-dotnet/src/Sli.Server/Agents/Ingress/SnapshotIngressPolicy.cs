using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

// Admission follows Python snapshot_stream.policy. The client helper uses UTF-16
// length and ASCII numeric parsing; adapt only those differences, then reuse it.
public static class SnapshotIngressPolicy
{
    private static int BoundedCodePoints(string value)
    {
        int count = 0;
        foreach (var unused in value.EnumerateRunes()) if (++count > 512) return count;
        return count;
    }

    public static SnapshotPolicy Parse(string module, JsonObject input)
    {
        static AgentException Invalid() => new("agent_snapshot_policy_invalid");
        var normalized = (JsonObject)input.DeepClone();
        if (JsonRead.TryString(normalized["scope"], out var scope))
        {
            int length = BoundedCodePoints(scope);
            if (length is < 1 or > 512) throw Invalid();
            if (scope.Length > 512) normalized["scope"] = new string('a', length);
        }
        foreach (var field in new[] { "dc", "search_bases", "groups" })
            if (normalized[field] is JsonArray array)
                for (int i = 0; i < array.Count; i++)
                    if (JsonRead.TryString(array[i], out var value))
                    {
                        int length = BoundedCodePoints(value);
                        if (length is < 1 or > 512) throw Invalid();
                        if (value.Length > 512) array[i] = new string('a', length);
                    }
        if (JsonRead.TryString(normalized["domain_sid"], out var sid))
        {
            const string prefix = "S-1-5-21-";
            if (!sid.StartsWith(prefix, StringComparison.Ordinal)) throw Invalid();
            var sidForValidation = new StringBuilder(prefix);
            foreach (var rune in sid[prefix.Length..].EnumerateRunes())
            {
                if (Rune.GetUnicodeCategory(rune) == UnicodeCategory.DecimalDigitNumber)
                {
                    int digit = CharUnicodeInfo.GetDecimalDigitValue(rune.ToString(), 0);
                    if (digit < 0) throw Invalid();
                    sidForValidation.Append((char)('0' + digit));
                }
                else sidForValidation.Append(rune.ToString());
            }
            normalized["domain_sid"] = sidForValidation.ToString();
        }
        string? originalRevision = null;
        if (JsonRead.TryString(normalized["policy_revision"], out var revision))
        {
            var digits = new StringBuilder();
            foreach (var rune in revision.EnumerateRunes())
            {
                if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) throw Invalid();
                int digit = CharUnicodeInfo.GetDecimalDigitValue(rune.ToString(), 0);
                if (digit < 0) throw Invalid();
                digits.Append((char)('0' + digit));
            }
            if (digits.Length == 0 || digits.Length > 4300) throw Invalid();
            var value = BigInteger.Parse(digits.ToString(), CultureInfo.InvariantCulture);
            if (value < 1 || value > 9007199254740991L) throw Invalid();
            originalRevision = revision;
            normalized["policy_revision"] = value.ToString(CultureInfo.InvariantCulture);
        }
        var result = SnapshotPolicy.Parse(module, normalized);
        if (input.ContainsKey("scope")) result.Config["scope"] = input["scope"]?.DeepClone();
        if (input.ContainsKey("domain_sid")) result.Config["domain_sid"] = input["domain_sid"]?.DeepClone();
        foreach (var field in new[] { "dc", "search_bases", "groups" })
            if (input.ContainsKey(field)) result.Config[field] = input[field]?.DeepClone();
        if (originalRevision is not null) result.Config["policy_revision"] = originalRevision;
        return result;
    }
}
