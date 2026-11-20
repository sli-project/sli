using System.Globalization;

namespace Sli.Server.Domains;

/// <summary>Matches parse_qs(..., keep_blank_values=False) for the domain route.</summary>
public static class DomainQuery
{
    // Only an absent selector means all accessible domains.
    public static long? ParseDomainId(IQueryCollection query)
    {
        if (!query.TryGetValue("domain_id", out var values)) return null;
        if (values.Count != 1 || values[0] is not { } value || value.Length is < 1 or > 19
            || value[0] == '0' || value.Any(c => c is < '0' or > '9')
            || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var id))
            throw new HomeQueryException("domain_scope_invalid");
        return id;
    }

    public static bool HasParameters(string? rawQuery)
    {
        if (string.IsNullOrEmpty(rawQuery))
        {
            return false;
        }

        ReadOnlySpan<char> query = rawQuery.AsSpan();
        if (query[0] == '?')
        {
            query = query[1..];
        }

        while (!query.IsEmpty)
        {
            int separator = query.IndexOf('&');
            ReadOnlySpan<char> pair = separator < 0 ? query : query[..separator];
            int equals = pair.IndexOf('=');
            if (equals >= 0 && equals < pair.Length - 1)
            {
                return true;
            }

            if (separator < 0)
            {
                break;
            }
            query = query[(separator + 1)..];
        }

        return false;
    }
}
