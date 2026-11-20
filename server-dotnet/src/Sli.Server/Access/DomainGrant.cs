using System.Collections.Frozen;

namespace Sli.Server.Access;

public enum DomainGrantKind { None, All, Scoped }

public sealed record DomainGrant(DomainGrantKind Kind, IReadOnlySet<long> DomainIds)
{
    public static DomainGrant None { get; } = new(DomainGrantKind.None, Array.Empty<long>().ToFrozenSet());
    public static DomainGrant All { get; } = new(DomainGrantKind.All, Array.Empty<long>().ToFrozenSet());
    public static DomainGrant Scoped(IEnumerable<long> ids)
    {
        var values = ids.ToFrozenSet();
        if (values.Any(id => id <= 0)) throw new ArgumentOutOfRangeException(nameof(ids));
        return values.Count == 0 ? None : new(DomainGrantKind.Scoped, values);
    }
}
