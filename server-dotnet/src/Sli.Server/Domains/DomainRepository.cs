using System.Globalization;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;

namespace Sli.Server.Domains;

/// <summary>Reads only domains admitted by the caller's composed access grant.</summary>
public interface IDomainRepository
{
    Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken cancellationToken);
}

public sealed class DomainRepository(IPostgresConnectionFactory connections) : IDomainRepository
{
    private const string DomainSql = """
        select d.id, d.fqdn as display_name, d.is_archived,
               m.slot_start_utc as snapshot_at_utc, m.created_at as published_at_utc,
               m.coverage_state as snapshot_state,
               observed.observed_at_utc, current_observation.observed_at_utc as default_observed_at_utc,
               events.event_at_utc, events.last_successful_collection_utc
        from domains d
        left join lateral (
            select manifest_id, slot_start_utc, created_at, coverage_state
            from ad_snapshot_manifests where domain_id=d.id
            order by slot_start_utc desc, manifest_id desc limit 1
        ) m on true
        left join lateral (
            select min(observed_at_utc) as observed_at_utc
            from ad_snapshot_manifest_sources where manifest_id=m.manifest_id
        ) observed on true
        left join lateral (
            select max(run.observed_at_utc) as observed_at_utc
            from ad_context_runs run
            where run.domain_id=d.id and run.status='completed'
        ) current_observation on true
        left join lateral (
            select max(c.last_event_time_utc) as event_at_utc,
                   max(c.last_successful_collection_utc) as last_successful_collection_utc
            from servers s join collection_channel_state c
              on lower(c.server_hostname)=lower(s.fqdn)
              or (lower(c.server_hostname)=lower(s.hostname) and not exists (
                  select 1 from servers other
                  where lower(other.hostname)=lower(s.hostname) and other.id<>s.id
              ))
            where s.domain_id=d.id
        ) events on true
        where (cast(@ids as bigint[]) is null or d.id=any(cast(@ids as bigint[])))
        order by d.fqdn, d.id
        """;

    public async Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(grant.DomainIds);
        if (grant.DomainIds.Any(id => id <= 0))
        {
            throw new ArgumentException("Domain IDs must be positive.", nameof(grant));
        }

        if (grant.Kind == DomainGrantKind.None || (grant.Kind == DomainGrantKind.Scoped && grant.DomainIds.Count == 0))
        {
            return Array.Empty<DomainItem>();
        }
        if (grant.Kind is not (DomainGrantKind.All or DomainGrantKind.Scoped)
            || (grant.Kind == DomainGrantKind.All && grant.DomainIds.Count != 0))
        {
            throw new ArgumentException("Invalid domain grant.", nameof(grant));
        }

        await using NpgsqlConnection connection = await connections.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(DomainSql, connection, transaction) { CommandTimeout = 0 };
        command.Parameters.Add(new NpgsqlParameter("ids", NpgsqlDbType.Array | NpgsqlDbType.Bigint)
        {
            Value = grant.Kind == DomainGrantKind.All ? DBNull.Value : grant.DomainIds.Order().ToArray()
        });
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        var items = new List<DomainItem>();
        while (await reader.ReadAsync(cancellationToken))
        {
            items.Add(new DomainItem(
                reader.GetInt64(0), reader.GetString(1), reader.GetBoolean(2),
                new DomainFreshness(
                    Timestamp(reader, 3), Timestamp(reader, 4), Text(reader, 5),
                    Timestamp(reader, 6), Timestamp(reader, 7), Text(reader, 8), Text(reader, 9))));
        }
        return items;
    }

    private static string? Text(NpgsqlDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string? Timestamp(NpgsqlDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        DateTime utc = reader.GetFieldValue<DateTime>(ordinal).ToUniversalTime();
        string value = utc.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        long microseconds = (utc.Ticks % TimeSpan.TicksPerSecond) / 10;
        if (microseconds != 0)
        {
            value += "." + microseconds.ToString("D6", CultureInfo.InvariantCulture);
        }
        return value + "+00:00";
    }
}
