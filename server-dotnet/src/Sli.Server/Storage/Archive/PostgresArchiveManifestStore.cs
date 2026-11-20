using Npgsql;

namespace Sli.Server.Storage.Archive;

// Each operation commits independently of the importer/core transaction, as in the Python adapter.
internal sealed class PostgresArchiveManifestStore(NpgsqlDataSource worker, bool lifecycleReadOnly = false) : IArchiveManifestStore
{
    const string Columns = "archive_set_id,archive_kind,format_version,block_index,first_event_id,last_event_id,row_count,raw_bytes,compressed_bytes,raw_sha256,archive_sha256,object_location,state,created_at,verified_at";
    async Task<T> Run<T>(Func<NpgsqlConnection,NpgsqlTransaction,Task<T>> action, CancellationToken ct)
    {
        await using var db = await worker.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        if (lifecycleReadOnly) {
            await using var readOnly = new NpgsqlCommand("set transaction read only", db, tx); await readOnly.ExecuteNonQueryAsync(ct);
        } else {
            await using (var role = new NpgsqlCommand("set local role adlog_storage_worker", db, tx)) await role.ExecuteNonQueryAsync(ct);
            await using var check = new NpgsqlCommand("select current_user", db, tx);
            if ((string?)await check.ExecuteScalarAsync(ct) != "adlog_storage_worker") throw new InvalidOperationException("storage_v2_worker_role_required");
        }
        var value = await action(db, tx);
        await tx.CommitAsync(ct);
        return value;
    }

    public async Task EnsureSetAsync(ArchiveSet set, CancellationToken ct) => _ = await Run(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand("""
            insert into storage_v2_archive_sets(archive_set_id,archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows,state)
            values (@id,@kind,@version,@first,@last,@rows,'staging')
            on conflict(archive_set_id) do update set archive_set_id=excluded.archive_set_id
            returning archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows
            """, db, tx);
        command.Parameters.AddWithValue("id", set.Id); command.Parameters.AddWithValue("kind", set.Kind);
        command.Parameters.AddWithValue("version", set.Version); command.Parameters.AddWithValue("first", set.FirstId);
        command.Parameters.AddWithValue("last", set.LastId); command.Parameters.AddWithValue("rows", (long)set.Rows);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct) || reader.GetString(0) != set.Kind || reader.GetInt32(1) != set.Version || reader.GetInt64(2) != set.FirstId || reader.GetInt64(3) != set.LastId || reader.GetInt64(4) != set.Rows)
            throw new InvalidDataException("archive_set_identity_conflict");
        return true;
    }, ct);

    public Task<ArchiveBlock?> GetAsync(Guid id, string kind, int index, CancellationToken ct) => Run(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand($"select {Columns} from storage_v2_archive_blocks where archive_set_id=@id and archive_kind=@kind and block_index=@index",db,tx);
        Identity(command,id,kind,index);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Read(reader) : null;
    },ct);

    public Task<ArchiveBlock> StageAsync(ArchiveBlock block, CancellationToken ct) => Run(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand($"""
            insert into storage_v2_archive_blocks(
                archive_set_id,archive_kind,format_version,block_index,first_event_id,last_event_id,
                row_count,raw_bytes,compressed_bytes,raw_sha256,archive_sha256,object_location,state,created_at,verified_at)
            values (@id,@kind,@version,@index,@first,@last,@rows,@raw_bytes,@compressed_bytes,@raw_sha,@archive_sha,@location,'staging',@created,@verified)
            on conflict(archive_set_id,archive_kind,block_index) do update set
                raw_bytes=excluded.raw_bytes,compressed_bytes=excluded.compressed_bytes,
                raw_sha256=excluded.raw_sha256,archive_sha256=excluded.archive_sha256,
                object_location=excluded.object_location,verified_at=excluded.verified_at
            where storage_v2_archive_blocks.archive_sha256=excluded.archive_sha256
              and storage_v2_archive_blocks.state in ('staging','verified','published')
              and storage_v2_archive_blocks.raw_sha256=excluded.raw_sha256
              and storage_v2_archive_blocks.format_version=excluded.format_version
              and storage_v2_archive_blocks.first_event_id=excluded.first_event_id
              and storage_v2_archive_blocks.last_event_id=excluded.last_event_id
              and storage_v2_archive_blocks.row_count=excluded.row_count
            returning {Columns}
            """,db,tx);
        Identity(command,block.SetId,block.Kind,block.Index);
        command.Parameters.AddWithValue("version", block.Version); command.Parameters.AddWithValue("first", block.FirstId);
        command.Parameters.AddWithValue("last", block.LastId); command.Parameters.AddWithValue("rows", block.Rows);
        command.Parameters.AddWithValue("raw_bytes", block.RawBytes); command.Parameters.AddWithValue("compressed_bytes", block.CompressedBytes);
        command.Parameters.AddWithValue("raw_sha", Convert.FromHexString(block.RawSha256)); command.Parameters.AddWithValue("archive_sha", Convert.FromHexString(block.ArchiveSha256));
        command.Parameters.AddWithValue("location", block.ObjectLocation); command.Parameters.AddWithValue("created", block.CreatedAt);
        command.Parameters.AddWithValue("verified", block.VerifiedAt ?? DateTime.UtcNow);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new InvalidDataException("archive_manifest_identity_conflict");
        return Read(reader);
    },ct);

    public Task<ArchiveBlock> MarkPublishedAsync(ArchiveBlock block, CancellationToken ct) => Run(async (db,tx) =>
    {
        ArchiveBlock result;
        await using (var command = new NpgsqlCommand($"""
            update storage_v2_archive_blocks set state='published',published_at=coalesce(published_at,now()),quarantine_reason=null
            where archive_set_id=@id and archive_kind=@kind and block_index=@index
              and state in ('staging','verified','published') and archive_sha256=@hash
            returning {Columns}
            """,db,tx))
        {
            Identity(command,block.SetId,block.Kind,block.Index); command.Parameters.AddWithValue("hash",Convert.FromHexString(block.ArchiveSha256));
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new InvalidDataException("archive_block_missing_or_quarantined");
            result=Read(reader);
        }
        await using (var command = new NpgsqlCommand("""
            update storage_v2_archive_sets set state='published',verified_at=coalesce(verified_at,now()),published_at=coalesce(published_at,now())
            where archive_set_id=@id and state<>'quarantined'
            """,db,tx))
        {
            command.Parameters.AddWithValue("id",block.SetId);
            if (await command.ExecuteNonQueryAsync(ct) != 1) throw new InvalidDataException("archive_set_missing_or_quarantined");
        }
        return result;
    },ct);

    public Task<ArchiveBlock?> FindPublishedAsync(string kind, long eventId, CancellationToken ct) => Run(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand($"""
            select {Columns} from storage_v2_archive_blocks
            where archive_kind=@kind and state='published' and first_event_id<=@event and last_event_id>=@event
            order by first_event_id desc,block_index desc limit 1
            """,db,tx);
        command.Parameters.AddWithValue("kind",kind); command.Parameters.AddWithValue("event",eventId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Read(reader) : null;
    },ct);

    // The lifecycle batch already owns a read-only snapshot. Keep exactly the
    // single-event winner (including overlapping ranges), with one round trip.
    internal static async Task<Dictionary<long,ArchiveBlock>> FindPublishedManyAsync(NpgsqlConnection db, NpgsqlTransaction tx, string kind, long[] ids, CancellationToken ct)
    {
        if (ids.Length == 0) return [];
        if (ids.Length > 1000) throw new ArgumentOutOfRangeException(nameof(ids));
        await using var command = new NpgsqlCommand($"""
            select block.*,wanted.event_id from unnest(@ids::bigint[]) wanted(event_id)
            cross join lateral (
                select {Columns} from storage_v2_archive_blocks
                where archive_kind=@kind and state='published' and first_event_id<=wanted.event_id and last_event_id>=wanted.event_id
                order by first_event_id desc,block_index desc limit 1
            ) block
            """, db, tx);
        command.Parameters.AddWithValue("kind", kind); command.Parameters.AddWithValue("ids", ids);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = new Dictionary<long,ArchiveBlock>();
        while (await reader.ReadAsync(ct)) result.Add(reader.GetInt64(15), Read(reader));
        return result;
    }
    public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind, long firstId, long lastId, CancellationToken ct) => Run<IReadOnlyList<ArchiveBlock>>(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand($"""
            select {Columns} from storage_v2_archive_blocks
            where archive_kind=@kind and state='published' and last_event_id>=@first and first_event_id<=@last
            order by first_event_id,last_event_id,archive_set_id,block_index
            """,db,tx);
        command.Parameters.AddWithValue("kind",kind); command.Parameters.AddWithValue("first",firstId); command.Parameters.AddWithValue("last",lastId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var blocks = new List<ArchiveBlock>();
        while (await reader.ReadAsync(ct)) blocks.Add(Read(reader));
        return blocks;
    },ct);

    public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind, long firstId, long lastId, int limit, CancellationToken ct) => Run<IReadOnlyList<ArchiveBlock>>(async (db,tx) =>
    {
        await using var command = new NpgsqlCommand($"""
            select {Columns} from storage_v2_archive_blocks
            where archive_kind=@kind and state='published' and last_event_id>=@first and first_event_id<=@last
            order by first_event_id,last_event_id,archive_set_id,block_index limit @limit
            """,db,tx) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("kind",kind); command.Parameters.AddWithValue("first",firstId);
        command.Parameters.AddWithValue("last",lastId); command.Parameters.AddWithValue("limit",limit);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var blocks = new List<ArchiveBlock>();
        while (await reader.ReadAsync(ct)) blocks.Add(Read(reader));
        return blocks;
    },ct);

    static void Identity(NpgsqlCommand command, Guid id, string kind, int index)
    { command.Parameters.AddWithValue("id",id); command.Parameters.AddWithValue("kind",kind); command.Parameters.AddWithValue("index",index); }
    internal static ArchiveBlock Read(System.Data.Common.DbDataReader reader) => new(reader.GetGuid(0),reader.GetString(1),reader.GetInt32(2),reader.GetInt32(3),
        reader.GetInt64(4),reader.GetInt64(5),reader.GetInt32(6),reader.GetInt64(7),reader.GetInt64(8),
        Convert.ToHexString(reader.GetFieldValue<byte[]>(9)),Convert.ToHexString(reader.GetFieldValue<byte[]>(10)),reader.GetString(11),reader.GetString(12),
        reader.GetDateTime(13),reader.IsDBNull(14) ? null : reader.GetDateTime(14));
}
