using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Tests.Agents;

// Every test owns a fresh cluster, loopback port and generated login; no inherited DSN.
internal sealed class PostCollectionPostgres(bool canonicalSchema = false, string host = "127.0.0.1", int? fixedPort = null, string database = "postgres", int maxConnections = 100) : IAsyncDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sli-p04-" + Guid.NewGuid().ToString("N"));
    private readonly Guid identity = Guid.NewGuid();
    private readonly string login = canonicalSchema ? "postgres" : "p04_" + Guid.NewGuid().ToString("N");
    private string bin = "", dsn = ""; private bool started;
    private Process? server;
    private Task<string>? serverOutput, serverError;
    internal string ConnectionString => dsn;
    internal string Root => root;
    internal string BinaryDirectory => bin;
    internal async Task<string> DiagnosticsAsync(CancellationToken ct)
    {
        await using var stream = new FileStream(Path.Combine(root, "data", "log", "p04.log"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream); return await reader.ReadToEndAsync(ct);
    }
    internal static string Repository([CallerFilePath] string path = "") => Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../../.."));

    private async Task ProcessAsync(string name, CancellationToken ct, params string[] args)
    {
        var info = new ProcessStartInfo(Path.Combine(bin, name + (OperatingSystem.IsWindows() ? ".exe" : ""))) {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("PG", StringComparison.OrdinalIgnoreCase)).ToArray()) info.Environment.Remove(key);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Cannot start isolated PostgreSQL");
        var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct); string result = await stdout + await stderr;
        if (process.ExitCode != 0) throw new InvalidOperationException(name + " failed: " + result);
    }

    internal async Task StartAsync(CancellationToken ct)
    {
        var candidates = OperatingSystem.IsWindows() ? new[] { "D:/PostgreSQL/18/bin", "C:/Program Files/PostgreSQL/18/bin", "C:/Program Files/PostgreSQL/17/bin" }
            : Directory.Exists("/usr/lib/postgresql") ? Directory.GetDirectories("/usr/lib/postgresql").OrderDescending().Select(d => Path.Combine(d, "bin")).ToArray() : ["/usr/local/pgsql/bin"];
        bin = candidates.FirstOrDefault(d => File.Exists(Path.Combine(d, "initdb" + (OperatingSystem.IsWindows() ? ".exe" : "")))) ?? throw new InvalidOperationException("PostgreSQL test binaries required");
        Directory.CreateDirectory(root);
        await ProcessAsync("initdb", ct, "-D", Path.Combine(root, "data"), "--username=" + login, "--auth=trust", "--no-locale", "--encoding=UTF8");
        await File.AppendAllTextAsync(Path.Combine(root, "data", "postgresql.conf"), $"\nmax_connections={maxConnections}\nsuperuser_reserved_connections=3\n", ct);
        using var listener = new TcpListener(IPAddress.Parse(host), fixedPort ?? 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        dsn = new NpgsqlConnectionStringBuilder { Host = host, Port = port, Database = "postgres", Username = login, Pooling = false, Timeout = 3, CommandTimeout = 15, SslMode = SslMode.Disable }.ConnectionString;
        if (OperatingSystem.IsWindows()) {
            // pg_ctl cannot create a second restricted token inside the managed Windows sandbox.
            // Start our own child with the existing restricted token; no elevation or server bypass flags.
            var info = new ProcessStartInfo(Path.Combine(bin, "postgres.exe")) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { "-D", Path.Combine(root, "data"), "-h", host, "-p", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "-c", "timezone=UTC", "-c", "logging_collector=on", "-c", "log_directory=log", "-c", "log_filename=p04.log" }) info.ArgumentList.Add(arg);
            server = Process.Start(info) ?? throw new InvalidOperationException("Cannot start isolated PostgreSQL");
            serverOutput = server.StandardOutput.ReadToEndAsync(); serverError = server.StandardError.ReadToEndAsync();
            bool acceptingConnections = false;
            for (int i = 0; i < 100; i++) {
                if (server.HasExited) throw new InvalidOperationException("Isolated PostgreSQL failed: " + await serverError);
                // Connecting while startup is in progress writes a FATAL to the
                // server log. Wait for our own postmaster's ready status first;
                // AssertNoSqlErrorsAsync must still reject every database error.
                try {
                    string[] status = await File.ReadAllLinesAsync(Path.Combine(root, "data", "postmaster.pid"), ct);
                    if (status.Length > 7 && status[7].Trim() == "ready") { acceptingConnections = true; break; }
                } catch (IOException) { }
                await Task.Delay(100, ct);
            }
            if (!acceptingConnections) throw new TimeoutException("Isolated PostgreSQL did not become ready");
            started = true;
        } else {
            // PostgreSQL resolves the socket path relative to this cluster's data directory.
            await ProcessAsync("pg_ctl", ct, "-D", Path.Combine(root, "data"), "-l", Path.Combine(root, "postgres.log"), "-o", $"-h {host} -p {port} -k . -c timezone=UTC -c logging_collector=on -c log_directory=log -c log_filename=p04.log", "-t", "10", "-w", "start");
            started = true;
        }
        // The postmaster can accept sockets before a backend has completed
        // startup on a busy runner. Bound fixture setup separately from app I/O.
        var setup = new NpgsqlConnectionStringBuilder(dsn) { Timeout = 10 };
        if (database != "postgres") {
            if (database != "sli") throw new ArgumentException(nameof(database));
            await using var initial = new NpgsqlConnection(setup.ConnectionString); await initial.OpenAsync(ct);
            await Sql(initial, "create database sli", ct);
            setup.Database = database;
            dsn = new NpgsqlConnectionStringBuilder(dsn) { Database = database }.ConnectionString;
        }
        await using var db = new NpgsqlConnection(setup.ConnectionString); await db.OpenAsync(ct);
        await using var seed = new NpgsqlCommand("create table sli_p04_test_owner(id uuid primary key); insert into sli_p04_test_owner values(@id)", db);
        seed.Parameters.AddWithValue("id", identity); await seed.ExecuteNonQueryAsync(ct);
        if (!canonicalSchema) await SchemaAsync(db, ct);
    }
    internal async Task ApplyFileAsync(string path, string? role, CancellationToken ct)
    {
        var settings = new NpgsqlConnectionStringBuilder(dsn);
        // Linux release SQL and its function-body hashes use LF, even on a CRLF checkout.
        string normalized = Path.Combine(root, "apply.sql");
        await File.WriteAllTextAsync(normalized, (await File.ReadAllTextAsync(path, ct)).Replace("\r\n", "\n"), ct);
        try {
            await ProcessAsync("psql", ct, "-X", "-q", "-w", "-v", "ON_ERROR_STOP=1", "-h", settings.Host!, "-p", settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "-U", role ?? settings.Username!, "-d", settings.Database!, "-f", normalized);
        } catch (InvalidOperationException error) { throw new InvalidOperationException(Path.GetFileName(path) + ": " + error.Message, error); }
    }
    internal async Task<NpgsqlConnection> OpenAsync(CancellationToken ct, string? role = null)
    {
        var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct);
        try {
            await using (var check = new NpgsqlCommand("select id from sli_p04_test_owner", db))
                if (await check.ExecuteScalarAsync(ct) is not Guid id || id != identity) throw new InvalidOperationException("Isolated PostgreSQL ownership mismatch");
            if (role is not null) {
                if (role is not ("adlog_context_worker" or "adlog_user")) throw new ArgumentException(nameof(role));
                await using var set = new NpgsqlCommand("set role " + role, db); await set.ExecuteNonQueryAsync(ct);
            }
            return db;
        } catch { await db.DisposeAsync(); throw; }
    }
    internal static async Task Sql(NpgsqlConnection db, string sql, CancellationToken ct)
    { await using var c = new NpgsqlCommand(sql, db); await c.ExecuteNonQueryAsync(ct); }

    internal static async Task InstallSnapshotChangeStorageAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await Sql(db, Table("165_ad_snapshot_change_history.sql", "ad_snapshot_history_confirmations"), ct);
        string migration = File.ReadAllText(Path.Combine(Repository(), "config/postgres_migrations/338_ad_snapshot_change_storage.sql"));
        await Sql(db, Regex.Match(migration, @"create table public\.ad_snapshot_change_history[\s\S]*?\) partition by range\(observed_at\);").Value, ct);
        await Sql(db, Regex.Match(migration, @"create function public\.create_ad_snapshot_change_partition[\s\S]*?\$\$;").Value, ct);
    }

    internal static async Task PublishSnapshotChangesAsync(NpgsqlConnection db, Guid manifest, CancellationToken ct)
    {
        await using var source = NpgsqlDataSource.Create(db.ConnectionString);
        var history = new SnapshotHistory(source, _ => null, () => throw new InvalidOperationException("Fixture only publishes snapshots"));
        await using var transaction = await db.BeginTransactionAsync(ct);
        await history.PublishManifest(db, transaction, manifest, ct);
        await transaction.CommitAsync(ct);
    }

    private static string Table(string file, string name)
    {
        string sql = File.ReadAllText(Path.Combine(Repository(), "config/postgres_migrations", file));
        var match = Regex.Match(sql, @"create table (?:if not exists )?(?:public\.)?" + Regex.Escape(name) + @"\s*\([\s\S]*?\r?\n\);", RegexOptions.IgnoreCase);
        if (!match.Success) throw new InvalidOperationException("Canonical test table not found: " + name);
        return match.Value;
    }
    private static async Task SchemaAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await Sql(db, """
            create role adlog_context_worker; create role adlog_user; create role adlog_nps_agent_import_worker;
            create table domains(id bigserial primary key,domain_sid text not null,fqdn text not null);
            insert into domains(id,domain_sid,fqdn) values(7,'S-1-5-21-100000001-200000002-300000003','directory.invalid');
            create table sli_agents(id uuid primary key,status text not null default 'active',assigned_modules jsonb not null);
            create table sli_agent_receipts(packet_id uuid primary key,agent_id uuid,module_id text,sequence bigint,envelope jsonb,envelope_sha256 text);
            create table sli_agent_snapshot_bindings(agent_id uuid,module_id text,primary key(agent_id,module_id));
            create table sli_agent_packet_inbox(packet_id uuid primary key,received_at timestamptz,imported_at timestamptz,envelope jsonb,packet jsonb,event_rows jsonb,
                module_disabled_at timestamptz check(module_disabled_at is null or imported_at is null));
            create table sli_agent_packet_quarantine(packet_id uuid primary key,reason_code text,event_ordinal integer);
            create table runtime_worker_heartbeats(worker_name text primary key,worker_id text,process_pid integer,status text,phase text,expected_interval_seconds integer,details_json jsonb,started_at timestamptz,heartbeat_at timestamptz,updated_at timestamptz);
            create table p04_plugins(plugin_id text primary key,installed boolean,enabled boolean);
            insert into p04_plugins values('sli.ad',true,true),('sli.gpo',true,true);
            create function read_plugin_states_v1() returns table(plugin_id text,installed boolean,enabled boolean) language sql security definer as $$select * from p04_plugins$$;
            """, ct);
        await Sql(db, Table("009_storage_v2_foundation.sql", "storage_v2_entity_type"), ct);
        await Sql(db, Table("009_storage_v2_foundation.sql", "entities_v2").Replace("id integer primary key", "id serial primary key"), ct);
        await Sql(db, Table("009_storage_v2_foundation.sql", "entity_details_v2"), ct);
        foreach (string name in new[] { "ad_context_runs", "ad_context_sections", "ad_context_entity_aliases", "ad_context_entity_versions", "ad_context_relation_versions", "ad_context_evidence" })
            await Sql(db, Table("017_ad_context_foundation.sql", name).Replace("references observed_entities(id)", "references entities_v2(id)"), ct);
        await Sql(db, "alter table ad_context_runs add column scope_json jsonb not null default '{}'::jsonb", ct);
        await Sql(db, Table("110_users_report_v2_reference.sql", "users_report_v2_snapshots").Replace("scope_sha256,bucket_start_utc,contract_id,schema_version", "scope_sha256,source_observed_at_utc,contract_id,schema_version"), ct);
        string computers = Table("114_computers_v6_source_snapshot.sql", "computers_v6_source_snapshots");
        computers = computers.Replace("and collector_sha256=decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex')", "and (collector_sha256=decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex') or (collector_version='sli-agent/ad-snapshot/1' and collector_sha256=sha256(convert_to('sli-agent/ad-snapshot/1','UTF8'))))");
        await Sql(db, computers, ct);
        foreach (string name in new[] { "sli_agent_snapshot_cycles", "sli_agent_snapshot_chunks" }) await Sql(db, Table("170_agent_snapshot_stream.sql", name), ct);
        string manifests = Table("121_ad_snapshot_manifest_foundation.sql", "ad_snapshot_manifests");
        manifests = manifests.Replace("contract_version='sli.ad-snapshot-manifest/1.0'", "contract_version in ('sli.ad-snapshot-manifest/1.0','sli.ad-snapshot-manifest/2.0','sli.ad-snapshot-manifest/3.0')")
            .Replace("check(slot_start_utc=date_trunc('day',slot_start_utc)\n        or slot_start_utc=date_trunc('day',slot_start_utc)+interval '12 hours'),", "")
            .Replace("check(slot_start_utc=date_trunc('day',slot_start_utc)\r\n        or slot_start_utc=date_trunc('day',slot_start_utc)+interval '12 hours'),", "");
        await Sql(db, manifests, ct);
        foreach (string name in new[] { "ad_snapshot_manifest_sources", "ad_snapshot_projection_receipts" }) await Sql(db, Table("121_ad_snapshot_manifest_foundation.sql", name), ct);
        await Sql(db, Table("129_ad_snapshot_projection_retention.sql", "ad_snapshot_projection_outputs"), ct);
        await Sql(db, Table("116_gpo_report_v2_reference.sql", "gpo_report_v2_source_snapshots"), ct);
        await InstallSnapshotChangeStorageAsync(db, ct);
        await Sql(db, """
            revoke all on function public.create_ad_snapshot_change_partition(timestamptz) from public;
            grant execute on function public.create_ad_snapshot_change_partition(timestamptz) to adlog_context_worker;
            grant select,insert on public.ad_snapshot_change_history,public.ad_snapshot_history_confirmations to adlog_context_worker;
            """, ct);
        string snapshotGuard = File.ReadAllText(Path.Combine(Repository(), "config/postgres_migrations/204_agent_gpo_history_slot_timestamp.sql"));
        await Sql(db, Regex.Match(snapshotGuard, @"create or replace function public\.ad_snapshot_history_confirmation_guard_v165[\s\S]*?\$\$;").Value, ct);
        await Sql(db, """
            revoke all on function public.ad_snapshot_history_confirmation_guard_v165() from public;
            create trigger ad_snapshot_history_confirmation_guard_v165 before insert or update or delete
                on public.ad_snapshot_history_confirmations for each row execute function public.ad_snapshot_history_confirmation_guard_v165();
            """, ct);
        var admission = File.ReadAllText(Path.Combine(Repository(), "config/postgres_migrations/380_disabled_module_intake.sql"));
        int functionStart = admission.IndexOf("create function public.agent_module_enabled_v380", StringComparison.Ordinal);
        int functionEnd = admission.IndexOf("alter table public.sli_agent_packet_inbox", StringComparison.Ordinal);
        if (functionStart < 0 || functionEnd <= functionStart)
            throw new InvalidOperationException("Canonical module admission SQL not found");
        await Sql(db, admission[functionStart..functionEnd], ct);
        string npsMigration = File.ReadAllText(Path.Combine(Repository(), "config/postgres_migrations/304_nps_agent_row_lock.sql"));
        await Sql(db, Regex.Match(npsMigration, @"create function public\.lock_nps_import_agent_v304[\s\S]*?\$\$;").Value, ct);
        await Sql(db, """
            alter table sli_agent_snapshot_cycles add column publication_state text not null default 'pending',add column manifest_id uuid references ad_snapshot_manifests(manifest_id),add column published_at timestamptz,add column gpo_source_run_id uuid references ad_context_runs(run_id),add column superseded_reason text,add column superseded_at timestamptz;
            create unique index p04_entity_open on ad_context_entity_versions(entity_id,source_section) where valid_to_utc is null;
            create unique index p04_relation_open on ad_context_relation_versions(domain_id,relation_key) where valid_to_utc is null;
            grant usage on schema public to adlog_context_worker,adlog_user;
            grant select on all tables in schema public to adlog_context_worker,adlog_user;
            grant select,insert,update on domains,storage_v2_entity_type,entities_v2,entity_details_v2,ad_context_runs,ad_context_sections,ad_context_entity_aliases,ad_context_entity_versions,ad_context_relation_versions,ad_context_evidence,ad_snapshot_projection_receipts to adlog_context_worker;
            grant insert on users_report_v2_snapshots,computers_v6_source_snapshots,ad_snapshot_manifests,ad_snapshot_manifest_sources,ad_snapshot_projection_outputs,gpo_report_v2_source_snapshots to adlog_context_worker;
            grant update(id) on sli_agents to adlog_context_worker;
            grant insert,update on runtime_worker_heartbeats to adlog_user;
            grant update(imported_at,module_disabled_at) on sli_agent_packet_inbox to adlog_user;
            grant insert on sli_agent_packet_quarantine to adlog_user;
            grant update(transport_state,completed_at,publication_state,manifest_id,published_at,gpo_source_run_id,superseded_reason,superseded_at) on sli_agent_snapshot_cycles to adlog_context_worker;
            grant usage,select on all sequences in schema public to adlog_context_worker;
            grant usage on schema public to adlog_nps_agent_import_worker;
            grant select on sli_agent_packet_inbox,sli_agent_packet_quarantine,sli_agent_receipts to adlog_nps_agent_import_worker;
            grant update(imported_at) on sli_agent_packet_inbox to adlog_nps_agent_import_worker;
            revoke all on function lock_nps_import_agent_v304(uuid) from public;
            grant execute on function lock_nps_import_agent_v304(uuid) to adlog_nps_agent_import_worker;
            """, ct);
    }
    public async ValueTask DisposeAsync()
    {
        if (started || File.Exists(Path.Combine(root, "data", "postmaster.pid"))) await ProcessAsync("pg_ctl", CancellationToken.None, "-D", Path.Combine(root, "data"), "-t", "10", "-w", "-m", "immediate", "stop");
        if (server is not null) { await server.WaitForExitAsync(); if (serverOutput is not null) await serverOutput; if (serverError is not null) await serverError; server.Dispose(); }
        // Only remove this fixture's unique directory after its own server has stopped.
        string resolved = Path.GetFullPath(root), parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        if (Directory.Exists(resolved) && Path.GetDirectoryName(resolved) == parent && Path.GetFileName(resolved).StartsWith("sli-p04-", StringComparison.Ordinal)) Directory.Delete(resolved, true);
    }
}
