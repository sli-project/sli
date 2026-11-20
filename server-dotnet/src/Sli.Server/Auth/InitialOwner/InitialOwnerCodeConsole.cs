using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Recovery;
using Sli.Server.Infrastructure;

namespace Sli.Server.Auth.InitialOwner;

public interface IInitialOwnerOperatorConnections : IPostgresConnectionFactory { }

// This privileged console profile is resolved lazily and is never the HTTP connection factory.
public sealed class InitialOwnerOperatorConnections : IInitialOwnerOperatorConnections
{
    private readonly PostgresConnectionFactory connections;
    public InitialOwnerOperatorConnections(IConfiguration configuration)
    {
        string value = configuration.GetConnectionString("InitialOwnerOperator")
            ?? configuration["Sli:InitialOwnerOperator:PostgresConnectionString"]
            ?? throw new InvalidOperationException("native_setup_configuration_conflict");
        connections = new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Sli"] = value }).Build());
    }
    public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => connections.OpenAsync(ct);
}

public sealed class InitialOwnerCodeConsole(IInitialOwnerOperatorConnections connections, IPasswordCodec passwords,
    ProtectedOwnerCodeStore store, OwnerRecoveryTerminal terminal) : IInitialOwnerCodeConsole
{
    public static OwnerCodeCommand NormalizeMode(OwnerCodeCommand command) =>
        command.CheckOnly ? command with { NewCode = false } : command;

    public async Task<OwnerCodeResult> ExecuteAsync(OwnerCodeCommand command, CancellationToken ct)
    {
        command = NormalizeMode(command);
        terminal.RequireRootInteractiveTerminal();
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var select = new NpgsqlCommand("""
            select u.password_hash,u.last_login_at,u.updated_at,clock_timestamp()
            from public.auth_users u join public.access_platform_owners o on o.user_id=u.id
            where u.username='platform-owner' and u.role='admin' and u.is_active=true
                and o.owner_key='primary' for update of u
            """, connection, transaction);
        string hash;
        bool claimed;
        DateTime? issued;
        DateTime checkedAt;
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("native_setup_owner_code_unavailable");
            hash = reader.GetString(0); claimed = !reader.IsDBNull(1);
            issued = reader.IsDBNull(2) ? null : reader.GetDateTime(2); checkedAt = reader.GetDateTime(3);
        }
        if (claimed)
        {
            if (!command.CheckOnly) store.RemoveCodeIfPresent();
            await transaction.CommitAsync(ct);
            return new("activated");
        }
        string code;
        if (command.NewCode)
        {
            code = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            store.ReplaceCode(code);
            await using var rotate = new NpgsqlCommand("""
                update public.auth_users set password_hash=@hash,updated_at=clock_timestamp()
                where username='platform-owner' and last_login_at is null
                """, connection, transaction);
            rotate.Parameters.AddWithValue("hash", passwords.Hash(code));
            await rotate.ExecuteNonQueryAsync(ct);
        }
        else
        {
            code = store.ReadCode();
            if (!passwords.Verify(hash, code).Valid) throw new InvalidOperationException("native_setup_owner_code_unavailable");
            if (!Regex.IsMatch(code, "\\A[A-Za-z0-9_-]{32,128}\\z", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("native_setup_secrets_failed");
            if (command.CheckOnly) { await transaction.CommitAsync(ct); return new("unclaimed"); }
            if (issued is null || !InitialOwnerSetup.CodeCurrent(issued.Value, checkedAt))
            { await transaction.CommitAsync(ct); return new("expired"); }
            if (store.ReceiptExists()) { await transaction.CommitAsync(ct); return new("pending"); }
        }
        // File/receipt writes precede the DB commit just like the native source. Explicit rotation repairs interruption.
        store.WriteReceipt();
        await transaction.CommitAsync(ct);
        return new("issued", code);
    }

    public async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (args.Length == 0 || args[0] != "owner-code" || args.Skip(1).Any(arg => arg is not ("--new-owner-code" or "--check-unclaimed-owner")))
        { Console.Error.WriteLine("usage: owner-code [--new-owner-code] [--check-unclaimed-owner]"); return 2; }
        try
        {
            var result = await ExecuteAsync(NormalizeMode(new(args.Contains("--new-owner-code"), args.Contains("--check-unclaimed-owner"))), ct);
            terminal.RequireRootInteractiveTerminal();
            Console.Out.WriteLine(result.Code ?? result.Status);
            return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 130; }
        catch (UnauthorizedAccessException error) when (error.Message is "host_root_required" or "terminal_required")
        { Console.Error.WriteLine(error.Message); return 1; }
        catch (InvalidOperationException error) when (error.Message is "native_setup_owner_code_unavailable" or "native_setup_secrets_failed" or "native_setup_configuration_conflict")
        { Console.Error.WriteLine(error.Message); return 1; }
        catch (Exception) { Console.Error.WriteLine("initial_owner_code_failed"); return 1; }
    }
}
