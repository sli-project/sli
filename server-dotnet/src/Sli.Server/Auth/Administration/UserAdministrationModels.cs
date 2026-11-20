using System.Text.Json;
using System.Numerics;

namespace Sli.Server.Auth.Administration;

public sealed record UserAdministrationActor(string Type, long? Id, string RemoteAddress);
public sealed record CreateUserCommand(string Username, string Password, string Role = "admin", bool IsService = false);
public sealed record UpdateUserCommand(BigInteger UserId, string? Role, bool? IsActive);
public sealed class UserAdministrationException(string code) : Exception(code);

public interface IUserAdministration
{
    Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct);
    Task<JsonElement> CreateAsync(CreateUserCommand command, UserAdministrationActor actor, CancellationToken ct);
    Task<JsonElement> UpdateAsync(UpdateUserCommand command, UserAdministrationActor actor, CancellationToken ct);
    Task<JsonElement> ResetPasswordAsync(BigInteger userId, string password, UserAdministrationActor actor, CancellationToken ct);
}
