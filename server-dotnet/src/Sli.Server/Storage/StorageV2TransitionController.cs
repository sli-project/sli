using System.Text.Json.Nodes;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Storage;

internal sealed class StorageRouteAuthorizationException(string code) : InvalidOperationException(code);

// Like the reference controller, this issues only an inert in-process capability.
// It does not authorize writes, persist state, start workers or touch the database.
internal static class StorageV2TransitionController
{
    internal const string Authority = "storage-v2-transition-controller/v1";
    static readonly object IssuanceSeal = new();

    internal sealed record Authorization
    {
        readonly object seal;
        internal Authorization(string digest, object seal) { PreflightDigest = digest; this.seal = seal; }
        internal string PreflightDigest { get; init; }
        internal string Authority { get; init; } = StorageV2TransitionController.Authority;
        internal string Status { get; init; } = "AUTHORIZED";
        internal string Mode { get; init; } = "dormant";
        internal string Route { get; init; } = "v2";
        internal string Owner { get; init; } = "V2";
        internal string AuthorizationKind { get; init; } = "controller";
        internal IReadOnlyList<string> SideEffects => Array.Empty<string>();
        internal bool HasSeal(object expected) => ReferenceEquals(seal, expected);
    }

    internal static Authorization IssueAuthorization(string preflightDigest)
    {
        if (string.IsNullOrEmpty(preflightDigest)) throw new ArgumentException("preflight_digest is required", nameof(preflightDigest));
        return new(preflightDigest, IssuanceSeal);
    }

    internal static bool IsControllerAuthorization(object? value) => value is Authorization a &&
        a.HasSeal(IssuanceSeal) && a.Authority == Authority && a.Status == "AUTHORIZED" &&
        a.Mode == "dormant" && a.Route == "v2" && a.Owner == "V2" &&
        a.AuthorizationKind == "controller" && !string.IsNullOrEmpty(a.PreflightDigest);

    internal static JsonObject ResolveStorageRoute(object? authorization = null, JsonObject? transitionState = null)
    {
        string kind;
        if (authorization is null)
        {
            if (transitionState is not null)
                throw new StorageRouteAuthorizationException("storage_transition_state_requires_controller_authorization");
            kind = "configured";
        }
        // Persisted capabilities are separately validated by DirectRuntimeAuthorization.
        else if (authorization is DirectRuntimeAuthorization) kind = "persisted-controller";
        else if (IsControllerAuthorization(authorization)) kind = "controller";
        else throw new StorageRouteAuthorizationException("storage_transition_authorization_invalid");
        // V1 relations were removed; configuration can never restore a V1 route.
        return new() { ["status"] = "READY", ["route"] = "v2", ["owner"] = "V2", ["authorization"] = kind };
    }
}
