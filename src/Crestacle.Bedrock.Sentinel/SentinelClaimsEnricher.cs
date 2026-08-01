using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Sentinel.Core.Interfaces;

namespace Crestacle.Bedrock.Sentinel;

/// <summary>
/// <see cref="IBedrockClaimsEnricher"/> that embeds Sentinel RBAC data and Bedrock
/// credential metadata into every issued JWT.
/// </summary>
/// <remarks>
/// <para>
/// Claims added to <c>EnrichAsync</c>:
/// <list type="bullet">
///   <item><c>"Permission.{Feature}.{Action}" = "true"</c> — one entry per granted permission.</item>
///   <item><c>"name"</c> — the user's full name from the Sentinel user record.</item>
///   <item><c>"mfa_enabled"</c> — <c>"true"</c> or <c>"false"</c> from the Bedrock credential record.</item>
/// </list>
/// </para>
/// <para>
/// Sentinel's <c>PermissionAuthorizationHandler</c> resolves permissions from the database
/// (with caching) on every authorisation check, so the permission claims are <b>not required</b>
/// for <c>[MustHavePermission]</c> to work server-side.  They are included here so that JWT
/// consumers outside Sentinel — API gateways, mobile clients, BFF layers — can evaluate
/// permissions without a back-channel call.
/// </para>
/// <para>
/// Enable via <c>builder.WithPermissionClaims()</c> after <c>AddSentinel()</c>.
/// </para>
/// <para>
/// <b>Token size:</b> every permission adds ~40–60 bytes to the JWT.  In applications with
/// large permission sets consider a dedicated slim-token endpoint instead.
/// </para>
/// </remarks>
internal sealed class SentinelClaimsEnricher(
    IUserPermissionRepository permissions,
    IUserRepository users,
    ICredentialRepository credentials)
    : IBedrockClaimsEnricher
{
    public async Task<IDictionary<string, string>> EnrichAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        // Sequential awaits: all three repositories share the same scoped DbContext instance,
        // so concurrent Task.WhenAll would trigger EF Core's "second operation" concurrency error.
        var perms = await permissions.GetPermissionsForUserAsync(userId.ToString(), ct);
        var user  = await users.GetByIdAsync(userId, ct);
        var cred  = await credentials.GetByUserIdAsync(userId, ct);

        var claims = perms.ToDictionary(p => p, _ => "true");
        claims["name"]        = user?.FullName ?? string.Empty;
        claims["mfa_enabled"] = cred?.MfaEnabled == true ? "true" : "false";
        return claims;
    }

    public async Task<IEnumerable<string>> GetRolesAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        var user = await users.GetByIdAsync(userId, ct);
        return user?.Roles.Select(r => r.Name) ?? [];
    }
}
