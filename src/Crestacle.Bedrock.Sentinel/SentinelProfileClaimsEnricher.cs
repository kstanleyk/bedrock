using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Sentinel.Core.Interfaces;

namespace Crestacle.Bedrock.Sentinel;

/// <summary>
/// <see cref="IBedrockClaimsEnricher"/> that embeds basic profile data -- name, MFA status,
/// and role names -- into every issued JWT, without the per-permission claims that
/// <see cref="SentinelClaimsEnricher"/> adds.
/// </summary>
/// <remarks>
/// <para>
/// Claims added to <c>EnrichAsync</c>:
/// <list type="bullet">
///   <item><c>"name"</c> — the user's full name from the Sentinel user record.</item>
///   <item><c>"mfa_enabled"</c> — <c>"true"</c> or <c>"false"</c> from the Bedrock credential record.</item>
/// </list>
/// Role names are embedded via <c>GetRolesAsync</c> and appear as standard JWT role claims
/// (see <c>RoleClaimType</c> in <c>BedrockJwtHelper</c>).
/// </para>
/// <para>
/// Use this instead of <see cref="SentinelClaimsEnricher"/> (<c>.WithPermissionClaims()</c>) when
/// your app needs the caller's name/MFA/role on every token but does not want one claim per
/// granted permission inflating token size -- the scenario that motivated splitting this out.
/// Permissions remain available via <c>GET api/auth/permissions/me</c> regardless of which
/// enricher (if any) is registered; <c>[MustHavePermission]</c> never depends on token claims.
/// </para>
/// <para>
/// Enable via <c>builder.WithProfileClaims()</c> after <c>AddSentinel()</c>. Mutually exclusive
/// with <c>.WithPermissionClaims()</c> -- the one called last wins, since both replace the single
/// registered <see cref="IBedrockClaimsEnricher"/>.
/// </para>
/// </remarks>
internal sealed class SentinelProfileClaimsEnricher(
    IUserRepository users,
    ICredentialRepository credentials)
    : IBedrockClaimsEnricher
{
    public async Task<IDictionary<string, string>> EnrichAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        // Sequential awaits: see SentinelClaimsEnricher.EnrichAsync for why (shared scoped
        // DbContext across these two repositories).
        //
        // userId here is Bedrock's OWN internal user id -- the exact string
        // GetByIdentityIdAsync is keyed on is Sentinel's User.IdentityId, which is
        // provisioned to equal that same string. Sentinel's User.Id is a SEPARATE,
        // independently generated Guid; GetByIdAsync(userId) would never match it.
        var user = await users.GetByIdentityIdAsync(userId.ToString(), ct);
        var cred = await credentials.GetByUserIdAsync(userId, ct);

        return new Dictionary<string, string>
        {
            ["name"]        = user?.FullName ?? string.Empty,
            ["mfa_enabled"] = cred?.MfaEnabled == true ? "true" : "false",
        };
    }

    public async Task<IEnumerable<string>> GetRolesAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        var user = await users.GetByIdentityIdAsync(userId.ToString(), ct);
        return user?.Roles.Select(r => r.Name) ?? [];
    }
}
