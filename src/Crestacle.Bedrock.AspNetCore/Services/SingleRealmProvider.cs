using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Crestacle.Bedrock.Core.Realm;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

/// <summary>
/// Default <see cref="IBedrockRealmProvider"/> — every existing single-realm consumer gets
/// this until it explicitly opts into multi-realm hosting via <c>WithRealmProvider&lt;T&gt;</c>.
/// Always resolves the SAME realm, built directly from the base <see cref="BedrockOptions"/>,
/// regardless of the requested host — genuinely realm-agnostic, so every service that reads
/// realm-scoped values through <see cref="IBedrockRealmProvider"/> behaves identically to
/// reading <see cref="BedrockOptions"/> directly, for a consumer that never configures realms.
/// <see cref="BedrockRealm.Name"/> is <see langword="null"/> here specifically so no
/// <c>realm</c> claim is ever added by a claims enricher that checks for it.
/// </summary>
internal sealed class SingleRealmProvider(IOptions<BedrockOptions> options) : IBedrockRealmProvider
{
    private readonly BedrockOptions _options = options.Value;

    public BedrockRealm? Resolve(string? host) => new()
    {
        Name = null,
        MfaMandatory = _options.Mfa.MandatoryRoles.Count > 0,
        MfaGracePeriodDays = _options.Mfa.GracePeriodDays,
        RefreshCookieName = _options.Session.RefreshCookieName,
        RefreshTokenExpiry = _options.Jwt.RefreshTokenExpiry,
        FrontendBaseUrl = _options.Email.FrontendBaseUrl,
    };
}
