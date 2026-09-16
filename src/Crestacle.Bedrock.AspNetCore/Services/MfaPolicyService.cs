using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

internal sealed class MfaPolicyService : IMfaPolicyService
{
    private readonly BedrockOptions _options;
    private readonly IBedrockRealmProvider _realmProvider;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public MfaPolicyService(
        IOptions<BedrockOptions> options,
        IBedrockRealmProvider realmProvider,
        IHttpContextAccessor httpContextAccessor)
    {
        _options = options.Value;
        _realmProvider = realmProvider;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Realm-aware, same mechanism as <see cref="ComputeGracePeriodEnd"/>. The parameter is
    /// unused deliberately, matching the pre-existing behavior this overrides (a global gate,
    /// not evaluated per-credential) — realm-scoping only changes WHICH global gate applies to
    /// the current request, not whether individual credentials are consulted.
    /// </summary>
    public bool IsMfaRequired(UserCredential credential)
    {
        var host = _httpContextAccessor.HttpContext?.Request.Host.Host;
        return _realmProvider.Resolve(host)?.MfaMandatory ?? _options.Mfa.MandatoryRoles.Count > 0;
    }

    public bool IsInGracePeriod(UserCredential credential)
        => !credential.MfaEnabled
           && credential.MfaGracePeriodEndsAt.HasValue
           && credential.MfaGracePeriodEndsAt.Value > DateTime.UtcNow;

    public bool GracePeriodExpired(UserCredential credential)
        => !credential.MfaEnabled
           && credential.MfaGracePeriodEndsAt.HasValue
           && credential.MfaGracePeriodEndsAt.Value < DateTime.UtcNow;

    /// <summary>
    /// Realm-aware: a multi-realm deployment's <see cref="IBedrockRealmProvider"/> (e.g. the
    /// internal realm's mandatory-no-grace policy) overrides <c>BedrockOptions.Mfa.GracePeriodDays</c>
    /// per the CURRENT request's <c>Host</c> header. A single-realm deployment's
    /// <c>SingleRealmProvider</c> always resolves the same base-options value, so this is
    /// behaviorally identical to the previous flat read for every consumer that hasn't
    /// opted into <c>WithRealmProvider&lt;T&gt;</c>.
    /// </summary>
    public DateTime ComputeGracePeriodEnd()
    {
        var host = _httpContextAccessor.HttpContext?.Request.Host.Host;
        var gracePeriodDays = _realmProvider.Resolve(host)?.MfaGracePeriodDays ?? _options.Mfa.GracePeriodDays;
        return DateTime.UtcNow.AddDays(gracePeriodDays);
    }

    public DateTime SetGracePeriod(UserCredential credential)
    {
        var end = ComputeGracePeriodEnd();
        credential.SetGracePeriod(end);
        return end;
    }
}
