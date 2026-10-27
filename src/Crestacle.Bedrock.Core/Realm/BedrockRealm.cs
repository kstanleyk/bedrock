namespace Crestacle.Bedrock.Core.Realm;

/// <summary>
/// Realm-scoped overrides for a single Bedrock deployment that serves more than one
/// distinct user population (e.g. a customer-facing realm and an internal-staff realm)
/// from ONE process sharing ONE signing key/JWKS, resolved per request via
/// <see cref="Interfaces.Services.IBedrockRealmProvider"/>.
/// </summary>
/// <remarks>
/// Every property here is a REPLACEMENT for the equivalent <c>BedrockOptions</c> value for
/// requests resolving to this realm — the base <c>BedrockOptions</c> configured via
/// <c>AddBedrockAspNetCore</c> remains the single-realm default for every consumer that
/// never registers a custom <see cref="Interfaces.Services.IBedrockRealmProvider"/>.
/// <see cref="Name"/> is nullable specifically so the default, always-matching
/// <c>SingleRealmProvider</c> can represent "no realm concept active" (existing consumers
/// see zero behavior change): a claims enricher that adds a <c>realm</c> claim only when
/// <see cref="Name"/> is non-null stays silent for every consumer that hasn't opted into
/// multi-realm hosting.
/// </remarks>
public sealed record BedrockRealm
{
    /// <summary>
    /// The value embedded as the <c>realm</c> claim on every token issued for this realm.
    /// <see langword="null"/> means "this deployment has no realm concept" — no <c>realm</c>
    /// claim is added (the default, single-realm behavior every existing consumer sees).
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// Overrides the "is MFA mandatory at all" gate (<c>BedrockOptions.Mfa.MandatoryRoles.Count &gt; 0</c>
    /// in the single-realm default) for this realm — logically separate from
    /// <see cref="MfaGracePeriodDays"/>: this decides WHETHER enrollment is ever forced, the
    /// grace period decides HOW LONG a user may defer it once it is.
    /// </summary>
    public required bool MfaMandatory { get; init; }

    /// <summary>Overrides <c>BedrockOptions.Mfa.GracePeriodDays</c> for this realm.</summary>
    public required int MfaGracePeriodDays { get; init; }

    /// <summary>Overrides <c>BedrockOptions.Session.RefreshCookieName</c> for this realm.</summary>
    public required string RefreshCookieName { get; init; }

    /// <summary>
    /// Overrides <c>BedrockOptions.Jwt.RefreshTokenExpiry</c> for this realm — governs both
    /// the server-side refresh-token record's real expiry AND the <c>Set-Cookie</c>
    /// response's own <c>Expires</c> attribute, which must agree with it.
    /// </summary>
    public required TimeSpan RefreshTokenExpiry { get; init; }

    /// <summary>Overrides <c>BedrockOptions.Email.FrontendBaseUrl</c> for this realm.</summary>
    public required string FrontendBaseUrl { get; init; }
}
