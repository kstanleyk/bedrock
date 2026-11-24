namespace Crestacle.Bedrock.AspNetCore.Authorization;

/// <summary>Well-known authorization policy names registered by <c>AddBedrockAspNetCore</c>.</summary>
public static class BedrockPolicyNames
{
    /// <summary>
    /// Requires an authenticated principal whose <c>token_type</c> claim is <c>"access"</c>
    /// (a real, full-session JWT) or <c>"api_key"</c> (stamped by
    /// <c>ApiKeyAuthenticationMiddleware</c>) — never a short-lived
    /// enrollment/challenge/step-up token. Deliberately an allowlist, not a blocklist of known
    /// special types: a future single-purpose token type Bedrock issues is excluded by default
    /// unless it explicitly carries one of these two values, rather than silently passing this
    /// policy the way a blocklist would. Apply to all standard business endpoints.
    /// </summary>
    public const string Default = "BedrockDefault";

    /// <summary>
    /// Requires a token with <c>token_type == "enrollment"</c>.
    /// Apply to the MFA enrollment endpoints (setup-totp, confirm-totp, setup-otp).
    /// </summary>
    public const string MfaEnrollment = "BedrockMfaEnrollment";

    /// <summary>
    /// Requires an authenticated user with a <c>bedrock_admin = "true"</c> claim.
    /// Grant this claim via <c>IBedrockClaimsEnricher</c> for trusted admin principals.
    /// </summary>
    public const string Admin = "BedrockAdmin";
}
