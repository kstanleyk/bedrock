namespace Crestacle.Bedrock.Core.Options;

/// <summary>
/// Root configuration object for all Bedrock subsystems.
/// Pass an instance to <c>AddBedrock(options => { ... })</c> at startup.
/// </summary>
public sealed class BedrockOptions
{
    /// <summary>JWT signing and validation settings.</summary>
    public JwtOptions Jwt { get; set; } = new();

    /// <summary>Password complexity and history settings.</summary>
    public PasswordOptions Password { get; set; } = new();

    /// <summary>Multi-factor authentication policy settings.</summary>
    public MfaOptions Mfa { get; set; } = new();

    /// <summary>Account lockout policy settings.</summary>
    public LockoutOptions Lockout { get; set; } = new();

    /// <summary>Per-user concurrent session settings.</summary>
    public SessionOptions Session { get; set; } = new();

    /// <summary>Anomaly detection settings.</summary>
    public AnomalyDetectionOptions AnomalyDetection { get; set; } = new();

    /// <summary>Email URL construction settings.</summary>
    public EmailOptions Email { get; set; } = new();

    /// <summary>Expiry settings for short-lived tokens and codes.</summary>
    public TokenExpiryOptions TokenExpiry { get; set; } = new();

    /// <summary>OTP send-rate-limiting settings.</summary>
    public OtpOptions Otp { get; set; } = new();

    /// <summary>WebAuthn / FIDO2 passkey relying-party settings.</summary>
    public PasskeyOptions Passkey { get; set; } = new();

    /// <summary>IP-based login rate limiting settings.</summary>
    public IpRateLimitOptions IpRateLimit { get; set; } = new();

    /// <summary>Optional caching for <c>IBedrockClaimsEnricher</c> results to reduce per-refresh DB round-trips.</summary>
    public ClaimsCacheOptions ClaimsCache { get; set; } = new();

    /// <summary>
    /// Validates that the options are in a consistent state.
    /// Throws <see cref="InvalidOperationException"/> when required settings are missing.
    /// <c>AddBedrockAspNetCore</c> registers this via <c>ValidateOnStart()</c>, so it runs
    /// automatically as part of the generic host's startup sequence — after every
    /// <c>Configure&lt;BedrockOptions&gt;</c> call (including appsettings-bound ones) has run,
    /// not during the <c>AddBedrockAspNetCore</c> call itself.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Jwt.SigningKey) && Jwt.SigningCertificate is null)
            throw new InvalidOperationException(
                "BedrockOptions: at least one of Jwt.SigningKey (HS256) or " +
                "Jwt.SigningCertificate (RS256) must be configured. " +
                "This key is required even when Jwt.ExternalTokenIssuer = true because " +
                "Bedrock uses it to sign and validate step-up, MFA challenge, and " +
                "enrollment tokens regardless of who issues access tokens.");

        if (Jwt.SigningCertificate is null && !string.IsNullOrWhiteSpace(Jwt.SigningKey) &&
            Jwt.SigningKey.Length < MinimumSigningKeyLength)
            throw new InvalidOperationException(
                $"BedrockOptions: Jwt.SigningKey is {Jwt.SigningKey.Length} characters long, " +
                $"but at least {MinimumSigningKeyLength} are required for HS256. A short or " +
                "predictable key makes tokens forgeable. Generate a suitable key with " +
                "`openssl rand -base64 32` and store it in a secrets manager.");
    }

    /// <summary>
    /// Minimum character length required for <see cref="JwtOptions.SigningKey"/> (HS256).
    /// Not enforced on the <see cref="JwtOptions.SigningCertificate"/> (RS256) path.
    /// </summary>
    private const int MinimumSigningKeyLength = 32;
}
