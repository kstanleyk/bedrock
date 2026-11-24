namespace Crestacle.Bedrock.Core.Options;

/// <summary>Multi-factor authentication policy settings.</summary>
public sealed class MfaOptions
{
    /// <summary>Issuer name displayed in TOTP authenticator apps.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Days before mandatory MFA enforcement begins once <see cref="MandatoryRoles"/> is
    /// non-empty. Default: 14 days.
    /// </summary>
    public int GracePeriodDays { get; set; } = 14;

    /// <summary>
    /// NOT per-role scoped despite the name:
    /// <see cref="Crestacle.Bedrock.Core.Interfaces.Services.IMfaPolicyService.IsMfaRequired(Crestacle.Bedrock.Core.Entities.UserCredential)"/>
    /// (the default implementation) only checks whether this list is non-empty, never which
    /// roles the specific credential being evaluated actually holds — <c>Crestacle.Bedrock.Core</c>
    /// has no concept of roles at all (that's a Sentinel/RBAC concern this package doesn't
    /// depend on). Setting ANY value here (e.g. <c>["admin"]</c>) makes MFA mandatory, with a
    /// grace period, for EVERY credential — not just ones holding that role. Treat this as a
    /// boolean "make MFA mandatory for everyone" switch, not a role filter, until a role-aware
    /// <c>IMfaPolicyService</c> implementation is wired in (e.g. by the
    /// <c>Crestacle.Bedrock.Sentinel</c> bridge package, which does have access to role data).
    /// </summary>
    public IList<string> MandatoryRoles { get; set; } = new List<string>();

    /// <summary>Number of recovery codes to generate per MFA setup. Default: 10.</summary>
    public int BackupCodeCount { get; set; } = 10;
}
