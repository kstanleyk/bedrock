using Crestacle.Bedrock.Core.Enumerations;

namespace Crestacle.Bedrock.Core.Entities;

/// <summary>
/// Short-lived record for step-up re-authentication. Single-use enforced at the challenge level;
/// the step-up JWT embeds the <see cref="Id"/> as the <c>challenge_id</c> claim.
/// </summary>
public sealed class StepUpChallenge
{
    private StepUpChallenge() { }

    /// <summary>Primary key; embedded as <c>challenge_id</c> claim in the step-up JWT.</summary>
    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    /// <summary>Verification method used for this step-up.</summary>
    public MfaMethod Method { get; private set; }

    /// <summary>SHA256 of the OTP code; null for TOTP (code verified on the fly).</summary>
    public string? CodeHash { get; private set; }

    public DateTime ExpiresAt { get; private set; }

    /// <summary>UTC timestamp when the step-up JWT was issued; null means unused.</summary>
    public DateTime? UsedAt { get; private set; }

    /// <summary>IP address that initiated the step-up; max 45 chars.</summary>
    public string IpAddress { get; private set; } = string.Empty;

    public string? TenantId { get; private set; }
    public DateTime CreatedAt { get; private set; }

    /// <summary>Optimistic concurrency token.</summary>
    public byte[]? RowVersion { get; private set; }

    // -------------------------------------------------------------------------
    // Factory
    // -------------------------------------------------------------------------

    public static StepUpChallenge Create(
        Guid userId,
        MfaMethod method,
        string? codeHash,
        string ipAddress,
        DateTime expiresAt,
        string? tenantId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        return new StepUpChallenge
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Method = method,
            CodeHash = codeHash,
            IpAddress = ipAddress,
            ExpiresAt = expiresAt,
            TenantId = tenantId,
            CreatedAt = DateTime.UtcNow
        };
    }

    // -------------------------------------------------------------------------
    // State methods
    // -------------------------------------------------------------------------

    /// <summary>Marks the challenge as consumed; called when the step-up JWT is issued.</summary>
    public void MarkUsed() => UsedAt = DateTime.UtcNow;

    // -------------------------------------------------------------------------
    // Computed properties
    // -------------------------------------------------------------------------

    /// <summary>Returns true when the challenge has not been used and has not expired.</summary>
    public bool IsValid => UsedAt is null && DateTime.UtcNow < ExpiresAt;
}
