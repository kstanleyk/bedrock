namespace Crestacle.Bedrock.Core.Entities;

/// <summary>
/// Represents one issued refresh token for a user. Never hard-deleted.
/// Soft-revoked with an audit chain linking each token to its successor via <see cref="ReplacedByTokenHash"/>.
/// </summary>
public sealed class RefreshToken
{
    private RefreshToken() { }

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }

    /// <summary>SHA256 hex of the raw opaque token; max 128 chars; unique index.</summary>
    public string TokenHash { get; private set; } = string.Empty;

    public DateTime ExpiresAt { get; private set; }
    public DateTime CreatedAt { get; private set; }

    /// <summary>IPv4 or IPv6 address that created this token; max 45 chars.</summary>
    public string CreatedByIp { get; private set; } = string.Empty;

    /// <summary>UTC revocation timestamp; null means the token is active.</summary>
    public DateTime? RevokedAt { get; private set; }

    /// <summary>IP address from which revocation was initiated; max 45 chars.</summary>
    public string? RevokedByIp { get; private set; }

    /// <summary>Hash of the successor token in the rotation chain; null if not replaced.</summary>
    public string? ReplacedByTokenHash { get; private set; }

    public string? TenantId { get; private set; }

    /// <summary>Optimistic concurrency token.</summary>
    public byte[]? RowVersion { get; private set; }

    // -------------------------------------------------------------------------
    // Factory
    // -------------------------------------------------------------------------

    public static RefreshToken Create(
        Guid userId,
        string tokenHash,
        DateTime expiresAt,
        string createdByIp,
        string? tenantId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(createdByIp);

        return new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = createdByIp,
            TenantId = tenantId
        };
    }

    // -------------------------------------------------------------------------
    // State methods
    // -------------------------------------------------------------------------

    /// <summary>Soft-revokes the token; optionally records the hash of the successor token.</summary>
    public void Revoke(string byIp, string? replacedByHash = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(byIp);
        RevokedAt = DateTime.UtcNow;
        RevokedByIp = byIp;
        ReplacedByTokenHash = replacedByHash;
    }

    // -------------------------------------------------------------------------
    // Computed properties
    // -------------------------------------------------------------------------

    /// <summary>Returns true when the token has not been revoked and has not expired.</summary>
    public bool IsActive => RevokedAt is null && DateTime.UtcNow < ExpiresAt;
}
