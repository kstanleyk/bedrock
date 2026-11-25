using Crestacle.Bedrock.Core.Enumerations;

namespace Crestacle.Bedrock.Core.Entities;

/// <summary>
/// Root credential record for a user. One record per user identity.
/// Tracks authentication state, MFA configuration, password expiry, and account lockout.
/// </summary>
public sealed class UserCredential
{
    private UserCredential() { }

    /// <summary>Primary key.</summary>
    public Guid Id { get; private set; }

    /// <summary>FK to the consuming application's user record — not a Bedrock entity.</summary>
    public Guid UserId { get; private set; }

    /// <summary>Email address; max 256 chars; unique per tenant.</summary>
    public string Email { get; private set; } = string.Empty;

    /// <summary>Argon2id password hash; max 512 chars.</summary>
    public string PasswordHash { get; private set; } = string.Empty;

    /// <summary>True once the email verification token is consumed.</summary>
    public bool EmailConfirmed { get; private set; }

    /// <summary>Lifecycle status of this credential.</summary>
    public AccountStatus Status { get; private set; }

    /// <summary>True when at least one MFA method is confirmed and active.</summary>
    public bool MfaEnabled { get; private set; }

    /// <summary>Active MFA method; null when MFA is disabled.</summary>
    public MfaMethod? MfaMethod { get; private set; }

    /// <summary>DataProtection-encrypted Base32 TOTP secret; null when TOTP is not configured.</summary>
    public string? TotpSecretEncrypted { get; private set; }

    /// <summary>True after the user confirms the first TOTP code.</summary>
    public bool TotpConfirmed { get; private set; }

    /// <summary>Consecutive failed login attempts; resets to zero on success.</summary>
    public int FailedLoginAttempts { get; private set; }

    /// <summary>UTC end of lockout window; null means not locked.</summary>
    public DateTime? LockoutEnd { get; private set; }

    /// <summary>
    /// True when the active lockout was set by an administrator via <see cref="AdminLock"/>
    /// rather than by <see cref="RecordFailedLogin"/>'s automatic timed lockout. Distinguishes
    /// the two so callers can avoid surfacing the 100-year <see cref="LockoutEnd"/> sentinel
    /// (used mechanically to keep <see cref="IsLockedOut"/> true indefinitely) as a literal date
    /// in a user-facing message.
    /// </summary>
    public bool IsAdminLocked { get; private set; }

    /// <summary>UTC end of MFA grace period; null means no active grace period.</summary>
    public DateTime? MfaGracePeriodEndsAt { get; private set; }

    /// <summary>UTC expiry of the current password; null means it never expires.</summary>
    public DateTime? PasswordExpiresAt { get; private set; }

    /// <summary>UTC timestamp of the last password change.</summary>
    public DateTime? PasswordChangedAt { get; private set; }

    /// <summary>Tenant identifier; null for single-tenant deployments.</summary>
    public string? TenantId { get; private set; }

    /// <summary>UTC creation timestamp.</summary>
    public DateTime CreatedAt { get; private set; }

    /// <summary>UTC timestamp of the last mutation.</summary>
    public DateTime UpdatedAt { get; private set; }

    /// <summary>Optimistic concurrency token (rowversion / xmin).</summary>
    public byte[]? RowVersion { get; private set; }

    // -------------------------------------------------------------------------
    // Factory
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a new credential in <see cref="AccountStatus.PendingVerification"/> state.
    /// </summary>
    public static UserCredential Create(
        Guid userId,
        string email,
        string passwordHash,
        string? tenantId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);

        var now = DateTime.UtcNow;
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Email = email,
            PasswordHash = passwordHash,
            Status = AccountStatus.PendingVerification,
            TenantId = tenantId,
            CreatedAt = now,
            UpdatedAt = now
        };
    }

    // -------------------------------------------------------------------------
    // State methods
    // -------------------------------------------------------------------------

    /// <summary>Marks the email as confirmed and transitions status to <see cref="AccountStatus.Active"/>.</summary>
    public void ConfirmEmail()
    {
        EmailConfirmed = true;
        Status = AccountStatus.Active;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Increments the failed login counter; locks the account when the threshold is reached.
    /// </summary>
    public void RecordFailedLogin(int maxAttempts, TimeSpan lockoutDuration)
    {
        FailedLoginAttempts++;
        if (FailedLoginAttempts >= maxAttempts)
        {
            LockoutEnd = DateTime.UtcNow.Add(lockoutDuration);
            Status = AccountStatus.Locked;
        }
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Resets the failed login counter and clears any active lockout.</summary>
    public void RecordSuccessfulLogin()
    {
        FailedLoginAttempts = 0;
        LockoutEnd = null;
        IsAdminLocked = false;
        if (Status == AccountStatus.Locked)
            Status = AccountStatus.Active;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Replaces the password hash and records the change timestamp.</summary>
    public void SetPassword(string newHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newHash);
        PasswordHash = newHash;
        PasswordChangedAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Activates the specified MFA method.</summary>
    public void EnableMfa(Enumerations.MfaMethod method)
    {
        MfaEnabled = true;
        MfaMethod = method;
        MfaGracePeriodEndsAt = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Clears all MFA fields and deactivates the second factor.</summary>
    public void DisableMfa()
    {
        MfaEnabled = false;
        MfaMethod = null;
        TotpSecretEncrypted = null;
        TotpConfirmed = false;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Stores an encrypted TOTP secret; resets confirmation until the user verifies the first code.</summary>
    public void SetTotpSecret(string encryptedSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedSecret);
        TotpSecretEncrypted = encryptedSecret;
        TotpConfirmed = false;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Marks TOTP as confirmed after the user verifies the first generated code.</summary>
    public void ConfirmTotp()
    {
        TotpConfirmed = true;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Sets the MFA grace period end date.</summary>
    public void SetGracePeriod(DateTime endsAt)
    {
        MfaGracePeriodEndsAt = endsAt;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Clears the MFA grace period.</summary>
    public void ClearGracePeriod()
    {
        MfaGracePeriodEndsAt = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Administratively suspends the account.</summary>
    public void Suspend()
    {
        Status = AccountStatus.Suspended;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Reactivates a suspended account.</summary>
    public void Reactivate()
    {
        Status = AccountStatus.Active;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Replaces the email address after the change-email token has been confirmed.</summary>
    public void ChangeEmail(string newEmail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newEmail);
        Email = newEmail;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Administratively locks the account indefinitely. <see cref="LockoutEnd"/> is still set to a
    /// 100-year-out sentinel so <see cref="IsLockedOut"/> keeps working unchanged for every existing
    /// caller that only reads that one field; <see cref="IsAdminLocked"/> is the explicit flag
    /// callers should branch on when deciding what to tell the user.
    /// </summary>
    public void AdminLock()
    {
        LockoutEnd = DateTime.UtcNow.AddYears(100);
        IsAdminLocked = true;
        Status = AccountStatus.Locked;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Clears an administrative lock and resets the failed-attempt counter.</summary>
    public void AdminUnlock()
    {
        LockoutEnd = null;
        IsAdminLocked = false;
        FailedLoginAttempts = 0;
        if (Status == AccountStatus.Locked)
            Status = AccountStatus.Active;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Forces an immediate password expiry so the consuming app can require the user
    /// to set a new password on their next interaction.
    /// </summary>
    public void ExpirePassword()
    {
        PasswordExpiresAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>Scrubs all PII from this credential to satisfy a GDPR erasure request.</summary>
    public void Anonymize()
    {
        Email = $"deleted-{UserId}@bedrock.invalid";
        PasswordHash = string.Empty;
        TotpSecretEncrypted = null;
        TotpConfirmed = false;
        MfaEnabled = false;
        MfaMethod = null;
        Status = AccountStatus.Suspended;
        UpdatedAt = DateTime.UtcNow;
    }

    // -------------------------------------------------------------------------
    // Computed properties
    // -------------------------------------------------------------------------

    /// <summary>Returns true if the lockout end is in the future.</summary>
    public bool IsLockedOut() => LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;

    /// <summary>Returns true if the password expiry date is in the past.</summary>
    public bool IsPasswordExpired() => PasswordExpiresAt.HasValue && PasswordExpiresAt.Value < DateTime.UtcNow;
}
