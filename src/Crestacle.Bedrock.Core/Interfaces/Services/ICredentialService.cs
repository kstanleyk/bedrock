using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;

namespace Crestacle.Bedrock.Core.Interfaces.Services;

/// <summary>
/// Orchestrates credential registration, email verification, password management,
/// first-factor login, MFA verification, and MFA enrollment.
/// </summary>
public interface ICredentialService
{
    // -------------------------------------------------------------------------
    // Registration & email
    // -------------------------------------------------------------------------

    /// <summary>Creates a new user credential with the given email and password and sends a verification email.</summary>
    /// <param name="userId">The application-assigned user identifier.</param>
    /// <param name="email">The user's email address; must be unique across the tenant.</param>
    /// <param name="password">The plaintext password; validated against configured complexity rules before hashing.</param>
    /// <param name="tenantId">Optional tenant identifier for multi-tenant deployments.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the email is already registered or the password fails complexity validation.</exception>
    Task RegisterAsync(Guid userId, string email, string password, string? tenantId = null, CancellationToken ct = default);

    /// <summary>Activates an email address using the verification token sent during registration.</summary>
    /// <param name="rawToken">The raw token value from the verification link (not pre-hashed).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the token is invalid, already used, or expired.</exception>
    Task ConfirmEmailAsync(string rawToken, CancellationToken ct = default);

    /// <summary>Re-sends the email verification message for an unconfirmed account.</summary>
    /// <param name="email">The email address of the unconfirmed account.</param>
    /// <param name="ct">Cancellation token.</param>
    Task ResendConfirmationAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Initiates an email address change. Validates the new address is not already in use,
    /// invalidates prior tokens, sends a confirmation link to the new address, and sends a
    /// security notice to the current address.
    /// </summary>
    /// <param name="userId">The authenticated user requesting the change.</param>
    /// <param name="newEmail">The new email address to change to.</param>
    /// <param name="ipAddress">The client IP address, recorded in the audit log.</param>
    /// <param name="userAgent">The client User-Agent, recorded in the audit log.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the new email is already registered.</exception>
    Task RequestEmailChangeAsync(Guid userId, string newEmail, string ipAddress, string userAgent, CancellationToken ct = default);

    /// <summary>
    /// Confirms an email change using the token sent to the new address. Updates the credential
    /// email, marks the token used, and revokes all active sessions (email change is a security event).
    /// </summary>
    /// <param name="rawToken">The raw token value from the confirmation link (not pre-hashed).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the token is invalid, expired, or the new email was claimed by another user.</exception>
    Task ConfirmEmailChangeAsync(string rawToken, CancellationToken ct = default);

    // -------------------------------------------------------------------------
    // Password management
    // -------------------------------------------------------------------------

    /// <summary>Changes the authenticated user's password after verifying the current one and revokes all active sessions.</summary>
    /// <param name="userId">The ID of the user changing their password.</param>
    /// <param name="currentPassword">The user's current plaintext password for verification.</param>
    /// <param name="newPassword">The new plaintext password; validated before being hashed and stored.</param>
    /// <param name="byIp">The IP address of the request, recorded in the audit log.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the current password is incorrect, the account is locked, or the new password fails validation.</exception>
    Task ChangePasswordAsync(Guid userId, string currentPassword, string newPassword, string byIp, CancellationToken ct = default);

    /// <summary>Initiates a password reset by sending a reset-link email if the address is registered.</summary>
    /// <remarks>Always completes without error regardless of whether the email is known, to prevent user enumeration.</remarks>
    /// <param name="email">The email address to send the reset link to.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RequestPasswordResetAsync(string email, CancellationToken ct = default);

    /// <summary>Completes a password reset using the token from the reset email and revokes all active sessions.</summary>
    /// <param name="rawToken">The raw token value from the password-reset link (not pre-hashed).</param>
    /// <param name="newPassword">The new plaintext password; validated before being hashed and stored.</param>
    /// <param name="byIp">The IP address of the request, recorded in the audit log.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="BedrockValidationException">Thrown when the token is invalid, expired, or the new password fails validation.</exception>
    Task ResetPasswordAsync(string rawToken, string newPassword, string byIp, CancellationToken ct = default);

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validates first-factor credentials and returns a <see cref="FirstFactorResult"/> describing
    /// the required next step: full success, MFA challenge, mandatory-MFA enrollment, or failure.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="password">The plaintext password to verify.</param>
    /// <param name="ip">The client IP address, used for anomaly detection and audit logging.</param>
    /// <param name="userAgent">The client User-Agent header, used for device fingerprinting.</param>
    /// <param name="fingerprintHash">Pre-computed device fingerprint hash.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="FirstFactorResult"/> indicating the outcome and any required next step.</returns>
    Task<FirstFactorResult> LoginFirstFactorAsync(string email, string password, string ip, string userAgent, string fingerprintHash, CancellationToken ct = default);

    /// <summary>
    /// Completes MFA verification: validates the challenge token, verifies the supplied code
    /// (TOTP, OTP, or recovery code), and returns the user ID on success.
    /// The caller is responsible for issuing the token pair via <see cref="IRefreshTokenService"/>.
    /// </summary>
    /// <param name="challengeToken">The short-lived challenge JWT issued after successful first-factor authentication.</param>
    /// <param name="code">The TOTP code, OTP code, or recovery code supplied by the user.</param>
    /// <param name="ip">The client IP address for audit logging.</param>
    /// <param name="userAgent">The client User-Agent for audit logging.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The authenticated user's ID.</returns>
    /// <exception cref="BedrockValidationException">Thrown when the challenge token is invalid, the code is incorrect, or the challenge has expired.</exception>
    Task<Guid> VerifyMfaAsync(string challengeToken, string code, string ip, string userAgent, CancellationToken ct = default);

    // -------------------------------------------------------------------------
    // MFA enrollment
    // -------------------------------------------------------------------------

    /// <summary>Generates a TOTP secret, stores it encrypted on the credential, and returns the QR URI.</summary>
    /// <param name="userId">The user enrolling TOTP.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="TotpSetupResult"/> containing the plaintext secret and the <c>otpauth://</c> QR URI.</returns>
    Task<TotpSetupResult> SetupTotpAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Confirms TOTP setup with the user's first code, activates MFA, and returns one-time recovery codes.</summary>
    /// <param name="userId">The user confirming TOTP enrollment.</param>
    /// <param name="code">The first 6-digit TOTP code from the authenticator app.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="RecoveryCodesResult"/> containing the plaintext recovery codes to display once.</returns>
    /// <exception cref="BedrockValidationException">Thrown when the TOTP code does not match the stored secret.</exception>
    Task<RecoveryCodesResult> ConfirmTotpAsync(Guid userId, string code, CancellationToken ct = default);

    /// <summary>Activates email or SMS OTP as the MFA method and returns one-time recovery codes.</summary>
    /// <param name="userId">The user enrolling OTP-based MFA.</param>
    /// <param name="method">The OTP delivery method: <see cref="MfaMethod.EmailOtp"/> or <see cref="MfaMethod.SmsOtp"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="RecoveryCodesResult"/> containing the plaintext recovery codes to display once.</returns>
    Task<RecoveryCodesResult> SetupOtpAsync(Guid userId, MfaMethod method, CancellationToken ct = default);

    /// <summary>Regenerates backup recovery codes, invalidating any previously issued codes.</summary>
    /// <param name="userId">The user requesting new recovery codes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="RecoveryCodesResult"/> containing the new plaintext recovery codes to display once.</returns>
    Task<RecoveryCodesResult> RegenerateRecoveryCodesAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Disables MFA for the user and invalidates all recovery codes.</summary>
    /// <param name="userId">The user disabling MFA.</param>
    /// <param name="ct">Cancellation token.</param>
    Task DisableMfaAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Returns how many unused recovery codes the user has remaining.</summary>
    /// <param name="userId">The user to query.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The count of unused recovery codes.</returns>
    Task<int> GetRemainingRecoveryCodeCountAsync(Guid userId, CancellationToken ct = default);

    // -------------------------------------------------------------------------
    // Magic link (passwordless login)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Sends a magic-link login email if the address belongs to an active account.
    /// Always completes without error regardless of whether the email is known, to prevent user enumeration.
    /// </summary>
    /// <param name="email">The email address to send the magic link to.</param>
    /// <param name="ipAddress">The client IP address, recorded in the audit log.</param>
    /// <param name="userAgent">The client User-Agent, recorded in the audit log.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RequestMagicLinkAsync(string email, string ipAddress, string userAgent, CancellationToken ct = default);

    /// <summary>
    /// Authenticates a user via a magic-link token. Returns the same <see cref="FirstFactorResult"/>
    /// as <see cref="LoginFirstFactorAsync"/>: full success, MFA challenge, mandatory-MFA enrollment, or failure.
    /// </summary>
    /// <param name="rawToken">The raw token value from the magic-link URL (not pre-hashed).</param>
    /// <param name="ipAddress">The client IP address for audit logging.</param>
    /// <param name="userAgent">The client User-Agent for audit logging.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="FirstFactorResult"/> indicating the outcome and any required next step.</returns>
    Task<FirstFactorResult> VerifyMagicLinkAsync(string rawToken, string ipAddress, string userAgent, CancellationToken ct = default);

    // -------------------------------------------------------------------------
    // Account erasure
    // -------------------------------------------------------------------------

    /// <summary>
    /// Anonymizes the credential for <paramref name="userId"/> to satisfy a GDPR/CCPA erasure
    /// request. Scrubs PII from the credential record, revokes all active sessions, and writes
    /// an immutable audit entry. Audit rows are intentionally retained as the security record.
    /// </summary>
    /// <param name="userId">The user whose credential should be anonymized.</param>
    /// <param name="ct">Cancellation token.</param>
    Task AnonymizeAsync(Guid userId, CancellationToken ct = default);
}
