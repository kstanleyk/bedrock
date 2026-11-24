namespace Crestacle.Bedrock.Core;

/// <summary>
/// Machine-readable error codes included in every <see cref="DTOs.BedrockResponse"/> failure payload.
/// Stable across patch versions; new codes may be added in minor versions.
/// </summary>
public static class BedrockErrorCodes
{
    // ── Authentication ────────────────────────────────────────────────────────

    /// <summary>The supplied credentials are incorrect.</summary>
    public const string InvalidCredentials = "invalid_credentials";

    /// <summary>The account has been locked after too many failed attempts.</summary>
    public const string AccountLocked = "account_locked";

    /// <summary>The email address has not been confirmed.</summary>
    public const string EmailNotConfirmed = "email_not_confirmed";

    /// <summary>The account does not exist or has been anonymized.</summary>
    public const string AccountNotFound = "account_not_found";

    // ── Tokens ────────────────────────────────────────────────────────────────

    /// <summary>The provided token is invalid, expired, or has already been used.</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>An attempt was made to reuse a rotated refresh token.</summary>
    public const string TokenReuse = "token_reuse";

    /// <summary>The session has exceeded its absolute maximum lifetime. Re-authentication required.</summary>
    public const string SessionExpired = "session_expired";

    // ── MFA ──────────────────────────────────────────────────────────────────

    /// <summary>An MFA challenge is required to complete this operation.</summary>
    public const string MfaRequired = "mfa_required";

    /// <summary>The MFA code is incorrect or has expired.</summary>
    public const string InvalidMfaCode = "invalid_mfa_code";

    /// <summary>MFA has not been configured for this account.</summary>
    public const string MfaNotConfigured = "mfa_not_configured";

    // ── Password ─────────────────────────────────────────────────────────────

    /// <summary>The password does not meet complexity requirements.</summary>
    public const string PasswordTooWeak = "password_too_weak";

    /// <summary>The password was used recently and cannot be reused.</summary>
    public const string PasswordInHistory = "password_in_history";

    /// <summary>The password has been found in a known data breach.</summary>
    public const string PasswordBreached = "password_breached";

    // ── Registration ─────────────────────────────────────────────────────────

    /// <summary>The email address is already registered.</summary>
    public const string DuplicateEmail = "duplicate_email";

    // ── Rate limiting ─────────────────────────────────────────────────────────

    /// <summary>Too many requests from this IP address.</summary>
    public const string IpRateLimited = "ip_rate_limited";

    /// <summary>Too many OTP or verification requests within the time window.</summary>
    public const string RateLimited = "rate_limited";

    // ── Access control ────────────────────────────────────────────────────────

    /// <summary>The caller does not have permission for this operation.</summary>
    public const string Forbidden = "forbidden";

    /// <summary>The requested resource does not exist.</summary>
    public const string NotFound = "not_found";

    /// <summary>A concurrent update conflict was detected. Retry the operation.</summary>
    public const string ConcurrencyConflict = "concurrency_conflict";

    // ── Generic ──────────────────────────────────────────────────────────────

    /// <summary>A validation rule was violated. See the <c>errors</c> array for details.</summary>
    public const string ValidationError = "validation_error";

    /// <summary>An unhandled, non-domain error occurred. The response body never includes the
    /// underlying exception's message or stack trace; see the server logs (keyed by the returned
    /// correlation reference) for details.</summary>
    public const string InternalError = "internal_error";
}
