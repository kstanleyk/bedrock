using System.ComponentModel.DataAnnotations;
using Crestacle.Bedrock.Core.Enumerations;

namespace Crestacle.Bedrock.AspNetCore.Models;

// Validation bounds below are informed by the corresponding EF column lengths where one exists
// (e.g. UserCredential.Email = 256, KnownDevice/Session.FingerprintHash = 128, ConsentRecord
// fields, Invitation.RoleHint, ApiKey.Name, PasskeyCredential.FriendlyName). Fields with no
// direct column equivalent (raw pre-hash tokens, JWTs, WebAuthn attestation/assertion payloads,
// external-IdP tokens) get a deliberately generous upper bound rather than a guessed-tight one,
// per this slice's own instruction not to reject currently-valid production data.

public sealed record RegisterRequest(
    [Required, EmailAddress, StringLength(256)] string Email,
    [Required, StringLength(128)] string Password);

public sealed record ConfirmEmailRequest(
    [Required, StringLength(512)] string Token);

public sealed record ResendConfirmationRequest(
    [Required, EmailAddress, StringLength(256)] string Email);

public sealed record LoginRequest(
    [Required, EmailAddress, StringLength(256)] string Email,
    [Required, StringLength(128)] string Password,
    [StringLength(128)] string? FingerprintHash = null);

public sealed record VerifyMfaRequest(
    [Required, StringLength(2048)] string ChallengeToken,
    [Required, StringLength(16)] string Code,
    [StringLength(128)] string? FingerprintHash = null);

public sealed record RefreshRequest(
    [StringLength(512)] string? RefreshToken = null,
    [StringLength(128)] string? FingerprintHash = null);

public sealed record RevokeRequest(
    [StringLength(512)] string? RefreshToken = null);

public sealed record ForgotPasswordRequest(
    [Required, EmailAddress, StringLength(256)] string Email);

public sealed record ResetPasswordRequest(
    [Required, StringLength(512)] string Token,
    [Required, StringLength(128)] string NewPassword);

public sealed record ChangePasswordRequest(
    [Required, StringLength(128)] string CurrentPassword,
    [Required, StringLength(128)] string NewPassword);

public sealed record ConfirmTotpRequest(
    [Required, StringLength(16)] string Code);

public sealed record SetupOtpRequest(MfaMethod Method);

public sealed record VerifyStepUpRequest(
    Guid ChallengeId,
    [Required, StringLength(16)] string Code);

public sealed record RecordConsentRequest(
    [Required, StringLength(50)] string PolicyType,
    [Required, StringLength(20)] string PolicyVersion);

public sealed record RequestEmailChangeRequest(
    [Required, EmailAddress, StringLength(256)] string NewEmail);

public sealed record ConfirmEmailChangeRequest(
    [Required, StringLength(512)] string TokenHash);

public sealed record MagicLinkRequest(
    [Required, EmailAddress, StringLength(256)] string Email);

public sealed record VerifyMagicLinkRequest(
    [Required, StringLength(512)] string TokenHash,
    [StringLength(128)] string? FingerprintHash = null);

public sealed record CompletePasskeyRegistrationRequest(
    [Required, StringLength(16384)] string AttestationResponse,
    [StringLength(100)] string? FriendlyName);

public sealed record BeginPasskeyAuthenticationRequest(
    [EmailAddress, StringLength(256)] string? Email);

public sealed record CompletePasskeyAuthenticationRequest(
    [Required, StringLength(16384)] string AssertionResponse);

public sealed record ExternalLoginRequest(
    [Required, StringLength(50)] string Provider,
    [Required, StringLength(4096)] string ProviderToken,
    [StringLength(128)] string? FingerprintHash = null);

public sealed record LinkExternalIdentityRequest(
    [Required, StringLength(50)] string Provider,
    [Required, StringLength(4096)] string ProviderToken);

public sealed record CreateInvitationRequest(
    [Required, EmailAddress, StringLength(256)] string TargetEmail,
    [StringLength(100)] string? RoleHint = null);

public sealed record AcceptInvitationRequest(
    [Required, StringLength(512)] string TokenHash,
    [Required, StringLength(128)] string Password);

public sealed record CreateApiKeyRequest(
    [StringLength(100)] string? Name = null);

public sealed record AdminResetPasswordRequest(
    [Required, StringLength(128)] string NewPassword);

public sealed record AdminChangeEmailRequest(
    [Required, EmailAddress, StringLength(256)] string NewEmail);
