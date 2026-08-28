using Crestacle.Bedrock.Core.Enumerations;

namespace Crestacle.Bedrock.AspNetCore.Models;

public sealed record AuditEntryResponse(
    Guid Id,
    AuditEventType EventType,
    string IpAddress,
    string UserAgent,
    Guid? UserId,
    DateTime OccurredAt);

public sealed record AuditQueryResponse(
    IReadOnlyList<AuditEntryResponse> Items,
    int TotalCount);

public sealed record StepUpInitiateResponse(Guid ChallengeId, MfaMethod Method);
public sealed record StepUpVerifyResponse(string StepUpToken);
public sealed record RemainingRecoveryCodesResponse(int RemainingCount);

public sealed record LoginResponse(
    string? AccessToken,
    string? RefreshToken,
    DateTime? AccessTokenExpiresAt,
    bool RequiresMfa,
    string? ChallengeToken,
    MfaMethod? ChallengeMethod,
    DateTime? ChallengeExpiresAt,
    bool RequiresEnrollment,
    string? EnrollmentToken,
    DateTime? MfaGracePeriodEndsAt);

public sealed record TokenResponse(
    string AccessToken,
    string? RefreshToken,
    DateTime AccessTokenExpiresAt);

public sealed record RequestEnrollmentResponse(string EnrollmentToken);

public sealed record SessionResponse(
    Guid Id,
    string DeviceFingerprint,
    string IpAddress,
    string UserAgent,
    DateTime CreatedAt,
    DateTime LastActivityAt);

public sealed record TotpSetupResponse(string QrUri);

public sealed record RecoveryCodesResponse(IReadOnlyList<string> Codes);

public sealed record ConsentRecordResponse(
    Guid Id,
    string PolicyType,
    string PolicyVersion,
    DateTime AcceptedAt,
    string IpAddress);

public sealed record PasskeyInfoResponse(
    Guid Id,
    string? FriendlyName,
    DateTime CreatedAt);

public sealed record ExternalIdentityResponse(
    Guid Id,
    string Provider,
    DateTime CreatedAt);

public sealed record ApiKeyResponse(
    Guid Id,
    string Prefix,
    string? Name,
    DateTime CreatedAt,
    DateTime? LastUsedAt,
    DateTime? ExpiresAt,
    bool IsActive);

public sealed record CreateApiKeyResponse(
    string RawKey,
    Guid Id,
    string Prefix,
    string? Name,
    DateTime CreatedAt,
    DateTime? ExpiresAt);
