using System.Text;
using System.Text.Json;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging;

namespace Crestacle.Bedrock.AspNetCore.Services;

internal sealed partial class PasskeyService : IPasskeyService
{
    private const string RegCachePrefix = "Bedrock:passkey-reg:";
    private const string AuthCachePrefix = "Bedrock:passkey-auth:";
    private static readonly TimeSpan OptionsTtl = TimeSpan.FromMinutes(5);

    private readonly IFido2 _fido2;
    private readonly IPasskeyCredentialRepository _passkeyRepo;
    private readonly ICredentialRepository _credentialRepo;
    private readonly IAuditRepository _auditRepo;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IBedrockCache _cache;
    private readonly IBedrockUnitOfWork _unitOfWork;
    private readonly ILogger<PasskeyService> _logger;

    public PasskeyService(
        IFido2 fido2,
        IPasskeyCredentialRepository passkeyRepo,
        ICredentialRepository credentialRepo,
        IAuditRepository auditRepo,
        IRefreshTokenService refreshTokenService,
        IBedrockCache cache,
        IBedrockUnitOfWork unitOfWork,
        ILogger<PasskeyService> logger)
    {
        _fido2 = fido2;
        _passkeyRepo = passkeyRepo;
        _credentialRepo = credentialRepo;
        _auditRepo = auditRepo;
        _refreshTokenService = refreshTokenService;
        _cache = cache;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // Registration
    // -------------------------------------------------------------------------

    public async Task<string> BeginRegistrationAsync(Guid userId, string username, CancellationToken ct = default)
    {
        var existing = await _passkeyRepo.GetForUserAsync(userId, ct);
        var excludeCredentials = existing
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToList();

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(userId.ToString()),
                Name = username,
                DisplayName = username
            },
            ExcludeCredentials = excludeCredentials,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Preferred
            },
            AttestationPreference = AttestationConveyancePreference.None
        });

        var json = options.ToJson();
        await _cache.SetAsync($"{RegCachePrefix}{userId}", json, OptionsTtl, ct);
        return json;
    }

    public async Task<PasskeyCredential> CompleteRegistrationAsync(
        Guid userId,
        string attestationResponseJson,
        string? friendlyName,
        CancellationToken ct = default)
    {
        var cachedOptionsJson = await _cache.GetAsync($"{RegCachePrefix}{userId}", ct)
            ?? throw new BedrockValidationException("Registration session has expired. Please begin again.");

        var storedOptions = CredentialCreateOptions.FromJson(cachedOptionsJson);

        AuthenticatorAttestationRawResponse attestationResponse;
        try
        {
            attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(attestationResponseJson)
                ?? throw new BedrockValidationException("Invalid attestation response.");
        }
        catch (JsonException)
        {
            throw new BedrockValidationException("Invalid attestation response.");
        }

        var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestationResponse,
            OriginalOptions = storedOptions,
            IsCredentialIdUniqueToUserCallback = async (p, ct2) =>
            {
                var existing = await _passkeyRepo.GetByCredentialIdAsync(p.CredentialId, ct2);
                return existing is null;
            }
        }, ct);

        var transports = result.Transports is { Length: > 0 }
            ? string.Join(",", result.Transports.Select(t => t.ToString().ToLowerInvariant()))
            : null;

        var credential = PasskeyCredential.Create(
            userId,
            result.Id,
            result.PublicKey,
            result.SignCount,
            transports: transports,
            isBackedUp: result.IsBackedUp,
            friendlyName: friendlyName,
            tenantId: null);

        await _passkeyRepo.AddAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasskeyRegistered, "unknown", "unknown", userId), ct);
        await _unitOfWork.SaveChangesAsync(ct);

        await _cache.RemoveAsync($"{RegCachePrefix}{userId}", ct);

        LogPasskeyRegistered(_logger, userId);
        return credential;
    }

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    public async Task<string> BeginAuthenticationAsync(string? email, CancellationToken ct = default)
    {
        var allowedCredentials = new List<PublicKeyCredentialDescriptor>();

        if (email is not null)
        {
            var userCredential = await _credentialRepo.GetByEmailAsync(email, ct);
            if (userCredential is not null)
            {
                var passkeys = await _passkeyRepo.GetForUserAsync(userCredential.UserId, ct);
                allowedCredentials = passkeys
                    .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                    .ToList();
            }
        }

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
            UserVerification = UserVerificationRequirement.Preferred
        });

        var json = options.ToJson();
        var challengeKey = Base64UrlEncode(options.Challenge);
        await _cache.SetAsync($"{AuthCachePrefix}{challengeKey}", json, OptionsTtl, ct);
        return json;
    }

    public async Task<LoginResult> CompleteAuthenticationAsync(
        string assertionResponseJson,
        string ipAddress,
        string userAgent,
        CancellationToken ct = default)
    {
        AuthenticatorAssertionRawResponse assertionResponse;
        try
        {
            assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(assertionResponseJson)
                ?? throw new BedrockValidationException("Invalid assertion response.");
        }
        catch (JsonException)
        {
            throw new BedrockValidationException("Invalid assertion response.");
        }

        // Extract challenge from clientDataJSON to look up the cached AssertionOptions.
        string challengeKey;
        try
        {
            using var clientData = JsonDocument.Parse(
                Encoding.UTF8.GetString(assertionResponse.Response.ClientDataJson));
            challengeKey = clientData.RootElement.GetProperty("challenge").GetString()
                ?? throw new BedrockValidationException("Invalid assertion response.");
        }
        catch (Exception ex) when (ex is not BedrockValidationException)
        {
            throw new BedrockValidationException("Invalid assertion response.");
        }

        var cachedOptionsJson = await _cache.GetAsync($"{AuthCachePrefix}{challengeKey}", ct)
            ?? throw new BedrockValidationException("Authentication session has expired. Please begin again.");

        var storedOptions = AssertionOptions.FromJson(cachedOptionsJson);

        // RawId contains the decoded credential ID bytes.
        var storedCred = await _passkeyRepo.GetByCredentialIdAsync(assertionResponse.RawId, ct)
            ?? throw new BedrockValidationException("Passkey not found.");

        var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertionResponse,
            OriginalOptions = storedOptions,
            StoredPublicKey = storedCred.PublicKeyCose,
            StoredSignatureCounter = (uint)storedCred.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = async (p, ct2) =>
            {
                if (p.UserHandle is null || p.UserHandle.Length == 0) return true;
                var handleStr = Encoding.UTF8.GetString(p.UserHandle);
                if (!Guid.TryParse(handleStr, out var handleUserId)) return false;
                return storedCred.UserId == handleUserId;
            }
        }, ct);

        // Cloned authenticator detection — reject if new count <= stored (except when both are zero).
        if (result.SignCount != 0 && result.SignCount <= (uint)storedCred.SignCount)
            throw new BedrockValidationException("Authenticator may be cloned. Authentication rejected.");

        storedCred.UpdateUsage(result.SignCount);
        await _passkeyRepo.UpdateAsync(storedCred, ct);

        var userCredential = await _credentialRepo.GetByUserIdAsync(storedCred.UserId, ct)
            ?? throw new BedrockValidationException("User not found.");

        if (userCredential.IsLockedOut())
            throw new BedrockAccountLockedException(userCredential.LockoutEnd!.Value, userCredential.IsAdminLocked);

        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasskeyAuthenticated, ipAddress, userAgent,
                storedCred.UserId, tenantId: userCredential.TenantId), ct);

        await _unitOfWork.SaveChangesAsync(ct);

        await _cache.RemoveAsync($"{AuthCachePrefix}{challengeKey}", ct);

        // Passkey login is phishing-resistant and satisfies both factors — issue tokens directly.
        var tokens = await _refreshTokenService.IssueAsync(
            storedCred.UserId,
            userCredential.Email,
            roles: [],
            ip: ipAddress,
            userAgent: userAgent,
            fingerprintHash: userAgent,
            tenantId: userCredential.TenantId,
            ct: ct);

        LogPasskeyAuthenticated(_logger, storedCred.UserId, userCredential.TenantId);
        return new LoginResult { Tokens = tokens };
    }

    // -------------------------------------------------------------------------
    // Credential management
    // -------------------------------------------------------------------------

    public async Task<IReadOnlyList<PasskeyCredential>> GetPasskeysAsync(Guid userId, CancellationToken ct = default)
        => await _passkeyRepo.GetForUserAsync(userId, ct);

    public async Task DeletePasskeyAsync(Guid passkeyId, Guid requestingUserId, CancellationToken ct = default)
    {
        var credential = await _passkeyRepo.GetByIdAsync(passkeyId, ct)
            ?? throw new BedrockValidationException("Passkey not found.");

        if (credential.UserId != requestingUserId)
            throw new BedrockValidationException("Passkey not found.");

        var userCredential = await _credentialRepo.GetByUserIdAsync(requestingUserId, ct);

        await _passkeyRepo.DeleteAsync(credential, ct);
        await _auditRepo.AddAsync(
            AuditEntry.Create(AuditEventType.PasskeyDeleted, "unknown", "unknown",
                requestingUserId, tenantId: userCredential?.TenantId), ct);
        await _unitOfWork.SaveChangesAsync(ct);

        LogPasskeyDeleted(_logger, requestingUserId);
    }

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------

    [LoggerMessage(4001, LogLevel.Information, "Passkey registered: userId={UserId}")]
    private static partial void LogPasskeyRegistered(ILogger logger, Guid userId);

    [LoggerMessage(4002, LogLevel.Information, "Passkey authenticated: userId={UserId} tenant={TenantId}")]
    private static partial void LogPasskeyAuthenticated(ILogger logger, Guid userId, string? tenantId);

    [LoggerMessage(4003, LogLevel.Information, "Passkey deleted: userId={UserId}")]
    private static partial void LogPasskeyDeleted(ILogger logger, Guid userId);

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
