using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Fido2NetLib;
using Fido2NetLib.Objects;
using FluentAssertions;
using NSubstitute;
using Xunit;
using FA = Fido2NetLib.AssertionOptions;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class PasskeyServiceTests
{
    private static readonly Guid UserId = Guid.NewGuid();
    private static readonly byte[] FakeCredId = new byte[32];
    private static readonly byte[] FakePubKey = new byte[64];

    private readonly IFido2 _fido2 = Substitute.For<IFido2>();
    private readonly IPasskeyCredentialRepository _passkeyRepo = Substitute.For<IPasskeyCredentialRepository>();
    private readonly ICredentialRepository _credentialRepo = Substitute.For<ICredentialRepository>();
    private readonly IAuditRepository _auditRepo = Substitute.For<IAuditRepository>();
    private readonly IRefreshTokenService _refreshTokens = Substitute.For<IRefreshTokenService>();
    private readonly IBedrockCache _cache = Substitute.For<IBedrockCache>();
    private readonly IBedrockUnitOfWork _unitOfWork = Substitute.For<IBedrockUnitOfWork>();

    private PasskeyService Build() => new(
        _fido2, _passkeyRepo, _credentialRepo, _auditRepo, _refreshTokens,
        _cache, _unitOfWork,
        Microsoft.Extensions.Logging.Abstractions.NullLogger<PasskeyService>.Instance);

    private static CredentialCreateOptions MakeCredentialCreateOptions(Guid? userId = null, string username = "test")
    {
        var uid = userId ?? UserId;
        return new CredentialCreateOptions
        {
            Rp = new PublicKeyCredentialRpEntity("Test", "localhost", ""),
            User = new Fido2User { Id = Encoding.UTF8.GetBytes(uid.ToString()), Name = username, DisplayName = username },
            Challenge = new byte[32],
            PubKeyCredParams = PubKeyCredParam.Defaults
        };
    }

    // -------------------------------------------------------------------------
    // BeginRegistrationAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BeginRegistration_StoresOptionsInCacheAndReturnsJson()
    {
        _passkeyRepo.GetForUserAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(new List<PasskeyCredential>());

        _fido2.RequestNewCredential(Arg.Any<RequestNewCredentialParams>())
            .Returns(MakeCredentialCreateOptions());

        var svc = Build();
        var json = await svc.BeginRegistrationAsync(UserId, "test@example.com");

        json.Should().NotBeNullOrEmpty();
        await _cache.Received(1).SetAsync(
            $"Bedrock:passkey-reg:{UserId}",
            Arg.Any<string>(),
            TimeSpan.FromMinutes(5),
            Arg.Any<CancellationToken>());
    }

    // -------------------------------------------------------------------------
    // CompleteRegistrationAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CompleteRegistration_WhenSessionExpired_Throws()
    {
        _cache.GetAsync($"Bedrock:passkey-reg:{UserId}", Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var svc = Build();
        await svc.Invoking(s => s.CompleteRegistrationAsync(UserId, "{}", null))
            .Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*expired*");
    }

    [Fact]
    public async Task CompleteRegistration_WhenAttestationInvalid_Throws()
    {
        _cache.GetAsync($"Bedrock:passkey-reg:{UserId}", Arg.Any<CancellationToken>())
            .Returns(MakeCredentialCreateOptions().ToJson());

        var svc = Build();
        await svc.Invoking(s => s.CompleteRegistrationAsync(UserId, "not-json", null))
            .Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*Invalid*");
    }

    [Fact]
    public async Task CompleteRegistration_PersistsCredentialAndAudits()
    {
        _cache.GetAsync($"Bedrock:passkey-reg:{UserId}", Arg.Any<CancellationToken>())
            .Returns(MakeCredentialCreateOptions().ToJson());

        var attestationResp = new AuthenticatorAttestationRawResponse();
        var attestJson = JsonSerializer.Serialize(attestationResp);

        _fido2.MakeNewCredentialAsync(Arg.Any<MakeNewCredentialParams>(), Arg.Any<CancellationToken>())
            .Returns(new RegisteredPublicKeyCredential
            {
                Id = FakeCredId,
                PublicKey = FakePubKey,
                SignCount = 1,
                IsBackedUp = false
            });

        var svc = Build();
        var credential = await svc.CompleteRegistrationAsync(UserId, attestJson, "My Key");

        credential.UserId.Should().Be(UserId);
        credential.FriendlyName.Should().Be("My Key");
        await _passkeyRepo.Received(1).AddAsync(Arg.Any<PasskeyCredential>(), Arg.Any<CancellationToken>());
        await _auditRepo.Received(1).AddAsync(
            Arg.Is<AuditEntry>(a => a.EventType == AuditEventType.PasskeyRegistered),
            Arg.Any<CancellationToken>());
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    // -------------------------------------------------------------------------
    // BeginAuthenticationAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BeginAuthentication_StoresOptionsInCacheKeyedByChallenge()
    {
        var challenge = new byte[32];
        new Random(42).NextBytes(challenge);
        var fakeOptions = new FA { Challenge = challenge };

        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>()).Returns(fakeOptions);

        var svc = Build();
        var json = await svc.BeginAuthenticationAsync(email: null);

        json.Should().NotBeNullOrEmpty();
        var expectedKey = "Bedrock:passkey-auth:" + Base64UrlEncode(challenge);
        await _cache.Received(1).SetAsync(
            expectedKey,
            Arg.Any<string>(),
            TimeSpan.FromMinutes(5),
            Arg.Any<CancellationToken>());
    }

    // -------------------------------------------------------------------------
    // CompleteAuthenticationAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CompleteAuthentication_WhenSessionExpired_Throws()
    {
        var assertion = BuildFakeAssertionRawResponse();
        var assertionJson = JsonSerializer.Serialize(assertion,
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns((string?)null);

        var svc = Build();
        await svc.Invoking(s => s.CompleteAuthenticationAsync(assertionJson, "127.0.0.1", "test-agent"))
            .Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*expired*");
    }

    [Fact]
    public async Task CompleteAuthentication_WhenPasskeyNotFound_Throws()
    {
        var assertion = BuildFakeAssertionRawResponse();
        var assertionJson = JsonSerializer.Serialize(assertion,
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FA { Challenge = new byte[32] }.ToJson());
        _passkeyRepo.GetByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns((PasskeyCredential?)null);

        var svc = Build();
        await svc.Invoking(s => s.CompleteAuthenticationAsync(assertionJson, "127.0.0.1", "test-agent"))
            .Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*not found*");
    }

    [Fact]
    public async Task CompleteAuthentication_WhenSignCountDecreased_ThrowsCloningException()
    {
        var assertion = BuildFakeAssertionRawResponse();
        var assertionJson = JsonSerializer.Serialize(assertion,
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FA { Challenge = new byte[32] }.ToJson());

        var storedCred = PasskeyCredential.Create(UserId, FakeCredId, FakePubKey, signCount: 10);
        _passkeyRepo.GetByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(storedCred);

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult { CredentialId = FakeCredId, SignCount = 5 }); // lower than stored 10

        var svc = Build();
        await svc.Invoking(s => s.CompleteAuthenticationAsync(assertionJson, "127.0.0.1", "test-agent"))
            .Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*cloned*");
    }

    [Fact]
    public async Task CompleteAuthentication_Success_IssuesTokens()
    {
        var assertion = BuildFakeAssertionRawResponse();
        var assertionJson = JsonSerializer.Serialize(assertion,
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FA { Challenge = new byte[32] }.ToJson());

        var storedCred = PasskeyCredential.Create(UserId, FakeCredId, FakePubKey, signCount: 5);
        _passkeyRepo.GetByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(storedCred);

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult { CredentialId = FakeCredId, SignCount = 6 });

        var userCred = UserCredential.Create(UserId, "user@example.com", "hash");
        _credentialRepo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(userCred);

        var fakeTokens = new Core.DTOs.TokenPair("access", "refresh", DateTime.UtcNow.AddMinutes(15));
        _refreshTokens.IssueAsync(
            UserId, Arg.Any<string>(), Arg.Any<IEnumerable<string>>(),
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(),
            Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(fakeTokens);

        var svc = Build();
        var result = await svc.CompleteAuthenticationAsync(assertionJson, "127.0.0.1", "agent");

        result.Tokens.Should().NotBeNull();
        result.Tokens!.AccessToken.Should().Be("access");
    }

    // -------------------------------------------------------------------------
    // H13 -- origin mismatch must be rejected. Every other test in this file mocks IFido2
    // with NSubstitute, which answers every call with a canned result regardless of input --
    // origin verification lives entirely inside Fido2NetLib itself (PasskeyService never
    // inspects clientDataJson's own "origin" field), so a mocked IFido2 cannot exercise this
    // path at all. This test wires PasskeyService to the REAL Fido2 implementation instead,
    // configured with a fixed RP/origin, and sends an assertion whose clientDataJson claims a
    // different origin -- confirmed empirically (see commit description) that Fido2NetLib
    // rejects on origin before it even reaches signature verification, so no real key material
    // is needed to isolate this check.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CompleteAuthentication_MismatchedOrigin_IsRejected()
    {
        const string rpId = "example.test";
        const string configuredOrigin = "https://example.test";
        const string attackerOrigin = "https://attacker.example";

        var realFido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = rpId,
            ServerName = "Test",
            Origins = new HashSet<string> { configuredOrigin },
        });

        var challenge = new byte[32];
        var storedOptions = new FA { Challenge = challenge, RpId = rpId };
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(storedOptions.ToJson());

        var storedCred = PasskeyCredential.Create(UserId, FakeCredId, FakePubKey, signCount: 0);
        _passkeyRepo.GetByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(storedCred);

        // A correctly-formed authenticatorData (right rpIdHash, user-present flag set) so the
        // ONLY thing wrong with this assertion is the origin -- isolating exactly what's under
        // test, not incidentally failing on some other check first.
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        var authenticatorData = new byte[37];
        Array.Copy(rpIdHash, authenticatorData, 32);
        authenticatorData[32] = 0x01; // user-present

        var clientData = new { type = "webauthn.get", challenge = Base64UrlEncode(challenge), origin = attackerOrigin };
        var clientDataBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(clientData));

        var assertion = new AuthenticatorAssertionRawResponse
        {
            RawId = FakeCredId,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                ClientDataJson = clientDataBytes,
                AuthenticatorData = authenticatorData,
                Signature = new byte[64],
            },
        };
        var assertionJson = JsonSerializer.Serialize(assertion,
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        var svc = new PasskeyService(
            realFido2, _passkeyRepo, _credentialRepo, _auditRepo, _refreshTokens,
            _cache, _unitOfWork, Microsoft.Extensions.Logging.Abstractions.NullLogger<PasskeyService>.Instance);

        await svc.Invoking(s => s.CompleteAuthenticationAsync(assertionJson, "127.0.0.1", "test-agent"))
            .Should().ThrowAsync<Fido2VerificationException>()
            .WithMessage("*origin*",
                because: "a clientDataJson origin that doesn't match the configured RP origin must be " +
                         "rejected -- this is enforced by Fido2NetLib itself; PasskeyService does no " +
                         "origin checking of its own and must not swallow or weaken this rejection");
    }

    // -------------------------------------------------------------------------
    // DeletePasskeyAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task DeletePasskey_NotFound_Throws()
    {
        _passkeyRepo.GetByIdAsync(Arg.Any<Guid>(), Arg.Any<CancellationToken>())
            .Returns((PasskeyCredential?)null);

        var svc = Build();
        await svc.Invoking(s => s.DeletePasskeyAsync(Guid.NewGuid(), UserId))
            .Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task DeletePasskey_WrongOwner_Throws()
    {
        var cred = PasskeyCredential.Create(Guid.NewGuid(), FakeCredId, FakePubKey, 0);
        _passkeyRepo.GetByIdAsync(Arg.Any<Guid>(), Arg.Any<CancellationToken>()).Returns(cred);

        var svc = Build();
        await svc.Invoking(s => s.DeletePasskeyAsync(cred.Id, UserId))
            .Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task DeletePasskey_Success_DeletesAndAudits()
    {
        var cred = PasskeyCredential.Create(UserId, FakeCredId, FakePubKey, 0);
        _passkeyRepo.GetByIdAsync(Arg.Any<Guid>(), Arg.Any<CancellationToken>()).Returns(cred);
        _credentialRepo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(UserCredential.Create(UserId, "user@example.com", "hash"));

        var svc = Build();
        await svc.DeletePasskeyAsync(cred.Id, UserId);

        await _passkeyRepo.Received(1).DeleteAsync(cred, Arg.Any<CancellationToken>());
        await _auditRepo.Received(1).AddAsync(
            Arg.Is<AuditEntry>(a => a.EventType == AuditEventType.PasskeyDeleted),
            Arg.Any<CancellationToken>());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static AuthenticatorAssertionRawResponse BuildFakeAssertionRawResponse()
    {
        var challenge = new byte[32];
        var clientData = new { type = "webauthn.get", challenge = Base64UrlEncode(challenge), origin = "https://localhost" };
        var clientDataBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(clientData));

        return new AuthenticatorAssertionRawResponse
        {
            RawId = FakeCredId,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                ClientDataJson = clientDataBytes,
                AuthenticatorData = new byte[37],
                Signature = new byte[64]
            }
        };
    }

    private static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
