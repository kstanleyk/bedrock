using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using FluentAssertions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

/// <summary>
/// Covers the step-up verify brute-force limiter added in SLICE H5: unlimited wrong-code
/// guesses against a single challenge must be throttled, and once the limit is exceeded the
/// challenge is invalidated outright (not merely "still rejected this one time").
/// </summary>
public sealed class StepUpServiceTests
{
    private sealed class InMemoryBedrockCache : IBedrockCache
    {
        private readonly Dictionary<string, string> _store = new();

        public Task SetAsync(string key, string value, TimeSpan expiry, CancellationToken ct = default)
        {
            _store[key] = value;
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string key, CancellationToken ct = default)
            => Task.FromResult(_store.TryGetValue(key, out var v) ? v : null);

        public Task RemoveAsync(string key, CancellationToken ct = default)
        {
            _store.Remove(key);
            return Task.CompletedTask;
        }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => Task.FromResult(_store.ContainsKey(key));

        public Task<bool> TryAcquireLockAsync(string key, TimeSpan ttl, CancellationToken ct = default)
            => Task.FromResult(true);

        public Task ReleaseLockAsync(string key, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private static readonly Guid UserId = Guid.NewGuid();
    private const string Email = "stepup-bruteforce@example.com";
    private const int MaxAttempts = 5;

    private readonly ICredentialRepository _credentialRepo = Substitute.For<ICredentialRepository>();
    private readonly IStepUpChallengeRepository _challengeRepo = Substitute.For<IStepUpChallengeRepository>();
    private readonly IOtpCodeRepository _otpCodeRepo = Substitute.For<IOtpCodeRepository>();
    private readonly IAuditRepository _auditRepo = Substitute.For<IAuditRepository>();
    private readonly IBedrockUnitOfWork _unitOfWork = Substitute.For<IBedrockUnitOfWork>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly IMfaService _mfaService = Substitute.For<IMfaService>();
    private readonly IOtpService _otpService = Substitute.For<IOtpService>();
    private readonly IEmailSender _emailSender = Substitute.For<IEmailSender>();
    private readonly ISmsSender _smsSender = Substitute.For<ISmsSender>();
    private readonly IBedrockEventPublisher _eventPublisher = Substitute.For<IBedrockEventPublisher>();

    private BedrockOptions MakeOptions() => new()
    {
        Jwt = { SigningKey = "test-key-that-is-long-enough-32b!" },
        Lockout = new LockoutOptions { MaxStepUpVerifyAttempts = MaxAttempts }
    };

    private StepUpService Build(BedrockOptions? options = null)
    {
        options ??= MakeOptions();
        var cache = new InMemoryBedrockCache();
        var otpSendLimiter = new OtpSendLimiter(cache, Options.Create(options));
        var stepUpAttemptLimiter = new StepUpAttemptLimiter(cache, Options.Create(options));

        return new StepUpService(
            _credentialRepo,
            _challengeRepo,
            _otpCodeRepo,
            _auditRepo,
            _unitOfWork,
            _tokenService,
            _mfaService,
            _otpService,
            _emailSender,
            _smsSender,
            _eventPublisher,
            otpSendLimiter,
            stepUpAttemptLimiter,
            Options.Create(options));
    }

    /// <summary>A TOTP-based challenge sidesteps OTP-code repository plumbing — the limiter is
    /// method-agnostic, so exercising it via TOTP verification is representative.</summary>
    private static (UserCredential credential, StepUpChallenge challenge) MakeTotpFixture()
    {
        var credential = UserCredential.Create(UserId, Email, "hash");
        credential.ConfirmEmail();
        credential.SetTotpSecret("encrypted-secret");
        credential.EnableMfa(MfaMethod.Totp);

        var challenge = StepUpChallenge.Create(
            UserId, MfaMethod.Totp, codeHash: null, ipAddress: "127.0.0.1",
            expiresAt: DateTime.UtcNow.AddMinutes(5));

        return (credential, challenge);
    }

    private void SetupFixture(UserCredential credential, StepUpChallenge challenge, bool codeIsValid)
    {
        _credentialRepo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(credential);
        _challengeRepo.GetByIdAsync(challenge.Id, Arg.Any<CancellationToken>()).Returns(challenge);
        _mfaService.VerifyTotp("encrypted-secret", Arg.Any<string>(), UserId, Arg.Any<CancellationToken>())
            .Returns(codeIsValid);
    }

    [Fact]
    public async Task VerifyAsync_WithinAttemptLimit_ThrowsOrdinaryValidationException()
    {
        var (credential, challenge) = MakeTotpFixture();
        SetupFixture(credential, challenge, codeIsValid: false);
        var svc = Build();

        for (var i = 0; i < MaxAttempts; i++)
        {
            var act = () => svc.VerifyAsync(UserId, challenge.Id, "000000", "127.0.0.1", "ua");
            await act.Should().ThrowAsync<BedrockValidationException>();
        }

        // Still not invalidated — MarkUsed must not have been called while under the limit.
        challenge.UsedAt.Should().BeNull();
    }

    [Fact]
    public async Task VerifyAsync_AttemptAfterLimitExceeded_ThrowsRateLimitExceptionAndInvalidatesChallenge()
    {
        var (credential, challenge) = MakeTotpFixture();
        SetupFixture(credential, challenge, codeIsValid: false);
        var svc = Build();

        for (var i = 0; i < MaxAttempts; i++)
        {
            var act = () => svc.VerifyAsync(UserId, challenge.Id, "000000", "127.0.0.1", "ua");
            await act.Should().ThrowAsync<BedrockValidationException>();
        }

        // The (MaxAttempts + 1)th attempt must be rate-limited, not just another 400.
        var rateLimited = () => svc.VerifyAsync(UserId, challenge.Id, "000000", "127.0.0.1", "ua");
        await rateLimited.Should().ThrowAsync<BedrockRateLimitException>();

        challenge.UsedAt.Should().NotBeNull("limit-exceeded must invalidate the challenge");
        await _challengeRepo.Received(1).UpdateAsync(challenge, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_SubsequentlyCorrectCode_StillRejectedAfterInvalidation()
    {
        var (credential, challenge) = MakeTotpFixture();
        SetupFixture(credential, challenge, codeIsValid: false);
        var svc = Build();

        for (var i = 0; i < MaxAttempts; i++)
        {
            var act = () => svc.VerifyAsync(UserId, challenge.Id, "000000", "127.0.0.1", "ua");
            await act.Should().ThrowAsync<BedrockValidationException>();
        }

        // Trip the limiter.
        var rateLimited = () => svc.VerifyAsync(UserId, challenge.Id, "000000", "127.0.0.1", "ua");
        await rateLimited.Should().ThrowAsync<BedrockRateLimitException>();

        // Now the attacker finally supplies the RIGHT code — must still be rejected because
        // the challenge itself (not just the attempt count) was invalidated.
        _mfaService.VerifyTotp("encrypted-secret", "123456", UserId, Arg.Any<CancellationToken>())
            .Returns(true);

        var afterInvalidation = () => svc.VerifyAsync(UserId, challenge.Id, "123456", "127.0.0.1", "ua");
        await afterInvalidation.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*expired or already been used*");
    }

    [Fact]
    public async Task VerifyAsync_DifferentChallenges_TrackAttemptsSeparately()
    {
        var (credential1, challenge1) = MakeTotpFixture();
        var challenge2 = StepUpChallenge.Create(
            UserId, MfaMethod.Totp, codeHash: null, ipAddress: "127.0.0.1",
            expiresAt: DateTime.UtcNow.AddMinutes(5));

        _credentialRepo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(credential1);
        _challengeRepo.GetByIdAsync(challenge1.Id, Arg.Any<CancellationToken>()).Returns(challenge1);
        _challengeRepo.GetByIdAsync(challenge2.Id, Arg.Any<CancellationToken>()).Returns(challenge2);
        _mfaService.VerifyTotp(Arg.Any<string>(), Arg.Any<string>(), UserId, Arg.Any<CancellationToken>())
            .Returns(false);

        var svc = Build();

        // Exhaust challenge1's attempt budget.
        for (var i = 0; i < MaxAttempts; i++)
            await Assert.ThrowsAsync<BedrockValidationException>(
                () => svc.VerifyAsync(UserId, challenge1.Id, "000000", "127.0.0.1", "ua"));
        await Assert.ThrowsAsync<BedrockRateLimitException>(
            () => svc.VerifyAsync(UserId, challenge1.Id, "000000", "127.0.0.1", "ua"));

        // challenge2 has its own independent counter and is unaffected.
        await Assert.ThrowsAsync<BedrockValidationException>(
            () => svc.VerifyAsync(UserId, challenge2.Id, "000000", "127.0.0.1", "ua"));
        challenge2.UsedAt.Should().BeNull();
    }
}
