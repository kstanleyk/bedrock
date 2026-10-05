using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Services;

public sealed class MfaServiceTests : IDisposable
{
    private sealed class CapturingEmailSender : IEmailSender
    {
        public string? LastOtpCode { get; private set; }
        public string? LastVerificationUrl { get; private set; }
        public Task SendEmailVerificationAsync(string e, string u, CancellationToken ct = default) { LastVerificationUrl = u; return Task.CompletedTask; }
        public Task SendPasswordResetAsync(string e, string u, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendAccountLockedAsync(string e, DateTime d, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendMfaOtpAsync(string e, string code, CancellationToken ct = default) { LastOtpCode = code; return Task.CompletedTask; }
        public Task SendAsync(string e, string s, string b, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendEmailChangeVerificationAsync(string e, string u, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendEmailChangeNotificationAsync(string e, CancellationToken ct = default) => Task.CompletedTask;
        public Task SendMagicLinkAsync(string e, string u, CancellationToken ct = default) => Task.CompletedTask;
    }

    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly ICredentialService _service;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";
    private const string TestSigningKey = "Bedrock-Integration-Test-Signing-Key-32B!";

    public MfaServiceTests()
    {
        (_context, _connection) = DbContextFactory.Create();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<BedrockContext>(_context);
        services.AddSingleton<IEmailSender>(_emailSender);
        services.AddBedrockEntityFramework<BedrockContext>();
        services.AddBedrockAspNetCore(opts =>
        {
            opts.Jwt.SigningKey = TestSigningKey;
            opts.Jwt.Issuer = "test";
            opts.Jwt.Audience = "test";
            opts.Password.MinLength = 12;
            opts.Lockout.MaxFailedAttempts = 3;
            opts.Lockout.Duration = TimeSpan.FromSeconds(30);
            opts.Mfa.Issuer = "TestApp";
            opts.Mfa.BackupCodeCount = 5;
        });
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

        _service = services.BuildServiceProvider().GetRequiredService<ICredentialService>();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<Guid> RegisterAndActivateAsync(string email)
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, email, ValidPassword);
        // The real raw token a user would receive by email (not the stored hash).
        var rawToken = Crestacle.Bedrock.Tests.Integration.Infrastructure.CapturingEmailSender
            .ExtractToken(_emailSender.LastVerificationUrl!);
        await _service.ConfirmEmailAsync(rawToken);
        return userId;
    }

    private static string ExtractTotpSecret(string qrUri)
    {
        var query = qrUri.Split('?')[1];
        foreach (var param in query.Split('&'))
        {
            var kv = param.Split('=', 2);
            if (kv[0] == "secret")
                return kv[1];
        }
        throw new InvalidOperationException("No 'secret' parameter in QR URI.");
    }

    private static string ComputeTotp(string base32Secret)
        => new Totp(Base32Encoding.ToBytes(base32Secret)).ComputeTotp();

    // -------------------------------------------------------------------------
    // SetupTotpAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task SetupTotpAsync_ReturnsOtpauthQrUri()
    {
        var userId = await RegisterAndActivateAsync("totp-setup@example.com");
        var result = await _service.SetupTotpAsync(userId);
        result.QrUri.Should().StartWith("otpauth://totp/");
    }

    [Fact]
    public async Task SetupTotpAsync_QrUriContainsIssuerAndEmail()
    {
        var userId = await RegisterAndActivateAsync("totp-qr@example.com");
        var result = await _service.SetupTotpAsync(userId);
        result.QrUri.Should().Contain("TestApp");
        result.QrUri.Should().Contain("totp-qr%40example.com");
    }

    // -------------------------------------------------------------------------
    // ConfirmTotpAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ConfirmTotpAsync_ValidCode_EnablesMfaAndReturnsRecoveryCodes()
    {
        var userId = await RegisterAndActivateAsync("totp-confirm@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var code = ComputeTotp(ExtractTotpSecret(setup.QrUri));

        var result = await _service.ConfirmTotpAsync(userId, code);

        result.Codes.Should().HaveCount(5);
        result.Codes.Should().AllSatisfy(c => c.Should().HaveLength(40));
        var cred = _context.UserCredentials.First(c => c.UserId == userId);
        cred.MfaEnabled.Should().BeTrue();
        cred.MfaMethod.Should().Be(MfaMethod.Totp);
    }

    [Fact]
    public async Task ConfirmTotpAsync_WrongCode_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("totp-bad@example.com");
        await _service.SetupTotpAsync(userId);

        var act = async () => await _service.ConfirmTotpAsync(userId, "000000");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*TOTP code is incorrect*");
    }

    [Fact]
    public async Task ConfirmTotpAsync_NoSetupInitiated_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("totp-noinit@example.com");

        var act = async () => await _service.ConfirmTotpAsync(userId, "123456");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*TOTP setup has not been initiated*");
    }

    // -------------------------------------------------------------------------
    // TOTP login flow
    // -------------------------------------------------------------------------

    [Fact]
    public async Task LoginFirstFactorAsync_TotpEnabled_ReturnsMfaChallenge()
    {
        var userId = await RegisterAndActivateAsync("totp-login@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));

        var result = await _service.LoginFirstFactorAsync(
            "totp-login@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        result.Succeeded.Should().BeTrue();
        result.Challenge.Should().NotBeNull();
        result.Challenge!.Method.Should().Be(MfaMethod.Totp);
        result.Challenge.ChallengeToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyMfaAsync_ValidTotpCode_ReturnsUserId()
    {
        var userId = await RegisterAndActivateAsync("totp-verify@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var secret = ExtractTotpSecret(setup.QrUri);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(secret));

        var loginResult = await _service.LoginFirstFactorAsync(
            "totp-verify@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        var verifiedUserId = await _service.VerifyMfaAsync(
            loginResult.Challenge!.ChallengeToken, ComputeTotp(secret), "127.0.0.1", "Agent/1.0");

        verifiedUserId.Should().Be(userId);
    }

    [Fact]
    public async Task VerifyMfaAsync_WrongTotpCode_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("totp-wrong@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));

        var loginResult = await _service.LoginFirstFactorAsync(
            "totp-wrong@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        var act = async () => await _service.VerifyMfaAsync(
            loginResult.Challenge!.ChallengeToken, "000000", "127.0.0.1", "Agent/1.0");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*verification code is incorrect*");
    }

    [Fact]
    public async Task VerifyMfaAsync_InvalidChallengeToken_ThrowsValidation()
    {
        var act = async () => await _service.VerifyMfaAsync(
            "not.a.valid.jwt", "123456", "127.0.0.1", "Agent/1.0");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*Invalid or expired challenge token*");
    }

    [Fact]
    public async Task VerifyMfaAsync_ReplayedTotpCode_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("totp-replay@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var secret = ExtractTotpSecret(setup.QrUri);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(secret));

        // First login: capture the code, then verify successfully
        var login1 = await _service.LoginFirstFactorAsync(
            "totp-replay@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");
        var code = ComputeTotp(secret);
        await _service.VerifyMfaAsync(login1.Challenge!.ChallengeToken, code, "127.0.0.1", "Agent/1.0");

        // Immediately initiate a second login — still within the 90-second TOTP validity window
        var login2 = await _service.LoginFirstFactorAsync(
            "totp-replay@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp2");

        // The same code must be rejected as a replay
        var act = async () => await _service.VerifyMfaAsync(
            login2.Challenge!.ChallengeToken, code, "127.0.0.1", "Agent/1.0");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*verification code is incorrect*");
    }

    [Fact]
    public async Task VerifyMfaAsync_ReusedChallengeToken_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("totp-reuse-challenge@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var secret = ExtractTotpSecret(setup.QrUri);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(secret));

        var loginResult = await _service.LoginFirstFactorAsync(
            "totp-reuse-challenge@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");
        var challengeToken = loginResult.Challenge!.ChallengeToken;

        await _service.VerifyMfaAsync(challengeToken, ComputeTotp(secret), "127.0.0.1", "Agent/1.0");

        var act = async () => await _service.VerifyMfaAsync(
            challengeToken, ComputeTotp(secret), "127.0.0.1", "Agent/1.0");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*expired or already been used*");
    }

    // -------------------------------------------------------------------------
    // Recovery codes
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyMfaAsync_ValidRecoveryCode_Succeeds()
    {
        var userId = await RegisterAndActivateAsync("recovery-valid@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var recoveryCodes = await _service.ConfirmTotpAsync(
            userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));

        var loginResult = await _service.LoginFirstFactorAsync(
            "recovery-valid@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        var verifiedUserId = await _service.VerifyMfaAsync(
            loginResult.Challenge!.ChallengeToken, recoveryCodes.Codes[0], "127.0.0.1", "Agent/1.0");

        verifiedUserId.Should().Be(userId);
    }

    [Fact]
    public async Task VerifyMfaAsync_ReusedRecoveryCode_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("recovery-reuse@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var recoveryCodes = await _service.ConfirmTotpAsync(
            userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));
        var plainCode = recoveryCodes.Codes[0];

        var login1 = await _service.LoginFirstFactorAsync(
            "recovery-reuse@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");
        await _service.VerifyMfaAsync(login1.Challenge!.ChallengeToken, plainCode, "127.0.0.1", "Agent/1.0");

        var login2 = await _service.LoginFirstFactorAsync(
            "recovery-reuse@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");
        var act = async () => await _service.VerifyMfaAsync(
            login2.Challenge!.ChallengeToken, plainCode, "127.0.0.1", "Agent/1.0");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task RegenerateRecoveryCodesAsync_ReplacesOriginalCodes()
    {
        var userId = await RegisterAndActivateAsync("regen@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        var original = await _service.ConfirmTotpAsync(
            userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));

        var regenerated = await _service.RegenerateRecoveryCodesAsync(userId);

        regenerated.Codes.Should().HaveCount(5);
        regenerated.Codes.Should().NotIntersectWith(original.Codes);
    }

    [Fact]
    public async Task RegenerateRecoveryCodesAsync_MfaNotEnabled_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("regen-fail@example.com");

        var act = async () => await _service.RegenerateRecoveryCodesAsync(userId);
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*MFA is not enabled*");
    }

    // -------------------------------------------------------------------------
    // Email OTP
    // -------------------------------------------------------------------------

    [Fact]
    public async Task SetupOtpAsync_EmailOtp_EnablesMfaAndReturnsRecoveryCodes()
    {
        var userId = await RegisterAndActivateAsync("otp-setup@example.com");

        var result = await _service.SetupOtpAsync(userId, MfaMethod.EmailOtp);

        result.Codes.Should().HaveCount(5);
        var cred = _context.UserCredentials.First(c => c.UserId == userId);
        cred.MfaEnabled.Should().BeTrue();
        cred.MfaMethod.Should().Be(MfaMethod.EmailOtp);
    }

    [Fact]
    public async Task VerifyMfaAsync_EmailOtpCode_Succeeds()
    {
        var userId = await RegisterAndActivateAsync("otp-verify@example.com");
        await _service.SetupOtpAsync(userId, MfaMethod.EmailOtp);

        var loginResult = await _service.LoginFirstFactorAsync(
            "otp-verify@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        var otpCode = _emailSender.LastOtpCode!;
        otpCode.Should().NotBeNullOrEmpty();

        var verifiedUserId = await _service.VerifyMfaAsync(
            loginResult.Challenge!.ChallengeToken, otpCode, "127.0.0.1", "Agent/1.0");

        verifiedUserId.Should().Be(userId);
    }

    [Fact]
    public async Task SetupOtpAsync_InvalidMethod_ThrowsValidation()
    {
        var userId = await RegisterAndActivateAsync("otp-invalid@example.com");

        var act = async () => await _service.SetupOtpAsync(userId, MfaMethod.Totp);
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*Method must be*");
    }

    // -------------------------------------------------------------------------
    // DisableMfaAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task DisableMfaAsync_ClearsMfaFromCredential()
    {
        var userId = await RegisterAndActivateAsync("disable@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));

        await _service.DisableMfaAsync(userId);

        var cred = _context.UserCredentials.First(c => c.UserId == userId);
        cred.MfaEnabled.Should().BeFalse();
        _context.RecoveryCodes.Count(c => c.UserId == userId && c.UsedAt == null).Should().Be(0);
    }

    [Fact]
    public async Task LoginFirstFactorAsync_AfterDisableMfa_SucceedsWithoutChallenge()
    {
        var userId = await RegisterAndActivateAsync("disable-login@example.com");
        var setup = await _service.SetupTotpAsync(userId);
        await _service.ConfirmTotpAsync(userId, ComputeTotp(ExtractTotpSecret(setup.QrUri)));
        await _service.DisableMfaAsync(userId);

        var result = await _service.LoginFirstFactorAsync(
            "disable-login@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        result.Succeeded.Should().BeTrue();
        result.Challenge.Should().BeNull();
    }

    // -------------------------------------------------------------------------
    // Mandatory MFA grace period
    // -------------------------------------------------------------------------

    [Fact]
    public async Task LoginFirstFactorAsync_MandatoryMfa_FirstEncounter_ReturnsGracePeriod()
    {
        var (ctx, conn) = DbContextFactory.Create();
        using var _ = conn;
        using var __ = ctx;

        var mandatoryEmailSender = new CapturingEmailSender();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<BedrockContext>(ctx);
        services.AddSingleton<IEmailSender>(mandatoryEmailSender);
        services.AddBedrockEntityFramework<BedrockContext>();
        services.AddBedrockAspNetCore(opts =>
        {
            opts.Jwt.SigningKey = TestSigningKey;
            opts.Jwt.Issuer = "test";
            opts.Jwt.Audience = "test";
            opts.Password.MinLength = 12;
            opts.Mfa.MandatoryRoles.Add("admin");
            opts.Mfa.GracePeriodDays = 14;
        });
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        var svc = services.BuildServiceProvider().GetRequiredService<ICredentialService>();

        var userId = Guid.NewGuid();
        await svc.RegisterAsync(userId, "mandatory@example.com", ValidPassword);
        // The real raw token a user would receive by email (not the stored hash).
        var rawToken = Crestacle.Bedrock.Tests.Integration.Infrastructure.CapturingEmailSender
            .ExtractToken(mandatoryEmailSender.LastVerificationUrl!);
        await svc.ConfirmEmailAsync(rawToken);

        var result = await svc.LoginFirstFactorAsync(
            "mandatory@example.com", ValidPassword, "127.0.0.1", "Agent/1.0", "fp1");

        result.Succeeded.Should().BeTrue();
        result.MfaGracePeriodEndsAt.Should().NotBeNull();
        result.MfaGracePeriodEndsAt!.Value.Should().BeCloseTo(DateTime.UtcNow.AddDays(14), TimeSpan.FromMinutes(1));
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}
