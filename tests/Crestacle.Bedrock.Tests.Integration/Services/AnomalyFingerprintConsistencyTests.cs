using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Services;

/// <summary>
/// Regression coverage for the anomaly-detector fingerprint scheme being inconsistent across
/// first-factor paths: LoginFirstFactorAsync's anomaly check is keyed on the client-supplied
/// fingerprintHash, but VerifyMfaAsync/VerifyMagicLinkAsync used to record a known-device row
/// under AnomalyDetector.ComputeFingerprint(userAgent, ip) instead -- a completely different
/// value space. A device recorded via one of those paths was therefore never recognized by a
/// later plain-password login using the same real fingerprint, permanently flagging it anomalous.
/// </summary>
public sealed class AnomalyFingerprintConsistencyTests : IDisposable
{
    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly ICredentialService _credentialService;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";
    private const string TestSigningKey = "Bedrock-Integration-Test-Signing-Key-32B!";

    public AnomalyFingerprintConsistencyTests()
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
            opts.AnomalyDetection.Enabled = true;
            // Global mandatory-MFA switch (see MfaOptions.MandatoryRoles's own doc comment):
            // puts a not-yet-enrolled user on the grace-period path, the one VerifyMagicLinkAsync
            // branch that calls RecordDeviceAsync while credential.MfaEnabled is still false --
            // the exact combination needed to observe the anomaly check on a LATER plain-password
            // login for the same account.
            opts.Mfa.MandatoryRoles = ["any-role"];
        });
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

        _credentialService = services.BuildServiceProvider().GetRequiredService<ICredentialService>();
    }

    private async Task<Guid> RegisterAndActivateAsync(string email)
    {
        var userId = Guid.NewGuid();
        await _credentialService.RegisterAsync(userId, email, ValidPassword);
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);
        await _credentialService.ConfirmEmailAsync(rawToken);
        return userId;
    }

    [Fact]
    public async Task DeviceRecordedDuringMagicLinkVerify_IsRecognizedByALaterPlainPasswordLogin()
    {
        const string email = "anomaly-fingerprint-consistency@example.com";
        const string fingerprint = "the-real-client-fingerprint";
        await RegisterAndActivateAsync(email);

        await _credentialService.RequestMagicLinkAsync(email, "1.2.3.4", "TestAgent/1.0");
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

        // First encounter: grace-period path records the device under `fingerprint`.
        var magicLinkResult = await _credentialService.VerifyMagicLinkAsync(
            rawToken, "1.2.3.4", "TestAgent/1.0", fingerprint);
        magicLinkResult.Succeeded.Should().BeTrue();
        magicLinkResult.MfaGracePeriodEndsAt.Should().NotBeNull();

        // A later plain-password login presenting the SAME real fingerprint must be recognized
        // as the same known device -- not forced into an anomaly-triggered OTP challenge, which
        // is what happens if the device was actually recorded under a different value space.
        var loginResult = await _credentialService.LoginFirstFactorAsync(
            email, ValidPassword, "1.2.3.4", "TestAgent/1.0", fingerprint);

        loginResult.Succeeded.Should().BeTrue();
        loginResult.Challenge.Should().BeNull(
            "the device fingerprint recorded during magic-link verification must match the " +
            "one LoginFirstFactorAsync's anomaly check uses, so this same device is recognized " +
            "and not forced into an unnecessary anomaly OTP challenge");
        loginResult.MfaGracePeriodEndsAt.Should().NotBeNull("still within the mandatory-MFA grace period");
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}
