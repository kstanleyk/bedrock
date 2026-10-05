using Crestacle.Bedrock.AspNetCore.Extensions;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Services;

public sealed class CredentialServiceTests : IDisposable
{
    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly ICredentialService _service;
    private readonly CapturingEmailSender _emailSender = new();

    private const string ValidPassword = "ValidP@ssword1!";

    public CredentialServiceTests()
    {
        (_context, _connection) = DbContextFactory.Create();

        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<BedrockContext>(_context)
            .AddSingleton<IEmailSender>(_emailSender)
            .AddBedrockEntityFramework<BedrockContext>()
            .AddBedrockAspNetCore(opts =>
            {
                opts.Jwt.SigningKey = "Bedrock-Integration-Test-Signing-Key-32B!";
                opts.Jwt.Issuer = "test";
                opts.Jwt.Audience = "test";
                opts.Password.MinLength = 12;
                opts.Password.HistoryDepth = 3;
                opts.Lockout.MaxFailedAttempts = 3;
                opts.Lockout.Duration = TimeSpan.FromSeconds(30);
                opts.TokenExpiry.EmailVerificationToken = TimeSpan.FromHours(24);
                opts.TokenExpiry.PasswordResetToken = TimeSpan.FromHours(1);
            })
            .BuildServiceProvider();

        _service = services.GetRequiredService<ICredentialService>();
    }

    // -------------------------------------------------------------------------
    // RegisterAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RegisterAsync_ValidInput_CreatesCredentialPendingVerification()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "user@example.com", ValidPassword);

        var credential = _context.UserCredentials.FirstOrDefault(c => c.UserId == userId);
        credential.Should().NotBeNull();
        credential!.Status.Should().Be(Core.Enumerations.AccountStatus.PendingVerification);
        credential.EmailConfirmed.Should().BeFalse();
    }

    [Fact]
    public async Task RegisterAsync_DuplicateEmail_ThrowsValidation()
    {
        await _service.RegisterAsync(Guid.NewGuid(), "dup@example.com", ValidPassword);

        var act = async () => await _service.RegisterAsync(Guid.NewGuid(), "dup@example.com", ValidPassword);
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    [Fact]
    public async Task RegisterAsync_WeakPassword_ThrowsValidation()
    {
        var act = async () => await _service.RegisterAsync(Guid.NewGuid(), "weak@example.com", "weak");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    // -------------------------------------------------------------------------
    // ConfirmEmailAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ConfirmEmailAsync_ValidToken_SetsEmailConfirmedAndActiveStatus()
    {
        var userId = Guid.NewGuid();
        const string email = "confirm@example.com";
        await _service.RegisterAsync(userId, email, ValidPassword);

        // The real raw token a user would receive by email — RegisterAsync hashes it before
        // storing, so confirming with this (not the stored hash) is the real round trip.
        var rawToken = CapturingEmailSender.ExtractToken(_emailSender.LastBodyFor(email)!);

        await _service.ConfirmEmailAsync(rawToken);

        var credential = _context.UserCredentials.First(c => c.UserId == userId);
        credential.EmailConfirmed.Should().BeTrue();
        credential.Status.Should().Be(Core.Enumerations.AccountStatus.Active);
    }

    [Fact]
    public async Task ConfirmEmailAsync_InvalidToken_ThrowsValidation()
    {
        var act = async () => await _service.ConfirmEmailAsync("nonexistent-token-hash");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    // -------------------------------------------------------------------------
    // ChangePasswordAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ChangePasswordAsync_CorrectCurrentPassword_UpdatesHash()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "change@example.com", ValidPassword);

        await _service.ChangePasswordAsync(userId, ValidPassword, "NewP@ssword1!", "127.0.0.1");

        var credential = _context.UserCredentials.First(c => c.UserId == userId);
        credential.PasswordHash.Should().NotBeNullOrEmpty();
        credential.PasswordChangedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task ChangePasswordAsync_WrongCurrentPassword_ThrowsValidation()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "changefail@example.com", ValidPassword);

        var act = async () => await _service.ChangePasswordAsync(userId, "WrongP@ss1!", "NewP@ssword1!", "127.0.0.1");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*Current password is incorrect*");
    }

    [Fact]
    public async Task ChangePasswordAsync_PasswordInHistory_ThrowsValidation()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "history@example.com", ValidPassword);

        var act = async () => await _service.ChangePasswordAsync(userId, ValidPassword, ValidPassword, "127.0.0.1");
        await act.Should().ThrowAsync<BedrockValidationException>()
            .WithMessage("*used recently*");
    }

    // -------------------------------------------------------------------------
    // RequestPasswordResetAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RequestPasswordResetAsync_UnknownEmail_DoesNotThrow()
    {
        var act = async () => await _service.RequestPasswordResetAsync("nobody@example.com");
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RequestPasswordResetAsync_KnownEmail_CreatesResetToken()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "reset@example.com", ValidPassword);

        await _service.RequestPasswordResetAsync("reset@example.com");

        _context.PasswordResetTokens.Any(t => t.UserId == userId).Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // ResetPasswordAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ResetPasswordAsync_InvalidToken_ThrowsValidation()
    {
        var act = async () => await _service.ResetPasswordAsync("bad-token", "NewP@ssword1!", "127.0.0.1");
        await act.Should().ThrowAsync<BedrockValidationException>();
    }

    // -------------------------------------------------------------------------
    // LoginFirstFactorAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task LoginFirstFactorAsync_CorrectCredentials_Succeeds()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "login@example.com", ValidPassword);

        var result = await _service.LoginFirstFactorAsync("login@example.com", ValidPassword, "127.0.0.1", "TestAgent/1.0", "fp1");

        result.Succeeded.Should().BeTrue();
        result.UserId.Should().Be(userId);
    }

    [Fact]
    public async Task LoginFirstFactorAsync_WrongPassword_Fails()
    {
        await _service.RegisterAsync(Guid.NewGuid(), "loginfail@example.com", ValidPassword);

        var result = await _service.LoginFirstFactorAsync("loginfail@example.com", "WrongP@ss1!", "127.0.0.1", "TestAgent/1.0", "fp1");

        result.Succeeded.Should().BeFalse();
        result.IsLockedOut.Should().BeFalse();
    }

    [Fact]
    public async Task LoginFirstFactorAsync_UnknownEmail_Fails()
    {
        var result = await _service.LoginFirstFactorAsync("ghost@example.com", ValidPassword, "127.0.0.1", "TestAgent/1.0", "fp1");
        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task LoginFirstFactorAsync_ExceedsMaxAttempts_ReturnsLocked()
    {
        await _service.RegisterAsync(Guid.NewGuid(), "lockout@example.com", ValidPassword);

        for (var i = 0; i < 3; i++)
            await _service.LoginFirstFactorAsync("lockout@example.com", "WrongP@ss1!", "127.0.0.1", "TestAgent/1.0", "fp1");

        var result = await _service.LoginFirstFactorAsync("lockout@example.com", ValidPassword, "127.0.0.1", "TestAgent/1.0", "fp1");

        result.IsLockedOut.Should().BeTrue();
        result.LockoutEnd.Should().NotBeNull();
    }

    [Fact]
    public async Task LoginFirstFactorAsync_SuccessfulLogin_ResetsFailedAttempts()
    {
        var userId = Guid.NewGuid();
        await _service.RegisterAsync(userId, "reset-counter@example.com", ValidPassword);

        await _service.LoginFirstFactorAsync("reset-counter@example.com", "WrongP@ss1!", "127.0.0.1", "TestAgent/1.0", "fp1");
        await _service.LoginFirstFactorAsync("reset-counter@example.com", ValidPassword, "127.0.0.1", "TestAgent/1.0", "fp1");

        var credential = _context.UserCredentials.First(c => c.UserId == userId);
        credential.FailedLoginAttempts.Should().Be(0);
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }
}
