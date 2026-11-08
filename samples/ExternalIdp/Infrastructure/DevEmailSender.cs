using Crestacle.Bedrock.Core.Interfaces;

namespace ExternalIdp.Infrastructure;

/// <summary>
/// Logs emails to the console instead of sending them.
/// Replace with a real implementation for production.
/// </summary>
public class DevEmailSender(ILogger<DevEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string htmlBody,
        CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] To: {To} | Subject: {Subject}\n{Body}",
            to, subject, htmlBody);
        return Task.CompletedTask;
    }

    public Task SendEmailVerificationAsync(string toEmail, string verificationUrl, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Verification link for {ToEmail}: {VerificationUrl}", toEmail, verificationUrl);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string toEmail, string resetUrl, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Password reset link for {ToEmail}: {ResetUrl}", toEmail, resetUrl);
        return Task.CompletedTask;
    }

    public Task SendAccountLockedAsync(string toEmail, DateTime lockoutEnd, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Account locked for {ToEmail} until {LockoutEnd}", toEmail, lockoutEnd);
        return Task.CompletedTask;
    }

    public Task SendMfaOtpAsync(string toEmail, string code, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] MFA OTP for {ToEmail}: {Code}", toEmail, code);
        return Task.CompletedTask;
    }

    public Task SendEmailChangeVerificationAsync(string newEmail, string confirmationUrl, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Email change confirmation for {NewEmail}: {ConfirmationUrl}", newEmail, confirmationUrl);
        return Task.CompletedTask;
    }

    public Task SendEmailChangeNotificationAsync(string oldEmail, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Email change notification sent to old address {OldEmail}", oldEmail);
        return Task.CompletedTask;
    }

    public Task SendMagicLinkAsync(string toEmail, string magicLinkUrl, CancellationToken ct = default)
    {
        logger.LogInformation("[EMAIL] Magic link for {ToEmail}: {MagicLinkUrl}", toEmail, magicLinkUrl);
        return Task.CompletedTask;
    }
}
