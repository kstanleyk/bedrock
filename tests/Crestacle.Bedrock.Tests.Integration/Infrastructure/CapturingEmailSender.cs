using System.Text.RegularExpressions;
using Crestacle.Bedrock.Core.Interfaces;

namespace Crestacle.Bedrock.Tests.Integration.Infrastructure;

/// <summary>
/// Captures the URL/body passed to each <see cref="IEmailSender"/> call, keyed by recipient, so
/// tests can extract the real raw token a user would actually receive by email — instead of
/// reading the stored token hash directly from the database and feeding that back in as if it
/// were the client-supplied value. The latter pattern doesn't exercise the real round trip (the
/// service must hash the raw token before comparing against the stored hash) and previously
/// masked a real bug where several Confirm/Reset/Accept/Verify methods skipped that hashing step.
/// </summary>
internal sealed class CapturingEmailSender : IEmailSender
{
    private readonly Dictionary<string, string> _lastBodyByEmail = new();

    public string? LastBodyFor(string email) => _lastBodyByEmail.GetValueOrDefault(email);

    /// <summary>Extracts the raw token from a captured URL or message body containing `?token=...`.</summary>
    public static string ExtractToken(string urlOrBody)
    {
        var match = Regex.Match(urlOrBody, "token=([^&\\s]+)");
        if (!match.Success)
            throw new InvalidOperationException($"No token found in captured email content: {urlOrBody}");
        return Uri.UnescapeDataString(match.Groups[1].Value);
    }

    public Task SendEmailVerificationAsync(string toEmail, string verificationUrl, CancellationToken ct = default)
    {
        _lastBodyByEmail[toEmail] = verificationUrl;
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string toEmail, string resetUrl, CancellationToken ct = default)
    {
        _lastBodyByEmail[toEmail] = resetUrl;
        return Task.CompletedTask;
    }

    public Task SendAccountLockedAsync(string toEmail, DateTime lockoutEnd, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task SendMfaOtpAsync(string toEmail, string code, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default)
    {
        _lastBodyByEmail[toEmail] = htmlBody;
        return Task.CompletedTask;
    }

    public Task SendEmailChangeVerificationAsync(string newEmail, string confirmationUrl, CancellationToken ct = default)
    {
        _lastBodyByEmail[newEmail] = confirmationUrl;
        return Task.CompletedTask;
    }

    public Task SendEmailChangeNotificationAsync(string oldEmail, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task SendMagicLinkAsync(string toEmail, string magicLinkUrl, CancellationToken ct = default)
    {
        _lastBodyByEmail[toEmail] = magicLinkUrl;
        return Task.CompletedTask;
    }
}
