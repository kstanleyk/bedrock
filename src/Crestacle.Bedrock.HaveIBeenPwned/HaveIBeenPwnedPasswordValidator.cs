using System.Security.Cryptography;
using System.Text;
using Crestacle.Bedrock.Core.Interfaces.Services;

namespace Crestacle.Bedrock.HaveIBeenPwned;

/// <summary>
/// Decorates an inner <see cref="IPasswordValidator"/> with a Have I Been Pwned k-anonymity
/// breach check. Complexity rules and history checks are delegated to the inner validator.
/// The HIBP API call is fail-open: a network failure never blocks registration.
/// </summary>
/// <remarks>
/// The HIBP range lookup is awaited directly, end-to-end, through <see cref="IsValidAsync"/> --
/// there is no <c>Task.Run(...).GetAwaiter().GetResult()</c> sync-over-async bridge here. That
/// bridge previously existed because <see cref="IPasswordValidator"/> exposed only a synchronous
/// <c>bool IsValid(...)</c> member; every caller of this validator (<c>CredentialService</c>,
/// <c>BedrockAdminService</c>) already runs inside an async method with a <see cref="CancellationToken"/>
/// in scope, so the interface itself was converted to async instead of keeping the bridge.
/// </remarks>
public sealed class HaveIBeenPwnedPasswordValidator : IPasswordValidator
{
    private const string BreachMessage =
        "This password has appeared in a known data breach. Please choose a different password.";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IPasswordValidator _inner;

    public HaveIBeenPwnedPasswordValidator(IHttpClientFactory httpClientFactory, IPasswordValidator inner)
    {
        _httpClientFactory = httpClientFactory;
        _inner = inner;
    }

    /// <inheritdoc/>
    public async Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default)
    {
        var (innerValid, innerErrors) = await _inner.IsValidAsync(password, ct).ConfigureAwait(false);
        if (!innerValid)
            return (false, innerErrors);

        try
        {
            var breached = await IsBreachedAsync(password, ct).ConfigureAwait(false);
            if (breached)
                return (false, [BreachMessage]);
        }
        catch
        {
            // fail-open: any exception (network, timeout, parse) → let the password through
        }

        return (true, innerErrors);
    }

    /// <inheritdoc/>
    public Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default)
        => _inner.IsPreviouslyUsedAsync(password, hashes, ct);

    private async Task<bool> IsBreachedAsync(string password, CancellationToken ct)
    {
        var hash = ComputeSha1Hex(password);
        var prefix = hash[..5];
        var suffix = hash[5..];

        var client = _httpClientFactory.CreateClient("hibp");
        var body = await client.GetStringAsync($"/range/{prefix}", ct).ConfigureAwait(false);

        // Each line is "<35-char-suffix>:<count>". A case-insensitive search for the suffix
        // string within the body is sufficient: the 35-char hex suffix won't collide with counts.
        return body.Contains(suffix, StringComparison.OrdinalIgnoreCase);
    }

    private static string ComputeSha1Hex(string password)
    {
        var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(bytes); // uppercase hex
    }
}
